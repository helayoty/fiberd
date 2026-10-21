//! The zygote's own mount namespace and what fills it before READY.
//! own_mountns (from fz_init) takes the namespace and prepare_ns (at
//! PREPARE mntns) fills it with what every mntns fiber must see.
//! cap_nested_userns denies nested user namespaces when fiberd asks.
//! All of it runs on the serving thread before any fiber is born. Every
//! open, mount, umount2 and raw system call goes through the sys seam,
//! so the fuzz harnesses can shim it.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use crate::child::{CAPABILITY_U32S_3, CAPABILITY_VERSION_3, CapData, CapHeader, prctl};
use crate::ctl::{self, Line, STRERROR_MAX};
use crate::mounts::{self, F_DROP, F_HIDE, F_RO, F_RUNDIR};
use crate::procfiles::{self, mountinfo_carry, mountinfo_next_sys};
use crate::sys::{self, Errno};
use crate::zygote::{Refused, Zygote, c_str, env_set, set_cstr};

/// What realpath promises to write at most.
const PATH_MAX: usize = libc::PATH_MAX as usize;
const _: () = assert!(
    PATH_MAX <= crate::abi::KEEP_MAX,
    "a realpath result fits a kept path"
);

/// The knob cap_nested_userns writes, under a proc mount.
const KNOB: &[u8] = b"sys/user/max_user_namespaces";
/// CAP_SYS_RESOURCE and CAP_SYS_ADMIN in linux/capability.h, which libc
/// does not carry.
const CAP_SYS_RESOURCE: u32 = 24;
const CAP_SYS_ADMIN: u32 = 21;

/// Fills buf with the parts, NUL-ended and cut to what fits.
fn fill(buf: &mut [u8], parts: &[&[u8]]) {
    let cap = buf.len().saturating_sub(1);
    let mut n = 0usize;
    for p in parts {
        let room = cap.saturating_sub(n);
        n = sys::append(buf, n, p.get(..room).unwrap_or(p));
    }
    if let Some(end) = buf.get_mut(n.min(cap)) {
        *end = 0;
    }
}

/// errno as decimal text, for the "errno %d" reasons.
fn errno_decimal(e: c_int) -> ([u8; 11], usize) {
    let mut d = [0u8; 11];
    let mut n = 0;
    if e < 0 {
        n = sys::append(&mut d, 0, b"-");
    }
    let n = sys::append_decimal(&mut d, n, e.unsigned_abs());
    (d, n)
}

/// The number of threads of this process, or -1 when /proc/self/task
/// cannot be read. getdents64 into a stack buffer, since opendir
/// allocates.
pub fn thread_count() -> c_int {
    // SAFETY: a static NUL-ended path.
    let fd = unsafe {
        sys::open(
            c"/proc/self/task".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return -1;
    }
    // struct linux_dirent64: d_ino u64, d_off i64, d_reclen u16 at 16,
    // d_type u8 at 18, d_name at 19.
    const RECLEN_AT: usize = 16;
    const NAME_AT: usize = 19;
    let mut n: c_int = 0;
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is live and buf.len() bytes long, and getdents64
        // writes at most that much into it.
        let got = unsafe {
            sys::syscall(
                libc::SYS_getdents64,
                [
                    c_long::from(fd),
                    buf.as_mut_ptr() as c_long,
                    buf.len() as c_long,
                    0,
                    0,
                ],
            )
        };
        let Some(got) = usize::try_from(got).ok().filter(|&g| g > 0) else {
            break;
        };
        let mut off = 0usize;
        while off < got {
            let (Some(&lo), Some(&hi)) = (
                buf.get(off.wrapping_add(RECLEN_AT)),
                buf.get(off.wrapping_add(RECLEN_AT).wrapping_add(1)),
            ) else {
                break;
            };
            let reclen = usize::from(u16::from_ne_bytes([lo, hi]));
            if reclen == 0 {
                break;
            }
            if buf
                .get(off.wrapping_add(NAME_AT))
                .is_some_and(|&c| c != b'.')
            {
                n = n.wrapping_add(1);
            }
            off = off.wrapping_add(reclen);
        }
    }
    // SAFETY: the descriptor opened above.
    unsafe { libc::close(fd) };
    n
}

/// lock_sys makes every mount under /sys read-only in place, once, in
/// the zygote's namespace, and every fiber's copy carries the flags. The
/// fiber is euid 0 with no capability, and kernfs checks only the owner
/// write bit for euid 0, so without this /sys/fs/cgroup would lift its
/// own and other grants' limits. Changing flags rather than stacking
/// binds keeps the tree CRIU dumps the same shape, and CRIU restores the
/// flags, so a resumed fiber is as closed as a born one.
///
/// mountinfo is read into a stack buffer, allocating nothing. A line
/// longer than the buffer is skipped rather than misread as several.
/// Every mount is tried even after a refusal, so as little as possible
/// stays writable. Returns 0, or -1 when any step failed.
pub fn lock_sys() -> c_int {
    let mut rc = 0;
    // SAFETY: a static NUL-ended path.
    let fd = unsafe {
        sys::open(
            c"/proc/self/mountinfo".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return -1;
    }
    let mut buf = [0u8; 8192];
    let mut have = 0usize;
    let mut skipping = false; // inside a line too long for buf
    loop {
        let room = buf.get_mut(have..).unwrap_or(&mut []);
        // SAFETY: read writes at most room.len() bytes of room, which is
        // live. An empty room reads 0 and ends the loop.
        let n = unsafe { libc::read(fd, room.as_mut_ptr().cast(), room.len()) };
        if n < 0 {
            if sys::errno() == libc::EINTR {
                continue;
            }
            rc = -1;
            break;
        }
        let Some(n) = usize::try_from(n).ok().filter(|&n| n > 0) else {
            break; // EOF. mountinfo ends every line with '\n'
        };
        have = have.wrapping_add(n);
        // Remount each complete line's mount point under /sys, then
        // carry the partial line to the front.
        let mut start = 0usize;
        while let Some(mp) = mountinfo_next_sys(&mut buf, have, &mut start, &mut skipping) {
            // SAFETY: the mount point is NUL-ended in buf, which is live.
            if unsafe { mounts::ro_remount(buf.as_ptr().wrapping_add(mp.off).cast()) } < 0 {
                rc = -1;
            }
        }
        have = mountinfo_carry(&mut buf, have, start, &mut skipping);
    }
    let e = sys::errno();
    // SAFETY: the descriptor opened above.
    unsafe { libc::close(fd) };
    sys::set_errno(e);
    // /sys/firmware (DMI, EFI, ACPI tables) says what the node is.
    // Covered, as runc and Docker mask it.
    // SAFETY: a static NUL-ended path.
    if unsafe { mounts::cover_empty(c"/sys/firmware".as_ptr()) } < 0 {
        rc = -1;
    }
    rc
}

/// Whether this process runs in a user namespace other than the
/// initial one, read from its uid_map.
pub fn in_child_userns() -> bool {
    let mut buf = [0u8; 128];
    // SAFETY: a static NUL-ended path.
    let fd = unsafe {
        sys::open(
            c"/proc/self/uid_map".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    // SAFETY: read writes at most 127 bytes of buf, which is live.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len().wrapping_sub(1)) };
    // SAFETY: the descriptor opened above.
    unsafe { libc::close(fd) };
    let Some(n) = usize::try_from(n).ok().filter(|&n| n > 0) else {
        return false;
    };
    if let Some(end) = buf.get_mut(n) {
        *end = 0;
    }
    procfiles::in_child_userns(&buf)
}

/// Writes val to the file at path, whole. 0, or -1 with errno, EIO for
/// a short write.
///
/// # Safety
/// path is NUL-ended and live for the call.
unsafe fn write_str(path: *const c_char, val: &[u8]) -> c_int {
    // SAFETY: by the contract above.
    let fd = unsafe { sys::open(path, libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return -1;
    }
    // SAFETY: write reads val.len() bytes of val, which is live.
    let n = unsafe { libc::write(fd, val.as_ptr().cast(), val.len()) };
    let saved = sys::errno();
    // SAFETY: the descriptor opened above.
    unsafe { libc::close(fd) };
    if usize::try_from(n) != Ok(val.len()) {
        sys::set_errno(if n < 0 { saved } else { libc::EIO });
        return -1;
    }
    0
}

/// A stderr line that ends in strerror(e).
fn complain(what: &[u8], e: c_int) {
    let mut buf = [0u8; STRERROR_MAX];
    let why = ctl::strerror(e, &mut buf);
    Line::new()
        .s(b"libfiberzygote: ")
        .s(what)
        .s(b": ")
        .s(why)
        .stderr();
}

/// cap_nested_userns sets user.max_user_namespaces to 0 in this user
/// namespace, so no fiber can make one and be capable again, then drops
/// CAP_SYS_RESOURCE, which would let a fiber raise the limit back. It is
/// refused in the initial namespace, where the write would reach the
/// host. A read-only /proc/sys (a container's default) is bypassed
/// through a short-lived proc mount. Ok, or the errno with a line on
/// stderr.
pub fn cap_nested_userns() -> Result<(), Errno> {
    if !in_child_userns() {
        Line::new()
            .s(b"libfiberzygote: FIBERD_USERNS_NESTED is set outside a user namespace; refusing to touch the host's limit")
            .stderr();
        return Err(Errno(libc::EPERM));
    }
    let direct = c"/proc/sys/user/max_user_namespaces";
    // SAFETY: a static NUL-ended path.
    let mut rc = unsafe { write_str(direct.as_ptr(), b"0") };
    if rc < 0 && (sys::errno() == libc::EROFS || sys::errno() == libc::EACCES) {
        let mut dir = *b"/tmp/.fz-proc-XXXXXX\0";
        // SAFETY: dir is a live NUL-ended template mkdtemp fills in place.
        if unsafe { libc::mkdtemp(dir.as_mut_ptr().cast()) }.is_null() {
            let e = Errno::last();
            complain(b"scratch for a proc mount", e.0);
            return Err(e);
        }
        // SAFETY: dir is NUL-ended and live, the rest static strings.
        if unsafe {
            sys::mount(
                c"proc".as_ptr(),
                dir.as_ptr().cast(),
                c"proc".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                ptr::null(),
            )
        } < 0
        {
            let e = Errno::last();
            let mut what = [0u8; 64];
            fill(&mut what, &[b"mount proc at ", c_str(&dir)]);
            complain(c_str(&what), e.0);
            // SAFETY: dir is NUL-ended and live.
            unsafe { libc::rmdir(dir.as_ptr().cast()) };
            return Err(e);
        }
        let mut path = [0u8; 192];
        fill(&mut path, &[c_str(&dir), b"/", KNOB]);
        // SAFETY: path is NUL-ended and live.
        rc = unsafe { write_str(path.as_ptr().cast(), b"0") };
        let saved = sys::errno();
        // SAFETY: dir is NUL-ended and live.
        unsafe {
            sys::umount2(dir.as_ptr().cast(), libc::MNT_DETACH);
            libc::rmdir(dir.as_ptr().cast());
        }
        sys::set_errno(saved);
    }
    if rc < 0 {
        let e = Errno::last();
        complain(b"user.max_user_namespaces=0", e.0);
        return Err(e);
    }
    // Read back through the regular /proc, which may be read-only but
    // is readable, so a write that landed elsewhere is caught.
    let mut got = [0u8; 32];
    // SAFETY: a static NUL-ended path.
    let fd = unsafe { sys::open(direct.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd >= 0 {
        // SAFETY: read writes at most 31 bytes of got, which is live.
        let n = unsafe { libc::read(fd, got.as_mut_ptr().cast(), got.len().wrapping_sub(1)) };
        if let Some(end) = usize::try_from(n)
            .ok()
            .filter(|&n| n > 0)
            .and_then(|n| got.get_mut(n))
        {
            *end = 0;
        }
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
    }
    let text = c_str(&got);
    let mut at = 0usize;
    let value = procfiles::scan_ulong(text, &mut at).unwrap_or(0);
    if value != 0 || text.is_empty() {
        Line::new()
            .s(b"libfiberzygote: user.max_user_namespaces reads ")
            .s(if text.is_empty() { b"nothing" } else { text })
            .s(b" after the write")
            .stderr();
        return Err(Errno(libc::EIO));
    }
    // SAFETY: integer arguments alone.
    if unsafe { prctl(libc::PR_CAPBSET_DROP, CAP_SYS_RESOURCE as libc::c_ulong, 0) } < 0 {
        let e = Errno::last();
        complain(b"drop CAP_SYS_RESOURCE from the bounding set", e.0);
        return Err(e);
    }
    let h = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; CAPABILITY_U32S_3];
    // SAFETY: h and d are live and laid out as capget writes them.
    if unsafe {
        sys::syscall(
            libc::SYS_capget,
            [(&raw const h) as c_long, d.as_mut_ptr() as c_long, 0, 0, 0],
        )
    } < 0
    {
        return Err(Errno::last());
    }
    // CAP_TO_INDEX(24) is 0 and CAP_TO_MASK(24) is 1 << 24.
    let mask: u32 = !(1u32 << (CAP_SYS_RESOURCE & 31));
    if let Some(w) = d.get_mut((CAP_SYS_RESOURCE >> 5) as usize) {
        w.effective &= mask;
        w.permitted &= mask;
        w.inheritable &= mask;
    }
    // SAFETY: h and d are live and laid out as capset reads them.
    if unsafe {
        sys::syscall(
            libc::SYS_capset,
            [(&raw const h) as c_long, d.as_ptr() as c_long, 0, 0, 0],
        )
    } < 0
    {
        let e = Errno::last();
        complain(b"drop CAP_SYS_RESOURCE", e.0);
        return Err(e);
    }
    Ok(())
}

/// keep_only_sys_admin narrows the calling thread to CAP_SYS_ADMIN,
/// which every birth's CLONE_NEWPID needs and criu's parasite runs
/// with. The bounding set first, so no exec regains another, then the
/// ambient set cleared, then the effective and permitted sets to it
/// alone with inheritable empty. It acts on this thread, the one every
/// fiber is forked from, so an engine thread started before fz_serve
/// keeps the container's capabilities and no fiber inherits them. Ok,
/// or the errno with a line on stderr.
pub fn keep_only_sys_admin() -> Result<(), Errno> {
    #[cfg(test)]
    if let Some(e) = *tests::FAKE_CAPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return if e == 0 { Ok(()) } else { Err(Errno(e)) };
    }
    narrow_to_sys_admin()
}

/// keep_only_sys_admin's work.
fn narrow_to_sys_admin() -> Result<(), Errno> {
    let zero: libc::c_ulong = 0;
    let mut c: libc::c_ulong = 0;
    // SAFETY: integer arguments alone, and the loop ends at the first
    // capability number the kernel does not know.
    while unsafe { prctl(libc::PR_CAPBSET_READ, c, zero) } >= 0 {
        // SAFETY: as above.
        if c != libc::c_ulong::from(CAP_SYS_ADMIN)
            && unsafe { prctl(libc::PR_CAPBSET_DROP, c, zero) } < 0
        {
            let e = Errno::last();
            complain(b"drop the bounding set to CAP_SYS_ADMIN", e.0);
            return Err(e);
        }
        c = c.wrapping_add(1);
    }
    // SAFETY: integer arguments alone.
    if unsafe {
        prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            zero,
        )
    } < 0
        && sys::errno() != libc::EINVAL
    {
        let e = Errno::last();
        complain(b"clear the ambient set", e.0);
        return Err(e);
    }
    let h = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; CAPABILITY_U32S_3];
    if let Some(w) = d.get_mut((CAP_SYS_ADMIN >> 5) as usize) {
        w.effective = 1u32 << (CAP_SYS_ADMIN & 31);
        w.permitted = w.effective;
    }
    // SAFETY: h and d are live and laid out as capset reads them.
    if unsafe {
        sys::syscall(
            libc::SYS_capset,
            [(&raw const h) as c_long, d.as_ptr() as c_long, 0, 0, 0],
        )
    } < 0
    {
        let e = Errno::last();
        complain(b"keep CAP_SYS_ADMIN alone", e.0);
        return Err(e);
    }
    Ok(())
}

impl Zygote<'_> {
    /// own_mountns moves the zygote into a private mount namespace of its
    /// own, which every mntns fiber's namespace copies. fiberd asks with
    /// FIBERD_OWN_MNTNS in the environment, since fz_init runs before
    /// fiberd's first line can be read.
    ///
    /// It must run from fz_init, before any thread exists. unshare moves
    /// the calling thread alone when the fs_struct is shared, and CRIU
    /// refuses a tree whose threads differ in namespace. Any refusal is
    /// kept in own_ns_why, and prepare_ns then fails closed.
    pub fn own_mountns(&mut self) {
        const TAIL: &[u8] = b", so the zygote took no mount namespace of its own";
        let why = &mut self.t.own_ns_why;
        if !env_set(c"FIBERD_OWN_MNTNS") {
            fill(why, &[b"FIBERD_OWN_MNTNS was not set", TAIL]);
            return;
        }
        let threads = thread_count();
        if threads != 1 {
            let what: &[u8] = if threads < 0 {
                b"the zygote cannot count its threads (/proc/self/task)"
            } else {
                b"a thread existed before fz_init"
            };
            fill(why, &[what, TAIL]);
            return;
        }
        // The raw syscall, so a fuzz harness that shims it keeps it
        // from running there.
        // SAFETY: integer arguments alone, and unshare moves this thread.
        if unsafe {
            sys::syscall(
                libc::SYS_unshare,
                [c_long::from(libc::CLONE_NEWNS), 0, 0, 0, 0],
            )
        } < 0
        {
            let (d, n) = errno_decimal(sys::errno());
            fill(
                why,
                &[
                    b"the zygote could not take a mount namespace of its own: unshare: errno ",
                    d.get(..n).unwrap_or(&[]),
                ],
            );
            return;
        }
        // SAFETY: static strings and nulls.
        if unsafe {
            sys::mount(
                ptr::null(),
                c"/".as_ptr(),
                ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                ptr::null(),
            )
        } < 0
        {
            let (d, n) = errno_decimal(sys::errno());
            fill(
                why,
                &[
                    b"the zygote could not make its mount namespace private: errno ",
                    d.get(..n).unwrap_or(&[]),
                ],
            );
            return;
        }
        self.st.have_own_ns = true;
    }

    /// The refusal for the first of prepare_ns's failed steps, in its
    /// order. A HIDE failure names the path and the error, since the
    /// cause is in fiberd's environment and fiberd's log is where it is
    /// read.
    pub fn prepare_why(
        &mut self,
        failed: c_int,
        hide_i: Option<usize>,
        hide_errno: c_int,
    ) -> Refused {
        if failed & F_RO != 0 {
            return Refused::Text(c"the zygote could not make /sys read-only in its namespace");
        }
        if failed & F_DROP != 0 {
            return Refused::Text(c"the zygote could not unmount a DROP path");
        }
        if failed & F_RUNDIR != 0 {
            return Refused::Text(c"the zygote could not narrow the run directory");
        }
        let path: &[u8] = hide_i
            .and_then(|i| self.t.hide.get(i))
            .map_or(b"?", |p| c_str(p));
        let mut buf = [0u8; STRERROR_MAX];
        let why = ctl::strerror(hide_errno, &mut buf);
        fill(
            &mut self.t.prepare_reason,
            &[
                b"the zygote could not cover a HIDE path (",
                path,
                b": ",
                why,
                b")",
            ],
        );
        Refused::Prepare
    }

    /// prepare_ns fills the zygote's namespace once, at PREPARE mntns.
    /// /sys goes read-only, DROP paths are unmounted, the run directory
    /// shows this grant's alone and HIDE directories are emptied (but
    /// for the zygote's own executable). Fibers copy the result, so a
    /// birth pays for nothing grant-wide.
    ///
    /// DROP comes before RUNDIR, so the restore root is gone before
    /// anything is mounted under it. RUNDIR comes before HIDE, so a HIDE
    /// path under another grant's directory is already gone.
    ///
    /// Fails closed. Any refused step, or no namespace of its own, sets
    /// paths_refused and fz_serve answers ERROR instead of READY. A line
    /// refused earlier keeps its reason. Returns 0, or -1.
    pub fn prepare_ns(&mut self) -> c_int {
        if self.st.paths_refused.is_some() {
            return -1;
        }
        if !self.st.have_own_ns {
            self.st.paths_refused = Some(if self.t.own_ns_why.first() != Some(&0) {
                Refused::OwnNs
            } else {
                Refused::Text(
                    c"fz_init did not run, so the zygote has no mount namespace of its own",
                )
            });
            return -1;
        }
        let mut failed = 0;
        let mut hide_i: Option<usize> = None;
        let mut hide_errno = 0;
        {
            let exe = &mut self.t.self_exe;
            // SAFETY: a static path, and exe has that many bytes with one
            // left for the NUL.
            let n = unsafe {
                libc::readlink(
                    c"/proc/self/exe".as_ptr(),
                    exe.as_mut_ptr().cast(),
                    exe.len().wrapping_sub(1),
                )
            };
            let n = usize::try_from(n).unwrap_or(0);
            if let Some(end) = exe.get_mut(n) {
                *end = 0;
            }
        }
        if lock_sys() < 0 {
            failed |= F_RO;
        }
        if mounts::drop_paths_now(self.t.drop.get(..self.st.ndrop).unwrap_or(&[])) < 0 {
            failed |= F_DROP;
        }
        if self.t.rundir_parent.first() != Some(&0) {
            // SAFETY: both are NUL-ended in their RUNDIR_MAX buffers.
            let rc = unsafe {
                mounts::narrow_rundir(
                    self.t.rundir_parent.as_ptr().cast(),
                    self.t.rundir_own.as_ptr().cast(),
                )
            };
            if rc < 0 {
                failed |= F_RUNDIR;
            }
        }
        // /proc/self/exe is resolved, so each HIDE path is too. With a
        // symlink in it the executable would not be bound back under the
        // cover. One that does not exist yet keeps its name.
        let nhide = self.st.nhide;
        for slot in self.t.hide.get_mut(..nhide).unwrap_or(&mut []) {
            let mut real = [0u8; PATH_MAX];
            // SAFETY: the slot is NUL-ended, and real has PATH_MAX bytes.
            if !unsafe { libc::realpath(slot.as_ptr().cast(), real.as_mut_ptr().cast()) }.is_null()
            {
                set_cstr(slot, c_str(&real));
            }
        }
        for i in 0..nhide {
            let Some(path) = self.t.hide.get(i) else {
                break;
            };
            // SAFETY: both NUL-ended in their storage.
            let c = unsafe {
                mounts::cover_hide(path.as_ptr().cast(), self.t.self_exe.as_ptr().cast())
            };
            if c < 0 && hide_i.is_none() {
                hide_i = Some(i);
                hide_errno = sys::errno();
            }
            if c < 0 {
                failed |= F_HIDE;
            }
            if let Some(covered) = self.t.hide_covered.get_mut(i) {
                *covered = u8::from(c > 0);
            }
        }
        if failed != 0 {
            let why = self.prepare_why(failed, hide_i, hide_errno);
            self.st.paths_refused = Some(why);
            return -1;
        }
        self.st.ns_prepared = true;
        0
    }

    /// cap_nested_userns as fz_serve runs it.
    pub fn cap_nested_userns(&mut self) -> Result<(), Errno> {
        #[cfg(test)]
        if let Some(e) = *tests::FAKE_NESTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return if e == 0 { Ok(()) } else { Err(Errno(e)) };
        }
        cap_nested_userns()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::type_complexity
    )]
    use super::*;
    use crate::zygote::{State, Tables};
    use std::sync::Mutex;

    /// What keep_only_sys_admin answers under test: 0 for Ok, else the
    /// errno. None runs the real drop. Changed only under crate::serial().
    pub(crate) static FAKE_CAPS: Mutex<Option<c_int>> = Mutex::new(Some(0));
    /// The same for Zygote::cap_nested_userns.
    pub(crate) static FAKE_NESTED: Mutex<Option<c_int>> = Mutex::new(None);

    /// The thread's capability sets, as capget gives them.
    fn capget() -> [CapData; CAPABILITY_U32S_3] {
        let h = CapHeader {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut d = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; CAPABILITY_U32S_3];
        // SAFETY: h and d are live and laid out as capget writes them.
        let r = unsafe {
            sys::syscall(
                libc::SYS_capget,
                [(&raw const h) as c_long, d.as_mut_ptr() as c_long, 0, 0, 0],
            )
        };
        assert_eq!(r, 0, "capget");
        d
    }

    #[test]
    fn narrow_to_sys_admin_leaves_that_alone() {
        let _serial = crate::serial();
        // Dropping the bounding set needs CAP_SETPCAP, so this runs in
        // the dev container as root and is a no-op in CI.
        if capget()[0].effective & (1 << 8) == 0 {
            return;
        }
        // The child's exit code names the first set that is wrong.
        let cases: &[(&str, fn() -> bool)] = &[
            ("effective is CAP_SYS_ADMIN alone", || {
                capget()[0].effective == 1 << CAP_SYS_ADMIN && capget()[1].effective == 0
            }),
            ("permitted is CAP_SYS_ADMIN alone", || {
                capget()[0].permitted == 1 << CAP_SYS_ADMIN && capget()[1].permitted == 0
            }),
            ("inheritable is empty", || {
                capget()[0].inheritable == 0 && capget()[1].inheritable == 0
            }),
            ("the bounding set is CAP_SYS_ADMIN alone", || {
                (0..64u32).all(|c| {
                    // SAFETY: integer arguments alone.
                    let has = unsafe { prctl(libc::PR_CAPBSET_READ, c.into(), 0) };
                    has < 0 || (has == 1) == (c == CAP_SYS_ADMIN)
                })
            }),
        ];
        // SAFETY: the child narrows its own sets, reads them and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            if narrow_to_sys_admin().is_err() {
                // SAFETY: _exit ends the child.
                unsafe { libc::_exit(100) };
            }
            for (i, (_, ok)) in cases.iter().enumerate() {
                if !ok() {
                    // SAFETY: _exit ends the child.
                    unsafe { libc::_exit(i as c_int + 1) };
                }
            }
            // SAFETY: _exit ends the child.
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        // SAFETY: status is live for the call.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, 0) },
            pid,
            "waitpid"
        );
        assert!(
            libc::WIFEXITED(status),
            "the child died: status {status:#x}"
        );
        let code = libc::WEXITSTATUS(status);
        assert_ne!(code, 100, "the drop was refused");
        if code != 0 {
            panic!("{}", cases[(code - 1) as usize].0);
        }
    }

    struct Rig {
        st: Box<State>,
        t: Box<Tables>,
    }

    impl Rig {
        fn new() -> Rig {
            // SAFETY: all zero bits are a Tables, as for the static.
            let t = unsafe { Box::<Tables>::new_zeroed().assume_init() };
            Rig {
                st: Box::new(State::new()),
                t,
            }
        }

        fn z(&mut self) -> Zygote<'_> {
            Zygote {
                st: &mut self.st,
                t: &mut self.t,
            }
        }
    }

    fn text(buf: &[u8]) -> String {
        String::from_utf8(c_str(buf).to_vec()).unwrap()
    }

    #[test]
    fn fill_cuts_as_snprintf_did() {
        let cases: &[(&str, usize, &[&[u8]], &[u8])] = &[
            ("fits", 8, &[b"ab", b"cd"], b"abcd\0"),
            ("nothing", 8, &[], b"\0"),
            ("cut in the second part", 4, &[b"ab", b"cdef"], b"abc\0"),
            ("cut in the first part", 2, &[b"abc", b"d"], b"a\0"),
            ("one byte holds the NUL alone", 1, &[b"abc"], b"\0"),
        ];
        for (name, cap, parts, want) in cases {
            let mut buf = vec![0xeeu8; *cap];
            fill(&mut buf, parts);
            assert_eq!(&buf[..want.len()], *want, "{name}");
        }
    }

    #[test]
    fn errno_decimal_is_the_number() {
        let cases: &[(&str, c_int, &str)] = &[
            ("EPERM", 1, "1"),
            ("zero", 0, "0"),
            ("large", 4095, "4095"),
            ("negative", -3, "-3"),
        ];
        for (name, e, want) in cases {
            let (d, n) = errno_decimal(*e);
            assert_eq!(&d[..n], want.as_bytes(), "{name}");
        }
    }

    #[test]
    fn thread_count_matches_proc() {
        // The harness runs tests on threads of its own, so the count is
        // whatever /proc says at the moment, and at least this thread.
        let cases: &[(&str, usize)] = &[("at least one thread", 1)];
        for (name, min) in cases {
            let got = thread_count();
            assert!(got >= *min as c_int, "{name}: {got}");
            let proc_count = std::fs::read_dir("/proc/self/task").unwrap().count();
            // Threads come and go between the two reads, so allow a few.
            assert!(
                (got - proc_count as c_int).abs() <= 4,
                "{name}: {got} against /proc's {proc_count}"
            );
        }
    }

    #[test]
    fn in_child_userns_agrees_with_uid_map() {
        let map = std::fs::read("/proc/self/uid_map").unwrap();
        let cases: &[(&str, bool)] = &[("this process", procfiles::in_child_userns(&map))];
        for (name, want) in cases {
            assert_eq!(in_child_userns(), *want, "{name}");
        }
    }

    #[test]
    fn own_mountns_says_why_it_took_no_namespace() {
        // The test harness has more than one thread, so the set case is
        // the thread refusal. Neither case reaches unshare.
        let cases: &[(&str, bool, &str)] = &[
            (
                "the variable unset",
                false,
                "FIBERD_OWN_MNTNS was not set, so the zygote took no mount namespace of its own",
            ),
            (
                "a thread before fz_init",
                true,
                "a thread existed before fz_init, so the zygote took no mount namespace of its own",
            ),
        ];
        let _keep = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(5)));
        for (name, set, want) in cases {
            // SAFETY: the test's own environment, read by this test alone.
            unsafe {
                if *set {
                    libc::setenv(c"FIBERD_OWN_MNTNS".as_ptr(), c"1".as_ptr(), 1);
                } else {
                    libc::unsetenv(c"FIBERD_OWN_MNTNS".as_ptr());
                }
            }
            let mut rig = Rig::new();
            rig.z().own_mountns();
            assert_eq!(text(&rig.t.own_ns_why), *want, "{name}");
            assert!(!rig.st.have_own_ns, "{name}");
        }
        // SAFETY: as above.
        unsafe { libc::unsetenv(c"FIBERD_OWN_MNTNS".as_ptr()) };
    }

    #[test]
    fn prepare_why_names_the_first_failed_step() {
        let cases: &[(&str, c_int, Option<usize>, c_int, &str)] = &[
            (
                "ro",
                F_RO,
                None,
                0,
                "the zygote could not make /sys read-only in its namespace",
            ),
            (
                "ro before drop",
                F_RO | F_DROP,
                None,
                0,
                "the zygote could not make /sys read-only in its namespace",
            ),
            (
                "drop",
                F_DROP | F_HIDE,
                Some(0),
                libc::EPERM,
                "the zygote could not unmount a DROP path",
            ),
            (
                "rundir",
                F_RUNDIR,
                None,
                0,
                "the zygote could not narrow the run directory",
            ),
            (
                "a hide path",
                F_HIDE,
                Some(0),
                libc::EACCES,
                "the zygote could not cover a HIDE path (/var/lib/fiberd/templates: Permission denied)",
            ),
            (
                "a slot never filled names nothing",
                F_HIDE,
                Some(7),
                libc::EPERM,
                "the zygote could not cover a HIDE path (: Operation not permitted)",
            ),
            (
                "no hide index",
                F_HIDE,
                None,
                libc::ENOENT,
                "the zygote could not cover a HIDE path (?: No such file or directory)",
            ),
        ];
        for (name, failed, hide_i, e, want) in cases {
            let mut rig = Rig::new();
            set_cstr(&mut rig.t.hide[0], b"/var/lib/fiberd/templates");
            rig.st.nhide = 1;
            let got = rig.z().prepare_why(*failed, *hide_i, *e);
            rig.st.paths_refused = Some(got);
            let refused = rig
                .z()
                .refused()
                .map(|r| String::from_utf8(r.to_vec()).unwrap());
            assert_eq!(refused.as_deref(), Some(*want), "{name}");
        }
    }

    #[test]
    fn prepare_ns_fails_closed_without_a_namespace() {
        let cases: &[(&str, Option<Refused>, &str, &str)] = &[
            (
                "a line refused earlier keeps its reason",
                Some(Refused::Text(c"RUNDIR refused")),
                "",
                "RUNDIR refused",
            ),
            (
                "fz_init did not run",
                None,
                "",
                "fz_init did not run, so the zygote has no mount namespace of its own",
            ),
            (
                "fz_init took no namespace",
                None,
                "a thread existed before fz_init, so the zygote took no mount namespace of its own",
                "a thread existed before fz_init, so the zygote took no mount namespace of its own",
            ),
        ];
        for (name, refused, why, want) in cases {
            let mut rig = Rig::new();
            rig.st.paths_refused = *refused;
            set_cstr(&mut rig.t.own_ns_why, why.as_bytes());
            assert_eq!(rig.z().prepare_ns(), -1, "{name}");
            assert!(!rig.st.ns_prepared, "{name}");
            let got = rig
                .z()
                .refused()
                .map(|r| String::from_utf8(r.to_vec()).unwrap());
            assert_eq!(got.as_deref(), Some(*want), "{name}");
        }
    }

    #[test]
    fn cap_nested_userns_refuses_the_initial_namespace() {
        // Only where this process is in the initial user namespace, so
        // the test never writes a real limit.
        if in_child_userns() {
            return;
        }
        let cases: &[(&str, Result<(), Errno>)] =
            &[("the initial namespace", Err(Errno(libc::EPERM)))];
        for (name, want) in cases {
            assert_eq!(cap_nested_userns(), *want, "{name}");
        }
    }

    #[test]
    fn lock_sys_without_privilege_reports_the_refusal() {
        // Non-root alone, since as root this would make /sys read-only
        // in the test's own namespace.
        // SAFETY: a query.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let cases: &[(&str, c_int)] = &[("every remount is refused", -1)];
        for (name, want) in cases {
            assert_eq!(lock_sys(), *want, "{name}");
        }
    }
}
