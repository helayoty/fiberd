//! The mount steps of a fiber's namespace, as mount_ns and prepare_ns
//! take them. mount_ns runs in the child, right after its clone, so
//! everything here keeps the rule at the top of child.rs. Nothing
//! allocates, locks or formats, every path is a NUL-ended string in
//! fixed storage, and every mount, umount2, mkdir and open goes through
//! the sys seam so the fuzz harnesses can shim it. The order of the
//! system calls in each function is the C's, since the exit codes and
//! the strace budgets of tests/integration/proc pin it.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{CStr, c_char, c_int, c_ulong};
use core::ptr;

use crate::abi::{KEEP_MAX, RUNDIR_MAX};
use crate::child::{EX_MNT_DROP, EX_MNT_HIDE, EX_MNT_PRIVATE, EX_MNT_PROC, EX_MNT_RO};
use crate::sys;

/// The steps of prepare_ns and mount_ns that can fail, as bits, for
/// their results, the reason every mntns CLONE is refused and the
/// child's exit code. The C enum has the same values.
pub const F_PRIVATE: c_int = 1;
/// The fiber's own /proc.
pub const F_PROC: c_int = 2;
/// The host controls under /proc and /sys made read-only.
pub const F_RO: c_int = 4;
/// The DROP paths unmounted.
pub const F_DROP: c_int = 8;
/// The HIDE paths covered.
pub const F_HIDE: c_int = 16;
/// The run directory narrowed.
pub const F_RUNDIR: c_int = 32;

/// MNT_DETACH, which libc types as a C int.
const MNT_DETACH: c_int = libc::MNT_DETACH;

const RO_NOSUID_NODEV_NOEXEC: c_ulong =
    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
const NOSUID_NODEV_NOEXEC: c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

/// What the zygote's namespace holds for mount_ns: the executable's
/// path and the HIDE and DROP tables, each path NUL-ended in KEEP_MAX
/// bytes of the C's storage.
pub struct Tables<'a> {
    /// The zygote's own executable, empty when unknown.
    pub self_exe: *const c_char,
    /// The HIDE paths.
    pub hide: &'a [[c_char; KEEP_MAX]],
    /// Which of them prepare_ns covered, one byte each.
    pub hide_covered: &'a [u8],
    /// The DROP paths.
    pub drop: &'a [[c_char; KEEP_MAX]],
}

/// ro_remount makes the mount at path read-only in this namespace
/// alone. MS_REMOUNT|MS_BIND changes the per-mount flags, not the
/// superblock, so fiberd and the host keep writing through their own
/// mounts of the same filesystem. The flags are set outright, so
/// nosuid, nodev and noexec are restated. Any mount point will do, with
/// no bind first.
///
/// # Safety
/// path is NUL-ended and live for the call.
pub unsafe fn ro_remount(path: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    unsafe {
        sys::mount(
            ptr::null(),
            path,
            ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | RO_NOSUID_NODEV_NOEXEC,
            ptr::null(),
        )
    }
}

/// What stat says about path. None when there is no such path or it
/// cannot be read, with errno set, and otherwise whether it is a
/// directory.
///
/// # Safety
/// path is NUL-ended and live for the call.
unsafe fn is_dir(path: *const c_char) -> Option<bool> {
    let mut st: libc::stat = crate::child::zeroed();
    // SAFETY: path by the contract above, st is a live struct stat.
    if unsafe { libc::stat(path, &raw mut st) } < 0 {
        return None;
    }
    Some(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// cover_empty mounts an empty read-only tmpfs over the directory at
/// path. Returns 0, -1 with errno, or 0 having done nothing when there
/// is no such path.
///
/// # Safety
/// path is NUL-ended and live for the call.
pub unsafe fn cover_empty(path: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    match unsafe { is_dir(path) } {
        None => {
            if sys::errno() == libc::ENOENT {
                0
            } else {
                -1
            }
        }
        Some(false) => {
            sys::set_errno(libc::ENOTDIR);
            -1
        }
        // SAFETY: by the contract above, the other strings are static.
        Some(true) => unsafe {
            sys::mount(
                c"tmpfs".as_ptr(),
                path,
                c"tmpfs".as_ptr(),
                RO_NOSUID_NODEV_NOEXEC,
                c"size=4k,mode=0555".as_ptr().cast(),
            )
        },
    }
}

/// A bind of path onto itself, so there is a mount to make read-only,
/// then the remount. -1 when either refused, as the C's || gave it.
///
/// # Safety
/// path is NUL-ended and live for the call.
unsafe fn bind_ro(path: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    let bound = unsafe { sys::mount(path, path, ptr::null(), libc::MS_BIND, ptr::null()) };
    // SAFETY: as above.
    if bound < 0 || unsafe { ro_remount(path) } < 0 {
        return -1;
    }
    0
}

/// lock_procsys takes away the fiber's write access to the kernel's
/// knobs under /proc/sys. The fiber is euid 0 in the initial user
/// namespace with every capability dropped, and sysctl checks the owner
/// write bit for euid 0 and asks for no capability. /proc/sys is a
/// directory of the proc mount, not a mount of its own, so it is bound
/// onto itself to have a mount to make read-only. A first MS_BIND
/// ignores MS_RDONLY and only the remount applies it. This is per fiber,
/// after its fresh /proc, because a pidns fiber's /proc is a mount of
/// its own that covers whatever the zygote bound on its /proc/sys.
fn lock_procsys() -> c_int {
    // SAFETY: a static string.
    unsafe { bind_ro(c"/proc/sys".as_ptr()) }
}

/// The paths runc and Docker list for a container, made read-only on
/// the fiber's fresh /proc. /proc/sysrq-trigger is root-owned 0200 and
/// its write asks for no capability, so without this a euid-0 fiber
/// with every capability dropped reboots, crashes or powers off the node
/// wherever kernel.sysrq allows it. The same owner-bit rule writes the
/// smp_affinity files under /proc/irq and what is under /proc/bus and
/// /proc/fs (nfsd). /proc/latency_stats is the one writable file among
/// runc's masked ones.
const PROC_RO: [&CStr; 5] = [
    c"/proc/sysrq-trigger",
    c"/proc/bus",
    c"/proc/fs",
    c"/proc/irq",
    c"/proc/latency_stats",
];

/// Covered with an empty read-only tmpfs, which CRIU dumps and restores
/// as it does a HIDE cover. /proc/scsi's scsi file takes devices off the
/// host and /proc/acpi's wakeup rewires the host's wakeup devices.
const PROC_MASKED: [&CStr; 2] = [c"/proc/scsi", c"/proc/acpi"];

/// lock_proc takes away the rest of what a fiber could write or see
/// under its fresh /proc. Each PROC_RO path is bound onto itself and
/// made read-only, as /proc/sys is, and each PROC_MASKED one is covered.
/// A path this kernel does not have is skipped, as runc skips it. One
/// that exists and cannot be locked fails the birth, since a fiber must
/// not run with it writable. Every path is tried whatever happened to
/// the ones before it. Returns 0, or -1 when any step failed.
///
/// runc's other masked files are not covered. /proc/kcore and
/// /proc/kmsg ask for a capability the fiber lacks (CAP_SYS_RAWIO,
/// CAP_SYSLOG). /proc/keys, /proc/timer_list and /proc/sched_debug are
/// read-only to begin with, and a mask would be a bind of another file,
/// which CRIU restores as the host's own path, so a resumed fiber would
/// see them again.
fn lock_proc() -> c_int {
    let mut rc = 0;
    for path in PROC_RO {
        let mut st: libc::stat = crate::child::zeroed();
        // SAFETY: a static string and a live struct stat.
        if unsafe { libc::stat(path.as_ptr(), &raw mut st) } < 0 {
            if sys::errno() != libc::ENOENT {
                rc = -1;
            }
            continue;
        }
        // SAFETY: a static string.
        if unsafe { bind_ro(path.as_ptr()) } < 0 {
            rc = -1;
        }
    }
    for path in PROC_MASKED {
        // SAFETY: a static string.
        if unsafe { cover_empty(path.as_ptr()) } < 0 {
            rc = -1;
        }
    }
    rc
}

/// The bytes fd_path needs: the prefix, ten digits and the NUL.
pub const FD_PATH_MAX: usize = 32;

/// fd_path writes "/proc/self/fd/<fd>" into buf, NUL-ended, and returns
/// the path. By hand, because the child uses no stdio.
pub fn fd_path(buf: &mut [u8; FD_PATH_MAX], fd: c_int) -> *const c_char {
    let n = sys::append(buf, 0, b"/proc/self/fd/");
    // A descriptor is never negative here, and C cast it to unsigned.
    let n = sys::append_decimal(buf, n, fd as u32);
    if let Some(end) = buf.get_mut(n) {
        *end = 0;
    }
    buf.as_ptr().cast()
}

/// narrow_rundir leaves the zygote, and so every fiber, one directory
/// of fiberd's run directory, its own grant's. Every grant's directory
/// (endpoint sockets, the zygote's log) sits under one parent, and a
/// fiber is euid 0, so without this a fiber of one grant could unlink
/// or rebind another grant's sockets. The parent is covered with an
/// empty read-only tmpfs, in the zygote's own namespace alone, and the
/// grant's own directory is bound back at its place from a descriptor
/// opened before the cover. What a fiber creates there (its endpoint)
/// lands in fiberd's real directory. The cwd is moved onto the bind,
/// and every fiber inherits it there, so a checkpoint names it through
/// the mount that will exist on restore. CRIU dumps the tmpfs with its
/// one empty directory and the bind as an external mount fiberd names
/// on restore, so a resumed fiber is bound to the resuming grant's
/// directory. Runs once, from prepare_ns. Returns 0, or -1, and every
/// mntns CLONE is then refused.
///
/// # Safety
/// parent and own are NUL-ended and live for the call.
pub unsafe fn narrow_rundir(parent: *const c_char, own: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    let fd = unsafe { sys::open(own, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return -1;
    }
    // SAFETY: by the contract above, the other strings are static.
    if unsafe {
        sys::mount(
            c"tmpfs".as_ptr(),
            parent,
            c"tmpfs".as_ptr(),
            NOSUID_NODEV_NOEXEC,
            c"size=64k,mode=0755".as_ptr().cast(),
        )
    } < 0
    {
        let e = sys::errno();
        // SAFETY: fd is the descriptor opened above.
        unsafe { libc::close(fd) };
        sys::set_errno(e);
        return -1;
    }
    let mut src = [0u8; FD_PATH_MAX];
    let src = fd_path(&mut src, fd);
    let mut rc = 0;
    // SAFETY: by the contract above, src is NUL-ended in a live buffer
    // and the rest are static strings. Each step runs only when the
    // one before it went through, as the C's || had it.
    let failed = unsafe {
        sys::mkdir(own, 0o755) < 0
            || sys::mount(src, own, ptr::null(), libc::MS_BIND, ptr::null()) < 0
            || sys::mount(
                ptr::null(),
                parent,
                ptr::null(),
                libc::MS_REMOUNT | RO_NOSUID_NODEV_NOEXEC,
                c"size=64k".as_ptr().cast(),
            ) < 0
            || libc::chdir(own) < 0
    };
    if failed {
        rc = -1;
    }
    // SAFETY: fd is the descriptor opened above.
    unsafe { libc::close(fd) };
    rc
}

/// under reports whether path lies inside dir (not dir itself).
pub fn under(path: &[u8], dir: &[u8]) -> bool {
    !dir.is_empty() && path.get(..dir.len()) == Some(dir) && path.get(dir.len()) == Some(&b'/')
}

/// bind_exe_back makes the zygote's executable visible again at its own
/// path inside the tmpfs just mounted over dir, and nothing else of dir.
/// The directories between are made in the tmpfs, an empty file stands
/// as the mount point, and the executable is bound onto it read-only,
/// with no setuid and no device nodes honoured, from src, a descriptor
/// of it opened by path before the cover. The descriptor matters:
/// /proc/self/exe still names the mount of the namespace the zygote was
/// started in, and a bind from another namespace's mount is EINVAL.
/// Fibers are forked from the zygote and map the same file, and CRIU
/// names a mapped file by its path, which must resolve in the fiber's
/// namespace to the file it maps, so a fiber whose executable sat under
/// a plain cover could not be parked. The bind is a mount fiberd names
/// on restore, like the run directory's.
///
/// The directories are made 0755, like the run directory's cover
/// (narrow_rundir), never 0555. The zygote runs with fiberd's narrow
/// capability set, which has no CAP_DAC_OVERRIDE, so uid 0 cannot
/// create anything in a directory without its owner's write bit. What
/// seals the cover is the read-only remount cover_hide ends with, which
/// no fiber can undo. Returns 0 or -1.
fn bind_exe_back(dir: &[u8], self_exe: &[u8], src: c_int) -> c_int {
    let mut path = [0u8; RUNDIR_MAX];
    let n = self_exe.len();
    if n >= RUNDIR_MAX {
        return -1;
    }
    sys::append(&mut path, 0, self_exe);
    // Each '/' after dir's own ends a directory to make. The walk starts
    // past the '/' that follows dir, since the caller checked under.
    let mut p = dir.len().wrapping_add(1);
    while let Some(rest) = path.get(p..n) {
        let k = sys::byte_at(rest, b'/');
        if k == rest.len() {
            break;
        }
        let at = p.wrapping_add(k);
        if let Some(c) = path.get_mut(at) {
            *c = 0;
        }
        // SAFETY: path is NUL-ended at `at` and live.
        if unsafe { sys::mkdir(path.as_ptr().cast(), 0o755) } < 0 && sys::errno() != libc::EEXIST {
            return -1;
        }
        if let Some(c) = path.get_mut(at) {
            *c = b'/';
        }
        p = at.wrapping_add(1);
    }
    // SAFETY: path is NUL-ended at n and live.
    let fd = unsafe {
        sys::open_mode(
            path.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o555,
        )
    };
    if fd < 0 {
        return -1;
    }
    // SAFETY: fd is the descriptor opened above.
    unsafe { libc::close(fd) };
    let mut from = [0u8; FD_PATH_MAX];
    let from = fd_path(&mut from, src);
    // SAFETY: from and path are NUL-ended in live buffers.
    let failed = unsafe {
        sys::mount(
            from,
            path.as_ptr().cast(),
            ptr::null(),
            libc::MS_BIND,
            ptr::null(),
        ) < 0
            || sys::mount(
                ptr::null(),
                path.as_ptr().cast(),
                ptr::null(),
                libc::MS_REMOUNT
                    | libc::MS_BIND
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                ptr::null(),
            ) < 0
    };
    if failed {
        return -1;
    }
    0
}

/// cover_hide covers the HIDE path with an empty read-only tmpfs.
/// Returns 1 when it did, 0 when the path does not exist (nothing to
/// hide yet) and -1 when it exists and could not be covered, with errno
/// set. A path that is not a directory fails, because a file cannot be
/// covered without CRIU binding the original back on restore. A path
/// that holds the zygote's own executable (self_exe) gets the executable
/// bound back inside the cover (bind_exe_back) before the cover is made
/// read-only. That cover is mounted 0755, so the zygote can build in it
/// without CAP_DAC_OVERRIDE (see bind_exe_back), and sealed by the
/// remount.
///
/// # Safety
/// path and self_exe are NUL-ended and live for the call.
pub unsafe fn cover_hide(path: *const c_char, self_exe: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    match unsafe { is_dir(path) } {
        None => {
            return if sys::errno() == libc::ENOENT { 0 } else { -1 };
        }
        Some(false) => {
            sys::set_errno(libc::ENOTDIR);
            return -1;
        }
        Some(true) => {}
    }
    // SAFETY: both by the contract above.
    let (exe, dir) = unsafe { (sys::c_bytes(self_exe), sys::c_bytes(path)) };
    if !under(exe, dir) {
        // SAFETY: path by the contract above, the rest static strings.
        let covered = unsafe {
            sys::mount(
                c"tmpfs".as_ptr(),
                path,
                c"tmpfs".as_ptr(),
                RO_NOSUID_NODEV_NOEXEC,
                c"size=4k,mode=0555".as_ptr().cast(),
            )
        };
        return if covered < 0 { -1 } else { 1 };
    }
    // SAFETY: self_exe by the contract above.
    let src = unsafe { sys::open(self_exe, libc::O_PATH | libc::O_CLOEXEC) };
    if src < 0 {
        return -1;
    }
    let mut rc = 1;
    // SAFETY: path by the contract above, the rest static strings. Each
    // step runs only when the one before it went through.
    let failed = unsafe {
        sys::mount(
            c"tmpfs".as_ptr(),
            path,
            c"tmpfs".as_ptr(),
            NOSUID_NODEV_NOEXEC,
            c"size=64k,mode=0755".as_ptr().cast(),
        ) < 0
            || bind_exe_back(dir, exe, src) < 0
            || sys::mount(
                ptr::null(),
                path,
                ptr::null(),
                libc::MS_REMOUNT | RO_NOSUID_NODEV_NOEXEC,
                c"size=64k".as_ptr().cast(),
            ) < 0
    };
    if failed {
        rc = -1;
    }
    let e = sys::errno();
    // SAFETY: src is the descriptor opened above.
    unsafe { libc::close(src) };
    sys::set_errno(e);
    rc
}

/// drop_paths_now unmounts every DROP path from the calling namespace.
/// Returns 0, or -1 when one that is mounted would not go. A path that
/// is no mount point, or does not exist, has nothing to drop.
pub fn drop_paths_now(drop: &[[c_char; KEEP_MAX]]) -> c_int {
    let mut rc = 0;
    for path in drop {
        // SAFETY: each kept path is NUL-ended within its storage.
        if unsafe { sys::umount2(path.as_ptr(), MNT_DETACH) } < 0 {
            let e = sys::errno();
            if e != libc::EINVAL && e != libc::ENOENT {
                rc = -1;
            }
        }
    }
    rc
}

/// mount_ns finishes the child's mount namespace, a copy of the
/// zygote's prepared one (prepare_ns in C). What is grant-wide is
/// already there, /sys read-only, the run directory narrowed and the
/// HIDE directories covered, so what remains is the fiber's own. Its
/// /proc shows only its pid namespace, /proc/sys and the other host
/// controls on that fresh /proc are read-only or covered (lock_proc),
/// the DROP paths are gone, and a HIDE directory that did not exist at
/// PREPARE is covered now if it has appeared. Returns the F_ bits of
/// the steps that failed, 0 when all went through, and the child ends
/// on any of them.
///
/// The copy is already private, since every mount in the zygote's
/// namespace is, and MS_REC|MS_PRIVATE on / restates it. When even that
/// is refused nothing is mounted or unmounted at all, since a change to
/// a shared mount would propagate back into the zygote's namespace.
/// DROP is repeated here, after the zygote dropped the same paths at
/// PREPARE, for a mount at that path the zygote's namespace holds all
/// the same (a restore root bound before the warm, dropped at PREPARE,
/// cannot reappear, but the step is one system call and fails closed).
///
/// # Safety
/// t.self_exe is NUL-ended and live, as is every path in its tables.
pub unsafe fn mount_ns(own_pidns: bool, t: &Tables<'_>) -> c_int {
    let mut failed = 0;
    // SAFETY: static strings.
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
        return F_PRIVATE;
    }
    // SAFETY: static strings.
    if own_pidns
        && unsafe {
            sys::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                NOSUID_NODEV_NOEXEC,
                ptr::null(),
            )
        } < 0
    {
        failed |= F_PROC;
    }
    // lock_proc runs only when lock_procsys went through, as the C's ||
    // had it. The child ends on either, so nothing is lost.
    if lock_procsys() < 0 || lock_proc() < 0 {
        failed |= F_RO;
    }
    if drop_paths_now(t.drop) < 0 {
        failed |= F_DROP;
    }
    for (i, path) in t.hide.iter().enumerate() {
        if t.hide_covered.get(i).is_some_and(|&c| c != 0) {
            continue;
        }
        // SAFETY: by the contract above.
        if unsafe { cover_hide(path.as_ptr(), t.self_exe) } < 0 {
            failed |= F_HIDE;
        }
    }
    failed
}

/// mount_exit is the child's exit code for the first of mount_ns's
/// failed steps, in the order mount_ns takes them.
pub fn mount_exit(failed: c_int) -> c_int {
    if failed & F_PRIVATE != 0 {
        return EX_MNT_PRIVATE;
    }
    if failed & F_PROC != 0 {
        return EX_MNT_PROC;
    }
    if failed & F_RO != 0 {
        return EX_MNT_RO;
    }
    if failed & F_DROP != 0 {
        return EX_MNT_DROP;
    }
    EX_MNT_HIDE
}

/// ro_remount, for lock_sys in the C shim.
///
/// # Safety
/// As ro_remount.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_ro_remount(path: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    unsafe { ro_remount(path) }
}

/// cover_empty, for lock_sys in the C shim.
///
/// # Safety
/// As cover_empty.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_cover_empty(path: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    unsafe { cover_empty(path) }
}

/// narrow_rundir, for prepare_ns in the C shim.
///
/// # Safety
/// As narrow_rundir.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_narrow_rundir(parent: *const c_char, own: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    unsafe { narrow_rundir(parent, own) }
}

/// cover_hide, for prepare_ns in the C shim.
///
/// # Safety
/// As cover_hide.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_cover_hide(path: *const c_char, self_exe: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    unsafe { cover_hide(path, self_exe) }
}

/// drop_paths_now, for prepare_ns in the C shim, over the first n
/// paths of the DROP table.
///
/// # Safety
/// paths points at n kept paths of KEEP_MAX bytes each, NUL-ended, or
/// n is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_drop_paths_now(paths: *const [c_char; KEEP_MAX], n: c_int) -> c_int {
    // SAFETY: by the contract above.
    drop_paths_now(unsafe { kept(paths, n) })
}

/// The first n kept paths at p as a slice, none when p is null.
///
/// # Safety
/// p points at n paths of KEEP_MAX bytes each, or is null.
pub unsafe fn kept<'a>(p: *const [c_char; KEEP_MAX], n: c_int) -> &'a [[c_char; KEEP_MAX]] {
    if p.is_null() {
        return &[];
    }
    let n = usize::try_from(n).unwrap_or(0).min(crate::abi::MAX_PATHS);
    // SAFETY: by the contract above.
    unsafe { core::slice::from_raw_parts(p, n) }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::type_complexity
    )]
    use super::*;
    use std::ffi::CString;

    /// A fresh path under the temp dir, with nothing at it.
    fn scratch(name: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("fiberzygote-core-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn cstr(p: &std::path::Path) -> CString {
        CString::new(p.to_str().unwrap()).unwrap()
    }

    #[test]
    fn mount_exit_names_the_first_failed_step() {
        let cases: &[(&str, c_int, c_int)] = &[
            ("private", F_PRIVATE, EX_MNT_PRIVATE),
            ("proc", F_PROC, EX_MNT_PROC),
            ("ro", F_RO, EX_MNT_RO),
            ("drop", F_DROP, EX_MNT_DROP),
            ("hide", F_HIDE, EX_MNT_HIDE),
            ("private before proc", F_PRIVATE | F_PROC, EX_MNT_PRIVATE),
            ("proc before ro", F_PROC | F_RO | F_HIDE, EX_MNT_PROC),
            ("ro before drop", F_RO | F_DROP, EX_MNT_RO),
            ("drop before hide", F_DROP | F_HIDE, EX_MNT_DROP),
            ("nothing named is hide", 0, EX_MNT_HIDE),
        ];
        for (name, failed, want) in cases {
            assert_eq!(mount_exit(*failed), *want, "{name}");
        }
    }

    #[test]
    fn under_is_a_strict_prefix_at_a_slash() {
        let cases: &[(&str, &[u8], &[u8], bool)] = &[
            ("inside", b"/a/b/c", b"/a/b", true),
            ("deep inside", b"/a/b/c/d", b"/a", true),
            ("the directory itself", b"/a/b", b"/a/b", false),
            ("a sibling with the prefix", b"/a/bc", b"/a/b", false),
            ("outside", b"/x/b", b"/a/b", false),
            ("shorter than the directory", b"/a", b"/a/b", false),
            ("an empty directory", b"/a/b", b"", false),
            ("an empty path", b"", b"/a", false),
            ("the root is never a directory here", b"/a", b"/", false),
        ];
        for (name, path, dir, want) in cases {
            assert_eq!(under(path, dir), *want, "{name}");
        }
    }

    #[test]
    fn fd_path_names_the_descriptor() {
        let cases: &[(&str, c_int, &str)] = &[
            ("zero", 0, "/proc/self/fd/0"),
            ("small", 7, "/proc/self/fd/7"),
            ("large", 4095, "/proc/self/fd/4095"),
            ("the largest", c_int::MAX, "/proc/self/fd/2147483647"),
        ];
        for (name, fd, want) in cases {
            let mut buf = [0xffu8; FD_PATH_MAX];
            let p = fd_path(&mut buf, *fd);
            // SAFETY: fd_path NUL-ends what it writes in buf.
            let got = unsafe { CStr::from_ptr(p) };
            assert_eq!(got.to_bytes(), want.as_bytes(), "{name}");
        }
    }

    #[test]
    fn covers_touch_nothing_that_is_no_directory() {
        // Only paths no mount can reach: a missing one is 0, a file is
        // ENOTDIR. Both make no mount call, so root and non-root agree.
        let file = scratch("file");
        std::fs::write(&file, b"x").unwrap();
        let missing = scratch("missing");
        let (file_c, missing_c) = (cstr(&file), cstr(&missing));
        let cases: &[(&str, &CString, c_int, c_int)] = &[
            ("a missing path", &missing_c, 0, 0),
            ("a file", &file_c, -1, libc::ENOTDIR),
        ];
        for (name, path, want, want_errno) in cases {
            sys::set_errno(0);
            // SAFETY: path is a live C string.
            let got = unsafe { cover_empty(path.as_ptr()) };
            assert_eq!(got, *want, "cover_empty {name}");
            if *want_errno != 0 {
                assert_eq!(sys::errno(), *want_errno, "cover_empty {name}: errno");
            }
            sys::set_errno(0);
            // SAFETY: both are live C strings.
            let got = unsafe { cover_hide(path.as_ptr(), c"".as_ptr()) };
            assert_eq!(got, *want, "cover_hide {name}");
            if *want_errno != 0 {
                assert_eq!(sys::errno(), *want_errno, "cover_hide {name}: errno");
            }
        }
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn drop_paths_now_skips_what_is_not_there() {
        fn kept_of(paths: &[&str]) -> Vec<[c_char; KEEP_MAX]> {
            paths
                .iter()
                .map(|p| {
                    let mut k = [0 as c_char; KEEP_MAX];
                    for (i, b) in p.bytes().enumerate() {
                        k[i] = b as c_char;
                    }
                    k
                })
                .collect()
        }
        let missing = scratch("gone");
        let missing = missing.to_str().unwrap();
        let cases: &[(&str, Vec<[c_char; KEEP_MAX]>)] = &[
            ("no paths", kept_of(&[])),
            ("one missing path", kept_of(&[missing])),
            (
                "two missing paths",
                kept_of(&[missing, "/nonexistent/fiberzygote"]),
            ),
        ];
        for (name, drop) in cases {
            assert_eq!(drop_paths_now(drop), 0, "{name}");
            // SAFETY: drop holds that many kept paths.
            let n = drop.len() as c_int;
            assert_eq!(
                unsafe { fz_rs_drop_paths_now(drop.as_ptr(), n) },
                0,
                "{name} through the entry"
            );
        }
    }

    #[test]
    fn narrow_rundir_refuses_without_the_own_directory() {
        // The open of own comes first, so a missing own fails before any
        // mount, for root and non-root alike.
        let missing = scratch("rundir");
        let own = cstr(&missing.join("own"));
        let parent = cstr(&missing);
        let cases: &[(&str, &CString, &CString, c_int)] =
            &[("own missing", &parent, &own, libc::ENOENT)];
        for (name, parent, own, want_errno) in cases {
            // SAFETY: both are live C strings.
            let got = unsafe { narrow_rundir(parent.as_ptr(), own.as_ptr()) };
            assert_eq!(got, -1, "{name}");
            assert_eq!(sys::errno(), *want_errno, "{name}: errno");
        }
    }
}
