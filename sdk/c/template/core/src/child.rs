//! The child's path, from the clone to the application. birth forks the
//! fiber and scrub_and_run takes it to on_fiber.
//!
//! THE RULE FOR THIS PATH. Nothing here may allocate, free, use stdio or
//! take a lock before on_fiber runs. The raw clone copies one thread, and
//! a lock another thread held then (malloc's, a stream's, the locale's)
//! stays held forever. Unlike fork(), the raw clone resets none of that,
//! nor the cached tid or the robust list. Only system calls and pure
//! string functions run here, errors go out with write(2), and the lints
//! below make an unchecked index or sum a compile error.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_ulonglong, c_void};
use core::mem::{offset_of, size_of};
use core::ptr;

use crate::abi::{FZ_CHANNEL_FD, FZ_CHANNEL_PEER_FD, OnFiber, RECORD_MAX, RecordStore};
use crate::ctl;
use crate::fiber;
use crate::mounts::{self, Tables};
use crate::sys;
use crate::zygote;

unsafe extern "C" {
    /// The process's environment, repointed by the child.
    static mut environ: *mut *mut c_char;
}

/// What the child's path needs from the zygote, built by handle_clone
/// before the clone. The pointers and slices name the zygote's statics,
/// which the child's copy of memory holds at the same addresses.
pub struct Child<'a> {
    /// The ready pipe's read end, the zygote's, closed first.
    pub ready_r: c_int,
    /// The ready pipe's write end, moved to fd 3.
    pub ready_w: c_int,
    /// fiberd's channel end as passed on the CLONE line.
    pub channel: c_int,
    /// The zygote's SIGCHLD descriptor, or -1.
    pub sigchld_fd: c_int,
    /// The pidns option.
    pub pidns: bool,
    /// The mntns option.
    pub mntns: bool,
    /// The nocaps option.
    pub nocaps: bool,
    /// FIBERD_USERNS_NESTED=deny was given.
    pub deny_nested_userns: bool,
    /// The fence the CLONE named, NUL-ended in the line.
    pub fence: *const c_char,
    /// The template's entry.
    pub on_fiber: OnFiber,
    /// The fiber's environment, null-ended, built by the parent.
    pub environ: *mut *mut c_char,
    /// The executable's path and the HIDE and DROP tables, for mount_ns.
    pub tables: Tables<'a>,
}

/// The child could not make its mount namespace private. This and the
/// codes below are the exits of a child that could not be confined or
/// set up. New codes go at the end, because fiberd's tests name the
/// existing ones. 116 is retired and not reused.
pub const EX_MNT_PRIVATE: c_int = 110;
/// The child could not mount its own /proc.
pub const EX_MNT_PROC: c_int = 111;
/// The child could not unmount a DROP path.
pub const EX_MNT_DROP: c_int = 112;
/// The child could not cover a HIDE path that appeared after READY.
pub const EX_MNT_HIDE: c_int = 113;
/// The child could not drop its capabilities.
pub const EX_CAPS: c_int = 114;
/// The child could not make the host controls under /proc read-only.
pub const EX_MNT_RO: c_int = 115;
/// The child could not install the user namespace filter.
pub const EX_USERNS: c_int = 117;
/// The child could not set up its descriptors.
pub const EX_FDS: c_int = 120;
/// The child did not get its incarnation record.
pub const EX_IDENTITY: c_int = 121;
/// The child could not join its cgroup leaf after the legacy clone.
pub const EX_CGROUP: c_int = 125;

/// CLONE_INTO_CGROUP from linux/sched.h of 5.7. libc's is an int, which
/// cannot hold it.
pub const CLONE_INTO_CGROUP: c_ulonglong = 0x2_0000_0000;

/// birth forks the fiber straight into its leaf cgroup. With pidns the
/// child is the init of its own pid namespace, so a checkpoint of it
/// restores without colliding with a live pid. A namespace the kernel
/// refuses fails the birth, so no fiber runs without one it asked for.
///
/// Without clone3 or CLONE_INTO_CGROUP (before 5.7), the legacy clone
/// runs and the child moves itself into its leaf in its first
/// instructions, or ends with EX_CGROUP rather than run charged to the
/// zygote's cgroup. Any other refusal of clone3 is the answer, with no
/// second try. Both are raw syscalls, so the child runs on a copy of
/// this stack with no atfork handlers.
///
/// Returns the child's pid, 0 in the child, or -1 with errno.
///
/// # Safety
/// The caller is the zygote's serving thread, and the child keeps to the
/// rule at the top of this module.
pub unsafe fn birth(cgroup_fd: c_int, want: c_ulonglong) -> libc::pid_t {
    let mut args: libc::clone_args = zeroed();
    args.exit_signal = libc::SIGCHLD as c_ulonglong;
    args.flags = want;
    if cgroup_fd >= 0 {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = cgroup_fd as c_ulonglong;
    }
    // SAFETY: args is a live clone_args of the 5.7 size, and the clone
    // returns twice, which the caller's contract covers.
    let pid = unsafe {
        sys::syscall(
            libc::SYS_clone3,
            [
                (&raw mut args) as c_long,
                size_of::<libc::clone_args>() as c_long,
                0,
                0,
                0,
            ],
        )
    };
    if pid >= 0 {
        return pid as libc::pid_t;
    }
    let e = sys::errno();
    if e != libc::ENOSYS && e != libc::EINVAL && e != libc::E2BIG {
        return -1;
    }
    // A zero stack (the child copies this one) and zero tids and tls, so
    // the arch's order of ptid, ctid and tls is moot.
    // SAFETY: a raw clone with no stack of its own, under the caller's
    // contract.
    let pid = unsafe {
        sys::syscall(
            libc::SYS_clone,
            [(want | libc::SIGCHLD as c_ulonglong) as c_long, 0, 0, 0, 0],
        )
    };
    if pid == 0 && cgroup_fd >= 0 {
        // SAFETY: the path is a static NUL-ended string, and openat
        // takes a descriptor the parent held open.
        let procs = unsafe {
            libc::openat(
                cgroup_fd,
                c"cgroup.procs".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            )
        };
        if procs < 0 {
            // SAFETY: _exit ends the child and never returns.
            unsafe { libc::_exit(EX_CGROUP) }
        }
        // "0" is the writer itself, whatever its pid namespace. The
        // kernel takes the byte whole or not at all.
        // SAFETY: write reads one byte of a static string.
        if unsafe { libc::write(procs, c"0".as_ptr().cast(), 1) } != 1 {
            // SAFETY: _exit ends the child and never returns.
            unsafe { libc::_exit(EX_CGROUP) }
        }
        // SAFETY: procs is the descriptor opened above.
        unsafe { libc::close(procs) };
    }
    pid as libc::pid_t
}

/// An all-zero value of a plain repr(C) struct.
pub(crate) fn zeroed<T: Copy>() -> T {
    // SAFETY: every caller's T is a repr(C) struct of integers, for which
    // all zero bits are a value.
    unsafe { core::mem::zeroed() }
}

/// The seccomp program's arch-specific words. The tests pin the native
/// arch's numbers against libc's.
pub struct Arch {
    /// AUDIT_ARCH_* for this arch.
    pub audit: u32,
    /// x86_64 alone has a second table under the same audit arch.
    pub x32: bool,
    /// __NR_unshare.
    pub unshare: u32,
    /// __NR_clone.
    pub clone: u32,
    /// __NR_clone3, the same everywhere.
    pub clone3: u32,
    /// __NR_setns.
    pub setns: u32,
}

/// x86_64, AUDIT_ARCH_X86_64 is EM_X86_64 with the 64-bit and
/// little-endian bits.
pub const X86_64: Arch = Arch {
    audit: 0xC000_003E,
    x32: true,
    unshare: 272,
    clone: 56,
    clone3: 435,
    setns: 308,
};

/// aarch64, AUDIT_ARCH_AARCH64 is EM_AARCH64 with the same two bits.
pub const AARCH64: Arch = Arch {
    audit: 0xC000_00B7,
    x32: false,
    unshare: 97,
    clone: 220,
    clone3: 435,
    setns: 268,
};

#[cfg(target_arch = "x86_64")]
const NATIVE: Arch = X86_64;
#[cfg(target_arch = "aarch64")]
const NATIVE: Arch = AARCH64;

/// __X32_SYSCALL_BIT. On x86_64 it selects the x32 table under the same
/// audit arch, where unshare and friends have other numbers.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The most words a program has, the x86_64 one with its x32 check.
pub const FILTER_MAX: usize = 25;

/// A seccomp program in fixed storage, built at compile time.
pub struct Filter {
    /// The words, the first len of them live.
    pub words: [libc::sock_filter; FILTER_MAX],
    /// How many words the program has.
    pub len: u16,
}

/// A BPF statement, BPF_STMT in linux/filter.h.
const fn stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

/// A BPF jump, BPF_JUMP in linux/filter.h.
const fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

const LD_W_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
const JEQ_K: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
const JGE_K: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
const JSET_K: u32 = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
const RET_K: u32 = libc::BPF_RET | libc::BPF_K;
const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
const NEWUSER: u32 = libc::CLONE_NEWUSER as u32;

/// The offsets the program loads from. ARGn_LO is the low 32 bits of
/// argument n, its first four bytes on a little-endian arch.
const NR_OFF: u32 = offset_of!(libc::seccomp_data, nr) as u32;
const ARCH_OFF: u32 = offset_of!(libc::seccomp_data, arch) as u32;
const ARG0_LO: u32 = offset_of!(libc::seccomp_data, args) as u32;
const ARG1_LO: u32 = ARG0_LO + 8;
const _: () = assert!(
    cfg!(target_endian = "little"),
    "FZ_ARG_LO adds 4 on a big-endian arch"
);

impl Filter {
    /// The program for arch, which refuses to make or join a user
    /// namespace. unshare and clone with CLONE_NEWUSER, and setns onto a
    /// user namespace (or onto whatever the descriptor is), get EPERM.
    /// clone3 gets ENOSYS, as an older kernel would answer, because
    /// seccomp cannot read its flags and libc then falls back to clone.
    /// On x86_64 an x32 number kills the process, as libseccomp and
    /// Docker do, so the other table cannot sidestep the matches.
    ///
    /// Built at compile time, so an index slip is a build error, not a
    /// panic on the child path.
    #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    pub const fn build(a: &Arch) -> Filter {
        let mut f = Filter {
            words: [stmt(0, 0); FILTER_MAX],
            len: 0,
        };
        let mut n = 0usize;
        f.words[n] = stmt(LD_W_ABS, ARCH_OFF);
        n += 1;
        f.words[n] = jump(JEQ_K, a.audit, 1, 0);
        n += 1;
        f.words[n] = stmt(RET_K, KILL);
        n += 1;
        f.words[n] = stmt(LD_W_ABS, NR_OFF);
        n += 1;
        if a.x32 {
            // nr >= X32_SYSCALL_BIT is an x32 call, not one of ours
            f.words[n] = jump(JGE_K, X32_SYSCALL_BIT, 0, 1);
            n += 1;
            f.words[n] = stmt(RET_K, KILL);
            n += 1;
        }
        // unshare(flags)
        f.words[n] = jump(JEQ_K, a.unshare, 0, 4);
        n += 1;
        f.words[n] = stmt(LD_W_ABS, ARG0_LO);
        n += 1;
        f.words[n] = jump(JSET_K, NEWUSER, 0, 1);
        n += 1;
        f.words[n] = stmt(RET_K, EPERM);
        n += 1;
        f.words[n] = stmt(RET_K, ALLOW);
        n += 1;
        // clone(flags, ...)
        f.words[n] = jump(JEQ_K, a.clone, 0, 4);
        n += 1;
        f.words[n] = stmt(LD_W_ABS, ARG0_LO);
        n += 1;
        f.words[n] = jump(JSET_K, NEWUSER, 0, 1);
        n += 1;
        f.words[n] = stmt(RET_K, EPERM);
        n += 1;
        f.words[n] = stmt(RET_K, ALLOW);
        n += 1;
        // clone3(struct clone_args *)
        f.words[n] = jump(JEQ_K, a.clone3, 0, 1);
        n += 1;
        f.words[n] = stmt(RET_K, ENOSYS);
        n += 1;
        // setns(fd, nstype)
        f.words[n] = jump(JEQ_K, a.setns, 0, 5);
        n += 1;
        f.words[n] = stmt(LD_W_ABS, ARG1_LO);
        n += 1;
        f.words[n] = jump(JEQ_K, 0, 2, 0);
        n += 1;
        f.words[n] = jump(JSET_K, NEWUSER, 1, 0);
        n += 1;
        f.words[n] = stmt(RET_K, ALLOW);
        n += 1;
        f.words[n] = stmt(RET_K, EPERM);
        n += 1;
        f.words[n] = stmt(RET_K, ALLOW);
        n += 1;
        f.len = n as u16;
        f
    }

    /// The live words.
    pub fn words(&self) -> &[libc::sock_filter] {
        self.words.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// The program for this arch, static so the child allocates nothing.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static FILTER: Filter = Filter::build(&NATIVE);

/// userns_filter installs the program above on the calling process.
/// Installing needs CAP_SYS_ADMIN in the caller's user namespace or
/// no_new_privs. Returns prctl's answer, 0 or -1 with errno, and ENOSYS
/// on an arch the table does not cover.
pub fn userns_filter() -> c_int {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        sys::set_errno(libc::ENOSYS);
        -1
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let prog = libc::sock_fprog {
            len: FILTER.len,
            // The kernel copies the program and writes nothing through
            // the pointer, whose type is sock_fprog's.
            filter: FILTER.words.as_ptr().cast_mut(),
        };
        // SAFETY: prog is live for the call, and the kernel only reads it.
        unsafe {
            prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as c_ulong,
                (&raw const prog) as c_ulong,
            )
        }
    }
}

/// prctl(2) with two arguments, the other two zero.
///
/// # Safety
/// What option does with a and b must be safe for this process, and a
/// pointer among them live for the call.
pub(crate) unsafe fn prctl(option: c_int, a: c_ulong, b: c_ulong) -> c_int {
    let zero: c_ulong = 0;
    // SAFETY: by the contract above.
    unsafe { libc::prctl(option, a, b, zero, zero) }
}

/// struct __user_cap_header_struct in linux/capability.h, which libc
/// does not carry.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CapHeader {
    pub(crate) version: u32,
    pub(crate) pid: c_int,
}

/// struct __user_cap_data_struct, one per 32 capabilities.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CapData {
    pub(crate) effective: u32,
    pub(crate) permitted: u32,
    pub(crate) inheritable: u32,
}

/// _LINUX_CAPABILITY_VERSION_3 and _LINUX_CAPABILITY_U32S_3.
pub(crate) const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub(crate) const CAPABILITY_U32S_3: usize = 2;

const _: () = {
    assert!(size_of::<CapHeader>() == 8);
    assert!(offset_of!(CapHeader, version) == 0);
    assert!(offset_of!(CapHeader, pid) == 4);
    assert!(size_of::<CapData>() == 12);
    assert!(
        size_of::<libc::clone_args>() == 88,
        "struct clone_args is the 5.7 layout"
    );
    assert!(size_of::<libc::sock_filter>() == 8);
    assert!(FILTER_MAX <= u16::MAX as usize);
};

/// drop_caps leaves the child with no capability it can use or regain.
/// no_new_privs means exec never raises permitted above the empty set,
/// the ambient set is cleared, the effective, permitted and inheritable
/// sets are emptied, and so is the bounding set where the caller holds
/// CAP_SETPCAP. A container's default set often lacks it, and
/// no_new_privs already covers what the bounding set would. Returns 0,
/// or -1 if no_new_privs or the empty sets were refused.
pub fn drop_caps() -> c_int {
    let mut rc = 0;
    let (zero, one): (c_ulong, c_ulong) = (0, 1);
    // SAFETY: integer arguments alone.
    if unsafe { prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero) } < 0 {
        rc = -1;
    }
    let mut c: c_ulong = 0;
    // SAFETY: integer arguments alone, and the loop ends at the first
    // capability number the kernel does not know.
    while unsafe { prctl(libc::PR_CAPBSET_READ, c, zero) } >= 0 {
        // SAFETY: as above.
        let _ = unsafe { prctl(libc::PR_CAPBSET_DROP, c, zero) };
        c = c.wrapping_add(1);
    }
    // SAFETY: integer arguments alone.
    if unsafe {
        prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong,
            zero,
        )
    } < 0
        && sys::errno() != libc::EINVAL
    {
        rc = -1;
    }
    let h = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let d = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; CAPABILITY_U32S_3];
    // SAFETY: h and d are live and laid out as capset reads them.
    if unsafe {
        sys::syscall(
            libc::SYS_capset,
            [(&raw const h) as c_long, d.as_ptr() as c_long, 0, 0, 0],
        )
    } < 0
    {
        rc = -1;
    }
    rc
}

/// Room for four descriptors in one SCM_RIGHTS control message, in u64
/// words so it is aligned as a cmsghdr is.
const CMSG_WORDS: usize = 4;
const _: () = {
    // SAFETY: CMSG_SPACE is arithmetic on its argument.
    let space = unsafe { libc::CMSG_SPACE(4 * size_of::<c_int>() as u32) } as usize;
    assert!(
        space == CMSG_WORDS * size_of::<u64>(),
        "the control buffer is CMSG_SPACE(4 ints)"
    );
};

/// channel_recv takes one message off fd into buf (cap bytes), with
/// flags added to recvmsg's. The first descriptor passed goes to
/// *fd_out, -1 for none, and any other is closed. Returns the byte
/// count, 0 at EOF, or -1 with errno. A message longer than cap is
/// EPROTO, with buf wiped. EINTR is retried.
///
/// # Safety
/// buf has cap writable bytes and fd_out is writable.
pub unsafe fn channel_recv(
    fd: c_int,
    flags: c_int,
    buf: *mut c_char,
    cap: usize,
    fd_out: &mut c_int,
) -> isize {
    let mut cbuf = [0u64; CMSG_WORDS];
    let mut iov = libc::iovec {
        iov_base: buf.cast::<c_void>(),
        iov_len: cap,
    };
    let mut mh: libc::msghdr = zeroed();
    mh.msg_iov = &raw mut iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf.as_mut_ptr().cast::<c_void>();
    mh.msg_controllen = size_of::<[u64; CMSG_WORDS]>();
    let r = loop {
        // SAFETY: mh, iov and cbuf are live for the call, and buf has
        // cap bytes by the contract above.
        let r = unsafe { libc::recvmsg(fd, &raw mut mh, libc::MSG_CMSG_CLOEXEC | flags) };
        if r < 0 && sys::errno() == libc::EINTR {
            continue;
        }
        break r;
    };
    *fd_out = -1;
    if r < 0 {
        return -1;
    }
    // SAFETY: mh describes cbuf, which the kernel filled, and each header
    // the walk yields lies inside it.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&raw const mh);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let n = (*c)
                    .cmsg_len
                    .wrapping_sub(libc::CMSG_LEN(0) as usize)
                    .checked_div(size_of::<c_int>())
                    .unwrap_or(0);
                let data = libc::CMSG_DATA(c);
                for i in 0..n {
                    let mut got: c_int = 0;
                    ptr::copy_nonoverlapping(
                        data.add(i.wrapping_mul(size_of::<c_int>())),
                        (&raw mut got).cast::<u8>(),
                        size_of::<c_int>(),
                    );
                    if *fd_out < 0 {
                        *fd_out = got;
                    } else {
                        libc::close(got);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&raw const mh, c);
        }
    }
    // A zero-length message is EOF to every caller, and on a seqpacket
    // channel one may still carry descriptors. They are closed here, or
    // they would leak behind the EOF.
    if r == 0 && *fd_out >= 0 {
        // SAFETY: fd_out is a descriptor the message just passed.
        unsafe { libc::close(*fd_out) };
        *fd_out = -1;
    }
    if r > 0 && mh.msg_flags & libc::MSG_TRUNC != 0 {
        if *fd_out >= 0 {
            // SAFETY: fd_out is a descriptor the message just passed.
            unsafe { libc::close(*fd_out) };
            *fd_out = -1;
        }
        // The refused message's first bytes may hold a seed, so buf is
        // wiped here for every caller.
        // SAFETY: buf has cap writable bytes, by the contract above.
        fiber::wipe(unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), cap) });
        sys::set_errno(libc::EPROTO);
        return -1;
    }
    r
}

/// read_incarnation takes the birth record, which fiberd queues before
/// the CLONE, off the channel into born. Any descriptor passed with it
/// is closed. Returns 0, or -1 with a reason for the zygote's log.
///
/// # Safety
/// born is live and nothing else touches it.
pub unsafe fn read_incarnation(
    fd: c_int,
    born: *mut RecordStore,
    why: &mut *const c_char,
) -> c_int {
    let mut passed = -1;
    // SAFETY: born's buf has RECORD_MAX bytes, by the contract above.
    let r = unsafe {
        channel_recv(
            fd,
            0,
            (&raw mut (*born).buf).cast::<c_char>(),
            RECORD_MAX,
            &mut passed,
        )
    };
    if passed >= 0 {
        // SAFETY: passed is a descriptor the message carried.
        unsafe { libc::close(passed) };
    }
    if r < 0 && sys::errno() == libc::EPROTO {
        *why = c"record too long".as_ptr();
        return -1;
    }
    if r < 0 {
        *why = c"recvmsg on the channel failed".as_ptr();
        return -1;
    }
    if r == 0 {
        *why = c"channel closed before the record arrived".as_ptr();
        return -1;
    }
    // SAFETY: born by the contract above, r bytes of record in its buf.
    unsafe { crate::record::fz_rs_parse_incarnation(born, r as usize, why) }
}

/// own_pair replaces fiberd's channel end by a pair of the fiber's own
/// at FZ_CHANNEL_FD and FZ_CHANNEL_PEER_FD. The fiber reads the first
/// and only holds the second, so a park dumps the pair whole and a
/// restore remakes it in the fiber's namespaces. fiberd then borrows the
/// peer to send the resume's record. Returns 0 or -1.
fn own_pair() -> c_int {
    let mut sv: [c_int; 2] = [-1, -1];
    // SAFETY: sv is live for the call.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) } < 0 {
        return -1;
    }
    let [read, peer] = sv;
    // FZ_CHANNEL_FD holds fiberd's end, so neither new end is there. The
    // peer's slot is the lowest free one, so an end may already sit in
    // it. The read end moves first, and the peer then covers whatever
    // is left at its slot, at most that read end's old number.
    // SAFETY: integer arguments alone.
    if unsafe { libc::dup2(read, FZ_CHANNEL_FD) } < 0 {
        return -1;
    }
    // SAFETY: as above.
    if peer != FZ_CHANNEL_PEER_FD && unsafe { libc::dup2(peer, FZ_CHANNEL_PEER_FD) } < 0 {
        return -1;
    }
    if read != FZ_CHANNEL_PEER_FD {
        // SAFETY: read is the pair's own descriptor.
        unsafe { libc::close(read) };
    }
    if peer != FZ_CHANNEL_PEER_FD {
        // SAFETY: peer is the pair's own descriptor.
        unsafe { libc::close(peer) };
    }
    0
}

/// The seven pieces of a child_say line, which the tests below pin.
fn say_parts<'a>(fence: &'a [u8], what: &'a [u8], why: &'a [u8]) -> [&'a [u8]; 7] {
    [b"libfiberzygote ", fence, b": ", what, b": ", why, b"\n"]
}

/// child_say writes a startup failure to stderr, still the zygote's log
/// here, with write(2) alone.
///
/// # Safety
/// The three strings are NUL-ended and live for the call.
unsafe fn child_say(fence: *const c_char, what: &CStr, why: *const c_char) {
    // SAFETY: by the contract above.
    let (fence, why) = unsafe { (sys::c_bytes(fence), sys::c_bytes(why)) };
    for part in say_parts(fence, what.to_bytes(), why) {
        // SAFETY: write reads part.len() bytes of part, which is live.
        unsafe { libc::write(2, part.as_ptr().cast(), part.len()) };
    }
}

/// "errno <e>" for child_say_errno, NUL-ended in a fixed buffer.
fn errno_why(e: c_int) -> [u8; 18] {
    let mut why = [0u8; 18];
    let n = sys::append(&mut why, 0, b"errno ");
    let n = sys::append_decimal(&mut why, n, e as u32);
    if let Some(end) = why.get_mut(n) {
        *end = 0;
    }
    why
}

/// child_say_errno is child_say with an errno value as the reason, as a
/// number. strerror translates through the locale under a lock the
/// child must not take.
///
/// # Safety
/// fence is NUL-ended and live for the call.
unsafe fn child_say_errno(fence: *const c_char, what: &CStr, e: c_int) {
    let why = errno_why(e);
    // SAFETY: fence by the contract above, why is NUL-ended.
    unsafe { child_say(fence, what, why.as_ptr().cast()) }
}

/// scrub_and_run is the child between the clone and the application,
/// under the rule at the top of this module. A fiber that cannot be set
/// up or confined as fiberd asked does not run. The child ends, its exit
/// code naming the step that failed.
///
/// # Safety
/// The caller is the child of birth, c is a live Child whose pointers
/// name the zygote's statics, and the whole process is this path's.
pub unsafe fn scrub_and_run(c: &Child<'_>) -> ! {
    // The zygote's state the child must not keep goes first, with plain
    // stores. Its control channel is not this child's, so fz_report_line
    // must fail rather than write into fd 3, and its report mutex may be
    // held by a thread that is not here (ctl.rs). None of it is read
    // before on_fiber, so the order against the calls below is moot.
    // SAFETY: the child is the process's one thread, by the contract
    // above, and c.environ is the null-ended array the parent built.
    unsafe {
        ctl::reset_for_child();
        zygote::reset_for_child();
        environ = c.environ;
        fiber::reset_for_child();
    }
    let born_store = fiber::born();
    // SAFETY: integer arguments alone, descriptors the zygote held.
    unsafe {
        libc::close(c.ready_r);
        if c.sigchld_fd >= 0 {
            libc::close(c.sigchld_fd);
        }
    }
    let mut channel = c.channel;
    if channel == 3 || channel == FZ_CHANNEL_FD {
        // Sitting where one of the two dup2 below lands, so it moves
        // above both first.
        // SAFETY: integer arguments alone.
        channel =
            unsafe { libc::fcntl(channel, libc::F_DUPFD, FZ_CHANNEL_PEER_FD.wrapping_add(1)) };
        if channel < 0 {
            // SAFETY: _exit ends the child and never returns.
            unsafe { libc::_exit(EX_FDS) }
        }
    }
    // The readiness pipe goes to fd 3, over the inherited control
    // descriptor, and the channel to FZ_CHANNEL_FD. All above is closed,
    // so nothing a ready fiber holds leads outside its tree except a
    // handoff fiber's channel, the one socket CRIU is told is external.
    // SAFETY: integer arguments alone.
    if unsafe { libc::dup2(c.ready_w, 3) } < 0 {
        // SAFETY: _exit ends the child and never returns.
        unsafe { libc::_exit(EX_FDS) }
    }
    // SAFETY: integer arguments alone.
    if unsafe { libc::dup2(channel, FZ_CHANNEL_FD) } < 0 {
        // SAFETY: _exit ends the child and never returns.
        unsafe { libc::_exit(EX_FDS) }
    }
    // The raw syscall, since glibc wraps it only from 2.34 and musl not
    // at all.
    // SAFETY: integer arguments alone.
    if unsafe {
        sys::syscall(
            libc::SYS_close_range,
            [
                c_long::from(FZ_CHANNEL_FD.wrapping_add(1)),
                c_long::from(u32::MAX),
                0,
                0,
                0,
            ],
        )
    } < 0
    {
        for fd in FZ_CHANNEL_FD.wrapping_add(1)..65536 {
            // SAFETY: integer argument alone.
            unsafe { libc::close(fd) };
        }
    }
    // The record, TLS identity included, is read into this child's memory
    // before any application code runs, so no checkpoint precedes it.
    // stderr stays the zygote's log until fz_fiber_ready, so a fiber that
    // fails to start can say why.
    let mut why: *const c_char = ptr::null();
    // SAFETY: the birth record's store is live and this path's alone.
    if unsafe { read_incarnation(FZ_CHANNEL_FD, born_store, &mut why) } < 0 {
        // SAFETY: fence by the contract above, why was set with the -1.
        unsafe {
            child_say(c.fence, c"incarnation record", why);
            libc::_exit(EX_IDENTITY)
        }
    }
    // SAFETY: the store is live and parsed, so inc.fence is a NUL-ended
    // field in its buf, and c.fence is NUL-ended.
    let born = unsafe { &*born_store };
    // A record for another fence means this is not the fiber fiberd
    // asked for.
    // SAFETY: both NUL-ended, as above.
    if unsafe { libc::strcmp(born.inc.fence, c.fence) } != 0 {
        // SAFETY: fence by the contract above, the reason is static.
        unsafe {
            child_say(
                c.fence,
                c"incarnation record",
                c"names another fence".as_ptr(),
            );
            libc::_exit(EX_IDENTITY)
        }
    }
    // SAFETY: the process's one thread, by the contract above.
    unsafe { fiber::set_served_generation(born.inc.generation) };
    // A handoff fiber keeps fiberd's channel for the connections it
    // passes. Any other takes a pair of its own.
    if born.inc.identity.is_null() && own_pair() < 0 {
        // SAFETY: _exit ends the child and never returns.
        unsafe { libc::_exit(EX_FDS) }
    }
    // SAFETY: a static string.
    let null = unsafe { sys::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if null >= 0 {
        // SAFETY: integer arguments alone.
        unsafe {
            libc::dup2(null, 0);
            libc::dup2(null, 1);
            if null > 3 {
                libc::close(null);
            }
        }
    }
    // An empty mask, so SIGCHLD (blocked in the zygote) reaches the
    // fiber. No PR_SET_PDEATHSIG, since a resumed fiber has another
    // parent and the runtime kills leaves through the cgroup. No
    // reseeding, since srandom takes libc's lock. The template reseeds
    // in on_fiber.
    let mut none: libc::sigset_t = zeroed();
    // SAFETY: none is live for both calls, the rest are integers.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::sigemptyset(&raw mut none);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const none, ptr::null_mut());
    }
    // Mounts first, while the capabilities they need are held. The
    // filter goes on before the drop, since installing may need
    // CAP_SYS_ADMIN.
    if c.mntns {
        // SAFETY: the tables name the zygote's statics, by the contract
        // above.
        let failed = unsafe { mounts::mount_ns(c.pidns, &c.tables) };
        if failed != 0 {
            // SAFETY: _exit ends the child and never returns.
            unsafe { libc::_exit(mounts::mount_exit(failed)) }
        }
    }
    if c.deny_nested_userns && userns_filter() < 0 {
        // SAFETY: fence by the contract above.
        unsafe {
            child_say_errno(c.fence, c"deny nested user namespaces", sys::errno());
            libc::_exit(EX_USERNS)
        }
    }
    if c.nocaps && drop_caps() < 0 {
        // SAFETY: _exit ends the child and never returns.
        unsafe { libc::_exit(EX_CAPS) }
    }
    // The record's address is taken from the store, not from the shared
    // reference above, since on_fiber may call fz_fiber_ready, which
    // writes the store (the seed).
    // SAFETY: the store is live, and only its address is taken.
    let inc = unsafe { &raw const (*born_store).inc };
    let rc = match c.on_fiber {
        // SAFETY: the template's entry, with the record it was promised.
        Some(on_fiber) => unsafe { on_fiber(inc) },
        // No template passes a null entry. abort takes nothing and never
        // returns.
        None => unsafe { libc::abort() },
    };
    // SAFETY: _exit ends the child and never returns.
    unsafe { libc::_exit(rc & 0xff) }
}

/// channel_recv as an extern entry, which the unit tests below drive.
///
/// # Safety
/// As channel_recv, and fd_out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_channel_recv(
    fd: c_int,
    flags: c_int,
    buf: *mut c_char,
    cap: usize,
    fd_out: *mut c_int,
) -> isize {
    let mut got = -1;
    // SAFETY: by the contract above.
    let r = unsafe { channel_recv(fd, flags, buf, cap, &mut got) };
    if !fd_out.is_null() {
        // SAFETY: writable by the contract above.
        unsafe { *fd_out = got };
    }
    r
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
    use core::mem::size_of_val;

    /// A word as (code, jt, jf, k), in BPF_JUMP's order.
    fn words(f: &Filter) -> Vec<(u16, u8, u8, u32)> {
        f.words()
            .iter()
            .map(|w| (w.code, w.jt, w.jf, w.k))
            .collect()
    }

    #[test]
    fn filter_is_the_c_program_word_for_word() {
        // The words with the kernel headers' values. BPF_LD|BPF_W|BPF_ABS
        // is 0x20, BPF_JMP|BPF_JEQ|BPF_K 0x15, BPF_JGE 0x35, BPF_JSET 0x45
        // and BPF_RET|BPF_K 0x06.
        let common_head: &[(u16, u8, u8, u32)] = &[(0x20, 0, 0, 4)];
        let x86_64_tail: &[(u16, u8, u8, u32)] = &[
            (0x15, 1, 0, 0xC000003E),
            (0x06, 0, 0, 0x80000000),
            (0x20, 0, 0, 0),
            (0x35, 0, 1, 0x40000000),
            (0x06, 0, 0, 0x80000000),
            (0x15, 0, 4, 272),
            (0x20, 0, 0, 16),
            (0x45, 0, 1, 0x10000000),
            (0x06, 0, 0, 0x00050001),
            (0x06, 0, 0, 0x7fff0000),
            (0x15, 0, 4, 56),
            (0x20, 0, 0, 16),
            (0x45, 0, 1, 0x10000000),
            (0x06, 0, 0, 0x00050001),
            (0x06, 0, 0, 0x7fff0000),
            (0x15, 0, 1, 435),
            (0x06, 0, 0, 0x00050026),
            (0x15, 0, 5, 308),
            (0x20, 0, 0, 24),
            (0x15, 2, 0, 0),
            (0x45, 1, 0, 0x10000000),
            (0x06, 0, 0, 0x7fff0000),
            (0x06, 0, 0, 0x00050001),
            (0x06, 0, 0, 0x7fff0000),
        ];
        let aarch64_tail: &[(u16, u8, u8, u32)] = &[
            (0x15, 1, 0, 0xC00000B7),
            (0x06, 0, 0, 0x80000000),
            (0x20, 0, 0, 0),
            (0x15, 0, 4, 97),
            (0x20, 0, 0, 16),
            (0x45, 0, 1, 0x10000000),
            (0x06, 0, 0, 0x00050001),
            (0x06, 0, 0, 0x7fff0000),
            (0x15, 0, 4, 220),
            (0x20, 0, 0, 16),
            (0x45, 0, 1, 0x10000000),
            (0x06, 0, 0, 0x00050001),
            (0x06, 0, 0, 0x7fff0000),
            (0x15, 0, 1, 435),
            (0x06, 0, 0, 0x00050026),
            (0x15, 0, 5, 268),
            (0x20, 0, 0, 24),
            (0x15, 2, 0, 0),
            (0x45, 1, 0, 0x10000000),
            (0x06, 0, 0, 0x7fff0000),
            (0x06, 0, 0, 0x00050001),
            (0x06, 0, 0, 0x7fff0000),
        ];
        let cases: &[(&str, &Arch, &[(u16, u8, u8, u32)], usize)] = &[
            ("x86_64", &X86_64, x86_64_tail, 25),
            ("aarch64", &AARCH64, aarch64_tail, 23),
        ];
        for (name, arch, tail, len) in cases {
            let f = Filter::build(arch);
            let want: Vec<_> = common_head.iter().chain(tail.iter()).copied().collect();
            assert_eq!(usize::from(f.len), *len, "{name}: length");
            assert_eq!(words(&f), want, "{name}");
        }
    }

    #[test]
    fn native_arch_numbers_are_libcs() {
        let cases: &[(&str, u32, c_long)] = &[
            ("unshare", NATIVE.unshare, libc::SYS_unshare),
            ("clone", NATIVE.clone, libc::SYS_clone),
            ("clone3", NATIVE.clone3, libc::SYS_clone3),
            ("setns", NATIVE.setns, libc::SYS_setns),
        ];
        for (name, got, want) in cases {
            assert_eq!(c_long::from(*got), *want, "{name}");
        }
        assert_eq!(
            NATIVE.x32,
            cfg!(target_arch = "x86_64"),
            "x86_64 alone has an x32 table"
        );
    }

    #[test]
    fn filter_fits_its_storage_and_prog() {
        let cases: &[(&str, &Arch)] = &[("x86_64", &X86_64), ("aarch64", &AARCH64)];
        for (name, arch) in cases {
            let f = Filter::build(arch);
            assert!(usize::from(f.len) <= FILTER_MAX, "{name}");
            assert_eq!(f.words().len(), usize::from(f.len), "{name}");
            // Every jump lands inside the program, as the kernel checks.
            for (i, w) in f.words().iter().enumerate() {
                if w.code == 0x15 || w.code == 0x35 || w.code == 0x45 {
                    for off in [w.jt, w.jf] {
                        assert!(
                            i + 1 + usize::from(off) < f.words().len(),
                            "{name}: word {i} jumps out"
                        );
                    }
                }
            }
            // The last word returns, so no run falls off the end.
            assert_eq!(f.words().last().map(|w| w.code), Some(0x06), "{name}");
        }
    }

    /// A SOCK_SEQPACKET pair, as the channel is.
    fn pair() -> [c_int; 2] {
        let mut sv = [-1; 2];
        // SAFETY: sv is live for the call.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair");
        sv
    }

    /// Sends data on sock as one message with fds in SCM_RIGHTS.
    fn send_fds(sock: c_int, data: &[u8], fds: &[c_int]) {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut cbuf = [0u64; 8];
        let mut mh: libc::msghdr = zeroed();
        mh.msg_iov = &raw mut iov;
        mh.msg_iovlen = 1;
        if !fds.is_empty() {
            let bytes = size_of_val(fds);
            mh.msg_control = cbuf.as_mut_ptr().cast();
            // SAFETY: CMSG_SPACE is arithmetic on its argument.
            mh.msg_controllen = unsafe { libc::CMSG_SPACE(bytes as u32) } as usize;
            // SAFETY: mh describes cbuf, which has room for 8 descriptors.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&raw const mh);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(bytes as u32) as usize;
                ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(c), bytes);
            }
        }
        // SAFETY: mh, iov and cbuf are live for the call.
        let r = unsafe { libc::sendmsg(sock, &raw const mh, libc::MSG_NOSIGNAL) };
        assert_eq!(r, data.len() as isize, "sendmsg");
    }

    /// Whether fd is open.
    fn is_open(fd: c_int) -> bool {
        // SAFETY: integer arguments alone.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        flags >= 0
    }

    #[test]
    fn channel_recv_takes_one_message_and_its_first_descriptor() {
        struct Case {
            name: &'static str,
            send: Option<(&'static [u8], usize)>, // data and how many descriptors ride along, None closes the peer
            cap: usize,
            want: isize,
            want_errno: c_int,
            want_fd: bool,
        }
        let cases = [
            Case {
                name: "a message",
                send: Some((b"hello", 0)),
                cap: 64,
                want: 5,
                want_errno: 0,
                want_fd: false,
            },
            Case {
                name: "a message with a descriptor",
                send: Some((b"i", 1)),
                cap: 64,
                want: 1,
                want_errno: 0,
                want_fd: true,
            },
            Case {
                name: "the first of two descriptors is kept, the second closed",
                send: Some((b"i", 2)),
                cap: 64,
                want: 1,
                want_errno: 0,
                want_fd: true,
            },
            Case {
                name: "a message longer than the buffer is EPROTO",
                send: Some((b"too long for four", 0)),
                cap: 4,
                want: -1,
                want_errno: libc::EPROTO,
                want_fd: false,
            },
            Case {
                name: "a long message with a descriptor closes it too",
                send: Some((b"too long for four", 1)),
                cap: 4,
                want: -1,
                want_errno: libc::EPROTO,
                want_fd: false,
            },
            Case {
                name: "a closed peer is EOF",
                send: None,
                cap: 64,
                want: 0,
                want_errno: 0,
                want_fd: false,
            },
        ];
        for tc in cases {
            let [ours, theirs] = pair();
            let mut sent: Vec<c_int> = Vec::new();
            match tc.send {
                Some((data, n)) => {
                    for _ in 0..n {
                        let [a, b] = pair();
                        // SAFETY: b is ours to close.
                        unsafe { libc::close(b) };
                        sent.push(a);
                    }
                    send_fds(theirs, data, &sent);
                }
                None => {
                    // SAFETY: theirs is ours to close.
                    unsafe { libc::close(theirs) };
                }
            }
            let mut buf = vec![0u8; tc.cap.max(1)];
            let mut got_fd = -2;
            sys::set_errno(0);
            // SAFETY: buf has cap bytes.
            let r = unsafe {
                fz_rs_channel_recv(
                    ours,
                    libc::MSG_DONTWAIT,
                    buf.as_mut_ptr().cast(),
                    tc.cap,
                    &mut got_fd,
                )
            };
            assert_eq!(r, tc.want, "{}", tc.name);
            if tc.want_errno != 0 {
                assert_eq!(sys::errno(), tc.want_errno, "{}: errno", tc.name);
            }
            if let Some((data, _)) = tc.send
                && r > 0
            {
                assert_eq!(
                    &buf[..r as usize],
                    &data[..r as usize],
                    "{}: bytes",
                    tc.name
                );
            }
            assert_eq!(got_fd >= 0, tc.want_fd, "{}: fd_out {got_fd}", tc.name);
            if tc.want_errno == libc::EPROTO {
                // The refused message's first bytes are not kept.
                assert!(buf.iter().all(|&b| b == 0), "{}: buf wiped", tc.name);
            }
            if got_fd >= 0 {
                assert!(is_open(got_fd), "{}: the kept descriptor is open", tc.name);
                // SAFETY: got_fd is the descriptor the message passed.
                unsafe { libc::close(got_fd) };
            }
            // Every passed descriptor the call did not hand over was
            // closed by it. The passed copies are new numbers, so the
            // senders' originals stay open and are closed here.
            for fd in sent {
                // SAFETY: fd is ours to close.
                unsafe { libc::close(fd) };
            }
            // SAFETY: ours to close, theirs may already be.
            unsafe {
                libc::close(ours);
                if tc.send.is_some() {
                    libc::close(theirs);
                }
            }
        }
    }

    #[test]
    fn child_say_lines_are_the_cs() {
        let cases: &[(&str, &[u8], &[u8], &[u8], &str)] = &[
            (
                "a record failure",
                b"g/1/1",
                b"incarnation record",
                b"record too long",
                "libfiberzygote g/1/1: incarnation record: record too long\n",
            ),
            (
                "an empty reason",
                b"f",
                b"what",
                b"",
                "libfiberzygote f: what: \n",
            ),
        ];
        for (name, fence, what, why, want) in cases {
            let line: Vec<u8> = say_parts(fence, what, why).concat();
            assert_eq!(line, want.as_bytes(), "{name}");
        }
    }

    #[test]
    fn errno_why_is_the_number() {
        let cases: &[(&str, c_int, &str)] = &[
            ("EPERM", libc::EPERM, "errno 1"),
            ("ENOSYS", libc::ENOSYS, "errno 38"),
            ("the largest int", c_int::MAX, "errno 2147483647"),
        ];
        for (name, e, want) in cases {
            let why = errno_why(*e);
            let got = CStr::from_bytes_until_nul(&why).unwrap();
            assert_eq!(got.to_bytes(), want.as_bytes(), "{name}");
        }
    }

    #[test]
    fn birth_refuses_as_clone3_did() {
        let _serial = crate::serial();
        // CLONE_NEWUSER with CLONE_FS is EINVAL from the kernel before
        // any child exists, on clone3 and on the clone it falls back to,
        // so the test stays one process. A seccomp profile that hides
        // CLONE_NEWUSER answers EPERM instead, and birth passes either
        // on. With a cgroup descriptor the flags are still what refuse.
        let flags = (libc::CLONE_NEWUSER | libc::CLONE_FS) as c_ulonglong;
        let cases: &[(&str, c_int)] = &[
            ("no cgroup descriptor", -1),
            ("a cgroup descriptor that is not open", 1 << 20),
        ];
        for (name, fd) in cases {
            // SAFETY: the flags are refused, so no child is made.
            let pid = unsafe { birth(*fd, flags) };
            let e = sys::errno();
            assert_eq!(pid, -1, "{name}");
            assert!(
                [libc::EINVAL, libc::EPERM].contains(&e),
                "{name}: errno {e}"
            );
        }
    }

    #[test]
    fn a_zero_length_message_leaks_no_descriptor() {
        // A zero-length seqpacket message reads as EOF, and the
        // descriptors it carries must not stay open behind it. Each is a
        // pipe's write end, so the read end sees EOF only once every copy
        // is closed.
        let cases: &[(&str, usize)] = &[("one descriptor", 1), ("two descriptors", 2)];
        for (name, n) in cases {
            let [ours, theirs] = pair();
            let mut reads = Vec::new();
            let mut writes = Vec::new();
            for _ in 0..*n {
                let mut p = [-1; 2];
                // SAFETY: p is live for the call.
                let rc = unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
                assert_eq!(rc, 0, "{name}: pipe2");
                reads.push(p[0]);
                writes.push(p[1]);
            }
            send_fds(theirs, b"", &writes);
            for fd in writes {
                // SAFETY: the test's own copy, the message holds another.
                unsafe { libc::close(fd) };
            }
            let mut buf = [0u8; 16];
            let mut got_fd = -2;
            // SAFETY: buf has 16 bytes.
            let r = unsafe {
                fz_rs_channel_recv(
                    ours,
                    libc::MSG_DONTWAIT,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut got_fd,
                )
            };
            assert_eq!(r, 0, "{name}: EOF");
            assert_eq!(got_fd, -1, "{name}: nothing handed over");
            for fd in reads {
                let mut b = [0u8; 1];
                // SAFETY: b is live for the call.
                let got = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
                assert_eq!(got, 0, "{name}: a passed write end is still open");
                // SAFETY: the test's own.
                unsafe { libc::close(fd) };
            }
            // SAFETY: the pair is the test's own.
            unsafe {
                libc::close(ours);
                libc::close(theirs);
            }
        }
    }
}
