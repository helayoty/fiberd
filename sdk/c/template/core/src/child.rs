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

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_ulonglong, c_void};
use core::mem::{offset_of, size_of};
use core::ptr;
#[cfg(test)]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::abi::{FZ_CHANNEL_FD, FZ_CHANNEL_PEER_FD, OnFiber, RECORD_MAX, RecordStore};
use crate::ctl;
use crate::fiber;
use crate::mounts::{self, Tables};
use crate::seccomp;
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
    /// The workspace tree passed on the CLONE line (ws), a detached
    /// mount the child moves to /workspace, or -1.
    pub ws_fd: c_int,
    /// The zygote's SIGCHLD descriptor, or -1.
    pub sigchld_fd: c_int,
    /// The pidns option.
    pub pidns: bool,
    /// The mntns option.
    pub mntns: bool,
    /// The nocaps option.
    pub nocaps: bool,
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
/// existing ones. 116 and 117 are retired and not reused.
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
/// The child could not set up its descriptors.
pub const EX_FDS: c_int = 120;
/// The child did not get its incarnation record.
pub const EX_IDENTITY: c_int = 121;
/// The child could not join its cgroup leaf after the legacy clone.
pub const EX_CGROUP: c_int = 125;
/// The child could not stack its filter, the one that closes the gates.
pub const EX_FILTER: c_int = 126;
/// The child could not mount its workspace at /workspace.
pub const EX_WORKSPACE: c_int = 127;

/// Where a fiber's workspace is mounted, fixed for every fiber.
pub const WORKSPACE: &CStr = c"/workspace";
/// MOVE_MOUNT_F_EMPTY_PATH from linux/mount.h: the source is the
/// descriptor itself.
const MOVE_MOUNT_F_EMPTY_PATH: c_uint = 0x4;

/// CLONE_INTO_CGROUP from linux/sched.h of 5.7. libc's is an int, which
/// cannot hold it.
pub const CLONE_INTO_CGROUP: c_ulonglong = 0x2_0000_0000;

// birth's clone3 gate, the one syscall instruction the fiber filter lets
// clone3 through. fz_clone3_gate_ret is the word after it, what
// seccomp_data.instruction_pointer holds for the call.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text.fz_clone3_gate,\"ax\",%progbits",
    ".balign 4",
    ".globl fz_clone3_gate",
    ".hidden fz_clone3_gate",
    ".type fz_clone3_gate,%function",
    "fz_clone3_gate:",
    "mov x8, #435",
    "svc #0",
    ".globl fz_clone3_gate_ret",
    ".hidden fz_clone3_gate_ret",
    "fz_clone3_gate_ret:",
    "ret",
    ".size fz_clone3_gate, .-fz_clone3_gate",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text.fz_clone3_gate,\"ax\",@progbits",
    ".balign 16",
    ".globl fz_clone3_gate",
    ".hidden fz_clone3_gate",
    ".type fz_clone3_gate,@function",
    "fz_clone3_gate:",
    "mov eax, 435",
    "syscall",
    ".globl fz_clone3_gate_ret",
    ".hidden fz_clone3_gate_ret",
    "fz_clone3_gate_ret:",
    "ret",
    ".size fz_clone3_gate, .-fz_clone3_gate",
);
// The child's move_mount gate, the one syscall instruction the runc
// program lets move_mount through, which mounts the workspace
// (mount_workspace). fz_move_mount_gate_ret is the word after it, as
// above. move_mount takes five arguments. On aarch64 they are x0 to x4
// for a call and a syscall alike. On x86_64 the fourth rides in rcx for
// a call and r10 for a syscall, so it moves over first.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text.fz_move_mount_gate,\"ax\",%progbits",
    ".balign 4",
    ".globl fz_move_mount_gate",
    ".hidden fz_move_mount_gate",
    ".type fz_move_mount_gate,%function",
    "fz_move_mount_gate:",
    "mov x8, #429",
    "svc #0",
    ".globl fz_move_mount_gate_ret",
    ".hidden fz_move_mount_gate_ret",
    "fz_move_mount_gate_ret:",
    "ret",
    ".size fz_move_mount_gate, .-fz_move_mount_gate",
);
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text.fz_move_mount_gate,\"ax\",@progbits",
    ".balign 16",
    ".globl fz_move_mount_gate",
    ".hidden fz_move_mount_gate",
    ".type fz_move_mount_gate,@function",
    "fz_move_mount_gate:",
    "mov eax, 429",
    "mov r10, rcx",
    "syscall",
    ".globl fz_move_mount_gate_ret",
    ".hidden fz_move_mount_gate_ret",
    "fz_move_mount_gate_ret:",
    "ret",
    ".size fz_move_mount_gate, .-fz_move_mount_gate",
);
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe extern "C" {
    /// clone3(args, size), the raw answer: a pid, 0, or -errno.
    #[cfg(not(feature = "fuzzshim"))]
    fn fz_clone3_gate(args: *mut libc::clone_args, size: usize) -> c_long;
    static fz_clone3_gate_ret: u8;
    /// move_mount(from_dfd, from_path, to_dfd, to_path, flags), the raw
    /// answer: 0 or -errno.
    #[cfg(not(feature = "fuzzshim"))]
    fn fz_move_mount_gate(
        from_dfd: c_int,
        from_path: *const c_char,
        to_dfd: c_int,
        to_path: *const c_char,
        flags: c_uint,
    ) -> c_long;
    static fz_move_mount_gate_ret: u8;
}

/// The address seccomp reports for a clone3 from the gate, read at run
/// time so ASLR is moot.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn gate_addr() -> u64 {
    (&raw const fz_clone3_gate_ret) as u64
}

/// The address seccomp reports for a move_mount from its gate, read at
/// run time as gate_addr is.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn move_mount_gate_addr() -> u64 {
    (&raw const fz_move_mount_gate_ret) as u64
}

/// clone3 through the gate, as libc's syscall answers: a pid, 0 in the
/// child, or -1 with errno. Under the fuzzshim it is the hook's call,
/// so a target never clones.
///
/// # Safety
/// args is live with size bytes, or null with a size the kernel refuses
/// before reading, and the clone returns twice.
pub(crate) unsafe fn clone3(args: *mut libc::clone_args, size: usize) -> c_long {
    #[cfg(all(
        not(feature = "fuzzshim"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        // SAFETY: by the contract above.
        let raw = unsafe { fz_clone3_gate(args, size) };
        if (-4095..0).contains(&raw) {
            sys::set_errno(raw.wrapping_neg() as c_int);
            return -1;
        }
        raw
    }
    #[cfg(not(all(
        not(feature = "fuzzshim"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    // SAFETY: by the contract above.
    unsafe {
        sys::syscall(libc::SYS_clone3, [args as c_long, size as c_long, 0, 0, 0])
    }
}

/// move_mount through its gate, as libc's syscall answers: 0, or -1
/// with errno. Under the fuzzshim it is the hook's call, so a target
/// never mounts.
///
/// # Safety
/// The paths are NUL-ended and live for the call, or go unread because
/// flags holds one the kernel refuses first.
pub(crate) unsafe fn move_mount(
    from_dfd: c_int,
    from_path: *const c_char,
    to_dfd: c_int,
    to_path: *const c_char,
    flags: c_uint,
) -> c_long {
    #[cfg(all(
        not(feature = "fuzzshim"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        // SAFETY: by the contract above.
        let raw = unsafe { fz_move_mount_gate(from_dfd, from_path, to_dfd, to_path, flags) };
        if (-4095..0).contains(&raw) {
            sys::set_errno(raw.wrapping_neg() as c_int);
            return -1;
        }
        raw
    }
    #[cfg(not(all(
        not(feature = "fuzzshim"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    // SAFETY: by the contract above.
    unsafe {
        sys::syscall(
            libc::SYS_move_mount,
            [
                c_long::from(from_dfd),
                from_path as c_long,
                c_long::from(to_dfd),
                to_path as c_long,
                c_long::from(flags),
            ],
        )
    }
}

/// birth forks the fiber straight into its leaf cgroup. With pidns the
/// child is the init of its own pid namespace, so a checkpoint of it
/// restores without colliding with a live pid. A namespace the kernel
/// refuses fails the birth, so no fiber runs without one it asked for.
///
/// The clone3 goes through the gate above, the one address the fiber
/// filter (seccomp.rs) lets it pass from. Without clone3 or
/// CLONE_INTO_CGROUP (before 5.7, or a filter outside the library that
/// hides it), the legacy clone runs and the child moves itself into its
/// leaf in its first instructions, or ends with EX_CGROUP rather than
/// run charged to the zygote's cgroup. Any other refusal of clone3 is
/// the answer, with no second try. Both are raw syscalls, so the child
/// runs on a copy of this stack with no atfork handlers.
///
/// Returns the child's pid, 0 in the child, or -1 with errno.
///
/// # Safety
/// The caller is the zygote's serving thread, and the child keeps to the
/// rule at the top of this module.
pub unsafe fn birth(cgroup_fd: c_int, want: c_ulonglong) -> libc::pid_t {
    #[cfg(test)]
    BIRTH_WANT.store(want, Ordering::Relaxed);
    let mut args: libc::clone_args = zeroed();
    args.exit_signal = libc::SIGCHLD as c_ulonglong;
    args.flags = want;
    if cgroup_fd >= 0 {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = cgroup_fd as c_ulonglong;
    }
    // SAFETY: args is a live clone_args of the 5.7 size, and the clone
    // returns twice, which the caller's contract covers.
    let pid = unsafe { clone3(&raw mut args, size_of::<libc::clone_args>()) };
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

/// The flags of the last birth, which the tests of handle_clone read,
/// since the clone itself is refused there before a child exists.
#[cfg(test)]
pub(crate) static BIRTH_WANT: AtomicU64 = AtomicU64::new(0);

/// An all-zero value of a plain repr(C) struct.
pub(crate) fn zeroed<T: Copy>() -> T {
    // SAFETY: every caller's T is a repr(C) struct of integers, for which
    // all zero bits are a value.
    unsafe { core::mem::zeroed() }
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

/// scrub_and_run is the child between the clone and the application,
/// under the rule at the top of this module. A fiber that cannot be set
/// up or confined as fiberd asked does not run. The child ends, its exit
/// code naming the step that failed.
///
/// # Safety
/// The caller is the child of birth, c is a live Child whose pointers
/// name the zygote's statics, and the whole process is this path's.
pub unsafe fn scrub_and_run(c: &Child<'_>) -> ! {
    // The workspace goes in first, while the descriptor is open, the
    // capability the move needs is held and the move_mount gate is
    // still open. A proc child's namespace is a copy of the zygote's
    // private one. A runc child's is a copy of the container's, whose
    // mounts runc made slaves. The mount propagates nowhere either way.
    // The descriptor is closed with everything else below.
    if c.ws_fd >= 0 && mount_workspace(c.ws_fd) < 0 {
        // SAFETY: fence by the contract above, the reason is static.
        unsafe {
            child_say(
                c.fence,
                c"workspace",
                c"move_mount to /workspace failed".as_ptr(),
            );
            libc::_exit(EX_WORKSPACE)
        }
    }
    // Then the filter that closes both gates, so no instruction of the
    // fiber's runs with either open. It needs the no_new_privs the real
    // install set, which is what INSTALLED says.
    if seccomp::INSTALLED.load(Ordering::Relaxed) && seccomp::close_gates() != 0 {
        // SAFETY: _exit ends the child and never returns.
        unsafe { libc::_exit(EX_FILTER) }
    }
    // The zygote's state the child must not keep goes next, with plain
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
    // zygote's program, inherited at the clone, lets a proc fiber mount.
    if c.mntns {
        // SAFETY: the tables name the zygote's statics, by the contract
        // above.
        let failed = unsafe { mounts::mount_ns(c.pidns, &c.tables) };
        if failed != 0 {
            // SAFETY: _exit ends the child and never returns.
            unsafe { libc::_exit(mounts::mount_exit(failed)) }
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

/// mount_workspace moves the detached tree at fd to WORKSPACE in the
/// calling namespace, as move_mount(2) with MOVE_MOUNT_F_EMPTY_PATH does,
/// through the gate above, the one address the runc program lets
/// move_mount pass from. A proc child goes through it too, since its
/// program lets move_mount pass from anywhere. Returns 0 or -1.
pub fn mount_workspace(fd: c_int) -> c_int {
    // SAFETY: integer arguments and static strings alone.
    let rc = unsafe {
        move_mount(fd, c"".as_ptr(), libc::AT_FDCWD, WORKSPACE.as_ptr(), MOVE_MOUNT_F_EMPTY_PATH)
    };
    if rc < 0 { -1 } else { 0 }
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
