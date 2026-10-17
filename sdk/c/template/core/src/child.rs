//! The child's path, from the clone to the application. birth forks the
//! fiber, scrub_and_run takes it from the clone to on_fiber, with the
//! mount steps in mounts.rs, userns_filter against nested user
//! namespaces and drop_caps for its capabilities. The C shim builds a
//! Child (abi.rs) before the clone, resets its own statics with plain
//! stores in the child and makes one call here.
//!
//! THE RULE FOR THIS PATH. Nothing here may allocate, free, use stdio
//! or take a lock before on_fiber runs, on either birth path. The clone
//! copies one thread of the zygote. The others (an engine) may hold
//! malloc's lock, a stream's lock, the locale's or libc's random state
//! lock at that instant, and the copy of such a lock is held forever.
//! glibc's fork() reinitialises those for its child and the raw clone
//! does not, which is also why nothing here relies on what fork() would
//! have reset (the thread descriptor's cached tid, the robust list).
//! Only system calls and pure string functions are used. Everything the
//! fiber needs built (its environment, its record) is built by the
//! parent before the clone or read into static storage with raw
//! syscalls, and errors are written with write(2) (child_say). The
//! lints below make an index or a sum a compile error unless it is
//! checked.
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

use crate::abi::{Child, FZ_CHANNEL_FD, FZ_CHANNEL_PEER_FD, RECORD_MAX, RecordStore};
use crate::mounts::{self, Tables};
use crate::sys;

/// Exit codes of a child that could not be confined or set up. New codes
/// go at the end, because fiberd's tests name the existing ones. 116
/// (the run directory) is retired and not reused. The C enum has the
/// same values, pinned there with _Static_assert, and exit_why in C
/// says what each stands for.
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

/// CLONE_INTO_CGROUP, as linux/sched.h of 5.7 spells it. Not libc's,
/// which types it as a C int it does not fit.
pub const CLONE_INTO_CGROUP: c_ulonglong = 0x2_0000_0000;

/// birth forks the fiber straight into its leaf cgroup. With pidns in
/// want the child is the init of its own pid namespace, so a checkpoint
/// of it restores anywhere without colliding with a live pid. With mntns
/// it gets a mount namespace of its own. Both need CAP_SYS_ADMIN, and a
/// namespace the kernel refuses fails the birth. No fiber runs without
/// one it was asked to have.
///
/// A kernel without clone3, or without CLONE_INTO_CGROUP (before 5.7),
/// gets the legacy clone with the same namespace flags. The child then
/// moves itself into its leaf before it touches memory, so the window
/// is its first instructions only. A child that cannot reach its leaf
/// ends there with EX_CGROUP, because it must not run charged to the
/// zygote's cgroup. Any other refusal of clone3 (EPERM for a namespace,
/// EBADF for a descriptor that is no cgroup) is the answer, with no
/// second try. Both calls are the raw syscall, so the child runs on a
/// copy of this stack with no atfork handlers, under the rule above.
///
/// Returns the child's pid, 0 in the child, or -1 with errno set by the
/// call that refused.
///
/// # Safety
/// The caller is the zygote's serving thread, and in the child it goes
/// on under the rule above.
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
    // Flags, then a zero stack (the child's is this one, copied) and
    // zero tids and tls. x86_64 takes (ptid, ctid, tls) and arm64
    // (ptid, tls, ctid). All three are zero, so the order is moot.
    // SAFETY: a raw clone with no stack of its own, as the C made it,
    // under the caller's contract.
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

/// An all-zero value of a plain C struct, as memset gave the C.
pub(crate) fn zeroed<T: Copy>() -> T {
    // SAFETY: every caller's T is a repr(C) struct of integers, for which
    // all zero bits are a value.
    unsafe { core::mem::zeroed() }
}

/// The seccomp program's arch-specific words. The audit arch the kernel
/// reports, whether an x32 table hides behind it, and the numbers of
/// the four calls the filter matches. The tables are pinned against
/// libc's numbers for the native arch in the tests, and against the C
/// program for both.
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

/// On x86_64 a number with this bit set selects the x32 table under the
/// same AUDIT_ARCH_X86_64, where unshare and friends have other numbers
/// than the ones matched below. The kernel calls it __X32_SYSCALL_BIT.
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

/// The offsets the program loads from, FZ_ARG_LO(i) in C: the low
/// 32 bits of argument i, which on these little-endian arches are the
/// first four bytes of it.
const NR_OFF: u32 = offset_of!(libc::seccomp_data, nr) as u32;
const ARCH_OFF: u32 = offset_of!(libc::seccomp_data, arch) as u32;
const ARG0_LO: u32 = offset_of!(libc::seccomp_data, args) as u32;
const ARG1_LO: u32 = ARG0_LO + 8;
const _: () = assert!(
    cfg!(target_endian = "little"),
    "FZ_ARG_LO adds 4 on a big-endian arch"
);

impl Filter {
    /// userns_filter's table in C, for arch. It refuses the system calls
    /// that make or join a user namespace. unshare and clone with
    /// CLONE_NEWUSER, and setns onto a user namespace (or onto whatever
    /// the descriptor is), get EPERM. clone3 gets ENOSYS, as a kernel
    /// without it would answer, because its flags sit in a struct
    /// seccomp cannot read, and libc then falls back to clone. On x86_64
    /// an x32 number kills the process, as libseccomp and Docker do, so
    /// the matches cannot be sidestepped through the other table.
    /// Everything else passes.
    ///
    /// The index and the count are checked at compile time, where a slip
    /// is a build error, not a panic on the child path.
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

/// The program for this arch, in bss as C's static table was.
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

/// prctl(2) with two arguments, the other two zero, as every call here
/// makes it.
///
/// # Safety
/// What option does with a and b must be safe for this process, and a
/// pointer among them live for the call.
unsafe fn prctl(option: c_int, a: c_ulong, b: c_ulong) -> c_int {
    let zero: c_ulong = 0;
    // SAFETY: by the contract above.
    unsafe { libc::prctl(option, a, b, zero, zero) }
}

/// struct __user_cap_header_struct in linux/capability.h, which libc
/// does not carry.
#[repr(C)]
#[derive(Clone, Copy)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// struct __user_cap_data_struct, one per 32 capabilities.
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// _LINUX_CAPABILITY_VERSION_3 and _LINUX_CAPABILITY_U32S_3.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAPABILITY_U32S_3: usize = 2;

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

/// Room for four descriptors in one SCM_RIGHTS control message, as the
/// C's cbuf had, aligned as a cmsghdr is.
const CMSG_WORDS: usize = 4;
const _: () = {
    // SAFETY: CMSG_SPACE is arithmetic on its argument.
    let space = unsafe { libc::CMSG_SPACE(4 * size_of::<c_int>() as u32) } as usize;
    assert!(
        space == CMSG_WORDS * size_of::<u64>(),
        "the control buffer is CMSG_SPACE(4 ints)"
    );
};

/// channel_recv takes one message off fd into buf, cap bytes, with
/// flags added to recvmsg's. The first descriptor passed with it goes to
/// *fd_out, -1 for none, and any other is closed. Returns the byte
/// count, 0 at EOF, or -1 with errno, EPROTO for a message longer than
/// a record. EINTR is retried, which cannot block a non-blocking read.
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
    if r > 0 && mh.msg_flags & libc::MSG_TRUNC != 0 {
        if *fd_out >= 0 {
            // SAFETY: fd_out is a descriptor the message just passed.
            unsafe { libc::close(*fd_out) };
            *fd_out = -1;
        }
        sys::set_errno(libc::EPROTO);
        return -1;
    }
    r
}

/// read_incarnation takes the birth record off the channel into born.
/// fiberd queues it before the CLONE, so it is there to read. Returns
/// 0, or -1 with a reason for the zygote's log. Anything passed with it
/// is not ours to keep.
///
/// # Safety
/// born is live and nothing else touches it.
unsafe fn read_incarnation(fd: c_int, born: *mut RecordStore, why: &mut *const c_char) -> c_int {
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

/// own_pair replaces fiberd's channel end, which the fiber is done with,
/// by a pair of the fiber's own at FZ_CHANNEL_FD and FZ_CHANNEL_PEER_FD.
/// The fiber reads the first and never the second, which it holds so the
/// pair is whole inside its tree: a park dumps both ends and a restore
/// remakes them in the fiber's namespaces, and fiberd then borrows the
/// peer to send the resume's record. System calls only, under the rule
/// above. Returns 0 or -1.
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

/// The seven pieces of a child_say line, written one write(2) each, as
/// the C did.
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
        // SAFETY: write reads part.len() bytes of part, which is live. One
        // write per part with no retry, as the C made it.
        unsafe { libc::write(2, part.as_ptr().cast(), part.len()) };
    }
}

/// "errno <e>" for child_say_errno, NUL-ended in a fixed buffer.
fn errno_why(e: c_int) -> [u8; 18] {
    let mut why = [0u8; 18];
    let n = sys::append(&mut why, 0, b"errno ");
    // C cast the value to unsigned.
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
/// under the rule at the top of this module. The C shim has already
/// reset its own statics with plain stores (the control descriptor and
/// handler, the report mutex, the channel and park state, ready_fd and
/// environ), none of which anything reads before on_fiber. What is
/// known only once the record is read, served_generation, is written
/// through c.
///
/// Descriptors first. The ready pipe's read end is the zygote's. The
/// zygote's SIGCHLD descriptor goes, wherever it sits. The readiness
/// pipe is parked at fd 3 (over the inherited control descriptor), the
/// fiber's channel to fiberd at FZ_CHANNEL_FD, everything above is
/// closed, and the standard three point at /dev/null (stderr once
/// ready). Nothing else a ready fiber holds leads outside its own tree,
/// and a handoff fiber's channel is the one socket CRIU is told is
/// external.
///
/// The fiber's record is the channel's first message, read here into
/// this child's memory so no application code runs without it and no
/// checkpoint is taken before it is consumed. It names the fence the
/// CLONE did, or the child is not the fiber fiberd asked for. A handoff
/// fiber keeps the channel for the connections fiberd passes it. Any
/// other fiber is done with fiberd's end and takes a pair of its own in
/// its place, which a park carries whole and a resume's record arrives
/// on. stderr stays the zygote's log until fz_fiber_ready, so a fiber
/// that fails to start can say why. No fiber is checkpointed before
/// then.
///
/// Session and signals. The mask is emptied, so SIGCHLD, blocked in the
/// zygote for its descriptor, reaches the fiber as usual. No
/// PR_SET_PDEATHSIG, because a resumed fiber has a different parent, and
/// the runtime kills leaves through the cgroup when the zygote or fiberd
/// goes away. No reseeding of anything, because srandom takes libc's
/// lock on the random state, which falls under the rule above, so the
/// template reseeds in on_fiber (see fz_on_fiber).
///
/// Mounts first, since they need the capabilities dropped right after.
/// A fiber that cannot be confined as fiberd asked does not run. The
/// child ends, its exit code naming the step that failed. The filter
/// goes on before the capabilities, since installing may need
/// CAP_SYS_ADMIN.
///
/// # Safety
/// The caller is the child of birth, c is a live Child whose pointers
/// are what abi.rs says, and the whole process is this path's.
pub unsafe fn scrub_and_run(c: &Child) -> ! {
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
    // The raw syscall, since glibc has a wrapper only from 2.34 and musl
    // has none. ~0U as the last descriptor, as the C passed it.
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
    let mut why: *const c_char = ptr::null();
    // SAFETY: c.born is the live store, by the contract above.
    if unsafe { read_incarnation(FZ_CHANNEL_FD, c.born, &mut why) } < 0 {
        // SAFETY: fence by the contract above, why was set with the -1.
        unsafe {
            child_say(c.fence, c"incarnation record", why);
            libc::_exit(EX_IDENTITY)
        }
    }
    // SAFETY: c.born is live and parsed, so inc.fence is a NUL-ended
    // field in its buf, and c.fence is NUL-ended.
    let born = unsafe { &*c.born };
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
    if !c.served_generation.is_null() {
        // SAFETY: a live static of the C's, by the contract above.
        unsafe { *c.served_generation = born.inc.generation };
    }
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
    let mut none: libc::sigset_t = zeroed();
    // SAFETY: none is live for both calls, the rest are integers.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::sigemptyset(&raw mut none);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const none, ptr::null_mut());
    }
    if c.mntns != 0 {
        // SAFETY: the tables are the C's statics, by the contract above.
        let tables = unsafe {
            Tables {
                self_exe: c.self_exe,
                hide: mounts::kept(c.hide, c.nhide),
                hide_covered: covered(c.hide_covered, c.nhide),
                drop: mounts::kept(c.drop, c.ndrop),
            }
        };
        // SAFETY: as above.
        let failed = unsafe { mounts::mount_ns(c.pidns != 0, &tables) };
        if failed != 0 {
            // SAFETY: _exit ends the child and never returns.
            unsafe { libc::_exit(mounts::mount_exit(failed)) }
        }
    }
    if c.deny_nested_userns != 0 && userns_filter() < 0 {
        // SAFETY: fence by the contract above.
        unsafe {
            child_say_errno(c.fence, c"deny nested user namespaces", sys::errno());
            libc::_exit(EX_USERNS)
        }
    }
    if c.nocaps != 0 && drop_caps() < 0 {
        // SAFETY: _exit ends the child and never returns.
        unsafe { libc::_exit(EX_CAPS) }
    }
    let rc = match c.on_fiber {
        // SAFETY: the template's entry, with the record it was promised.
        Some(on_fiber) => unsafe { on_fiber(&raw const born.inc) },
        // No template passes a null entry, and the C would have crashed
        // on the call. abort takes nothing and never returns.
        None => unsafe { libc::abort() },
    };
    // SAFETY: _exit ends the child and never returns.
    unsafe { libc::_exit(rc & 0xff) }
}

/// The first n covered flags at p as a slice, none when p is null.
///
/// # Safety
/// p points at n bytes, or is null.
unsafe fn covered<'a>(p: *const u8, n: c_int) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    let n = usize::try_from(n).unwrap_or(0).min(crate::abi::MAX_PATHS);
    // SAFETY: by the contract above.
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// scrub_and_run, for the C shim. Never returns.
///
/// # Safety
/// As scrub_and_run, and c is a live struct fz_rs_child.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_scrub_and_run(c: *const Child) -> ! {
    // SAFETY: by the contract above.
    unsafe {
        match c.as_ref() {
            Some(c) => scrub_and_run(c),
            None => libc::abort(),
        }
    }
}

/// channel_recv, for the C shim and the fiber-side API still there.
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

/// birth, for the C shim. The pid, 0 in the child, or -1 with errno.
///
/// # Safety
/// As birth.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_birth(cgroup_fd: c_int, want: c_ulonglong) -> libc::pid_t {
    // SAFETY: by the contract above.
    unsafe { birth(cgroup_fd, want) }
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

    /// A word as (code, jt, jf, k), which is how the C program reads.
    fn words(f: &Filter) -> Vec<(u16, u8, u8, u32)> {
        f.words()
            .iter()
            .map(|w| (w.code, w.jt, w.jf, w.k))
            .collect()
    }

    #[test]
    fn filter_is_the_c_program_word_for_word() {
        // The C program's words, as the BPF_STMT and BPF_JUMP lines of
        // userns_filter in main's C encode them with the kernel headers'
        // values (the aarch64 table dumped from that C, the x86_64 one
        // from the same lines with its numbers). BPF_LD|BPF_W|BPF_ABS is
        // 0x20, BPF_JMP|BPF_JEQ|BPF_K 0x15, BPF_JGE 0x35, BPF_JSET 0x45
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
}
