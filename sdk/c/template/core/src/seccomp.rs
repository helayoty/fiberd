//! The fiber seccomp filter (docs/design/seccomp.md). One program,
//! default allow, that the zygote installs once before READY and every
//! fiber inherits by reference at the clone. Calls that need no
//! capability yet reach deep kernel code answer an errno, four calls
//! have an argument checked, and a foreign arch or an x32 number kills
//! the process. A runc zygote, whose fibers keep CAP_SYS_ADMIN and never
//! get a mount namespace, takes a second program that also refuses the
//! mount family. Both are built and checked at compile time, so a jump
//! that lands outside the program is a build error.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{c_int, c_long, c_ulong};
use core::mem::offset_of;

use crate::child::prctl;
use crate::sys;

/// The program's arch-specific numbers. The tests pin the native arch's
/// against libc's.
pub struct Arch {
    /// AUDIT_ARCH_* for this arch.
    pub audit: u32,
    /// x86_64 alone has a second table under the same audit arch.
    pub x32: bool,
    /// __NR_clone, its flags in argument 0.
    pub clone: u32,
    /// __NR_unshare, its flags in argument 0.
    pub unshare: u32,
    /// __NR_socket, family in argument 0 and protocol in argument 2.
    pub socket: u32,
    /// __NR_personality, the persona in argument 0.
    pub personality: u32,
    /// The calls refused outright with EPERM, sorted by number.
    pub plain: &'static [u32],
    /// The mount family, sorted by number, refused by the runc program
    /// alone. A proc fiber's mount_ns runs after the clone and needs
    /// them.
    pub mounts: &'static [u32],
}

/// x86_64, AUDIT_ARCH_X86_64 is EM_X86_64 with the 64-bit and
/// little-endian bits.
pub const X86_64: Arch = Arch {
    audit: 0xC000_003E,
    x32: true,
    clone: 56,
    unshare: 272,
    socket: 41,
    personality: 135,
    plain: &[
        101, // ptrace
        103, // syslog
        134, // uselib
        139, // sysfs
        153, // vhangup
        154, // modify_ldt
        156, // _sysctl
        163, // acct
        164, // settimeofday
        167, // swapon
        168, // swapoff
        169, // reboot
        170, // sethostname
        171, // setdomainname
        172, // iopl
        173, // ioperm
        174, // create_module
        175, // init_module
        176, // delete_module
        177, // get_kernel_syms
        178, // query_module
        179, // quotactl
        180, // nfsservctl
        212, // lookup_dcookie
        227, // clock_settime
        246, // kexec_load
        248, // add_key
        249, // request_key
        250, // keyctl
        298, // perf_event_open
        300, // fanotify_init
        305, // clock_adjtime
        308, // setns
        310, // process_vm_readv
        311, // process_vm_writev
        312, // kcmp
        313, // finit_module
        320, // kexec_file_load
        321, // bpf
        323, // userfaultfd
        425, // io_uring_setup
        426, // io_uring_enter
        427, // io_uring_register
        438, // pidfd_getfd
        443, // quotactl_fd
        447, // memfd_secret
        460, // lsm_set_self_attr
    ],
    mounts: &[
        155, // pivot_root
        161, // chroot
        165, // mount
        166, // umount2
        303, // name_to_handle_at
        304, // open_by_handle_at
        428, // open_tree
        429, // move_mount
        430, // fsopen
        431, // fsconfig
        432, // fsmount
        433, // fspick
        442, // mount_setattr
        467, // open_tree_attr
    ],
};

/// aarch64, AUDIT_ARCH_AARCH64 is EM_AARCH64 with the same two bits.
pub const AARCH64: Arch = Arch {
    audit: 0xC000_00B7,
    x32: false,
    clone: 220,
    unshare: 97,
    socket: 198,
    personality: 92,
    plain: &[
        18,  // lookup_dcookie
        42,  // nfsservctl
        58,  // vhangup
        60,  // quotactl
        89,  // acct
        104, // kexec_load
        105, // init_module
        106, // delete_module
        112, // clock_settime
        116, // syslog
        117, // ptrace
        142, // reboot
        161, // sethostname
        162, // setdomainname
        170, // settimeofday
        217, // add_key
        218, // request_key
        219, // keyctl
        224, // swapon
        225, // swapoff
        241, // perf_event_open
        262, // fanotify_init
        266, // clock_adjtime
        268, // setns
        270, // process_vm_readv
        271, // process_vm_writev
        272, // kcmp
        273, // finit_module
        280, // bpf
        282, // userfaultfd
        294, // kexec_file_load
        425, // io_uring_setup
        426, // io_uring_enter
        427, // io_uring_register
        438, // pidfd_getfd
        443, // quotactl_fd
        447, // memfd_secret
        460, // lsm_set_self_attr
    ],
    mounts: &[
        39,  // umount2
        40,  // mount
        41,  // pivot_root
        51,  // chroot
        264, // name_to_handle_at
        265, // open_by_handle_at
        428, // open_tree
        429, // move_mount
        430, // fsopen
        431, // fsconfig
        432, // fsmount
        433, // fspick
        442, // mount_setattr
        467, // open_tree_attr
    ],
};

/// Which program. Fiber is the design's list. Runc adds the mount
/// family, since a runc fiber keeps CAP_SYS_ADMIN and could mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Program {
    /// The fiber filter, for a zygote whose fibers may take a mount
    /// namespace (proc).
    Fiber,
    /// The fiber filter plus the mount family (runc).
    Runc,
}

/// The longest equality chain, both lists of x86_64.
const CHAIN_MAX: usize = 64;

/// This arch's numbers.
#[cfg(target_arch = "x86_64")]
pub const NATIVE: Arch = X86_64;
/// This arch's numbers.
#[cfg(target_arch = "aarch64")]
pub const NATIVE: Arch = AARCH64;

/// __NR_clone3, the same on every arch.
const CLONE3: u32 = 435;

/// __X32_SYSCALL_BIT. On x86_64 it selects the x32 table under the same
/// audit arch, where the numbers above mean other calls.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The six CLONE_NEW* flags a fiber may not use. CLONE_NEWPID and
/// CLONE_NEWNS pass, since birth's legacy clone carries them.
const NEW_NS_REFUSED: u32 = 0x80 // CLONE_NEWTIME
    | 0x0200_0000 // CLONE_NEWCGROUP
    | 0x0400_0000 // CLONE_NEWUTS
    | 0x0800_0000 // CLONE_NEWIPC
    | 0x1000_0000 // CLONE_NEWUSER
    | 0x4000_0000; // CLONE_NEWNET

const AF_UNIX: u32 = libc::AF_UNIX as u32;
const AF_INET: u32 = libc::AF_INET as u32;
const AF_INET6: u32 = libc::AF_INET6 as u32;
const AF_NETLINK: u32 = libc::AF_NETLINK as u32;
const NETLINK_ROUTE: u32 = 0;
const NETLINK_GENERIC: u32 = 16;

/// The personas Docker allows. The query, PER_LINUX, PER_LINUX32 and
/// either with ADDR_NO_RANDOMIZE, which fz_init sets.
const PER_QUERY: u32 = 0xFFFF_FFFF;
const PER_LINUX: u32 = 0;
const PER_LINUX32: u32 = 8;
const ADDR_NO_RANDOMIZE: u32 = libc::ADDR_NO_RANDOMIZE as u32;

const LD_W_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
const JEQ_K: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
const JGE_K: u32 = libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K;
const JSET_K: u32 = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
const RET_K: u32 = libc::BPF_RET | libc::BPF_K;

/// The actions. An errno answer carries the number in its low 16 bits.
const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
const EAFNOSUPPORT: u32 = libc::SECCOMP_RET_ERRNO | libc::EAFNOSUPPORT as u32;
const EPROTONOSUPPORT: u32 = libc::SECCOMP_RET_ERRNO | libc::EPROTONOSUPPORT as u32;

/// The offsets the program loads from. ARGn_LO is the low 32 bits of
/// argument n, its first four bytes on a little-endian arch.
const NR_OFF: u32 = offset_of!(libc::seccomp_data, nr) as u32;
const ARCH_OFF: u32 = offset_of!(libc::seccomp_data, arch) as u32;
const ARG0_LO: u32 = offset_of!(libc::seccomp_data, args) as u32;
const ARG2_LO: u32 = ARG0_LO + 16;
const _: () = assert!(
    cfg!(target_endian = "little"),
    "ARGn_LO adds 4 on a big-endian arch"
);

/// The most words a program has.
pub const PROG_MAX: usize = 112;

/// A seccomp program in fixed storage, built at compile time.
pub struct Prog {
    /// The words, the first len of them live.
    pub words: [libc::sock_filter; PROG_MAX],
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

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
impl Prog {
    const fn push(&mut self, w: libc::sock_filter) {
        assert!(
            (self.len as usize) < PROG_MAX,
            "the program outgrew PROG_MAX"
        );
        self.words[self.len as usize] = w;
        self.len += 1;
    }

    /// The index of the word after the one pushed next.
    const fn next(&self) -> usize {
        self.len as usize + 1
    }

    const fn ld(&mut self, off: u32) {
        self.push(stmt(LD_W_ABS, off));
    }

    const fn ret(&mut self, action: u32) {
        self.push(stmt(RET_K, action));
    }

    /// A jump to absolute word indexes, neither behind the next word.
    const fn jmp(&mut self, code: u32, k: u32, jt: usize, jf: usize) {
        let next = self.next();
        assert!(jt >= next && jf >= next, "a jump goes backwards");
        assert!(jt - next <= 255 && jf - next <= 255, "a jump is too far");
        self.push(libc::sock_filter {
            code: code as u16,
            jt: (jt - next) as u8,
            jf: (jf - next) as u8,
            k,
        });
    }

    /// The program for arch. The plain refusals are one sorted equality
    /// chain, and the four argument checks each end in a return, so a
    /// loaded argument never reaches the next check.
    pub const fn build(a: &Arch, which: Program) -> Prog {
        let mut p = Prog {
            words: [stmt(0, 0); PROG_MAX],
            len: 0,
        };
        let (chain, n) = match which {
            Program::Fiber => merge(a.plain, &[]),
            Program::Runc => merge(a.plain, a.mounts),
        };
        // Where the shared returns land, so every jump to one is
        // absolute.
        let head = if a.x32 { 6 } else { 4 };
        let allow = head + n + 1 + 4 + 11 + 7;
        let eperm = allow + 1;
        let enosys = allow + 2;

        p.ld(ARCH_OFF);
        p.jmp(JEQ_K, a.audit, p.next() + 1, p.next());
        p.ret(KILL);
        p.ld(NR_OFF);
        if a.x32 {
            p.jmp(JGE_K, X32_SYSCALL_BIT, p.next(), p.next() + 1);
            p.ret(KILL);
        }
        let mut i = 0;
        while i < n {
            p.jmp(JEQ_K, chain[i], eperm, p.next());
            i += 1;
        }
        // clone3's flags sit in a struct seccomp cannot read. ENOSYS, as
        // an old kernel answers, so libc falls back to clone.
        p.jmp(JEQ_K, CLONE3, enosys, p.next());
        // clone and unshare. The kernel reads clone's low 32 bits alone,
        // and refuses unshare any high bit with EINVAL, so the low word
        // is the whole check.
        let after = p.len as usize + 4;
        p.jmp(JEQ_K, a.clone, p.next() + 1, p.next());
        p.jmp(JEQ_K, a.unshare, p.next(), after);
        p.ld(ARG0_LO);
        p.jmp(JSET_K, NEW_NS_REFUSED, eperm, allow);
        // socket(family, type, protocol). EAFNOSUPPORT is what a kernel
        // without the family answers.
        let after = p.len as usize + 11;
        p.jmp(JEQ_K, a.socket, p.next(), after);
        p.ld(ARG0_LO);
        p.jmp(JEQ_K, AF_UNIX, allow, p.next());
        p.jmp(JEQ_K, AF_INET, allow, p.next());
        p.jmp(JEQ_K, AF_INET6, allow, p.next());
        p.jmp(JEQ_K, AF_NETLINK, p.next() + 1, p.next());
        p.ret(EAFNOSUPPORT);
        p.ld(ARG2_LO);
        p.jmp(JEQ_K, NETLINK_ROUTE, allow, p.next());
        p.jmp(JEQ_K, NETLINK_GENERIC, allow, p.next());
        p.ret(EPROTONOSUPPORT);
        // personality(persona)
        let after = p.len as usize + 7;
        p.jmp(JEQ_K, a.personality, p.next(), after);
        p.ld(ARG0_LO);
        p.jmp(JEQ_K, PER_QUERY, allow, p.next());
        p.jmp(JEQ_K, PER_LINUX, allow, p.next());
        p.jmp(JEQ_K, PER_LINUX32, allow, p.next());
        p.jmp(JEQ_K, PER_LINUX | ADDR_NO_RANDOMIZE, allow, p.next());
        p.jmp(JEQ_K, PER_LINUX32 | ADDR_NO_RANDOMIZE, allow, eperm);
        assert!(
            p.len as usize == allow,
            "the sections are not the size the layout says"
        );
        p.ret(ALLOW);
        p.ret(EPERM);
        p.ret(ENOSYS);
        assert!(
            p.check(),
            "a jump leaves the program or it does not end in a return"
        );
        p
    }

    /// Whether every jump lands inside the program and the last word
    /// returns, as the kernel checks.
    pub const fn check(&self) -> bool {
        let n = self.len as usize;
        if n == 0 || n > PROG_MAX {
            return false;
        }
        let mut i = 0;
        while i < n {
            let w = self.words[i];
            if (w.code & 0x07) == libc::BPF_JMP as u16
                && (i + 1 + w.jt as usize >= n || i + 1 + w.jf as usize >= n)
            {
                return false;
            }
            i += 1;
        }
        self.words[n - 1].code == RET_K as u16
    }

    /// The live words.
    pub fn words(&self) -> &[libc::sock_filter] {
        self.words.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// Two sorted lists as one sorted list and its length. Both must be
/// sorted with no repeat, which the asserts make a build error.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn merge(a: &[u32], b: &[u32]) -> ([u32; CHAIN_MAX], usize) {
    let mut out = [0u32; CHAIN_MAX];
    let (mut i, mut j, mut n) = (0, 0, 0);
    while i < a.len() || j < b.len() {
        let take_a = j >= b.len() || (i < a.len() && a[i] < b[j]);
        let v = if take_a { a[i] } else { b[j] };
        if take_a {
            i += 1;
        } else {
            j += 1;
        }
        assert!(
            n == 0 || v > out[n - 1],
            "a list is not sorted or repeats the other"
        );
        assert!(n < CHAIN_MAX, "the chain outgrew CHAIN_MAX");
        out[n] = v;
        n += 1;
    }
    (out, n)
}

/// The programs for this arch, static so nothing is built at run time.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static PROG: Prog = Prog::build(&NATIVE, Program::Fiber);
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static PROG_RUNC: Prog = Prog::build(&NATIVE, Program::Runc);

const _: () = {
    assert!(size_of::<libc::sock_filter>() == 8);
    assert!(PROG_MAX <= u16::MAX as usize);
};

/// Why install was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// no_new_privs or the seccomp call failed with this errno.
    Errno(c_int),
    /// TSYNC could not cover this thread, one with a filter of its own.
    Thread(c_int),
}

/// install puts the program on every thread of the process, under
/// no_new_privs so no capability is needed. Fibers inherit it at the
/// clone. A refusal means the zygote must not serve.
pub fn install(which: Program) -> Result<(), Refusal> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = which;
        Err(Refusal::Errno(libc::ENOSYS))
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let p = match which {
            Program::Fiber => &PROG,
            Program::Runc => &PROG_RUNC,
        };
        let prog = libc::sock_fprog {
            len: p.len,
            // The kernel copies the program and writes nothing through
            // the pointer, whose type is sock_fprog's.
            filter: p.words.as_ptr().cast_mut(),
        };
        match apply(&prog) {
            0 => Ok(()),
            r if r < 0 => Err(Refusal::Errno(sys::errno())),
            tid => Err(Refusal::Thread(tid as c_int)),
        }
    }
}

/// seccomp's answer: 0, -1 with errno, or the tid TSYNC could not
/// cover. The tests fake it, so a serve that reaches READY does not
/// filter the test process.
fn apply(prog: &libc::sock_fprog) -> c_long {
    #[cfg(test)]
    if let Some((r, e)) = *tests::FAKE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        tests::SEEN_LEN.store(prog.len, std::sync::atomic::Ordering::Relaxed);
        sys::set_errno(e);
        return r;
    }
    apply_real(prog)
}

/// no_new_privs, then seccomp(SET_MODE_FILTER, TSYNC).
fn apply_real(prog: &libc::sock_fprog) -> c_long {
    let (zero, one): (c_ulong, c_ulong) = (0, 1);
    // SAFETY: integer arguments alone.
    if unsafe { prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero) } < 0 {
        return -1;
    }
    // SAFETY: prog and its words are live for the call, and the kernel
    // only reads them.
    unsafe {
        sys::syscall(
            libc::SYS_seccomp,
            [
                c_long::from(libc::SECCOMP_SET_MODE_FILTER),
                libc::SECCOMP_FILTER_FLAG_TSYNC as c_long,
                (prog as *const libc::sock_fprog) as c_long,
                0,
                0,
            ],
        )
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
    use std::sync::Mutex;

    /// What apply answers under test: (return, errno). None runs the real
    /// install. Changed only under crate::serial().
    pub(crate) static FAKE: Mutex<Option<(c_long, c_int)>> = Mutex::new(Some((0, 0)));
    /// The length of the program the faked apply was given.
    pub(crate) static SEEN_LEN: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

    /// A cBPF interpreter for the five codes the program uses, over a
    /// seccomp_data of nr, arch and args.
    fn run(p: &Prog, arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
        let words = p.words();
        let (mut pc, mut acc) = (0usize, 0u32);
        for _ in 0..words.len() {
            let w = words[pc];
            let (jt, jf) = (usize::from(w.jt), usize::from(w.jf));
            let k = w.k;
            pc += 1;
            match u32::from(w.code) {
                LD_W_ABS => {
                    let at = k as usize;
                    acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                }
                JEQ_K => pc += if acc == k { jt } else { jf },
                JGE_K => pc += if acc >= k { jt } else { jf },
                JSET_K => pc += if acc & k != 0 { jt } else { jf },
                RET_K => return k,
                other => panic!("word {pc}: code {other:#x}"),
            }
        }
        panic!("the program loops");
    }

    /// A call's number, the same on both arches or one per arch.
    enum Nr {
        Both(u32),
        Per { x86_64: u32, aarch64: u32 },
        Of(fn(&Arch) -> u32),
    }

    impl Nr {
        fn on(&self, a: &Arch) -> u32 {
            match *self {
                Nr::Both(n) => n,
                Nr::Per { x86_64, aarch64 } => {
                    if a.x32 {
                        x86_64
                    } else {
                        aarch64
                    }
                }
                Nr::Of(f) => f(a),
            }
        }
    }

    struct Case {
        name: &'static str,
        nr: Nr,
        args: [u64; 6],
        want: u32,
    }

    fn case(name: &'static str, nr: Nr, args: [u64; 6], want: u32) -> Case {
        Case {
            name,
            nr,
            args,
            want,
        }
    }

    fn arg0(a: u64) -> [u64; 6] {
        [a, 0, 0, 0, 0, 0]
    }

    const SIGCHLD: u64 = 17;
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const CLONE_NEWPID: u64 = 0x2000_0000;
    const CLONE_NEWUSER: u64 = 0x1000_0000;
    const CLONE_FS: u64 = 0x200;
    /// What glibc's pthread_create passes.
    const CLONE_THREAD_FLAGS: u64 = 0x3d0f00;

    #[test]
    fn the_program_answers_the_vectors_on_both_arches() {
        let cases = [
            case(
                "getpid",
                Nr::Per {
                    x86_64: 39,
                    aarch64: 172,
                },
                arg0(0),
                ALLOW,
            ),
            case(
                "ioctl",
                Nr::Per {
                    x86_64: 16,
                    aarch64: 29,
                },
                [1, 0x5413, 0, 0, 0, 0],
                ALLOW,
            ),
            case(
                "prctl",
                Nr::Per {
                    x86_64: 157,
                    aarch64: 167,
                },
                arg0(38),
                ALLOW,
            ),
            case(
                "seccomp",
                Nr::Per {
                    x86_64: 317,
                    aarch64: 277,
                },
                arg0(1),
                ALLOW,
            ),
            case(
                "memfd_create",
                Nr::Per {
                    x86_64: 319,
                    aarch64: 279,
                },
                arg0(0),
                ALLOW,
            ),
            case("landlock_create_ruleset", Nr::Both(444), arg0(0), ALLOW),
            case("pidfd_open", Nr::Both(434), arg0(1), ALLOW),
            case(
                "adjtimex",
                Nr::Per {
                    x86_64: 159,
                    aarch64: 171,
                },
                arg0(0),
                ALLOW,
            ),
            case(
                "a number the kernel does not have yet",
                Nr::Both(999),
                arg0(0),
                ALLOW,
            ),
            case("clone3", Nr::Both(CLONE3), arg0(0), ENOSYS),
            case(
                "clone of a thread",
                Nr::Of(|a| a.clone),
                arg0(CLONE_THREAD_FLAGS),
                ALLOW,
            ),
            case("clone of a fork", Nr::Of(|a| a.clone), arg0(SIGCHLD), ALLOW),
            case(
                "clone into a pid and mount namespace, birth's fallback",
                Nr::Of(|a| a.clone),
                arg0(CLONE_NEWPID | CLONE_NEWNS | SIGCHLD),
                ALLOW,
            ),
            case(
                "clone into a user namespace",
                Nr::Of(|a| a.clone),
                arg0(CLONE_NEWUSER | SIGCHLD),
                EPERM,
            ),
            case(
                "clone into a network namespace",
                Nr::Of(|a| a.clone),
                arg0(0x4000_0000 | SIGCHLD),
                EPERM,
            ),
            case(
                "clone into a time namespace",
                Nr::Of(|a| a.clone),
                arg0(0x80 | SIGCHLD),
                EPERM,
            ),
            case(
                "clone into a cgroup namespace",
                Nr::Of(|a| a.clone),
                arg0(0x0200_0000 | SIGCHLD),
                EPERM,
            ),
            case(
                "clone into a uts namespace",
                Nr::Of(|a| a.clone),
                arg0(0x0400_0000 | SIGCHLD),
                EPERM,
            ),
            case(
                "clone into an ipc namespace",
                Nr::Of(|a| a.clone),
                arg0(0x0800_0000 | SIGCHLD),
                EPERM,
            ),
            case(
                "clone with a high bit, the kernel drops it",
                Nr::Of(|a| a.clone),
                arg0(1 << 40 | SIGCHLD),
                ALLOW,
            ),
            case(
                "clone with a high bit and a user namespace",
                Nr::Of(|a| a.clone),
                arg0(1 << 40 | CLONE_NEWUSER),
                EPERM,
            ),
            case(
                "unshare(CLONE_FS)",
                Nr::Of(|a| a.unshare),
                arg0(CLONE_FS),
                ALLOW,
            ),
            case(
                "unshare of a pid and mount namespace",
                Nr::Of(|a| a.unshare),
                arg0(CLONE_NEWPID | CLONE_NEWNS),
                ALLOW,
            ),
            case(
                "unshare of a user namespace",
                Nr::Of(|a| a.unshare),
                arg0(CLONE_NEWUSER),
                EPERM,
            ),
            case(
                "unshare of a user and mount namespace",
                Nr::Of(|a| a.unshare),
                arg0(CLONE_NEWUSER | CLONE_NEWNS),
                EPERM,
            ),
            case(
                "socket(AF_UNIX)",
                Nr::Of(|a| a.socket),
                [1, 1, 0, 0, 0, 0],
                ALLOW,
            ),
            case(
                "socket(AF_INET)",
                Nr::Of(|a| a.socket),
                [2, 1, 0, 0, 0, 0],
                ALLOW,
            ),
            case(
                "socket(AF_INET6)",
                Nr::Of(|a| a.socket),
                [10, 2, 0, 0, 0, 0],
                ALLOW,
            ),
            case(
                "socket(AF_NETLINK, NETLINK_ROUTE)",
                Nr::Of(|a| a.socket),
                [16, 3, 0, 0, 0, 0],
                ALLOW,
            ),
            case(
                "socket(AF_NETLINK, NETLINK_GENERIC)",
                Nr::Of(|a| a.socket),
                [16, 3, 16, 0, 0, 0],
                ALLOW,
            ),
            case(
                "socket(AF_NETLINK, NETLINK_SOCK_DIAG)",
                Nr::Of(|a| a.socket),
                [16, 3, 4, 0, 0, 0],
                EPROTONOSUPPORT,
            ),
            case(
                "socket(AF_NETLINK, NETLINK_KOBJECT_UEVENT)",
                Nr::Of(|a| a.socket),
                [16, 3, 15, 0, 0, 0],
                EPROTONOSUPPORT,
            ),
            case(
                "socket(AF_PACKET)",
                Nr::Of(|a| a.socket),
                [17, 3, 0, 0, 0, 0],
                EAFNOSUPPORT,
            ),
            case(
                "socket(AF_ALG)",
                Nr::Of(|a| a.socket),
                [38, 5, 0, 0, 0, 0],
                EAFNOSUPPORT,
            ),
            case(
                "socket(AF_VSOCK)",
                Nr::Of(|a| a.socket),
                [40, 1, 0, 0, 0, 0],
                EAFNOSUPPORT,
            ),
            case(
                "socket(AF_UNSPEC)",
                Nr::Of(|a| a.socket),
                [0, 1, 0, 0, 0, 0],
                EAFNOSUPPORT,
            ),
            case(
                "personality query",
                Nr::Of(|a| a.personality),
                arg0(0xFFFF_FFFF),
                ALLOW,
            ),
            case(
                "personality(PER_LINUX)",
                Nr::Of(|a| a.personality),
                arg0(0),
                ALLOW,
            ),
            case(
                "personality(PER_LINUX32)",
                Nr::Of(|a| a.personality),
                arg0(8),
                ALLOW,
            ),
            case(
                "personality(ADDR_NO_RANDOMIZE), fz_init's",
                Nr::Of(|a| a.personality),
                arg0(0x0004_0000),
                ALLOW,
            ),
            case(
                "personality(PER_LINUX32 | ADDR_NO_RANDOMIZE)",
                Nr::Of(|a| a.personality),
                arg0(0x0004_0008),
                ALLOW,
            ),
            case(
                "personality(UNAME26)",
                Nr::Of(|a| a.personality),
                arg0(0x0002_0000),
                EPERM,
            ),
            case(
                "personality(READ_IMPLIES_EXEC)",
                Nr::Of(|a| a.personality),
                arg0(0x0040_0000),
                EPERM,
            ),
            case(
                "personality(MMAP_PAGE_ZERO)",
                Nr::Of(|a| a.personality),
                arg0(0x0010_0000),
                EPERM,
            ),
            case(
                "personality(ADDR_NO_RANDOMIZE | UNAME26)",
                Nr::Of(|a| a.personality),
                arg0(0x0006_0000),
                EPERM,
            ),
        ];
        let arches: &[(&str, &Arch)] = &[("x86_64", &X86_64), ("aarch64", &AARCH64)];
        let programs = [Program::Fiber, Program::Runc];
        for ((arch_name, a), which) in arches
            .iter()
            .flat_map(|a| programs.iter().map(move |w| (a, *w)))
        {
            let p = Prog::build(a, which);
            for tc in &cases {
                let got = run(&p, a.audit, tc.nr.on(a), tc.args);
                assert_eq!(got, tc.want, "{arch_name} {which:?}: {}", tc.name);
            }
            // One case per plain refusal, whatever the arguments.
            for &nr in a.plain {
                assert_eq!(
                    run(&p, a.audit, nr, [u64::MAX; 6]),
                    EPERM,
                    "{arch_name} {which:?}: nr {nr}"
                );
            }
            // The mount family, which only the runc program refuses.
            let mounts = if which == Program::Runc { EPERM } else { ALLOW };
            for &nr in a.mounts {
                assert_eq!(
                    run(&p, a.audit, nr, [u64::MAX; 6]),
                    mounts,
                    "{arch_name} {which:?}: mount nr {nr}"
                );
            }
            // The other arch's table is foreign, and i386's too.
            let other = if a.x32 { AARCH64.audit } else { X86_64.audit };
            assert_eq!(
                run(&p, other, 39, arg0(0)),
                KILL,
                "{arch_name} {which:?}: a foreign arch"
            );
            assert_eq!(
                run(&p, 0x4000_0003, 39, arg0(0)),
                KILL,
                "{arch_name} {which:?}: i386"
            );
            // x86_64 alone has an x32 table under its audit arch.
            let x32 = if a.x32 { KILL } else { ALLOW };
            assert_eq!(
                run(&p, a.audit, X32_SYSCALL_BIT | 39, arg0(0)),
                x32,
                "{arch_name} {which:?}: an x32 number"
            );
        }
    }

    #[test]
    fn the_programs_are_short_and_checked() {
        let cases: &[(&str, &Arch, Program, usize)] = &[
            ("x86_64 fiber", &X86_64, Program::Fiber, 79),
            ("x86_64 runc", &X86_64, Program::Runc, 93),
            ("aarch64 fiber", &AARCH64, Program::Fiber, 68),
            ("aarch64 runc", &AARCH64, Program::Runc, 82),
        ];
        for (name, arch, which, len) in cases {
            let p = Prog::build(arch, *which);
            assert_eq!(usize::from(p.len), *len, "{name}: length");
            assert_eq!(p.words().len(), *len, "{name}: live words");
            assert!(p.check(), "{name}");
        }
    }

    #[test]
    fn merge_keeps_the_order() {
        let cases: &[(&str, &[u32], &[u32], &[u32])] = &[
            ("both empty", &[], &[], &[]),
            ("one empty", &[1, 5], &[], &[1, 5]),
            ("interleaved", &[1, 5, 9], &[2, 6], &[1, 2, 5, 6, 9]),
            ("one after the other", &[1, 2], &[3, 4], &[1, 2, 3, 4]),
        ];
        for (name, a, b, want) in cases {
            let (out, n) = merge(a, b);
            assert_eq!(&out[..n], *want, "{name}");
        }
    }

    #[test]
    fn check_refuses_a_broken_program() {
        let cases: &[(&str, fn(&mut Prog))] = &[
            ("a jump past the end", |p| p.words[1].jt = 255),
            ("a jump to the end", |p| {
                let n = usize::from(p.len);
                p.words[n - 4].jt = 3;
            }),
            ("no return at the end", |p| {
                let n = usize::from(p.len);
                p.words[n - 1] = stmt(LD_W_ABS, 0);
            }),
            ("empty", |p| p.len = 0),
        ];
        for (name, bend) in cases {
            let mut p = Prog::build(&NATIVE, Program::Fiber);
            bend(&mut p);
            assert!(!p.check(), "{name}");
        }
    }

    #[test]
    fn native_numbers_are_libcs() {
        let plain: &[(&str, c_long)] = &[
            ("ptrace", libc::SYS_ptrace),
            ("syslog", libc::SYS_syslog),
            ("vhangup", libc::SYS_vhangup),
            ("acct", libc::SYS_acct),
            ("settimeofday", libc::SYS_settimeofday),
            ("swapon", libc::SYS_swapon),
            ("swapoff", libc::SYS_swapoff),
            ("reboot", libc::SYS_reboot),
            ("sethostname", libc::SYS_sethostname),
            ("setdomainname", libc::SYS_setdomainname),
            ("init_module", libc::SYS_init_module),
            ("delete_module", libc::SYS_delete_module),
            ("quotactl", libc::SYS_quotactl),
            ("nfsservctl", libc::SYS_nfsservctl),
            ("lookup_dcookie", libc::SYS_lookup_dcookie),
            ("clock_settime", libc::SYS_clock_settime),
            ("kexec_load", libc::SYS_kexec_load),
            ("add_key", libc::SYS_add_key),
            ("request_key", libc::SYS_request_key),
            ("keyctl", libc::SYS_keyctl),
            ("perf_event_open", libc::SYS_perf_event_open),
            ("fanotify_init", libc::SYS_fanotify_init),
            ("clock_adjtime", libc::SYS_clock_adjtime),
            ("setns", libc::SYS_setns),
            ("process_vm_readv", libc::SYS_process_vm_readv),
            ("process_vm_writev", libc::SYS_process_vm_writev),
            ("kcmp", libc::SYS_kcmp),
            ("finit_module", libc::SYS_finit_module),
            ("kexec_file_load", libc::SYS_kexec_file_load),
            ("bpf", libc::SYS_bpf),
            ("userfaultfd", libc::SYS_userfaultfd),
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_uring_enter", libc::SYS_io_uring_enter),
            ("io_uring_register", libc::SYS_io_uring_register),
            ("pidfd_getfd", libc::SYS_pidfd_getfd),
            ("quotactl_fd", libc::SYS_quotactl_fd),
            ("memfd_secret", libc::SYS_memfd_secret),
            // libc 0.2.191 has no SYS_lsm_set_self_attr. 460 on every arch.
            ("lsm_set_self_attr", 460),
            #[cfg(target_arch = "x86_64")]
            ("uselib", libc::SYS_uselib),
            #[cfg(target_arch = "x86_64")]
            ("sysfs", libc::SYS_sysfs),
            #[cfg(target_arch = "x86_64")]
            ("_sysctl", libc::SYS__sysctl),
            #[cfg(target_arch = "x86_64")]
            ("modify_ldt", libc::SYS_modify_ldt),
            #[cfg(target_arch = "x86_64")]
            ("iopl", libc::SYS_iopl),
            #[cfg(target_arch = "x86_64")]
            ("ioperm", libc::SYS_ioperm),
            // libc has no names for the three removed module calls.
            #[cfg(target_arch = "x86_64")]
            ("create_module", 174),
            #[cfg(target_arch = "x86_64")]
            ("get_kernel_syms", 177),
            #[cfg(target_arch = "x86_64")]
            ("query_module", 178),
        ];
        assert_eq!(plain.len(), NATIVE.plain.len(), "a name per number");
        for (name, nr) in plain {
            assert!(
                NATIVE.plain.contains(&(*nr as u32)),
                "{name} ({nr}) is not in the native list"
            );
        }
        let mounts: &[(&str, c_long)] = &[
            ("mount", libc::SYS_mount),
            ("umount2", libc::SYS_umount2),
            ("pivot_root", libc::SYS_pivot_root),
            ("chroot", libc::SYS_chroot),
            ("name_to_handle_at", libc::SYS_name_to_handle_at),
            ("open_by_handle_at", libc::SYS_open_by_handle_at),
            ("open_tree", libc::SYS_open_tree),
            ("move_mount", libc::SYS_move_mount),
            ("fsopen", libc::SYS_fsopen),
            ("fsconfig", libc::SYS_fsconfig),
            ("fsmount", libc::SYS_fsmount),
            ("fspick", libc::SYS_fspick),
            ("mount_setattr", libc::SYS_mount_setattr),
            // libc 0.2.191 has no SYS_open_tree_attr. 467 on every arch.
            ("open_tree_attr", 467),
        ];
        assert_eq!(mounts.len(), NATIVE.mounts.len(), "a name per mount number");
        for (name, nr) in mounts {
            assert!(
                NATIVE.mounts.contains(&(*nr as u32)),
                "{name} ({nr}) is not in the native mount list"
            );
        }
        let checked: &[(&str, u32, c_long)] = &[
            ("clone", NATIVE.clone, libc::SYS_clone),
            ("unshare", NATIVE.unshare, libc::SYS_unshare),
            ("socket", NATIVE.socket, libc::SYS_socket),
            ("personality", NATIVE.personality, libc::SYS_personality),
            ("clone3", CLONE3, libc::SYS_clone3),
        ];
        for (name, got, want) in checked {
            assert_eq!(c_long::from(*got), *want, "{name}");
        }
        assert_eq!(
            NATIVE.x32,
            cfg!(target_arch = "x86_64"),
            "x86_64 alone has an x32 table"
        );
        assert_eq!(
            NEW_NS_REFUSED,
            (libc::CLONE_NEWUSER
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWCGROUP) as u32
                | 0x80,
            "the refused namespace flags"
        );
        assert_eq!(ADDR_NO_RANDOMIZE, 0x0004_0000);
    }

    /// Waits for pid and returns its status.
    fn wait(pid: libc::pid_t) -> c_int {
        let mut status = 0;
        // SAFETY: status is live for the call.
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid, "waitpid");
        status
    }

    #[test]
    fn the_kernel_takes_the_program_and_answers_as_the_vectors_say() {
        let _serial = crate::serial();
        // Each case is a raw call made under the real filter in a forked
        // child, and the child's exit code is the first case that did
        // not answer as expected, or 0. Only system calls run there.
        struct Live {
            name: &'static str,
            nr: c_long,
            args: [c_long; 5],
            want: c_int, // 0 for success, else the errno
        }
        let live = [
            Live {
                name: "getpid",
                nr: libc::SYS_getpid,
                args: [0; 5],
                want: 0,
            },
            Live {
                name: "io_uring_setup",
                nr: libc::SYS_io_uring_setup,
                args: [1, 0, 0, 0, 0],
                want: libc::EPERM,
            },
            Live {
                name: "kcmp",
                nr: libc::SYS_kcmp,
                args: [0; 5],
                want: libc::EPERM,
            },
            Live {
                name: "clone3",
                nr: libc::SYS_clone3,
                args: [0; 5],
                want: libc::ENOSYS,
            },
            Live {
                name: "unshare(CLONE_NEWUSER)",
                nr: libc::SYS_unshare,
                args: [c_long::from(libc::CLONE_NEWUSER), 0, 0, 0, 0],
                want: libc::EPERM,
            },
            Live {
                name: "unshare(CLONE_FS)",
                nr: libc::SYS_unshare,
                args: [c_long::from(libc::CLONE_FS), 0, 0, 0, 0],
                want: 0,
            },
            Live {
                name: "socket(AF_ALG)",
                nr: libc::SYS_socket,
                args: [38, c_long::from(libc::SOCK_SEQPACKET), 0, 0, 0],
                want: libc::EAFNOSUPPORT,
            },
            Live {
                name: "socket(AF_NETLINK, NETLINK_SOCK_DIAG)",
                nr: libc::SYS_socket,
                args: [
                    c_long::from(libc::AF_NETLINK),
                    c_long::from(libc::SOCK_RAW),
                    4,
                    0,
                    0,
                ],
                want: libc::EPROTONOSUPPORT,
            },
            Live {
                name: "socket(AF_NETLINK, NETLINK_ROUTE)",
                nr: libc::SYS_socket,
                args: [
                    c_long::from(libc::AF_NETLINK),
                    c_long::from(libc::SOCK_RAW),
                    0,
                    0,
                    0,
                ],
                want: 0,
            },
            Live {
                name: "socket(AF_UNIX)",
                nr: libc::SYS_socket,
                args: [
                    c_long::from(libc::AF_UNIX),
                    c_long::from(libc::SOCK_STREAM),
                    0,
                    0,
                    0,
                ],
                want: 0,
            },
            Live {
                name: "personality query",
                nr: libc::SYS_personality,
                args: [0xFFFF_FFFF, 0, 0, 0, 0],
                want: 0,
            },
            Live {
                name: "personality(UNAME26)",
                nr: libc::SYS_personality,
                args: [0x0002_0000, 0, 0, 0, 0],
                want: libc::EPERM,
            },
        ];
        // SAFETY: the child makes raw system calls and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let prog = libc::sock_fprog {
                len: PROG.len,
                filter: PROG.words.as_ptr().cast_mut(),
            };
            if apply_real(&prog) != 0 {
                // SAFETY: _exit ends the child.
                unsafe { libc::_exit(100) };
            }
            for (i, tc) in live.iter().enumerate() {
                // SAFETY: each call takes integers, a null pointer where
                // one is read (clone3, io_uring_setup) fails before use.
                let r = unsafe { sys::syscall(tc.nr, tc.args) };
                let ok = if tc.want == 0 {
                    r >= 0
                } else {
                    r == -1 && sys::errno() == tc.want
                };
                if !ok {
                    // SAFETY: _exit ends the child.
                    unsafe { libc::_exit(i as c_int + 1) };
                }
            }
            // SAFETY: _exit ends the child.
            unsafe { libc::_exit(0) };
        }
        let status = wait(pid);
        assert!(
            libc::WIFEXITED(status),
            "the child died: status {status:#x}"
        );
        let code = libc::WEXITSTATUS(status);
        assert_ne!(code, 100, "the kernel refused the program");
        if code != 0 {
            panic!(
                "{}: not the answer expected",
                live[(code - 1) as usize].name
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn an_x32_number_dies_with_sigsys() {
        let _serial = crate::serial();
        // SAFETY: the child installs the filter and makes one raw call.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let prog = libc::sock_fprog {
                len: PROG.len,
                filter: PROG.words.as_ptr().cast_mut(),
            };
            if apply_real(&prog) != 0 {
                // SAFETY: _exit ends the child.
                unsafe { libc::_exit(100) };
            }
            // SAFETY: an x32 getpid, which the filter kills.
            unsafe {
                sys::syscall(c_long::from(X32_SYSCALL_BIT | 39), [0; 5]);
                libc::_exit(1)
            };
        }
        let status = wait(pid);
        assert!(
            libc::WIFSIGNALED(status),
            "the child exited: status {status:#x}"
        );
        assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
    }
}
