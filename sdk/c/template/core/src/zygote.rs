//! The zygote side: fz_init and fz_serve, the serving loop, its children
//! and the state they share. prepare.rs does the namespace work before
//! READY over the same state.
//!
//! Only the serving thread touches State and Tables. What a template may
//! touch from any thread is ctl.rs's. The tests of tests/integration/proc
//! pin the order of the system calls (reap after the pending deadlines,
//! the syscall budgets).
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{CStr, c_char, c_int, c_long, c_ulonglong, c_void};
use core::mem::size_of;
use core::ptr;

use crate::abi::{
    ENGINE_MAX, ENV_VALUE_MAX, FENCE_MAX, FZ_CHANNEL_FD, KEEP_MAX, Kept, MAX_KIDS, MAX_LINE,
    MAX_PASSED, MAX_PATHS, MAX_PENDING, OnFiber, RUNDIR_MAX,
};
use crate::child::{self, Child, zeroed};
use crate::ctl::{self, Line, STRERROR_MAX, deadline_of, ms_until, now_ts, recv_line};
use crate::fiber::{Global, READY_BYTE};
use crate::line::{self, CloneRefusal, Setup};
use crate::mounts;
use crate::prepare::keep_only_sys_admin;
use crate::seccomp;
use crate::sys::{self, Errno};

/// The reason the zygote refuses every mntns CLONE, or ends on instead
/// of READY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A fixed reason.
    Text(&'static CStr),
    /// own_ns_why, why fz_init took no mount namespace of its own.
    OwnNs,
    /// prepare_reason, the HIDE path prepare_ns could not cover.
    Prepare,
}

/// The longest fence, endpoint and session, as the ERROR lines name
/// them.
const FENCE_LEN_MAX: c_int = (FENCE_MAX - 1) as c_int;
const ENV_LEN_MAX: c_int = (ENV_VALUE_MAX - 1) as c_int;

/// own_ns_why's storage.
pub const OWN_NS_WHY_MAX: usize = 160;
/// prepare_reason's storage.
pub const PREPARE_REASON_MAX: usize = RUNDIR_MAX + 96;

/// The small fields, in .data.
pub struct State {
    /// SIGCHLD, blocked since fz_init, read in the poll set. Opened once
    /// per process. The child closes it and unblocks the signal.
    pub sigchld_fd: c_int,
    /// Why a HIDE, DROP, RUNDIR or PREPARE line was refused, or None.
    /// Set before READY, it is sent as the ERROR the zygote ends on
    /// instead of READY. Set after READY (a setup line that came late),
    /// every later mntns CLONE is refused with it instead.
    pub paths_refused: Option<Refused>,
    /// own_mountns went through.
    pub have_own_ns: bool,
    /// prepare_ns went through, so mntns fibers may be born.
    pub ns_prepared: bool,
    /// How many HIDE paths Tables.hide holds.
    pub nhide: usize,
    /// How many DROP paths Tables.drop holds.
    pub ndrop: usize,
    /// How many fibers Tables.kids holds.
    pub nkids: usize,
    /// How many children Tables.pending holds.
    pub npending: usize,
    /// How many pids Tables.doomed holds.
    pub ndoomed: usize,
}

impl State {
    /// The state before fz_init.
    pub const fn new() -> State {
        State {
            sigchld_fd: -1,
            paths_refused: None,
            have_own_ns: false,
            ns_prepared: false,
            nhide: 0,
            ndrop: 0,
            nkids: 0,
            npending: 0,
            ndoomed: 0,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::new()
    }
}

/// A fiber that reported ready, pid to fence, for its EXITED line.
#[derive(Clone, Copy)]
pub struct Kid {
    /// Its pid.
    pub pid: libc::pid_t,
    /// Its fence, NUL-ended.
    pub fence: [u8; FENCE_MAX],
}

/// A child forked but not yet ready. The loop polls every ready pipe at
/// once, so a storm is forked back to back and each CLONE is
/// acknowledged the moment its own child reports, never behind the
/// others.
#[derive(Clone, Copy)]
pub struct Pending {
    /// Its pid.
    pub pid: libc::pid_t,
    /// The zygote's end of its readiness pipe.
    pub ready_fd: c_int,
    /// Its fence, NUL-ended.
    pub fence: [u8; FENCE_MAX],
    /// When it is killed if it has not reported.
    pub deadline: libc::timespec,
}

/// The fiber's environment, built by the parent before the clone and
/// assigned whole in the child. Static storage is reused per clone, and
/// the child's copy-on-write pages keep this clone's values.
pub struct Env {
    /// FIBERD_FENCE=<fence>
    pub fence: [u8; 14 + FENCE_MAX],
    /// FIBERD_ENDPOINT=<endpoint>
    pub endpoint: [u8; 17 + ENV_VALUE_MAX],
    /// FIBERD_ENGINE=<endpoint>
    pub engine: [u8; 15 + ENGINE_MAX],
    /// FIBERD_CHANNEL_FD=4
    pub channel: [u8; 19 + 16],
    /// FIBERD_SESSION=<session>
    pub session: [u8; 16 + ENV_VALUE_MAX],
    /// The entries, null-ended, which environ points at in the child.
    pub environ: [*mut c_char; 6],
}

/// The fixed storage, all zero at rest, in .bss. A page costs only once
/// touched, but under THP=always one write faults in a whole 2 MiB
/// window that a park then writes out, so the tables stay small.
pub struct Tables {
    /// What a mntns fiber must not see (HIDE), resolved by prepare_ns.
    /// keep_path refuses a path too long for its slot rather than cut it.
    pub hide: [Kept; MAX_PATHS],
    /// Which HIDE paths prepare_ns found and covered. One missing then is
    /// looked for again at each birth (mount_ns), so a directory fiberd
    /// makes after READY is still hidden.
    pub hide_covered: [u8; MAX_PATHS],
    /// What a mntns fiber must not keep (DROP, unmounted).
    pub drop: [Kept; MAX_PATHS],
    /// fiberd's run directory (RUNDIR), NUL-ended, empty until sent.
    pub rundir_parent: [u8; RUNDIR_MAX],
    /// This grant's directory in it.
    pub rundir_own: [u8; RUNDIR_MAX],
    /// The zygote's own executable as /proc/self/exe names it, read once
    /// at PREPARE. Empty when it could not be read. A HIDE path that
    /// holds it is covered with the executable bound back at its place
    /// (cover_hide), since fiberd runs a registry template from its
    /// template cache and hides the cache.
    pub self_exe: [u8; RUNDIR_MAX],
    /// Why fz_init took no mount namespace of its own, NUL-ended.
    pub own_ns_why: [u8; OWN_NS_WHY_MAX],
    /// The HIDE path prepare_ns could not cover and why, NUL-ended.
    pub prepare_reason: [u8; PREPARE_REASON_MAX],
    /// Fibers that reported ready.
    pub kids: [Kid; MAX_KIDS],
    /// Children forked but not yet ready.
    pub pending: [Pending; MAX_PENDING],
    /// Children killed before ready that the kernel had not let go of
    /// within the bounded wait (doom). Their CLONE is already answered,
    /// so when they are finally reaped nothing is said about them.
    pub doomed: [libc::pid_t; MAX_PENDING],
    /// The fiber's environment.
    pub env: Env,
    /// The session named on the CLONE line, decoded, for the fiber's
    /// environment.
    pub session: [u8; ENV_VALUE_MAX],
    /// The line being served, read_setup's and then the loop's.
    pub line: [u8; MAX_LINE],
    /// The poll set, the control socket, the SIGCHLD descriptor and
    /// every pending readiness pipe.
    pub fds: [libc::pollfd; 2 + MAX_PENDING],
}

static STATE: Global<State> = Global::new(State::new());
// SAFETY: Tables is integers, byte arrays and raw pointers, for which all
// zero bits are a value (null for the pointers).
static TABLES: Global<Tables> = Global::new(unsafe { core::mem::zeroed() });

/// The zygote's state, as references, so unit tests can drive the loop
/// over state of their own.
pub struct Zygote<'a> {
    /// The small fields.
    pub st: &'a mut State,
    /// The fixed storage.
    pub t: &'a mut Tables,
}

/// The Zygote of the statics.
///
/// # Safety
/// The caller is the serving thread, in an entry, and holds no other
/// reference into the statics while this one lives.
unsafe fn global<'a>() -> Zygote<'a> {
    // SAFETY: by the contract above, each static is referenced once.
    unsafe {
        Zygote {
            st: &mut *STATE.get(),
            t: &mut *TABLES.get(),
        }
    }
}

/// The child's reset of this module's state, a plain store before its
/// first system call. The SIGCHLD descriptor is the zygote's alone.
///
/// # Safety
/// The caller is the child of birth, the only thread of the process.
pub unsafe fn reset_for_child() {
    // SAFETY: by the contract above.
    unsafe { (*STATE.get()).sigchld_fd = -1 };
}

/// The bytes of a NUL-ended string in buf, the NUL not included.
pub fn c_str(buf: &[u8]) -> &[u8] {
    buf.get(..sys::nul_at(buf)).unwrap_or(&[])
}

/// Copies s into buf, NUL-ended, cut to what fits.
pub fn set_cstr(buf: &mut [u8], s: &[u8]) {
    let cap = buf.len().saturating_sub(1);
    let n = sys::append(buf, 0, s.get(..cap).unwrap_or(s));
    if let Some(end) = buf.get_mut(n) {
        *end = 0;
    }
}

/// strerror(e) in a fixed buffer, for a line.
fn errno_text(e: c_int) -> ([u8; STRERROR_MAX], usize) {
    let mut buf = [0u8; STRERROR_MAX];
    let n = ctl::strerror(e, &mut buf).len();
    (buf, n)
}

/// What a library exit code (a child that could not be confined or set
/// up) stands for, or None for any other code (the template's own).
pub fn exit_why(code: c_int) -> Option<&'static [u8]> {
    Some(match code {
        child::EX_MNT_PRIVATE => b"could not make its mount namespace private",
        child::EX_MNT_PROC => b"could not mount its own /proc",
        child::EX_MNT_DROP => b"could not unmount a DROP path",
        child::EX_MNT_HIDE => b"could not cover a HIDE path that appeared after READY",
        child::EX_CAPS => b"could not drop its capabilities",
        child::EX_MNT_RO => b"could not make the host controls under /proc read-only",
        child::EX_FDS => b"could not set up its descriptors",
        child::EX_IDENTITY => b"did not get its incarnation record",
        child::EX_CGROUP => b"could not join its cgroup leaf",
        child::EX_FILTER => b"could not stack its clone3 filter",
        child::EX_WORKSPACE => b"could not mount its workspace at /workspace",
        _ => return None,
    })
}

/// The line a child that died before ready gets: the signal, or the
/// exit code with what it stands for when the library assigned it.
pub fn died_line(fence: &[u8], status: c_int) -> Line {
    let mut l = Line::new();
    l.s(b"ERROR ").s(fence).s(b" died before ready: ");
    if libc::WIFSIGNALED(status) {
        l.s(b"signal:").int(libc::WTERMSIG(status));
        return l;
    }
    let code = libc::WEXITSTATUS(status);
    l.s(b"exit:").int(code);
    if let Some(why) = exit_why(code) {
        l.s(b" (").s(why).s(b")");
    }
    l
}

/// The EXITED line of a fiber that reported ready.
pub fn exited_line(pid: libc::pid_t, status: c_int) -> Line {
    let mut l = Line::new();
    l.s(b"EXITED ").int(pid).s(b" ");
    if libc::WIFSIGNALED(status) {
        l.s(b"signal:").int(libc::WTERMSIG(status));
    } else {
        l.s(b"exit:").int(libc::WEXITSTATUS(status));
    }
    l
}

/// send_died answers a CLONE whose child died before ready.
fn send_died(ctl_fd: c_int, fence: &[u8], status: c_int) {
    died_line(fence, status).send(ctl_fd);
}

/// wait_bounded reaps pid if it ends within ms milliseconds, polling
/// with WNOHANG. The zygote never blocks in waitpid, since a child the
/// kernel holds after SIGKILL (a mount namespace being torn down, a
/// stuck filesystem) would stall every grant's clones. Returns what
/// waitpid returns, 0 while the child is still there.
pub fn wait_bounded(pid: libc::pid_t, status: &mut c_int, ms: c_int) -> libc::pid_t {
    let mut ms = ms;
    loop {
        let w = loop {
            // SAFETY: status is live for the call.
            let w = unsafe { libc::waitpid(pid, status, libc::WNOHANG) };
            if w < 0 && sys::errno() == libc::EINTR {
                continue;
            }
            break w;
        };
        if w != 0 || ms <= 0 {
            return w;
        }
        ms = ms.wrapping_sub(1);
        let one_ms = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        // SAFETY: one_ms is live for the call, and the remainder is not
        // asked for.
        unsafe { libc::nanosleep(&raw const one_ms, ptr::null_mut()) };
    }
}

/// reported_ready says whether a pending child's pipe holds its ready
/// record, without waiting. A child that reported and exited while the
/// loop sat in a bounded wait on another is reaped before its pipe is
/// polled, and must be answered as a fiber that ran, not a failed birth.
pub fn reported_ready(fd: c_int) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: p is live for the call, and one entry long.
    if unsafe { libc::poll(&raw mut p, 1, 0) } <= 0 || p.revents & libc::POLLIN == 0 {
        return false;
    }
    let mut rec = [0u8; 2];
    let n = loop {
        // SAFETY: read writes at most two bytes of rec, which is live.
        let n = unsafe { libc::read(fd, rec.as_mut_ptr().cast(), rec.len()) };
        if n < 0 && sys::errno() == libc::EINTR {
            continue;
        }
        break n;
    };
    n == 1 && rec.first() == Some(&READY_BYTE)
}

impl Zygote<'_> {
    /// remember notes a fiber that reported ready, for its EXITED line.
    pub fn remember(&mut self, pid: libc::pid_t, fence: &[u8]) {
        let n = self.st.nkids;
        if n >= MAX_KIDS {
            return;
        }
        if let Some(k) = self.t.kids.get_mut(n) {
            k.pid = pid;
            set_cstr(&mut k.fence, fence);
            self.st.nkids = n.wrapping_add(1);
        }
    }

    /// forget drops a fiber from the kids.
    pub fn forget(&mut self, pid: libc::pid_t) {
        let n = self.st.nkids;
        let kids = self.t.kids.get_mut(..n).unwrap_or(&mut []);
        if let Some(i) = kids.iter().position(|k| k.pid == pid) {
            let last = n.wrapping_sub(1);
            if let Some(&moved) = kids.get(last)
                && let Some(slot) = kids.get_mut(i)
            {
                *slot = moved;
            }
            self.st.nkids = last;
        }
    }

    /// drop_pending closes a pending child's pipe and drops its entry,
    /// swapping in the last one.
    pub fn drop_pending(&mut self, i: usize) {
        let n = self.st.npending;
        let pending = self.t.pending.get_mut(..n).unwrap_or(&mut []);
        if let Some(p) = pending.get(i) {
            // SAFETY: an integer argument alone.
            unsafe { libc::close(p.ready_fd) };
            let last = n.wrapping_sub(1);
            if let Some(&moved) = pending.get(last)
                && let Some(slot) = pending.get_mut(i)
            {
                *slot = moved;
            }
            self.st.npending = last;
        }
    }

    /// pending_index finds a pid among the pending children.
    pub fn pending_index(&self, pid: libc::pid_t) -> Option<usize> {
        self.t
            .pending
            .get(..self.st.npending)
            .unwrap_or(&[])
            .iter()
            .position(|p| p.pid == pid)
    }

    /// doom kills a pending child and reaps it if the kernel lets go of
    /// it in time. One it does not is left to reap with its CLONE
    /// answered.
    pub fn doom(&mut self, pid: libc::pid_t) {
        // SAFETY: integer arguments alone.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        if wait_bounded(pid, &mut status, 500) == 0 && self.st.ndoomed < MAX_PENDING {
            let n = self.st.ndoomed;
            if let Some(slot) = self.t.doomed.get_mut(n) {
                *slot = pid;
                self.st.ndoomed = n.wrapping_add(1);
            }
        }
    }

    /// forget_doomed says whether a reaped pid was doomed, and drops it.
    pub fn forget_doomed(&mut self, pid: libc::pid_t) -> bool {
        let n = self.st.ndoomed;
        let doomed = self.t.doomed.get_mut(..n).unwrap_or(&mut []);
        if let Some(i) = doomed.iter().position(|&d| d == pid) {
            let last = n.wrapping_sub(1);
            if let Some(&moved) = doomed.get(last)
                && let Some(slot) = doomed.get_mut(i)
            {
                *slot = moved;
            }
            self.st.ndoomed = last;
            return true;
        }
        false
    }

    /// The fence of pending child i, a copy, since the entry may move.
    fn pending_fence(&self, i: usize) -> [u8; FENCE_MAX] {
        self.t.pending.get(i).map_or([0; FENCE_MAX], |p| p.fence)
    }

    /// reap takes every child that is gone. A pending child that never
    /// reported is answered with the reason it died, one that reported
    /// and ended inside one bounded wait is answered CLONED, and every
    /// fiber gets its EXITED line.
    pub fn reap(&mut self, ctl_fd: c_int) {
        loop {
            let mut status = 0;
            // SAFETY: status is live for the call.
            let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
            if pid <= 0 {
                return;
            }
            if self.forget_doomed(pid) {
                continue;
            }
            if let Some(i) = self.pending_index(pid) {
                let fence = self.pending_fence(i);
                let ready_fd = self.t.pending.get(i).map_or(-1, |p| p.ready_fd);
                if !reported_ready(ready_fd) {
                    // Died before it ever reported ready.
                    send_died(ctl_fd, c_str(&fence), status);
                    self.drop_pending(i);
                    continue;
                }
                // Ready, then gone, both inside one bounded wait.
                Line::new()
                    .s(b"CLONED ")
                    .s(c_str(&fence))
                    .s(b" ")
                    .int(pid)
                    .send(ctl_fd);
                self.drop_pending(i);
            }
            self.forget(pid);
            exited_line(pid, status).send(ctl_fd);
        }
    }

    /// settle_pending answers pending child i, whose pipe became
    /// readable or closed. Only the ready record (fz_fiber_ready) makes
    /// a fiber. Otherwise a live child is killed and the CLONE answered
    /// with an ERROR. Nothing here waits unbounded on a live child, which
    /// would stall every other grant's clones.
    pub fn settle_pending(&mut self, ctl_fd: c_int, i: usize) {
        let Some(&p) = self.t.pending.get(i) else {
            return;
        };
        let fence = c_str(&p.fence);
        let mut rec = [0u8; 2];
        let n = loop {
            // SAFETY: read writes at most two bytes of rec, which is live.
            let n = unsafe { libc::read(p.ready_fd, rec.as_mut_ptr().cast(), rec.len()) };
            if n < 0 && sys::errno() == libc::EINTR {
                continue;
            }
            break n;
        };
        if n == 1 && rec.first() == Some(&READY_BYTE) {
            self.remember(p.pid, fence);
            Line::new()
                .s(b"CLONED ")
                .s(fence)
                .s(b" ")
                .int(p.pid)
                .send(ctl_fd);
            self.drop_pending(i);
            return;
        }
        let mut status = 0;
        // SAFETY: status is live for the call.
        let mut w = unsafe { libc::waitpid(p.pid, &raw mut status, libc::WNOHANG) };
        // An exiting child closes the pipe a moment before it can be
        // reaped, while its mount namespace is torn down. On EOF, give it
        // that moment. A fiber that closed the pipe and runs on costs the
        // zygote 200ms, not a hang.
        if n == 0 && w == 0 {
            w = wait_bounded(p.pid, &mut status, 200);
        }
        if w == 0 {
            // Alive. It closed the pipe or wrote something else on it.
            self.doom(p.pid);
            if n > 0 {
                Line::new()
                    .s(b"ERROR ")
                    .s(fence)
                    .s(b" wrote 0x")
                    .hex2(rec.first().copied().unwrap_or(0))
                    .s(b" on the readiness pipe instead of reporting ready (fd 3 is not the fiber's to use); killed")
                    .send(ctl_fd);
            } else {
                Line::new()
                    .s(b"ERROR ")
                    .s(fence)
                    .s(b" closed the readiness pipe without reporting ready; killed")
                    .send(ctl_fd);
            }
        } else if w == p.pid {
            // Gone before reporting (or right after misreporting).
            send_died(ctl_fd, fence, status);
        } else {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" closed the readiness pipe without reporting ready")
                .send(ctl_fd);
        }
        self.drop_pending(i);
    }

    /// expire_pending kills and reports every pending child past its
    /// deadline.
    pub fn expire_pending(&mut self, ctl_fd: c_int) {
        let mut i = 0usize;
        while i < self.st.npending {
            let Some(&p) = self.t.pending.get(i) else {
                return;
            };
            if ms_until(p.deadline) > 0 {
                i = i.wrapping_add(1);
                continue;
            }
            self.doom(p.pid);
            Line::new()
                .s(b"ERROR ")
                .s(c_str(&p.fence))
                .s(b" deadline exceeded before ready")
                .send(ctl_fd);
            self.drop_pending(i);
        }
    }

    /// The text of the refusal the zygote holds, if any.
    pub fn refused(&self) -> Option<&[u8]> {
        self.st.paths_refused.map(|r| match r {
            Refused::Text(s) => s.to_bytes(),
            Refused::OwnNs => c_str(&self.t.own_ns_why),
            Refused::Prepare => c_str(&self.t.prepare_reason),
        })
    }

    /// keep_path keeps a HIDE or DROP line's path, or refuses it when the
    /// table is full or the path does not fit its slot with its NUL. A
    /// refusal leaves its reason in paths_refused, which serve sends
    /// instead of READY, so fiberd fails the warm (fail closed).
    pub fn keep_path(&mut self) {
        let hide = self.t.line.first() == Some(&b'H');
        let line = c_str(&self.t.line);
        let path = line.get(5..).unwrap_or(&[]);
        let (paths, count) = if hide {
            (&mut self.t.hide, &mut self.st.nhide)
        } else {
            (&mut self.t.drop, &mut self.st.ndrop)
        };
        let why: &'static CStr = match (hide, *count < MAX_PATHS, path.len() < KEEP_MAX) {
            (_, true, true) => {
                if let Some(slot) = paths.get_mut(*count) {
                    set_cstr(slot, path);
                    *count = count.wrapping_add(1);
                }
                return;
            }
            (true, false, _) => c"HIDE: too many paths",
            (false, false, _) => c"DROP: too many paths",
            (true, true, false) => c"HIDE: path too long",
            (false, true, false) => c"DROP: path too long",
        };
        self.st.paths_refused = Some(Refused::Text(why));
        Line::new()
            .s(b"libfiberzygote: ")
            .s(why.to_bytes())
            .s(b" refused")
            .stderr();
    }

    /// read_setup takes fiberd's setup lines before READY. HIDE, DROP
    /// and RUNDIR name what every mntns fiber's namespace must have.
    /// PREPARE mntns ends them and prepares the namespace (prepare_ns).
    /// PREPARE none means no fiber will ask for one. A refused line fails
    /// the warm closed, as in keep_path, and any other line is a protocol
    /// error. Returns Ok(true) to serve, Ok(false) when fiberd closed the
    /// channel first.
    pub fn read_setup(&mut self, ctl_fd: c_int) -> Result<bool, Errno> {
        let mut passed = [-1; MAX_PASSED];
        loop {
            let n = recv_line(ctl_fd, &mut self.t.line, &mut passed);
            close_passed(&passed);
            if n < 0 {
                return Err(Errno::last());
            }
            if n == 0 {
                return Ok(false);
            }
            match line::setup_kind(&self.t.line) {
                Setup::Hide | Setup::Drop => self.keep_path(),
                Setup::Rundir => {
                    let Tables {
                        line,
                        rundir_parent,
                        rundir_own,
                        ..
                    } = &mut *self.t;
                    if let Err(why) = line::parse_rundir(line, rundir_parent, rundir_own) {
                        self.st.paths_refused = Some(Refused::Text(c"RUNDIR refused"));
                        Line::new()
                            .s(b"libfiberzygote: RUNDIR refused: ")
                            .s(why.to_bytes())
                            .stderr();
                    }
                }
                Setup::PrepareMntns => {
                    if self.prepare_ns() < 0 {
                        let mut l = Line::new();
                        l.s(b"libfiberzygote: PREPARE refused: ")
                            .s(self.refused().unwrap_or(b""));
                        l.stderr();
                    }
                    return Ok(true);
                }
                Setup::PrepareNone => return Ok(true),
                Setup::Other => {
                    Line::new()
                        .s(b"libfiberzygote: expected HIDE, DROP, RUNDIR or PREPARE before READY, got ")
                        .cut(c_str(&self.t.line), 60)
                        .stderr();
                    return Err(Errno(libc::EPROTO));
                }
            }
        }
    }

    /// rebind_ctl takes the control socket fiberd sends as a REBIND
    /// message on the bootstrap one and puts it at ctl_fd in its place.
    /// fiberd makes that socket in this zygote's network namespace,
    /// where a checkpoint of the zygote finds it.
    pub fn rebind_ctl(&mut self, ctl_fd: c_int) -> Result<(), Errno> {
        let mut line = [0u8; 64];
        let mut passed = [-1; MAX_PASSED];
        let n = recv_line(ctl_fd, &mut line, &mut passed);
        if n <= 0 || !line::is_rebind(&line) || passed.first().is_none_or(|&fd| fd < 0) {
            close_passed(&passed);
            let mut l = Line::new();
            l.s(b"libfiberzygote: expected REBIND with a socket, got ");
            if n > 0 {
                l.s(c_str(&line));
            } else {
                l.s(b"end of stream");
            }
            l.stderr();
            return Err(Errno(libc::EPROTO));
        }
        let sock = passed.first().copied().unwrap_or(-1);
        // SAFETY: integer arguments alone.
        if unsafe { libc::dup2(sock, ctl_fd) } < 0 {
            return Err(Errno::last());
        }
        close_passed(&passed);
        Ok(())
    }

    /// handle_clone answers one CLONE line, Tables.line, forking the
    /// fiber. `CLONE <fence> <endpoint> <deadline_ms> <hexpayload|->
    /// <hexsession|-> [opt,opt...]`. line::parse_clone cuts the line up
    /// in place, and each ERROR is sent from here, in order with the
    /// checks on the zygote's own state. The loop closes passed after.
    pub fn handle_clone(&mut self, ctl_fd: c_int, passed: &[c_int; MAX_PASSED], on_fiber: OnFiber) {
        let Tables {
            line,
            session,
            env,
            pending,
            hide,
            hide_covered,
            drop,
            self_exe,
            own_ns_why,
            prepare_reason,
            ..
        } = &mut *self.t;
        let st = &mut *self.st;
        let cl = line::parse_clone(line, session);
        // Until the fence is known to fit, it goes on the line cut to
        // what the records hold, so the line is sent rather than dropped.
        let fence_raw: &[u8] = cl.fence.map_or(b"?", |f| f.of(line));
        if cl.refusal == Some(CloneRefusal::Malformed) {
            Line::new()
                .s(b"ERROR ")
                .cut(fence_raw, FENCE_MAX.wrapping_sub(1))
                .s(b" malformed CLONE")
                .send(ctl_fd);
            return;
        }
        if cl.refusal == Some(CloneRefusal::FenceTooLong) {
            Line::new()
                .s(b"ERROR ")
                .cut(fence_raw, FENCE_MAX.wrapping_sub(1))
                .s(b" fence too long (at most ")
                .int(FENCE_LEN_MAX)
                .s(b" characters)")
                .send(ctl_fd);
            return;
        }
        let fence = fence_raw;
        if cl.refusal == Some(CloneRefusal::UnknownOption) {
            // Refused, never skipped. A fiber born without what an option
            // asked for would run with less than fiberd believes.
            let opt: &[u8] = cl.unknown.map_or(b"", |o| o.of(line));
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" unknown CLONE option ")
                .s(opt)
                .send(ctl_fd);
            return;
        }
        if cl.mntns
            && let Some(refused) = st.paths_refused
        {
            let why: &[u8] = match refused {
                Refused::Text(s) => s.to_bytes(),
                Refused::OwnNs => c_str(own_ns_why),
                Refused::Prepare => c_str(prepare_reason),
            };
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" refused: the mount namespace cannot hide what fiberd asked (")
                .s(why)
                .s(b")")
                .send(ctl_fd);
            return;
        }
        if cl.mntns && !st.ns_prepared {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" refused: no mount namespace was prepared before READY (fiberd sent PREPARE none)")
                .send(ctl_fd);
            return;
        }
        // The channel is the last descriptor passed. Before it, with ws,
        // comes the workspace tree, and before that the cgroup's when
        // there is one. The ws option says whether the tree is there,
        // so a line with two descriptors is read right either way.
        let (cgroup_fd, ws_fd, channel) = sort_passed(passed, cl.ws);
        if channel < 0 {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" CLONE without a channel")
                .send(ctl_fd);
            return;
        }
        if cl.ws && ws_fd < 0 {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" CLONE with ws but no workspace descriptor")
                .send(ctl_fd);
            return;
        }
        if cl.ws && !cl.mntns {
            // The tree goes into the child's own namespace. Without one
            // it would land in the zygote's, in front of every sibling.
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" CLONE with ws needs mntns")
                .send(ctl_fd);
            return;
        }
        // The payload reaches the fiber on its record, not from here. The
        // session goes in the fiber's environment, so a NUL inside it, or
        // more than fits, is refused rather than cut.
        if cl.refusal == Some(CloneRefusal::SessionTooLong) {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" session too long (at most ")
                .int(ENV_LEN_MAX)
                .s(b" bytes)")
                .send(ctl_fd);
            return;
        }
        if cl.refusal == Some(CloneRefusal::SessionNul) {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" session holds a NUL byte")
                .send(ctl_fd);
            return;
        }
        if st.npending >= MAX_PENDING {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" too many clones in flight")
                .send(ctl_fd);
            return;
        }
        // The fiber's environment is built here, so the child only points
        // environ at it.
        let endpoint: &[u8] = cl.endpoint.map_or(b"", |e| e.of(line));
        set_env(&mut env.fence, b"FIBERD_FENCE=", fence);
        // Checked on the length itself, since env.endpoint also has room
        // for the name.
        if endpoint.len() >= ENV_VALUE_MAX {
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" endpoint too long (at most ")
                .int(ENV_LEN_MAX)
                .s(b" characters)")
                .send(ctl_fd);
            return;
        }
        set_env(&mut env.endpoint, b"FIBERD_ENDPOINT=", endpoint);
        let engine = ctl::engine_endpoint();
        let engine = c_str(&engine);
        let mut ne = 0usize;
        let mut put = |entry: *mut c_char| {
            if let Some(slot) = env.environ.get_mut(ne) {
                *slot = entry;
                ne = ne.wrapping_add(1);
            }
        };
        put(env.fence.as_mut_ptr().cast());
        put(env.endpoint.as_mut_ptr().cast());
        if !engine.is_empty() {
            set_env(&mut env.engine, b"FIBERD_ENGINE=", engine);
            put(env.engine.as_mut_ptr().cast());
        }
        let mut fd_text = [0u8; 16];
        let fd_n = sys::append_decimal(&mut fd_text, 0, FZ_CHANNEL_FD as u32);
        set_env(
            &mut env.channel,
            b"FIBERD_CHANNEL_FD=",
            fd_text.get(..fd_n).unwrap_or(&[]),
        );
        put(env.channel.as_mut_ptr().cast());
        if cl.session_len != 0 {
            set_env(&mut env.session, b"FIBERD_SESSION=", c_str(session));
            put(env.session.as_mut_ptr().cast());
        }
        put(ptr::null_mut());
        let mut rp = [-1 as c_int; 2];
        // SAFETY: rp is live for the call.
        if unsafe { libc::pipe2(rp.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            let (why, n) = errno_text(sys::errno());
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" pipe: ")
                .s(why.get(..n).unwrap_or(&[]))
                .send(ctl_fd);
            return;
        }
        let [ready_r, ready_w] = rp;
        // What the child's path needs, built before the clone so the
        // child does nothing but its plain stores and the path itself.
        let child = Child {
            ready_r,
            ready_w,
            channel,
            ws_fd,
            sigchld_fd: st.sigchld_fd,
            pidns: cl.pidns,
            mntns: cl.mntns,
            nocaps: cl.nocaps,
            fence: fence.as_ptr().cast(),
            on_fiber,
            environ: env.environ.as_mut_ptr(),
            tables: mounts::Tables {
                self_exe: self_exe.as_ptr().cast(),
                hide: hide.get(..st.nhide).unwrap_or(&[]),
                hide_covered: hide_covered.get(..st.nhide).unwrap_or(&[]),
                drop: drop.get(..st.ndrop).unwrap_or(&[]),
            },
        };
        let mut want: c_ulonglong = 0;
        if cl.pidns {
            want |= libc::CLONE_NEWPID as c_ulonglong;
        }
        if cl.mntns {
            want |= libc::CLONE_NEWNS as c_ulonglong;
        }
        // SAFETY: the serving thread, and the child goes on under
        // scrub_and_run's rule.
        let pid = unsafe { child::birth(cgroup_fd, want) };
        if pid < 0 {
            let (why, n) = errno_text(sys::errno());
            Line::new()
                .s(b"ERROR ")
                .s(fence)
                .s(b" clone: ")
                .s(why.get(..n).unwrap_or(&[]))
                .send(ctl_fd);
            // SAFETY: the pipe's own descriptors.
            unsafe {
                libc::close(ready_r);
                libc::close(ready_w);
            }
            return;
        }
        if pid == 0 {
            // SAFETY: the child of birth, with a live Child whose
            // pointers name the zygote's statics, which this copy of
            // memory holds at the same addresses.
            unsafe { child::scrub_and_run(&child) }
        }
        // SAFETY: the pipe's write end, the child's now.
        unsafe { libc::close(ready_w) };
        // Do not wait here. Park the child and return to the loop, so
        // the next CLONE in a storm is forked right away.
        if let Some(p) = pending.get_mut(st.npending) {
            p.pid = pid;
            p.ready_fd = ready_r;
            set_cstr(&mut p.fence, fence);
            p.deadline = deadline_of(now_ts(), cl.deadline_ms);
            st.npending = st.npending.wrapping_add(1);
        }
    }

    /// fz_serve's body. Ok(0) when fiberd closes the channel, or an
    /// error with the errno the entry sets.
    pub fn serve(&mut self, ctl_fd: c_int, on_fiber: OnFiber) -> Result<c_int, Errno> {
        // SAFETY: integer arguments alone.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        // All before READY, so a zygote that skipped fz_init, cannot deny
        // nested user namespaces or cannot take its channel never serves
        // and fiberd sees the warm fail. SIGCHLD unblocked here means it
        // may be unblocked in a thread fz_init would have covered, and a
        // fiber's exit would then reach the loop a timeout late.
        let mut have: libc::sigset_t = zeroed();
        // SAFETY: have is live for both calls.
        let blocked = unsafe {
            libc::pthread_sigmask(libc::SIG_BLOCK, ptr::null(), &raw mut have) == 0
                && libc::sigismember(&raw const have, libc::SIGCHLD) == 1
        };
        if !blocked {
            Line::new()
                .s(b"libfiberzygote: SIGCHLD is not blocked; call fz_init first thing in main")
                .stderr();
            return Err(Errno(libc::EINVAL));
        }
        if self.st.sigchld_fd < 0 {
            let mut chld: libc::sigset_t = zeroed();
            // SAFETY: chld is live for the calls.
            let fd = unsafe {
                libc::sigemptyset(&raw mut chld);
                libc::sigaddset(&raw mut chld, libc::SIGCHLD);
                libc::signalfd(-1, &raw const chld, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC)
            };
            if fd < 0 {
                return Err(Errno::last());
            }
            self.st.sigchld_fd = fd;
        }
        if env_set(c"FIBERD_CTL_REBIND") {
            self.rebind_ctl(ctl_fd)?;
        }
        if env_is(c"FIBERD_USERNS_NESTED", b"deny") {
            self.cap_nested_userns()?;
        }
        // The setup lines and their namespace come before READY, so READY
        // means every mntns fiber's namespace is ready to copy. Every fiber
        // of a plain proc grant asks for one, so a zygote that could not
        // build it sends an ERROR instead and fiberd fails the warm.
        if !self.read_setup(ctl_fd)? {
            return Ok(0);
        }
        if let Some(why) = self.refused() {
            Line::new().s(b"ERROR ? ").s(why).send(ctl_fd);
            return Err(Errno(libc::ENOTRECOVERABLE));
        }
        // A runc zygote (FIBERD_USERNS_NESTED=deny, what fiberd sets when
        // the zygote keeps capabilities in a user namespace of its own)
        // serves no mntns fiber, so its fibers keep CAP_SYS_ADMIN alone
        // and may not mount. The drop acts on this thread, the one every
        // fiber is forked from. An engine thread started before fz_serve
        // keeps the container's capabilities and no fiber inherits them.
        // Fail closed, as cap_nested_userns.
        let runc = env_is(c"FIBERD_USERNS_NESTED", b"deny");
        if runc && let Err(Errno(e)) = keep_only_sys_admin() {
            let (text, n) = errno_text(e);
            Line::new()
                .s(b"ERROR ? capabilities: ")
                .s(text.get(..n).unwrap_or(&[]))
                .send(ctl_fd);
            return Err(Errno(libc::ENOTRECOVERABLE));
        }
        // The fiber filter, last so the proc mounts above ran without
        // it, on every thread so an engine thread is covered. Fibers
        // inherit it at the clone. Fail closed, as cap_nested_userns.
        let program = if runc {
            seccomp::Program::Runc
        } else {
            seccomp::Program::Fiber
        };
        if let Err(refusal) = seccomp::install(program) {
            let mut why = Line::new();
            why.s(b"seccomp filter: ");
            match refusal {
                seccomp::Refusal::Errno(e) => {
                    let (text, n) = errno_text(e);
                    why.s(text.get(..n).unwrap_or(&[]));
                }
                seccomp::Refusal::Thread(tid) => {
                    why.s(b"thread ").int(tid).s(b" would not take it");
                }
            }
            Line::new().s(b"libfiberzygote: ").s(why.bytes()).stderr();
            Line::new().s(b"ERROR ? ").s(why.bytes()).send(ctl_fd);
            return Err(Errno(libc::ENOTRECOVERABLE));
        }
        if Line::new().s(b"READY").send(ctl_fd) < 0 {
            return Err(Errno::last());
        }
        ctl::set_ctl_fd(ctl_fd); // from here on other threads may fz_report_line
        loop {
            // Poll the control socket, the SIGCHLD descriptor and every
            // pending readiness pipe, no longer than the nearest deadline.
            // The 100ms is a backstop. A SIGCHLD taken elsewhere (a thread
            // that unblocked it) then costs a wait, not a hang.
            let npending = self.st.npending;
            let mut timeout: c_long = 100;
            {
                let Tables { fds, pending, .. } = &mut *self.t;
                if let Some(f) = fds.first_mut() {
                    *f = libc::pollfd {
                        fd: ctl_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                }
                if let Some(f) = fds.get_mut(1) {
                    *f = libc::pollfd {
                        fd: self.st.sigchld_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                }
                for (i, p) in pending.get(..npending).unwrap_or(&[]).iter().enumerate() {
                    if let Some(f) = fds.get_mut(i.wrapping_add(2)) {
                        *f = libc::pollfd {
                            fd: p.ready_fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                    }
                    let left = ms_until(p.deadline).max(0);
                    if left < timeout {
                        timeout = left;
                    }
                }
            }
            let nfds = npending.wrapping_add(2);
            // SAFETY: fds holds at least nfds live entries.
            let r = unsafe {
                libc::poll(
                    self.t.fds.as_mut_ptr(),
                    nfds as libc::nfds_t,
                    timeout as c_int,
                )
            };
            if r < 0 && sys::errno() != libc::EINTR {
                return Err(Errno::last());
            }
            // Drain the signal. Exits coalesce into one pending SIGCHLD,
            // and reap below takes every child that is gone.
            if self
                .t
                .fds
                .get(1)
                .is_some_and(|f| f.revents & libc::POLLIN != 0)
            {
                let mut si: libc::signalfd_siginfo = zeroed();
                // SAFETY: si is live for the call and sizeof si long.
                while unsafe {
                    libc::read(
                        self.st.sigchld_fd,
                        (&raw mut si).cast::<c_void>(),
                        size_of::<libc::signalfd_siginfo>(),
                    )
                } > 0
                {}
            }
            // Settle children whose pipes spoke, walking backwards because
            // settling removes entries by swapping in the last one.
            let mut i = npending;
            while i > 0 {
                i = i.wrapping_sub(1);
                let spoke = self.t.fds.get(i.wrapping_add(2)).is_some_and(|f| {
                    f.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                });
                if spoke {
                    self.settle_pending(ctl_fd, i);
                }
            }
            self.expire_pending(ctl_fd);
            self.reap(ctl_fd);
            let ctl_spoke =
                self.t.fds.first().is_some_and(|f| {
                    f.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                });
            if !ctl_spoke {
                continue;
            }
            let mut passed = [-1; MAX_PASSED];
            let n = recv_line(ctl_fd, &mut self.t.line, &mut passed);
            if n <= 0 {
                // What rode with a line that ends the loop is nobody's.
                // An error after the first bytes (a line longer than the
                // buffer) leaves their descriptors here.
                close_passed(&passed);
                if n == 0 {
                    // fiberd gone: take the family with us.
                    for k in self.t.kids.get(..self.st.nkids).unwrap_or(&[]) {
                        // SAFETY: integer arguments alone.
                        unsafe { libc::kill(k.pid, libc::SIGKILL) };
                    }
                    for p in self.t.pending.get(..self.st.npending).unwrap_or(&[]) {
                        // SAFETY: integer arguments alone.
                        unsafe { libc::kill(p.pid, libc::SIGKILL) };
                    }
                    return Ok(0);
                }
                return Err(Errno::last());
            }
            let line = c_str(&self.t.line);
            if line.starts_with(b"CLONE ") {
                self.handle_clone(ctl_fd, &passed, on_fiber);
            } else if line.starts_with(b"HIDE ")
                || line.starts_with(b"DROP ")
                || line.starts_with(b"RUNDIR ")
                || line.starts_with(b"PREPARE ")
            {
                // The namespace was prepared before READY and takes no
                // more. A path asked for now would go unhidden, so every
                // mntns CLONE from here on is refused rather than born
                // short.
                if self.st.paths_refused.is_none() {
                    self.st.paths_refused = Some(Refused::Text(
                        c"a setup line (HIDE, DROP, RUNDIR or PREPARE) came after READY",
                    ));
                }
                let word = sys::byte_at(line, b' ');
                Line::new()
                    .s(b"ERROR ? ")
                    .cut(line, word)
                    .s(b" after READY refused: the namespace was prepared before READY; every mntns CLONE is refused")
                    .send(ctl_fd);
            } else if let Some(handler) = ctl::handler() {
                // SAFETY: the template's handler, with the NUL-ended line.
                unsafe { handler(self.t.line.as_ptr().cast()) };
            } else {
                Line::new().s(b"ERROR ? unknown message").send(ctl_fd);
            }
            close_passed(&passed);
        }
    }
}

/// sort_passed names the descriptors a CLONE line carried: the cgroup's,
/// the workspace tree and the channel, each -1 when the line carried
/// none. The channel is always the last one. With ws the tree is the one
/// before it, and the cgroup's comes first only when all three are
/// there. Without ws the cgroup's is the first of two.
pub fn sort_passed(passed: &[c_int; MAX_PASSED], ws: bool) -> (c_int, c_int, c_int) {
    let n = passed.iter().take_while(|&&fd| fd >= 0).count();
    let at = |i: usize| passed.get(i).copied().unwrap_or(-1);
    match (ws, n) {
        (_, 0) => (-1, -1, -1),
        (false, 1) | (true, 1) => (-1, -1, at(0)),
        (false, _) => (at(0), -1, at(n.wrapping_sub(1))),
        (true, 2) => (-1, at(0), at(1)),
        (true, _) => (at(0), at(1), at(2)),
    }
}

/// Closes every descriptor a line carried.
fn close_passed(passed: &[c_int; MAX_PASSED]) {
    for &fd in passed {
        if fd >= 0 {
            // SAFETY: a descriptor the line carried, ours to close.
            unsafe { libc::close(fd) };
        }
    }
}

/// Builds "NAME=value" NUL-ended in buf, cut to what fits.
fn set_env(buf: &mut [u8], name: &[u8], value: &[u8]) {
    let cap = buf.len().saturating_sub(1);
    let n = sys::append(buf, 0, name.get(..cap).unwrap_or(name));
    let room = cap.saturating_sub(n);
    let n = sys::append(buf, n, value.get(..room).unwrap_or(value));
    if let Some(end) = buf.get_mut(n) {
        *end = 0;
    }
}

/// Whether name is set in the environment.
pub(crate) fn env_set(name: &CStr) -> bool {
    // SAFETY: a NUL-ended name, and getenv reads the process's own
    // environment.
    !unsafe { libc::getenv(name.as_ptr()) }.is_null()
}

/// Whether name is set to value in the environment.
fn env_is(name: &CStr, value: &[u8]) -> bool {
    // SAFETY: as env_set.
    let p = unsafe { libc::getenv(name.as_ptr()) };
    if p.is_null() {
        return false;
    }
    // SAFETY: getenv's answer is NUL-ended, and nothing writes the
    // environment meanwhile.
    unsafe { sys::c_bytes(p) == value }
}

/// block_sigchld blocks SIGCHLD in the calling thread, for fz_serve's
/// descriptor.
pub fn block_sigchld() {
    let mut chld: libc::sigset_t = zeroed();
    // SAFETY: chld is live for the calls.
    unsafe {
        libc::sigemptyset(&raw mut chld);
        libc::sigaddset(&raw mut chld, libc::SIGCHLD);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const chld, ptr::null_mut());
    }
}

/// fz_init in libfiberzygote.h.
///
/// # Safety
/// argv is what main was given, a null-ended array of NUL-ended strings,
/// live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_init(argc: c_int, argv: *const *const c_char) {
    let _ = argc;
    // Before any thread exists, so every thread inherits it. A thread
    // with SIGCHLD unblocked would take a child's exit with the default
    // action, and the loop's descriptor (fz_serve) would never see it.
    // The mask survives the re-exec below.
    block_sigchld();
    // SAFETY: an entry on the main thread before any other exists.
    let mut z = unsafe { global() };
    // SAFETY: an integer argument alone, a query.
    let p = unsafe { libc::personality(0xffff_ffff) };
    if p == -1 || p & libc::ADDR_NO_RANDOMIZE != 0 {
        z.own_mountns();
        return;
    }
    // SAFETY: an integer argument alone.
    if unsafe { libc::personality((p | libc::ADDR_NO_RANDOMIZE) as libc::c_ulong) } == -1 {
        z.own_mountns();
        return;
    }
    // Re-exec so the new personality applies to every mapping. Loops are
    // impossible, because the second incarnation sees the flag and
    // returns. The mount namespace is taken by the incarnation that goes
    // on, so it is taken once.
    // SAFETY: a static path and argv by the contract above.
    unsafe { libc::execv(c"/proc/self/exe".as_ptr(), argv) };
    // If exec fails we carry on randomised, and deltas will be larger.
    z.own_mountns();
}

/// fz_serve in libfiberzygote.h: 0 when fiberd closes the channel, -1
/// with errno on a protocol or system error.
#[unsafe(no_mangle)]
pub extern "C" fn fz_serve(ctl_fd: c_int, on_fiber: OnFiber) -> c_int {
    // SAFETY: an entry on the serving thread.
    let got = unsafe { global() }.serve(ctl_fd, on_fiber);
    match got {
        Ok(v) => v,
        Err(Errno(e)) => {
            sys::set_errno(e);
            -1
        }
    }
}

/// What the test fixtures reach (tests/integration/proc/testdata), in
/// an archive built with the testhooks feature alone.
#[cfg(feature = "testhooks")]
mod testhooks {
    use core::ffi::c_int;

    /// wait_bounded, for testdata/waitbounded.c.
    ///
    /// # Safety
    /// status is writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fz_rs_wait_bounded(
        pid: libc::pid_t,
        status: *mut c_int,
        ms: c_int,
    ) -> libc::pid_t {
        let mut st = 0;
        let w = super::wait_bounded(pid, &mut st, ms);
        if !status.is_null() {
            // SAFETY: writable by the contract above.
            unsafe { *status = st };
        }
        w
    }
}

/// The length of a kept path's slot is what abi.rs says.
const _: () = assert!(size_of::<Kept>() == KEEP_MAX);

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

    /// A zygote with state of its own.
    struct Rig {
        st: Box<State>,
        t: Box<Tables>,
    }

    impl Rig {
        fn new() -> Rig {
            // SAFETY: all zero bits are a Tables, as for TABLES.
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

    /// A SOCK_STREAM pair, as the control socket is.
    fn pair() -> [c_int; 2] {
        let mut sv = [-1; 2];
        // SAFETY: sv is live for the call.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair");
        sv
    }

    /// Every line the zygote sent, without waiting.
    fn lines(fd: c_int) -> Vec<String> {
        let mut got = Vec::new();
        loop {
            let mut buf = [0u8; 8192];
            // SAFETY: buf is live for the call.
            let n =
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if n <= 0 {
                break;
            }
            got.extend_from_slice(&buf[..n as usize]);
        }
        String::from_utf8(got)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Writes data on fd whole.
    fn write(fd: c_int, data: &[u8]) {
        assert_eq!(ctl::write_all(fd, data), 0, "write");
    }

    fn close(fd: c_int) {
        // SAFETY: the test's own.
        unsafe { libc::close(fd) };
    }

    /// A child that pauses until killed.
    fn sleeper() -> libc::pid_t {
        // SAFETY: the child calls pause and _exit alone.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: as above.
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        pid
    }

    /// A pipe, read end and write end.
    fn pipe() -> [c_int; 2] {
        let mut p = [-1; 2];
        // SAFETY: p is live for the call.
        assert_eq!(
            unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2"
        );
        p
    }

    #[test]
    fn exit_why_names_the_librarys_codes() {
        let cases: &[(&str, c_int, Option<&str>)] = &[
            (
                "110",
                110,
                Some("could not make its mount namespace private"),
            ),
            ("111", 111, Some("could not mount its own /proc")),
            ("112", 112, Some("could not unmount a DROP path")),
            (
                "113",
                113,
                Some("could not cover a HIDE path that appeared after READY"),
            ),
            ("114", 114, Some("could not drop its capabilities")),
            (
                "115",
                115,
                Some("could not make the host controls under /proc read-only"),
            ),
            ("116 is retired", 116, None),
            ("117 is retired", 117, None),
            ("120", 120, Some("could not set up its descriptors")),
            ("121", 121, Some("did not get its incarnation record")),
            ("125", 125, Some("could not join its cgroup leaf")),
            ("126", 126, Some("could not stack its clone3 filter")),
            (
                "127",
                127,
                Some("could not mount its workspace at /workspace"),
            ),
            ("the template's own", 3, None),
            ("zero", 0, None),
        ];
        for (name, code, want) in cases {
            assert_eq!(exit_why(*code), want.map(str::as_bytes), "{name}");
        }
    }

    #[test]
    fn died_and_exited_lines_are_the_cs() {
        let exit = |code: c_int| code << 8;
        let cases: &[(&str, c_int, &str, &str)] = &[
            (
                "a signal",
                9,
                "ERROR g/1/1 died before ready: signal:9",
                "EXITED 77 signal:9",
            ),
            (
                "an exit the library assigned",
                exit(121),
                "ERROR g/1/1 died before ready: exit:121 (did not get its incarnation record)",
                "EXITED 77 exit:121",
            ),
            (
                "the template's own exit",
                exit(3),
                "ERROR g/1/1 died before ready: exit:3",
                "EXITED 77 exit:3",
            ),
            (
                "exit zero",
                exit(0),
                "ERROR g/1/1 died before ready: exit:0",
                "EXITED 77 exit:0",
            ),
        ];
        for (name, status, died, exited) in cases {
            assert_eq!(
                died_line(b"g/1/1", *status).bytes(),
                died.as_bytes(),
                "{name}"
            );
            assert_eq!(
                exited_line(77, *status).bytes(),
                exited.as_bytes(),
                "{name}"
            );
        }
    }

    #[test]
    fn set_cstr_and_set_env_cut_as_snprintf_did() {
        let cases: &[(&str, usize, &[u8], &[u8], &[u8])] = &[
            ("fits", 16, b"A=", b"b", b"A=b\0"),
            ("an empty value", 16, b"A=", b"", b"A=\0"),
            ("cut in the value", 6, b"A=", b"bcdefg", b"A=bcd\0"),
            ("cut in the name", 3, b"ABCD=", b"x", b"AB\0"),
            ("one byte holds the NUL alone", 1, b"A=", b"b", b"\0"),
        ];
        for (name, cap, key, value, want) in cases {
            let mut buf = vec![0xeeu8; *cap];
            set_env(&mut buf, key, value);
            assert_eq!(&buf[..want.len()], *want, "{name}");
            let mut buf = vec![0xeeu8; *cap];
            let whole = [*key, *value].concat();
            set_cstr(&mut buf, &whole);
            assert_eq!(&buf[..want.len()], *want, "{name}: set_cstr");
        }
    }

    #[test]
    fn kids_and_doomed_are_swap_removed() {
        let mut rig = Rig::new();
        let cases: &[(&str, &[(libc::pid_t, &str)], libc::pid_t, &[libc::pid_t])] = &[
            ("forget the only one", &[(1, "a")], 1, &[]),
            (
                "forget the first of three",
                &[(1, "a"), (2, "b"), (3, "c")],
                1,
                &[3, 2],
            ),
            ("forget the last", &[(1, "a"), (2, "b")], 2, &[1]),
            ("forget one that is not there", &[(1, "a")], 9, &[1]),
        ];
        for (name, kids, forget, want) in cases {
            rig.st.nkids = 0;
            for (pid, fence) in *kids {
                rig.z().remember(*pid, fence.as_bytes());
            }
            assert_eq!(rig.st.nkids, kids.len(), "{name}: remembered");
            rig.z().forget(*forget);
            let got: Vec<libc::pid_t> = rig.t.kids[..rig.st.nkids].iter().map(|k| k.pid).collect();
            assert_eq!(got, *want, "{name}");
            // The same shape for the doomed.
            rig.st.ndoomed = 0;
            for (pid, _) in *kids {
                rig.t.doomed[rig.st.ndoomed] = *pid;
                rig.st.ndoomed += 1;
            }
            let was = rig.z().forget_doomed(*forget);
            assert_eq!(was, kids.iter().any(|(p, _)| p == forget), "{name}: doomed");
            assert_eq!(
                &rig.t.doomed[..rig.st.ndoomed],
                *want,
                "{name}: doomed left"
            );
        }
        // A full table remembers no more.
        rig.st.nkids = MAX_KIDS;
        rig.z().remember(5, b"x");
        assert_eq!(rig.st.nkids, MAX_KIDS, "a full table keeps its count");
        // A fence is kept NUL-ended and whole.
        rig.st.nkids = 0;
        let fence = [b'f'; FENCE_MAX - 1];
        rig.z().remember(6, &fence);
        assert_eq!(&rig.t.kids[0].fence[..FENCE_MAX - 1], &fence[..]);
        assert_eq!(rig.t.kids[0].fence[FENCE_MAX - 1], 0);
    }

    #[test]
    fn wait_bounded_never_blocks() {
        let _serial = crate::serial();
        let cases: &[(&str, bool, c_int, bool, u128, u128)] = &[
            (
                "a live child is given up on at the bound",
                false,
                100,
                false,
                100,
                1500,
            ),
            (
                "a dead child is reaped before the bound",
                true,
                100,
                true,
                0,
                99,
            ),
            ("a bound of zero asks once", false, 0, false, 0, 50),
        ];
        for (name, kill, ms, want_reaped, lo, hi) in cases {
            let pid = sleeper();
            if *kill {
                // SAFETY: the test's own child.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            let t0 = std::time::Instant::now();
            let mut status = 0;
            let w = wait_bounded(pid, &mut status, *ms);
            let took = t0.elapsed().as_millis();
            assert_eq!(w == pid, *want_reaped, "{name}: {w}");
            assert!(took >= *lo && took <= *hi, "{name}: took {took}ms");
            if w == 0 {
                // SAFETY: the test's own child.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &raw mut status, 0);
                }
            }
        }
    }

    #[test]
    fn reported_ready_reads_the_record_without_waiting() {
        let cases: &[(&str, Option<&[u8]>, bool)] = &[
            ("the ready record", Some(b"r"), true),
            ("another byte", Some(b"x"), false),
            ("two bytes", Some(b"rr"), false),
            ("nothing yet", None, false),
            ("closed", Some(b""), false),
        ];
        for (name, data, want) in cases {
            let [r, w] = pipe();
            match data {
                Some(b"") => close(w),
                Some(d) => write(w, d),
                None => {}
            }
            assert_eq!(reported_ready(r), *want, "{name}");
            close(r);
            if !matches!(data, Some(b"")) {
                close(w);
            }
        }
    }

    #[test]
    fn settle_pending_answers_each_way_the_pipe_can_speak() {
        let _serial = crate::serial();
        struct Case {
            name: &'static str,
            // What the child does: writes these bytes, then closes or
            // not, then exits with this code or stays.
            pipe: Option<&'static [u8]>,
            close_pipe: bool,
            exit: Option<c_int>,
            want: &'static str,
            want_kid: bool,
        }
        let cases = [
            Case {
                name: "ready",
                pipe: Some(b"r"),
                close_pipe: false,
                exit: None,
                want: "CLONED f ",
                want_kid: true,
            },
            Case {
                name: "another byte, alive",
                pipe: Some(b"x"),
                close_pipe: false,
                exit: None,
                want: "ERROR f wrote 0x78 on the readiness pipe instead of reporting ready (fd 3 is not the fiber's to use); killed",
                want_kid: false,
            },
            Case {
                name: "closed, alive",
                pipe: None,
                close_pipe: true,
                exit: None,
                want: "ERROR f closed the readiness pipe without reporting ready; killed",
                want_kid: false,
            },
            Case {
                name: "closed by an exit",
                pipe: None,
                close_pipe: true,
                exit: Some(121),
                want: "ERROR f died before ready: exit:121 (did not get its incarnation record)",
                want_kid: false,
            },
            Case {
                name: "closed by a template exit",
                pipe: None,
                close_pipe: true,
                exit: Some(3),
                want: "ERROR f died before ready: exit:3",
                want_kid: false,
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            let [ours, theirs] = pair();
            let [r, w] = pipe();
            // SAFETY: the child writes, closes and exits or pauses alone.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork");
            if pid == 0 {
                // SAFETY: as above.
                unsafe {
                    if let Some(d) = tc.pipe {
                        libc::write(w, d.as_ptr().cast(), d.len());
                    }
                    if tc.close_pipe {
                        libc::close(w);
                    }
                    match tc.exit {
                        Some(code) => libc::_exit(code),
                        None => loop {
                            libc::pause();
                        },
                    }
                }
            }
            close(w);
            // Let the child act, and the exit's EOF reach the pipe.
            std::thread::sleep(std::time::Duration::from_millis(100));
            rig.t.pending[0] = Pending {
                pid,
                ready_fd: r,
                fence: {
                    let mut f = [0u8; FENCE_MAX];
                    f[0] = b'f';
                    f
                },
                deadline: now_ts(),
            };
            rig.st.npending = 1;
            rig.z().settle_pending(ours, 0);
            let got = lines(theirs);
            assert_eq!(got.len(), 1, "{}: {got:?}", tc.name);
            assert!(got[0].starts_with(tc.want), "{}: {}", tc.name, got[0]);
            assert_eq!(rig.st.npending, 0, "{}: dropped", tc.name);
            assert_eq!(
                rig.st.nkids,
                usize::from(tc.want_kid),
                "{}: remembered",
                tc.name
            );
            // A live child was doomed (killed and reaped, or noted).
            let mut status = 0;
            // SAFETY: the test's own child, or one already reaped.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &raw mut status, 0);
            }
            close(ours);
            close(theirs);
        }
    }

    #[test]
    fn reap_answers_what_it_finds() {
        let _serial = crate::serial();
        // A child that reported ready and exited inside a bounded wait
        // is CLONED then EXITED, one that never reported is an ERROR, a
        // doomed one is silent, and a fiber gets its EXITED line.
        struct Case {
            name: &'static str,
            pending: bool,
            ready: bool,
            doomed: bool,
            kid: bool,
            want: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "ready then gone inside one wait",
                pending: true,
                ready: true,
                doomed: false,
                kid: false,
                want: &["CLONED f ", "EXITED "],
            },
            Case {
                name: "died before it reported",
                pending: true,
                ready: false,
                doomed: false,
                kid: false,
                want: &["ERROR f died before ready: exit:7"],
            },
            Case {
                name: "doomed",
                pending: false,
                ready: false,
                doomed: true,
                kid: false,
                want: &[],
            },
            Case {
                name: "a fiber",
                pending: false,
                ready: false,
                doomed: false,
                kid: true,
                want: &["EXITED "],
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            let [ours, theirs] = pair();
            let [r, w] = pipe();
            // SAFETY: the child writes and exits alone.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork");
            if pid == 0 {
                // SAFETY: as above.
                unsafe {
                    if tc.ready {
                        libc::write(w, b"r".as_ptr().cast(), 1);
                    }
                    libc::_exit(7);
                }
            }
            close(w);
            if tc.pending {
                rig.t.pending[0] = Pending {
                    pid,
                    ready_fd: r,
                    fence: {
                        let mut f = [0u8; FENCE_MAX];
                        f[0] = b'f';
                        f
                    },
                    deadline: now_ts(),
                };
                rig.st.npending = 1;
            } else {
                close(r);
            }
            if tc.doomed {
                rig.t.doomed[0] = pid;
                rig.st.ndoomed = 1;
            }
            if tc.kid {
                rig.z().remember(pid, b"f");
            }
            // Wait for the exit without reaping it.
            let mut si: libc::siginfo_t = zeroed();
            // SAFETY: si is live for the call.
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &raw mut si,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            rig.z().reap(ours);
            let got = lines(theirs);
            assert_eq!(got.len(), tc.want.len(), "{}: {got:?}", tc.name);
            for (g, w) in got.iter().zip(tc.want) {
                assert!(g.starts_with(w), "{}: {g}", tc.name);
            }
            assert_eq!(rig.st.npending, 0, "{}", tc.name);
            assert_eq!(rig.st.ndoomed, 0, "{}", tc.name);
            assert_eq!(rig.st.nkids, 0, "{}", tc.name);
            close(ours);
            close(theirs);
        }
    }

    #[test]
    fn expire_pending_kills_what_is_past_its_deadline() {
        let _serial = crate::serial();
        let mut rig = Rig::new();
        let [ours, theirs] = pair();
        let past = sleeper();
        let soon = sleeper();
        let fence = |c: u8| {
            let mut f = [0u8; FENCE_MAX];
            f[0] = c;
            f
        };
        let [pr, pw] = pipe();
        let [sr, sw] = pipe();
        rig.t.pending[0] = Pending {
            pid: past,
            ready_fd: pr,
            fence: fence(b'p'),
            deadline: now_ts(),
        };
        rig.t.pending[1] = Pending {
            pid: soon,
            ready_fd: sr,
            fence: fence(b's'),
            deadline: deadline_of(now_ts(), 60_000),
        };
        rig.st.npending = 2;
        rig.z().expire_pending(ours);
        assert_eq!(
            lines(theirs),
            vec!["ERROR p deadline exceeded before ready"]
        );
        assert_eq!(rig.st.npending, 1);
        assert_eq!(rig.t.pending[0].pid, soon, "the one left");
        let mut status = 0;
        // SAFETY: the test's own children.
        unsafe {
            assert_eq!(
                libc::waitpid(past, &raw mut status, 0),
                -1,
                "already reaped by doom"
            );
            libc::kill(soon, libc::SIGKILL);
            libc::waitpid(soon, &raw mut status, 0);
        }
        for fd in [ours, theirs, pw, sr, sw] {
            close(fd);
        }
    }

    #[test]
    fn read_setup_keeps_what_fiberd_sends() {
        struct Case {
            name: &'static str,
            lines: &'static str,
            want: Result<bool, Errno>,
            want_hide: &'static [&'static str],
            want_drop: &'static [&'static str],
            want_rundir: Option<(&'static str, &'static str)>,
            want_refused: Option<&'static str>,
        }
        // Paths at and past a slot's KEEP_MAX bytes. The cases hold
        // static strings, so these are leaked for the test's life.
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        let fits = leak(format!("/{}", "a".repeat(KEEP_MAX - 2)));
        let at_max = leak(format!("/{}", "b".repeat(KEEP_MAX - 1)));
        let far = leak(format!("/{}", "c".repeat(5000)));
        let fits_kept: &'static [&'static str] = Box::leak(vec![fits].into_boxed_slice());
        let cases = [
            Case {
                name: "a HIDE path of KEEP_MAX - 1 bytes is kept whole",
                lines: leak(format!("HIDE {fits}\nPREPARE none\n")),
                want: Ok(true),
                want_hide: fits_kept,
                want_drop: &[],
                want_rundir: None,
                want_refused: None,
            },
            Case {
                name: "a HIDE path of KEEP_MAX bytes is refused, not cut",
                lines: leak(format!("HIDE /a\nHIDE {at_max}\nDROP /b\nPREPARE none\n")),
                want: Ok(true),
                want_hide: &["/a"],
                want_drop: &["/b"],
                want_rundir: None,
                want_refused: Some("HIDE: path too long"),
            },
            Case {
                name: "a DROP path of 5001 bytes is refused, not cut",
                lines: leak(format!("DROP {far}\nHIDE /a\nPREPARE none\n")),
                want: Ok(true),
                want_hide: &["/a"],
                want_drop: &[],
                want_rundir: None,
                want_refused: Some("DROP: path too long"),
            },
            Case {
                name: "prepare none",
                lines: "HIDE /a\nDROP /b\nRUNDIR /r /r/g\nPREPARE none\n",
                want: Ok(true),
                want_hide: &["/a"],
                want_drop: &["/b"],
                want_rundir: Some(("/r", "/r/g")),
                want_refused: None,
            },
            Case {
                name: "fiberd gone",
                lines: "HIDE /a\n",
                want: Ok(false),
                want_hide: &["/a"],
                want_drop: &[],
                want_rundir: None,
                want_refused: None,
            },
            Case {
                name: "a protocol error",
                lines: "CLONE f e 50 - -\n",
                want: Err(Errno(libc::EPROTO)),
                want_hide: &[],
                want_drop: &[],
                want_rundir: None,
                want_refused: None,
            },
            Case {
                name: "a refused RUNDIR",
                lines: "RUNDIR /r /x\nPREPARE none\n",
                want: Ok(true),
                want_hide: &[],
                want_drop: &[],
                want_rundir: None,
                want_refused: Some("RUNDIR refused"),
            },
            Case {
                name: "too many HIDE paths",
                lines: "HIDE /0\nHIDE /1\nHIDE /2\nHIDE /3\nHIDE /4\nHIDE /5\nHIDE /6\nHIDE /7\nHIDE /8\nHIDE /9\nHIDE /10\nHIDE /11\nHIDE /12\nHIDE /13\nHIDE /14\nHIDE /15\nHIDE /16\nPREPARE none\n",
                want: Ok(true),
                want_hide: &[
                    "/0", "/1", "/2", "/3", "/4", "/5", "/6", "/7", "/8", "/9", "/10", "/11",
                    "/12", "/13", "/14", "/15",
                ],
                want_drop: &[],
                want_rundir: None,
                want_refused: Some("HIDE: too many paths"),
            },
            Case {
                name: "prepare mntns without a namespace of its own",
                lines: "PREPARE mntns\n",
                want: Ok(true),
                want_hide: &[],
                want_drop: &[],
                want_rundir: None,
                want_refused: Some(
                    "fz_init did not run, so the zygote has no mount namespace of its own",
                ),
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            let [ours, theirs] = pair();
            write(theirs, tc.lines.as_bytes());
            // SAFETY: an integer argument alone.
            unsafe { libc::shutdown(theirs, libc::SHUT_WR) };
            let got = rig.z().read_setup(ours);
            assert_eq!(got, tc.want, "{}", tc.name);
            let kept = |paths: &[Kept], n: usize| -> Vec<String> {
                paths[..n]
                    .iter()
                    .map(|p| String::from_utf8(c_str(p).to_vec()).unwrap())
                    .collect()
            };
            assert_eq!(
                kept(&rig.t.hide, rig.st.nhide),
                tc.want_hide,
                "{}: hide",
                tc.name
            );
            assert_eq!(
                kept(&rig.t.drop, rig.st.ndrop),
                tc.want_drop,
                "{}: drop",
                tc.name
            );
            let rundir = if rig.t.rundir_parent[0] == 0 {
                None
            } else {
                Some((
                    String::from_utf8(c_str(&rig.t.rundir_parent).to_vec()).unwrap(),
                    String::from_utf8(c_str(&rig.t.rundir_own).to_vec()).unwrap(),
                ))
            };
            assert_eq!(
                rundir.as_ref().map(|(p, o)| (p.as_str(), o.as_str())),
                tc.want_rundir,
                "{}: rundir",
                tc.name
            );
            let refused = rig
                .z()
                .refused()
                .map(|r| String::from_utf8(r.to_vec()).unwrap());
            assert_eq!(refused.as_deref(), tc.want_refused, "{}: refused", tc.name);
            close(ours);
            close(theirs);
        }
    }

    #[test]
    fn rebind_ctl_takes_the_socket_it_is_sent() {
        let cases: &[(&str, &[u8], bool, bool, Result<(), Errno>)] = &[
            ("REBIND with a socket", b"REBIND\n", true, false, Ok(())),
            (
                "REBIND without one",
                b"REBIND\n",
                false,
                false,
                Err(Errno(libc::EPROTO)),
            ),
            (
                "another word",
                b"CLONE\n",
                true,
                false,
                Err(Errno(libc::EPROTO)),
            ),
            ("end of stream", b"", false, true, Err(Errno(libc::EPROTO))),
        ];
        for (name, line, with_socket, eof, want) in cases {
            let mut rig = Rig::new();
            let [boot, boot_peer] = pair();
            let [ctl, ctl_peer] = pair();
            let fds: Vec<c_int> = if *with_socket { vec![ctl] } else { vec![] };
            if !line.is_empty() {
                ctl::send_with_fds(boot_peer, line, &fds);
            }
            if *eof {
                // SAFETY: an integer argument alone.
                unsafe { libc::shutdown(boot_peer, libc::SHUT_WR) };
            }
            let got = rig.z().rebind_ctl(boot);
            assert_eq!(got, *want, "{name}");
            if got.is_ok() {
                // boot is now the control socket, so what is written on
                // it arrives at ctl's peer.
                write(boot, b"READY\n");
                assert_eq!(lines(ctl_peer), vec!["READY"], "{name}: rebound");
            }
            for fd in [boot, boot_peer, ctl, ctl_peer] {
                close(fd);
            }
        }
    }

    #[test]
    fn sort_passed_names_each_descriptor() {
        let cases: &[(&str, [c_int; MAX_PASSED], bool, (c_int, c_int, c_int))] = &[
            ("nothing", [-1, -1, -1], false, (-1, -1, -1)),
            ("nothing with ws", [-1, -1, -1], true, (-1, -1, -1)),
            ("the channel alone", [7, -1, -1], false, (-1, -1, 7)),
            (
                "the channel alone with ws is no tree",
                [7, -1, -1],
                true,
                (-1, -1, 7),
            ),
            ("cgroup and channel", [5, 7, -1], false, (5, -1, 7)),
            ("tree and channel", [6, 7, -1], true, (-1, 6, 7)),
            ("cgroup, tree and channel", [5, 6, 7], true, (5, 6, 7)),
            (
                "three without ws keep the ends",
                [5, 6, 7],
                false,
                (5, -1, 7),
            ),
        ];
        for (name, passed, ws, want) in cases {
            assert_eq!(sort_passed(passed, *ws), *want, "{name}");
        }
    }

    #[test]
    fn handle_clone_refuses_in_the_cs_order() {
        let _serial = crate::serial();
        struct Case {
            name: &'static str,
            line: &'static str,
            channel: bool,
            // The workspace tree rides before the channel. Here it is a
            // pipe end, which stands in for the descriptor.
            ws: bool,
            refused: Option<Refused>,
            prepared: bool,
            npending: usize,
            want: &'static str,
        }
        let long_fence = {
            let s: &'static str =
                Box::leak(format!("CLONE {} e 50 - -", "b".repeat(128)).into_boxed_str());
            s
        };
        let cut_fence = {
            let s: &'static str =
                Box::leak(format!("CLONE {} e 50 - -", "c".repeat(200)).into_boxed_str());
            s
        };
        let long_endpoint = {
            let s: &'static str =
                Box::leak(format!("CLONE ep e{} 50 - -", "e".repeat(1023)).into_boxed_str());
            s
        };
        let cases = [
            Case {
                name: "malformed",
                line: "CLONE s5 e",
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR s5 malformed CLONE",
            },
            Case {
                name: "malformed without a fence",
                line: "CLONE",
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR ? malformed CLONE",
            },
            Case {
                name: "a fence of 128 is too long, and named cut to 127",
                line: long_fence,
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb fence too long (at most 127 characters)",
            },
            Case {
                name: "a longer fence is cut on the line",
                line: cut_fence,
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc fence too long (at most 127 characters)",
            },
            Case {
                name: "an unknown option is refused before the state checks",
                line: "CLONE f e 50 - 00 mntns,foo",
                channel: true,
                ws: false,
                refused: Some(Refused::Text(c"RUNDIR refused")),
                prepared: true,
                npending: 0,
                want: "ERROR f unknown CLONE option foo",
            },
            Case {
                name: "an unknown option on a long fence is the fence's refusal",
                line: "CLONE ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd e 50 - - foo",
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd fence too long (at most 127 characters)",
            },
            Case {
                name: "mntns with a refusal",
                line: "CLONE f e 50 - 00 mntns",
                channel: true,
                ws: false,
                refused: Some(Refused::Text(c"RUNDIR refused")),
                prepared: true,
                npending: 0,
                want: "ERROR f refused: the mount namespace cannot hide what fiberd asked (RUNDIR refused)",
            },
            Case {
                name: "mntns with fz_init's refusal",
                line: "CLONE f e 50 - - mntns",
                channel: true,
                ws: false,
                refused: Some(Refused::OwnNs),
                prepared: false,
                npending: 0,
                want: "ERROR f refused: the mount namespace cannot hide what fiberd asked (own ns why)",
            },
            Case {
                name: "mntns unprepared",
                line: "CLONE f e 50 - - mntns",
                channel: false,
                ws: false,
                refused: None,
                prepared: false,
                npending: 0,
                want: "ERROR f refused: no mount namespace was prepared before READY (fiberd sent PREPARE none)",
            },
            Case {
                name: "no channel",
                line: "CLONE f e 50 - 00",
                channel: false,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR f CLONE without a channel",
            },
            Case {
                name: "ws with the channel alone",
                line: "CLONE f e 50 - 00 mntns,ws",
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR f CLONE with ws but no workspace descriptor",
            },
            Case {
                name: "ws without mntns",
                line: "CLONE f e 50 - 00 ws",
                channel: true,
                ws: true,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR f CLONE with ws needs mntns",
            },
            Case {
                name: "ws with mntns reaches the session check",
                line: "CLONE s6 e 50 - 6100 mntns,ws",
                channel: true,
                ws: true,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR s6 session holds a NUL byte",
            },
            Case {
                name: "session with a NUL",
                line: "CLONE s4 e 50 - 6100",
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR s4 session holds a NUL byte",
            },
            Case {
                name: "too many in flight",
                line: "CLONE f e 50 - -",
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: MAX_PENDING,
                want: "ERROR f too many clones in flight",
            },
            Case {
                name: "endpoint too long",
                line: long_endpoint,
                channel: true,
                ws: false,
                refused: None,
                prepared: true,
                npending: 0,
                want: "ERROR ep endpoint too long (at most 1023 characters)",
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            set_cstr(&mut rig.t.own_ns_why, b"own ns why");
            rig.st.paths_refused = tc.refused;
            rig.st.ns_prepared = tc.prepared;
            rig.st.npending = tc.npending;
            let [ours, theirs] = pair();
            let [chan, chan_peer] = pair();
            let [tree, tree_peer] = pair();
            let passed = match (tc.ws, tc.channel) {
                (true, true) => [tree, chan, -1],
                (true, false) => [tree, -1, -1],
                (false, true) => [chan, -1, -1],
                (false, false) => [-1, -1, -1],
            };
            rig.t.line[..tc.line.len()].copy_from_slice(tc.line.as_bytes());
            rig.t.line[tc.line.len()] = 0;
            rig.z().handle_clone(ours, &passed, None);
            assert_eq!(lines(theirs), vec![tc.want], "{}", tc.name);
            assert_eq!(rig.st.npending, tc.npending, "{}: nothing forked", tc.name);
            for fd in [ours, theirs, chan, chan_peer, tree, tree_peer] {
                close(fd);
            }
        }
    }

    #[test]
    fn handle_clone_builds_the_fibers_environment() {
        let _serial = crate::serial();
        // Each case is parsed and answered up to the clone, which fails
        // on a channel that is no descriptor at all, so no child is
        // made and the environment built for it can be read back.
        struct Case {
            name: &'static str,
            line: &'static str,
            engine: &'static [u8],
            want: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "the least",
                line: "CLONE g/1/7 /run/f/7.sock 50 - -",
                engine: b"",
                want: &[
                    "FIBERD_FENCE=g/1/7",
                    "FIBERD_ENDPOINT=/run/f/7.sock",
                    "FIBERD_CHANNEL_FD=4",
                ],
            },
            Case {
                name: "an engine and a session",
                line: "CLONE f e 50 - 7365737331",
                engine: b"/run/engine.sock",
                want: &[
                    "FIBERD_FENCE=f",
                    "FIBERD_ENDPOINT=e",
                    "FIBERD_ENGINE=/run/engine.sock",
                    "FIBERD_CHANNEL_FD=4",
                    "FIBERD_SESSION=sess1",
                ],
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            rig.st.ns_prepared = true;
            let engine = std::ffi::CString::new(tc.engine).unwrap();
            // SAFETY: a live NUL-ended string.
            unsafe { ctl::fz_set_engine(engine.as_ptr()) };
            let [ours, theirs] = pair();
            rig.t.line[..tc.line.len()].copy_from_slice(tc.line.as_bytes());
            rig.t.line[tc.line.len()] = 0;
            // A cgroup descriptor that is not open, so clone3 refuses
            // with EBADF before any child exists, root or not, and the
            // channel is a socket that is.
            let passed = [1 << 20, ours, -1];
            rig.z().handle_clone(ours, &passed, None);
            let got = lines(theirs);
            assert_eq!(got.len(), 1, "{}: {got:?}", tc.name);
            assert!(
                got[0].starts_with("ERROR ") && got[0].contains(" clone: "),
                "{}: {}",
                tc.name,
                got[0]
            );
            let env: Vec<String> = rig
                .t
                .env
                .environ
                .iter()
                .take_while(|p| !p.is_null())
                .map(|&p| {
                    // SAFETY: each entry is a NUL-ended string in Tables.
                    unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned()
                })
                .collect();
            assert_eq!(env, tc.want, "{}", tc.name);
            assert_eq!(rig.st.npending, 0, "{}", tc.name);
            close(ours);
            close(theirs);
        }
        // SAFETY: null names no engine.
        unsafe { ctl::fz_set_engine(ptr::null()) };
    }

    #[test]
    fn serve_closes_what_a_refused_line_passed() {
        // A line longer than the buffer ends serve with EMSGSIZE, and the
        // descriptors that rode with its first bytes must still be closed.
        // Each is a pipe's write end, so its read end sees EOF only once
        // every copy is closed.
        let _serial = crate::serial();
        // SIGCHLD blocked in this thread, as fz_init leaves it.
        let mut chld: libc::sigset_t = zeroed();
        let mut old: libc::sigset_t = zeroed();
        // SAFETY: both sets are live for the calls.
        unsafe {
            libc::sigemptyset(&raw mut chld);
            libc::sigaddset(&raw mut chld, libc::SIGCHLD);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const chld, &raw mut old);
        }
        let cases: &[(&str, usize, Result<c_int, Errno>)] = &[
            ("one descriptor", 1, Err(Errno(libc::EMSGSIZE))),
            ("two descriptors", 2, Err(Errno(libc::EMSGSIZE))),
        ];
        for (name, n, want) in cases {
            let mut rig = Rig::new();
            let [ours, theirs] = pair();
            write(theirs, b"PREPARE none\n");
            let mut reads = Vec::new();
            let mut writes = Vec::new();
            for _ in 0..*n {
                let [r, w] = pipe();
                // SAFETY: integer arguments alone.
                unsafe { libc::fcntl(r, libc::F_SETFL, libc::O_NONBLOCK) };
                reads.push(r);
                writes.push(w);
            }
            // The descriptors ride with the line's first bytes, and the
            // line runs on past the buffer with no newline.
            ctl::send_with_fds(theirs, b"CLONE ", &writes);
            for w in writes {
                close(w);
            }
            write(theirs, &vec![b'x'; MAX_LINE + 100]);
            let got = rig.z().serve(ours, None);
            assert_eq!(got, *want, "{name}");
            for r in reads {
                let mut b = [0u8; 1];
                // SAFETY: b is live for the call.
                let got = unsafe { libc::read(r, b.as_mut_ptr().cast(), 1) };
                assert_eq!(got, 0, "{name}: a passed write end is still open");
                close(r);
            }
            close(rig.st.sigchld_fd);
            close(ours);
            close(theirs);
        }
        ctl::set_ctl_fd(-1);
        // SAFETY: old is live for the call.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, ptr::null_mut()) };
    }

    #[test]
    fn serve_does_not_serve_without_the_filter() {
        // A refused install ends serve with ERROR ? and no READY, so
        // fiberd fails the warm.
        let _serial = crate::serial();
        let mut chld: libc::sigset_t = zeroed();
        let mut old: libc::sigset_t = zeroed();
        // SAFETY: both sets are live for the calls.
        unsafe {
            libc::sigemptyset(&raw mut chld);
            libc::sigaddset(&raw mut chld, libc::SIGCHLD);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const chld, &raw mut old);
        }
        let cases: &[(&str, (c_long, c_int), &str)] = &[
            (
                "the kernel refused the program",
                (-1, libc::EINVAL),
                "ERROR ? seccomp filter: Invalid argument",
            ),
            (
                "no_new_privs or the install was not permitted",
                (-1, libc::EACCES),
                "ERROR ? seccomp filter: Permission denied",
            ),
            (
                "a thread TSYNC could not cover",
                (4242, 0),
                "ERROR ? seccomp filter: thread 4242 would not take it",
            ),
        ];
        for (name, fake, want) in cases {
            *seccomp::tests::FAKE.lock().unwrap() = Some(*fake);
            let mut rig = Rig::new();
            let [ours, theirs] = pair();
            write(theirs, b"PREPARE none\n");
            let got = rig.z().serve(ours, None);
            assert_eq!(got, Err(Errno(libc::ENOTRECOVERABLE)), "{name}");
            assert_eq!(lines(theirs), vec![(*want).to_owned()], "{name}: no READY");
            close(rig.st.sigchld_fd);
            close(ours);
            close(theirs);
        }
        *seccomp::tests::FAKE.lock().unwrap() = Some((0, 0));
        ctl::set_ctl_fd(-1);
        // SAFETY: old is live for the call.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, ptr::null_mut()) };
    }

    #[test]
    fn a_runc_zygote_keeps_sys_admin_and_takes_the_runc_program() {
        // With FIBERD_USERNS_NESTED=deny serve narrows its capabilities
        // and installs the runc program. A refused drop is ERROR ? and
        // no READY, like a refused install.
        let _serial = crate::serial();
        let mut chld: libc::sigset_t = zeroed();
        let mut old: libc::sigset_t = zeroed();
        // SAFETY: both sets are live for the calls.
        unsafe {
            libc::sigemptyset(&raw mut chld);
            libc::sigaddset(&raw mut chld, libc::SIGCHLD);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const chld, &raw mut old);
        }
        // SAFETY: under serial, and nothing else reads the environment
        // meanwhile.
        unsafe { std::env::set_var("FIBERD_USERNS_NESTED", "deny") };
        *crate::prepare::tests::FAKE_NESTED.lock().unwrap() = Some(0);
        let runc_len = seccomp::Prog::build(&seccomp::NATIVE, seccomp::Program::Runc).len;
        struct Case {
            name: &'static str,
            caps: c_int,
            install: (c_long, c_int),
            want: Result<c_int, Errno>,
            lines: &'static [&'static str],
        }
        let cases = [
            Case {
                name: "the drop is refused",
                caps: libc::EPERM,
                install: (0, 0),
                want: Err(Errno(libc::ENOTRECOVERABLE)),
                lines: &["ERROR ? capabilities: Operation not permitted"],
            },
            Case {
                name: "the drop passes and the install is refused",
                caps: 0,
                install: (-1, libc::EINVAL),
                want: Err(Errno(libc::ENOTRECOVERABLE)),
                lines: &["ERROR ? seccomp filter: Invalid argument"],
            },
            Case {
                name: "both pass and the zygote serves",
                caps: 0,
                install: (0, 0),
                want: Ok(0),
                lines: &["READY"],
            },
        ];
        for tc in &cases {
            *crate::prepare::tests::FAKE_CAPS.lock().unwrap() = Some(tc.caps);
            *seccomp::tests::FAKE.lock().unwrap() = Some(tc.install);
            seccomp::tests::SEEN_LEN.store(0, std::sync::atomic::Ordering::Relaxed);
            let mut rig = Rig::new();
            let [ours, theirs] = pair();
            write(theirs, b"PREPARE none\n");
            // fiberd gone after the setup, so a serving zygote returns.
            // SAFETY: integer arguments alone.
            unsafe { libc::shutdown(theirs, libc::SHUT_WR) };
            let got = rig.z().serve(ours, None);
            assert_eq!(got, tc.want, "{}", tc.name);
            assert_eq!(lines(theirs), tc.lines.to_vec(), "{}", tc.name);
            if tc.want.is_ok() {
                let seen = seccomp::tests::SEEN_LEN.load(std::sync::atomic::Ordering::Relaxed);
                assert_eq!(seen, runc_len, "{}: the runc program", tc.name);
            }
            close(rig.st.sigchld_fd);
            close(ours);
            close(theirs);
        }
        // SAFETY: as above.
        unsafe { std::env::remove_var("FIBERD_USERNS_NESTED") };
        *crate::prepare::tests::FAKE_NESTED.lock().unwrap() = None;
        *crate::prepare::tests::FAKE_CAPS.lock().unwrap() = Some(0);
        *seccomp::tests::FAKE.lock().unwrap() = Some((0, 0));
        ctl::set_ctl_fd(-1);
        // SAFETY: old is live for the call.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, ptr::null_mut()) };
    }
}
