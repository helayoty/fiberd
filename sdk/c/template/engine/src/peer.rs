//! Who is asking. The engine never trusts the fence a line carries. It
//! names the caller's cgroup itself from the kernel, maps that cgroup
//! to a fence with the LEAF, UNLEAF and RELAY lines fiberd sent on
//! fd 3, and seals itself with the core's Engine seccomp program before
//! the first accept. This file is the engine's security core. main.rs
//! and ctl.rs call it and nothing here reads a request line.

// ---- imports and bounds ----

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use fiberzygote_core::seccomp::{self, Program, Refusal};
use libc::{c_int, c_void, socklen_t};

/// Longest cgroup path the map keeps, in bytes.
pub const CGROUP_MAX: usize = 240;
/// Most LEAF mappings held at once.
pub const LEAVES_MAX: usize = 4096;
/// Most RELAY cgroups held at once.
pub const RELAYS_MAX: usize = 64;

/// Longest fence the map keeps, in bytes. The caller validates fences
/// before they reach the map, and this bound stands on its own.
const FENCE_MAX: usize = 128;

/// How much of /proc/<pid>/cgroup is read. A file that fills it is
/// refused, since its end was never seen.
const CGROUP_FILE_MAX: usize = 4096;

/// The getsockopt that hands out a pidfd for the peer, Linux 6.5. The
/// value is spelled here so an older libc still builds.
const SO_PEERPIDFD: c_int = 77;

// ---- Refused ----

/// Why a peer or a control line was refused. One token each, it goes
/// on the wire as `ERROR <fence> <reason>` or into stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The socket gave no pidfd or no credentials for its peer.
    Peer,
    /// The peer's pid is 0 or negative, so it is not visible here.
    Pid,
    /// The peer's /proc/<pid>/cgroup could not be read whole.
    Proc,
    /// The cgroup path is malformed, or the file has no single `0::` line.
    Cgroup,
    /// The peer exited after its cgroup was read, so the pid may have
    /// been another process's.
    Dead,
    /// The fence bytes are malformed.
    Fence,
    /// The table is full.
    Full,
}

impl Refused {
    /// The one-word reason.
    pub fn token(self) -> &'static str {
        match self {
            Refused::Peer => "peer",
            Refused::Pid => "pid",
            Refused::Proc => "proc",
            Refused::Cgroup => "cgroup",
            Refused::Dead => "dead",
            Refused::Fence => "fence",
            Refused::Full => "full",
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

// ---- path and fence checks ----

/// Whether b is printable ASCII with no space. A LEAF or RELAY line is
/// split on spaces, so a path or fence with a space could never arrive
/// on fd 3, and the kernel writes neither NUL nor a newline into a name.
fn printable(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}

/// check_path accepts a cgroup v2 path as the kernel prints it for a
/// live cgroup. Absolute, at most CGROUP_MAX bytes, printable with no
/// space, so " (deleted)" is refused twice over, and every component
/// non-empty and neither "." nor "..", so a path from outside the
/// engine's cgroup namespace ("/../x") is refused. cgroup_of, leaf and
/// relay all use it, so a mapping can only ever equal a real path.
fn check_path(path: &[u8]) -> Result<(), Refused> {
    if path.is_empty() || path.len() > CGROUP_MAX {
        return Err(Refused::Cgroup);
    }
    if path.first() != Some(&b'/') {
        return Err(Refused::Cgroup);
    }
    if path.ends_with(b" (deleted)") {
        return Err(Refused::Cgroup);
    }
    if !path.iter().all(|&b| printable(b)) {
        return Err(Refused::Cgroup);
    }
    let rest = path.get(1..).unwrap_or(&[]);
    for part in rest.split(|&b| b == b'/') {
        if part.is_empty() || part == b"." || part == b".." {
            return Err(Refused::Cgroup);
        }
    }
    Ok(())
}

/// check_fence accepts a fence as ctl.rs validates it, so the map never
/// trusts its caller for memory safety. Non-empty, at most FENCE_MAX
/// bytes, printable with no space, and not the "-" that DEVICE lines
/// use for the pool total.
fn check_fence(fence: &[u8]) -> Result<(), Refused> {
    if fence.is_empty() || fence.len() > FENCE_MAX || fence == b"-" {
        return Err(Refused::Fence);
    }
    if !fence.iter().all(|&b| printable(b)) {
        return Err(Refused::Fence);
    }
    Ok(())
}

// ---- the cgroup file ----

/// read_bounded reads path whole into buf and gives how much it holds.
/// A file that cannot be opened or read, or that fills buf, is refused,
/// since the end of a full buffer was never seen. The descriptor closes
/// with the File on every path.
fn read_bounded(path: &str, buf: &mut [u8]) -> Result<usize, Refused> {
    let mut file = File::open(path).map_err(|_| Refused::Proc)?;
    let mut got = 0usize;
    loop {
        if got >= buf.len() {
            return Err(Refused::Proc);
        }
        let room = buf.get_mut(got..).ok_or(Refused::Proc)?;
        match file.read(room) {
            Ok(0) => return Ok(got),
            Ok(n) => got = got.checked_add(n).ok_or(Refused::Proc)?,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(Refused::Proc),
        }
    }
}

/// cgroup_unified finds the cgroup v2 line of a /proc/<pid>/cgroup
/// file, "0::<path>", and gives its path without the newline. Exactly
/// one such line, newline-terminated. The lines of a hybrid v1
/// hierarchy ("1:name=systemd:/...") may come before or after it and
/// are skipped. A NUL anywhere refuses the file, since the kernel
/// writes none, and so does an unterminated last line.
fn cgroup_unified(buf: &[u8]) -> Result<&[u8], Refused> {
    if buf.contains(&0) {
        return Err(Refused::Cgroup);
    }
    let mut found: Option<&[u8]> = None;
    let mut rest = buf;
    while !rest.is_empty() {
        let nl = rest
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(Refused::Cgroup)?;
        let line = rest.get(..nl).ok_or(Refused::Cgroup)?;
        if let Some(path) = line.strip_prefix(b"0::") {
            if found.is_some() {
                return Err(Refused::Cgroup);
            }
            found = Some(path);
        }
        let next = nl.checked_add(1).ok_or(Refused::Cgroup)?;
        rest = rest.get(next..).ok_or(Refused::Cgroup)?;
    }
    found.ok_or(Refused::Cgroup)
}

// ---- cgroup_of ----

/// peer_pidfd takes a pidfd for the process on the other end of conn.
/// The kernel pinned that process at connect time, so a pid reused
/// after the peer's exit cannot pass. There is no pidfd_open fallback.
/// The target kernel is 6.17 and the fallback would open whatever
/// process holds the pid by then, which is the hole the pidfd closes.
fn peer_pidfd(conn: BorrowedFd<'_>) -> Result<OwnedFd, Refused> {
    let mut fd: c_int = -1;
    let mut len = size_of::<c_int>() as socklen_t;
    // SAFETY: fd and len are live locals of the sizes passed, and the
    // kernel writes at most len bytes into fd.
    let r = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&raw mut fd).cast::<c_void>(),
            &raw mut len,
        )
    };
    if r != 0 || len as usize != size_of::<c_int>() || fd < 0 {
        return Err(Refused::Peer);
    }
    // SAFETY: the kernel just installed fd in this process and nothing
    // else owns it, so OwnedFd closes it once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// peer_pid gives the pid of the process on the other end of conn, in
/// the engine's pid namespace, from SO_PEERCRED. The kernel takes it
/// from the same peer it pinned for SO_PEERPIDFD, so the two cannot
/// name different processes. It is the thread group id, never a
/// thread's. A peer not visible in this pid namespace shows as 0 and is
/// refused. The fdinfo `Pid:` line of the pidfd would say the same with
/// one more open, read and parse under the filter.
fn peer_pid(conn: BorrowedFd<'_>) -> Result<libc::pid_t, Refused> {
    let mut cr = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as socklen_t;
    // SAFETY: cr and len are live locals of the sizes passed, and the
    // kernel writes at most len bytes into cr.
    let r = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cr).cast::<c_void>(),
            &raw mut len,
        )
    };
    if r != 0 || len as usize != size_of::<libc::ucred>() {
        return Err(Refused::Peer);
    }
    if cr.pid <= 0 {
        return Err(Refused::Pid);
    }
    Ok(cr.pid)
}

/// alive says whether the process behind pidfd has not exited. POLLIN
/// on a pidfd means it has, so the file just read may have been another
/// process's. The poll needs no kill permission, unlike
/// pidfd_send_signal. A poll error counts as exited.
fn alive(pidfd: &OwnedFd) -> bool {
    let mut pf = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pf is a live local and the count passed is one.
    let r = unsafe { libc::poll(&raw mut pf, 1, 0) };
    r == 0
}

/// The cgroup v2 path of the process on the other end of conn, as the
/// `0::` line of /proc/<pid>/cgroup names it, checked live after the
/// read.
pub fn cgroup_of(conn: BorrowedFd<'_>) -> Result<Vec<u8>, Refused> {
    let pidfd = peer_pidfd(conn)?;
    let pid = peer_pid(conn)?;
    let path = format!("/proc/{pid}/cgroup");
    let mut buf = [0u8; CGROUP_FILE_MAX];
    let n = read_bounded(&path, &mut buf)?;
    let file = buf.get(..n).ok_or(Refused::Proc)?;
    let cgroup = cgroup_unified(file)?;
    check_path(cgroup)?;
    if !alive(&pidfd) {
        return Err(Refused::Dead);
    }
    Ok(cgroup.to_vec())
}

// ---- Map ----

/// Which cgroup is whose fence, from fiberd's LEAF, UNLEAF and RELAY
/// lines. One thread owns it, so no lock. Both tables are bounded, and
/// every key passed check_path, so a key can only equal a path
/// cgroup_of would give.
#[derive(Default)]
pub struct Map {
    /// cgroup to fence.
    leaves: HashMap<Vec<u8>, Vec<u8>>,
    /// cgroups whose peers may name any fence with a LEAF.
    relays: HashSet<Vec<u8>>,
}

impl Map {
    /// LEAF <fence> <cgroup>. A later LEAF for the same cgroup replaces
    /// its fence. A new cgroup past LEAVES_MAX is refused.
    pub fn leaf(&mut self, fence: &[u8], cgroup: &[u8]) -> Result<(), Refused> {
        check_fence(fence)?;
        check_path(cgroup)?;
        if !self.leaves.contains_key(cgroup) && self.leaves.len() >= LEAVES_MAX {
            return Err(Refused::Full);
        }
        self.leaves.insert(cgroup.to_vec(), fence.to_vec());
        Ok(())
    }

    /// UNLEAF <fence>. Drops every mapping to fence. Unknown is fine.
    pub fn unleaf(&mut self, fence: &[u8]) {
        self.leaves.retain(|_, f| f.as_slice() != fence);
    }

    /// RELAY <cgroup>. A repeat is fine. A new cgroup past RELAYS_MAX is
    /// refused.
    pub fn relay(&mut self, cgroup: &[u8]) -> Result<(), Refused> {
        check_path(cgroup)?;
        if self.relays.contains(cgroup) {
            return Ok(());
        }
        if self.relays.len() >= RELAYS_MAX {
            return Err(Refused::Full);
        }
        self.relays.insert(cgroup.to_vec());
        Ok(())
    }

    /// Whether cgroup has any mapping, LEAF or RELAY. A miss makes the
    /// caller drain fd 3 and ask again.
    pub fn known(&self, cgroup: &[u8]) -> bool {
        self.leaves.contains_key(cgroup) || self.relays.contains(cgroup)
    }

    /// Whether a peer in cgroup may name fence. Its own LEAF fence, or,
    /// for a RELAY cgroup, any fence that has a LEAF.
    pub fn may_name(&self, cgroup: &[u8], fence: &[u8]) -> bool {
        let own = self.leaves.get(cgroup);
        if own.is_some_and(|f| f.as_slice() == fence) {
            return true;
        }
        self.relays.contains(cgroup) && self.leaves.values().any(|f| f.as_slice() == fence)
    }
}

// ---- seal ----

/// Why seal failed, printable for stderr. The engine must not serve
/// after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unsealed(pub Refusal);

impl fmt::Display for Unsealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Refusal::Errno(e) => write!(f, "seccomp refused with errno {e}"),
            Refusal::Thread(tid) => write!(f, "seccomp could not cover thread {tid}"),
        }
    }
}

/// Installs the core's Engine seccomp program on every thread (TSYNC),
/// under no_new_privs. main calls it once, after the pool is zeroed and
/// the socket bound, before READY and the first accept, so the driver's
/// start-up runs unfiltered and everything that reads fiber input runs
/// filtered.
pub fn seal() -> Result<(), Unsealed> {
    seccomp::install(Program::Engine).map_err(Unsealed)
}
