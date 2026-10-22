//! fd 3, the engine's channel to fiberd. A SOCK_SEQPACKET unix socket
//! where one message is one line of at most 256 bytes, ending in a
//! newline. The engine sends ENGINE, GPU, READY, DEVICE and ERROR, and
//! fiberd sends LEAF, UNLEAF, RELAY and EVICT. A message from fiberd may
//! carry descriptors, which M5's SAVE and RESTORE will take. This
//! milestone closes every one that arrives.

// ---- the channel ----

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr;

use libc::{c_int, c_void, socklen_t};

use crate::proto::{self, LINE_MAX};

/// The descriptor fiberd passes the channel on.
const CTL_FD: c_int = 3;

/// fd 3, owned. Every send is one whole line or the engine exits.
pub struct Ctl {
    fd: OwnedFd,
}

/// gone ends the engine on a broken fd 3. fiberd reads the exit as
/// every slice going to zero.
pub fn gone(why: &str) -> ! {
    eprintln!("refengine: fd 3: {why}");
    std::process::exit(1)
}

impl Ctl {
    /// open takes fd 3 after checking it is a SOCK_SEQPACKET socket, so a
    /// start without fiberd fails by name.
    pub fn open() -> Result<Ctl, String> {
        let mut ty: c_int = 0;
        let mut len = size_of::<c_int>() as socklen_t;
        // SAFETY: ty and len are live locals of the sizes passed, and the
        // kernel writes at most len bytes into ty.
        let r = unsafe {
            libc::getsockopt(
                CTL_FD,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut ty).cast::<c_void>(),
                &raw mut len,
            )
        };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("fd 3 is not a socket: {err}"));
        }
        if ty != libc::SOCK_SEQPACKET {
            return Err("fd 3 is not a SOCK_SEQPACKET socket".to_owned());
        }
        // SAFETY: integer arguments alone.
        unsafe { libc::fcntl(CTL_FD, libc::F_SETFD, libc::FD_CLOEXEC) };
        // SAFETY: fd 3 is open, it is a socket, and nothing else in the
        // engine owns it, so OwnedFd closes it once.
        Ok(Ctl {
            fd: unsafe { OwnedFd::from_raw_fd(CTL_FD) },
        })
    }

    /// send writes line and its newline as one message. A line that
    /// would pass LINE_MAX is a bug, and a send that fails is a broken
    /// fd 3, so both end the engine. A full socket waits, so no line is
    /// ever dropped.
    pub fn send(&self, line: &str) {
        let mut msg = Vec::with_capacity(line.len().saturating_add(1));
        msg.extend_from_slice(line.as_bytes());
        msg.push(b'\n');
        if msg.len() > LINE_MAX {
            gone("a line to fiberd is longer than 256 bytes");
        }
        loop {
            // SAFETY: msg is live for the call and the kernel only reads
            // msg.len() bytes of it.
            let r = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    msg.as_ptr().cast::<c_void>(),
                    msg.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if usize::try_from(r).is_ok_and(|n| n == msg.len()) {
                return;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) if r < 0 => {}
                Some(libc::EAGAIN) if r < 0 => self.wait(libc::POLLOUT),
                _ => gone(&format!("send: {err}")),
            }
        }
    }

    /// error sends `ERROR <fence> <why>`, with "-" for a line that named
    /// no valid fence.
    pub fn error(&self, fence: &[u8], why: &str) {
        let fence = if proto::valid_fence(fence) {
            String::from_utf8_lossy(fence)
        } else {
            "-".into()
        };
        self.send(&format!("ERROR {fence} {why}"));
    }

    /// wait blocks until fd 3 is ready for events, or has hung up.
    fn wait(&self, events: i16) {
        let mut pf = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: pf is a live local and the count passed is one.
        unsafe { libc::poll(&raw mut pf, 1, -1) };
    }
}

impl AsFd for Ctl {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// ---- receiving ----

/// What one non-blocking read of fd 3 gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Recv {
    /// One line, its newline cut off.
    Line(Vec<u8>),
    /// A message that is no line, too long or with no newline at its
    /// end.
    Bad,
    /// Nothing pending.
    Empty,
    /// fiberd closed fd 3, or it broke.
    Closed,
}

/// Room for the descriptors one message may carry, more than any line
/// will send. Extra ones the kernel drops and closes itself.
const CMSG_WORDS: usize = 16;

impl Ctl {
    /// recv reads one pending message without blocking, with recvmsg so
    /// the descriptors it carries arrive too. They are closed at once in
    /// this milestone. A zero-length read is fiberd closing the socket,
    /// since fiberd never sends an empty message. msghdr's lengths are
    /// size_t on glibc and narrower on musl, hence the casts.
    #[allow(clippy::unnecessary_cast)]
    pub fn recv(&self) -> Recv {
        let mut buf = [0u8; LINE_MAX + 1];
        let mut cbuf = [0u64; CMSG_WORDS];
        loop {
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast::<c_void>(),
                iov_len: buf.len(),
            };
            // SAFETY: msghdr is plain data, and all zero is a valid
            // empty one.
            let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
            mh.msg_iov = &raw mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = cbuf.as_mut_ptr().cast::<c_void>();
            mh.msg_controllen = size_of_val(&cbuf) as _;
            // SAFETY: mh, iov, buf and cbuf are live for the call, and
            // the kernel writes at most their lengths.
            let r = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &raw mut mh,
                    libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
                )
            };
            if r < 0 {
                return match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => Recv::Empty,
                    _ => Recv::Closed,
                };
            }
            close_passed(&mh);
            let Ok(n) = usize::try_from(r) else {
                return Recv::Closed;
            };
            if n == 0 {
                return Recv::Closed;
            }
            if mh.msg_flags & libc::MSG_TRUNC != 0 || n > LINE_MAX {
                return Recv::Bad;
            }
            return match buf.get(..n) {
                Some([line @ .., b'\n']) => Recv::Line(line.to_vec()),
                _ => Recv::Bad,
            };
        }
    }
}

/// close_passed closes every descriptor an SCM_RIGHTS message put in
/// this process. M5 takes the one SAVE and RESTORE carry instead.
/// cmsg_len is size_t on glibc and narrower on musl, hence the cast.
#[allow(clippy::unnecessary_cast)]
fn close_passed(mh: &libc::msghdr) {
    // SAFETY: mh is the header recvmsg just filled, and its control
    // buffer is live. CMSG_FIRSTHDR and CMSG_NXTHDR stay inside
    // msg_controllen, which the kernel set.
    let mut c = unsafe { libc::CMSG_FIRSTHDR(mh) };
    while !c.is_null() {
        // SAFETY: c points at a whole cmsghdr inside the control buffer.
        let h = unsafe { ptr::read_unaligned(c) };
        if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: CMSG_LEN of 0 is the header's own length, a const.
            let head = unsafe { libc::CMSG_LEN(0) } as usize;
            let count = (h.cmsg_len as usize).saturating_sub(head) / size_of::<c_int>();
            // SAFETY: c is a valid cmsghdr, so its data follows it.
            let data = unsafe { libc::CMSG_DATA(c) }.cast::<c_int>();
            for i in 0..count {
                // SAFETY: the kernel wrote count descriptors after the
                // header, inside the control buffer, maybe unaligned.
                let fd = unsafe { ptr::read_unaligned(data.add(i)) };
                if fd >= 0 {
                    // SAFETY: the kernel just installed fd here and
                    // nothing else owns it, so dropping closes it once.
                    drop(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        // SAFETY: as for CMSG_FIRSTHDR, c is a header of mh's buffer.
        c = unsafe { libc::CMSG_NXTHDR(mh, c) };
    }
}

// ---- control lines ----

/// One line from fiberd. No line is acked, a refusal sends ERROR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control<'a> {
    /// `LEAF <fence> <cgroup>`
    Leaf {
        /// The fiber's fence.
        fence: &'a [u8],
        /// Its cgroup, as the `0::` line of /proc/<pid>/cgroup names it.
        cgroup: &'a [u8],
    },
    /// `UNLEAF <fence>`
    Unleaf {
        /// The fence whose mappings go.
        fence: &'a [u8],
    },
    /// `RELAY <cgroup>`
    Relay {
        /// The cgroup whose peers may name any fence with a LEAF.
        cgroup: &'a [u8],
    },
    /// `EVICT <fence>`
    Evict {
        /// The fence whose slice goes.
        fence: &'a [u8],
    },
}

/// parse reads one control line, its newline already cut off. None is
/// a line the engine does not know, or a fence that is not a valid one.
/// The cgroup is checked where it is mapped, in peer.rs.
pub fn parse(line: &mut [u8]) -> Option<Control<'_>> {
    let (spans, n) = proto::tokens(line)?;
    let line: &[u8] = line;
    let [a, b, c] = spans.map(|s| s.of(line));
    let ctl = match (a, n) {
        (b"LEAF", 3) => Control::Leaf {
            fence: b,
            cgroup: c,
        },
        (b"UNLEAF", 2) => Control::Unleaf { fence: b },
        (b"RELAY", 2) => Control::Relay { cgroup: b },
        (b"EVICT", 2) => Control::Evict { fence: b },
        _ => return None,
    };
    let fence = match ctl {
        Control::Leaf { fence, .. } => fence,
        Control::Unleaf { fence } | Control::Evict { fence } => fence,
        Control::Relay { .. } => return Some(ctl),
    };
    proto::valid_fence(fence).then_some(ctl)
}
