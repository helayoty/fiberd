//! The control channel between fiberd and the zygote. recv_line reads
//! one line with its descriptors, Line builds and sends one, and the
//! entries a template may call from any thread live here.
//!
//! Threads. Only the serving thread touches the zygote's state, but an
//! engine template reports from any thread, so the fields here are
//! shared. One mutex keeps every line whole.
//!
//! No formatting machinery. A line is built from its pieces, and the
//! tests below pin the bytes fiberd reads.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::abi::{ENGINE_MAX, MAX_PASSED, REPORT_MAX, SEND_MAX};
use crate::child::zeroed;
use crate::fiber::Global;
use crate::sys;

/// fz_on_control in the header: the template's handler for lines such as
/// EVICT.
pub type OnControl = Option<unsafe extern "C" fn(*const c_char)>;

/// The control descriptor, -1 before READY and in a fiber. Written once
/// by the serving thread and read by any reporter, hence atomic.
static CTL_FD: AtomicI32 = AtomicI32::new(-1);
/// The template's control handler, as a pointer, null for none.
static HANDLER: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
/// The engine's endpoint, NUL-ended, empty for none. Set before fz_serve.
static ENGINE: Global<[u8; ENGINE_MAX]> = Global::new([0; ENGINE_MAX]);
/// One mutex keeps the lines whole.
static CTL_MU: Global<libc::pthread_mutex_t> = Global::new(libc::PTHREAD_MUTEX_INITIALIZER);

/// The control descriptor, or -1.
pub fn ctl_fd() -> c_int {
    CTL_FD.load(Ordering::Relaxed)
}

/// Notes the control descriptor. From here on other threads may report.
pub fn set_ctl_fd(fd: c_int) {
    CTL_FD.store(fd, Ordering::Relaxed);
}

/// The template's control handler, or None.
pub fn handler() -> OnControl {
    let p = HANDLER.load(Ordering::Relaxed);
    if p.is_null() {
        None
    } else {
        // SAFETY: a non-null value was stored by fz_set_control from a
        // function pointer of this type, and a pointer round-trips.
        Some(unsafe { core::mem::transmute::<*mut (), unsafe extern "C" fn(*const c_char)>(p) })
    }
}

/// A copy of the engine's endpoint, NUL-ended.
pub fn engine_endpoint() -> [u8; ENGINE_MAX] {
    // SAFETY: the static is set before fz_serve and read after, by the
    // header's contract, so no write overlaps this read.
    unsafe { ptr::read(ENGINE.get()) }
}

/// The child's reset, before its first system call. The channel is the
/// zygote's, so fz_report_line from a fiber must fail rather than write
/// into whatever lands at fd 3. The copied mutex may be held by a thread
/// that does not exist here, so it starts over.
///
/// # Safety
/// The caller is the child of birth, the only thread of the process.
pub unsafe fn reset_for_child() {
    CTL_FD.store(-1, Ordering::Relaxed);
    HANDLER.store(ptr::null_mut(), Ordering::Relaxed);
    // SAFETY: by the contract above, nothing else touches the mutex.
    unsafe { ptr::write(CTL_MU.get(), libc::PTHREAD_MUTEX_INITIALIZER) };
}

/// Writes all of buf to fd, retrying on EINTR. 0, or -1 with errno from
/// the write that failed.
pub fn write_all(fd: c_int, buf: &[u8]) -> c_int {
    let mut rest = buf;
    while !rest.is_empty() {
        // SAFETY: write reads at most rest.len() bytes of rest, which is live.
        let w = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if w < 0 {
            if sys::errno() == libc::EINTR {
                continue;
            }
            return -1;
        }
        let Some(left) = usize::try_from(w).ok().and_then(|w| rest.get(w..)) else {
            return -1;
        };
        rest = left;
    }
    0
}

/// Writes buf to fd under the control mutex, so a line another thread
/// reports lands whole between the loop's own. 0 or -1.
fn write_locked(fd: c_int, buf: &[u8]) -> c_int {
    // SAFETY: the mutex is a live static initialised with its
    // initialiser, and every lock here is paired with the unlock below.
    unsafe { libc::pthread_mutex_lock(CTL_MU.get()) };
    let rc = write_all(fd, buf);
    // SAFETY: as above.
    unsafe { libc::pthread_mutex_unlock(CTL_MU.get()) };
    rc
}

/// A control line built by hand. len counts the whole line even past the
/// buffer, so a line that would not fit is refused rather than cut.
pub struct Line {
    buf: [u8; SEND_MAX],
    len: usize,
}

impl Default for Line {
    fn default() -> Self {
        Line::new()
    }
}

impl Line {
    /// An empty line.
    pub const fn new() -> Line {
        Line {
            buf: [0; SEND_MAX],
            len: 0,
        }
    }

    /// Appends s, as %s.
    pub fn s(&mut self, s: &[u8]) -> &mut Line {
        sys::append(&mut self.buf, self.len.min(SEND_MAX), s);
        self.len = self.len.saturating_add(s.len());
        self
    }

    /// Appends at most n bytes of s, as %.*s.
    pub fn cut(&mut self, s: &[u8], n: usize) -> &mut Line {
        self.s(s.get(..n).unwrap_or(s))
    }

    /// Appends a NUL-ended string, as %s.
    ///
    /// # Safety
    /// p is NUL-ended and live for the call.
    pub unsafe fn cstr(&mut self, p: *const c_char) -> &mut Line {
        // SAFETY: by the contract above.
        self.s(unsafe { sys::c_bytes(p) })
    }

    /// Appends v in decimal, as %d.
    pub fn int(&mut self, v: c_int) -> &mut Line {
        if v < 0 {
            self.s(b"-");
        }
        let mut digits = [0u8; 10];
        let n = sys::append_decimal(&mut digits, 0, v.unsigned_abs());
        self.s(digits.get(..n).unwrap_or(&[]))
    }

    /// Appends b as two lower-case hex digits, as %02x.
    pub fn hex2(&mut self, b: u8) -> &mut Line {
        let digit = |d: u8| -> u8 {
            if d < 10 {
                b'0'.wrapping_add(d)
            } else {
                b'a'.wrapping_add(d.wrapping_sub(10))
            }
        };
        self.s(&[digit(b >> 4), digit(b & 0xf)])
    }

    /// The line so far, cut to what the buffer holds.
    pub fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len.min(SEND_MAX)).unwrap_or(&[])
    }

    /// Whether the line, newline included, fits the buffer.
    pub fn fits(&self) -> bool {
        self.len < SEND_MAX
    }

    /// Sends the line with a newline on fd, under the control mutex. 0, or
    /// -1 for a line that does not fit or a failed write (errno set).
    pub fn send(&mut self, fd: c_int) -> c_int {
        if !self.fits() {
            return -1;
        }
        let n = self.len;
        if let Some(end) = self.buf.get_mut(n) {
            *end = b'\n';
        }
        let n = n.wrapping_add(1);
        write_locked(fd, self.buf.get(..n).unwrap_or(&[]))
    }

    /// Writes the line with a newline to stderr, the zygote's log. No
    /// lock, since stderr is not the channel.
    pub fn stderr(&mut self) {
        let n = self.len.min(SEND_MAX.wrapping_sub(1));
        if let Some(end) = self.buf.get_mut(n) {
            *end = b'\n';
        }
        let n = n.wrapping_add(1);
        write_all(2, self.buf.get(..n).unwrap_or(&[]));
    }
}

/// Room for strerror's text, under 64 bytes in the POSIX locale.
pub const STRERROR_MAX: usize = 128;

/// strerror(e) as a byte string in buf. An errno glibc does not know
/// gives "Unknown error N".
pub fn strerror(e: c_int, buf: &mut [u8; STRERROR_MAX]) -> &[u8] {
    // SAFETY: buf is live and buf.len() bytes long. The XSI strerror_r
    // writes a NUL-ended string into it, whatever it returns.
    unsafe { libc::strerror_r(e, buf.as_mut_ptr().cast(), buf.len()) };
    if let Some(last) = buf.last_mut() {
        *last = 0;
    }
    buf.get(..sys::nul_at(buf)).unwrap_or(&[])
}

/// Room for four descriptors in one SCM_RIGHTS control message, aligned
/// as a cmsghdr is.
const CMSG_WORDS: usize = 4;

/// Reads one line off fd into buf, NUL-ended. Descriptors riding along
/// land in fds_out in order, unused slots -1 and extras closed. Returns
/// the line length, 0 on EOF, or -1 on error (EMSGSIZE for a line longer
/// than buf).
///
/// A peek with no control buffer, so nothing is installed, finds the
/// newline, then exactly that much is read with descriptors. They stay
/// with the right line because an AF_UNIX stream read never crosses into
/// a message whose SCM_RIGHTS differ, and fiberd sends descriptors on
/// the CLONE line alone. A long line may take several reads.
pub fn recv_line(fd: c_int, buf: &mut [u8], fds_out: &mut [c_int; MAX_PASSED]) -> isize {
    let cap = buf.len();
    let mut len = 0usize;
    let mut nfds = 0usize;
    *fds_out = [-1; MAX_PASSED];
    while len.wrapping_add(1) < cap {
        let Some(room) = buf.get_mut(len..cap.wrapping_sub(1)) else {
            break;
        };
        let mut iov = libc::iovec {
            iov_base: room.as_mut_ptr().cast::<c_void>(),
            iov_len: room.len(),
        };
        let mut mh: libc::msghdr = zeroed();
        mh.msg_iov = &raw mut iov;
        mh.msg_iovlen = 1;
        // SAFETY: mh and iov are live for the call, and iov names room,
        // which is live.
        let r = unsafe { libc::recvmsg(fd, &raw mut mh, libc::MSG_PEEK) };
        if r < 0 {
            if sys::errno() == libc::EINTR {
                continue;
            }
            return -1;
        }
        let Ok(r) = usize::try_from(r) else {
            return -1;
        };
        if r == 0 {
            if let Some(end) = buf.get_mut(len) {
                *end = 0;
            }
            return len as isize;
        }
        let peeked = room.get(..r.min(room.len())).unwrap_or(&[]);
        let nl = sys::byte_at(peeked, b'\n');
        let want = if nl < peeked.len() {
            nl.wrapping_add(1)
        } else {
            peeked.len()
        };
        let mut cbuf = [0u64; CMSG_WORDS];
        iov.iov_len = want;
        mh.msg_iov = &raw mut iov;
        mh.msg_control = cbuf.as_mut_ptr().cast::<c_void>();
        mh.msg_controllen = size_of::<[u64; CMSG_WORDS]>();
        // SAFETY: as above, with cbuf live for the call.
        let r = unsafe { libc::recvmsg(fd, &raw mut mh, libc::MSG_CMSG_CLOEXEC) };
        if r < 0 {
            if sys::errno() == libc::EINTR {
                continue;
            }
            return -1;
        }
        let Ok(r) = usize::try_from(r) else {
            return -1;
        };
        if r == 0 {
            if let Some(end) = buf.get_mut(len) {
                *end = 0;
            }
            return len as isize;
        }
        // SAFETY: mh describes cbuf, which the kernel filled, and each
        // header the walk yields lies inside it.
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
                        match fds_out.get_mut(nfds) {
                            Some(slot) => {
                                *slot = got;
                                nfds = nfds.wrapping_add(1);
                            }
                            None => {
                                libc::close(got);
                            }
                        }
                    }
                }
                c = libc::CMSG_NXTHDR(&raw const mh, c);
            }
        }
        len = len.wrapping_add(r);
        let last = len.wrapping_sub(1);
        if buf.get(last) == Some(&b'\n') {
            if let Some(end) = buf.get_mut(last) {
                *end = 0;
            }
            return len as isize;
        }
    }
    sys::set_errno(libc::EMSGSIZE);
    -1
}

/// The monotonic clock's reading.
pub fn now_ts() -> libc::timespec {
    let mut ts: libc::timespec = zeroed();
    // SAFETY: ts is live for the call.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    ts
}

/// The milliseconds from now to t, negative once past.
pub fn ms_until(t: libc::timespec) -> c_long {
    let n = now_ts();
    (t.tv_sec.wrapping_sub(n.tv_sec))
        .wrapping_mul(1000)
        .wrapping_add(t.tv_nsec.wrapping_sub(n.tv_nsec) / 1_000_000)
}

/// now plus ms milliseconds, a pending child's deadline.
pub fn deadline_of(now: libc::timespec, ms: c_int) -> libc::timespec {
    let mut d = now;
    d.tv_sec = d.tv_sec.wrapping_add(c_long::from(ms / 1000));
    d.tv_nsec = d
        .tv_nsec
        .wrapping_add(c_long::from(ms % 1000).wrapping_mul(1_000_000));
    if d.tv_nsec >= 1_000_000_000 {
        d.tv_sec = d.tv_sec.wrapping_add(1);
        d.tv_nsec = d.tv_nsec.wrapping_sub(1_000_000_000);
    }
    d
}

/// Names the engine's endpoint, which every fiber finds as
/// FIBERD_ENGINE. Null names none. A longer one is cut to ENGINE_MAX - 1
/// bytes.
///
/// # Safety
/// endpoint is NUL-ended and live for the call, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_set_engine(endpoint: *const c_char) {
    let src: &[u8] = if endpoint.is_null() {
        b""
    } else {
        // SAFETY: by the contract above.
        unsafe { sys::c_bytes(endpoint) }
    };
    let mut value = [0u8; ENGINE_MAX];
    sys::append(
        &mut value,
        0,
        src.get(..ENGINE_MAX.wrapping_sub(1)).unwrap_or(src),
    );
    // SAFETY: set before fz_serve, by the header's contract, so no read
    // overlaps this write.
    unsafe { ptr::write(ENGINE.get(), value) };
}

/// Installs the template's handler for lines such as EVICT.
#[unsafe(no_mangle)]
pub extern "C" fn fz_set_control(handler: OnControl) {
    let p = handler.map_or(ptr::null_mut(), |f| f as *mut ());
    HANDLER.store(p, Ordering::Relaxed);
}

/// Sends one line the template formatted, newline appended, under the
/// mutex so it lands whole. It is never read past REPORT_MAX bytes, so a
/// string with no NUL in reach is refused. -1 with errno EINVAL for a
/// null line or one holding a newline, EMSGSIZE for REPORT_MAX
/// characters or more, EBADF with no channel (before READY, and always
/// in a fiber), or the write's own.
///
/// # Safety
/// line is NUL-ended and live for the call, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_report_line(line: *const c_char) -> c_int {
    // SAFETY: by the contract above.
    match unsafe { report_line(line) } {
        Ok(()) => 0,
        Err(e) => {
            sys::set_errno(e.0);
            -1
        }
    }
}

/// The body of fz_report_line, with the errno as a value.
///
/// # Safety
/// As fz_report_line.
unsafe fn report_line(line: *const c_char) -> Result<(), sys::Errno> {
    if line.is_null() {
        return Err(sys::Errno(libc::EINVAL));
    }
    let mut buf = [0u8; REPORT_MAX];
    let mut n = 0usize;
    loop {
        let Some(slot) = buf.get_mut(n) else {
            // REPORT_MAX characters and no NUL yet: no room for the newline.
            return Err(sys::Errno(libc::EMSGSIZE));
        };
        // SAFETY: line is NUL-ended (the contract of fz_report_line), and
        // the bytes before n were not its NUL, so byte n is still its.
        let b = unsafe { line.cast::<u8>().add(n).read() };
        if b == 0 {
            break;
        }
        if b == b'\n' {
            return Err(sys::Errno(libc::EINVAL));
        }
        *slot = b;
        n = n.wrapping_add(1);
    }
    // n < REPORT_MAX here, so the newline fits.
    let Some(nl) = buf.get_mut(n) else {
        return Err(sys::Errno(libc::EMSGSIZE));
    };
    *nl = b'\n';
    let fd = ctl_fd();
    if fd < 0 {
        return Err(sys::Errno(libc::EBADF));
    }
    if write_locked(fd, buf.get(..=n).unwrap_or(&[])) < 0 {
        return Err(sys::Errno::last());
    }
    Ok(())
}

/// Sends data on sock as one message, with fds in SCM_RIGHTS, for the
/// tests here and in zygote.rs.
#[cfg(test)]
pub(crate) fn send_with_fds(sock: c_int, data: &[u8], fds: &[c_int]) {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut cbuf = [0u64; 8];
    let mut mh: libc::msghdr = zeroed();
    mh.msg_iov = &raw mut iov;
    mh.msg_iovlen = 1;
    if !fds.is_empty() {
        let bytes = core::mem::size_of_val(fds);
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

    /// Everything the peer wrote, without waiting.
    fn drain(fd: c_int) -> Vec<u8> {
        let mut got = Vec::new();
        loop {
            let mut buf = [0u8; 8192];
            // SAFETY: buf is live for the call.
            let n =
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if n <= 0 {
                return got;
            }
            got.extend_from_slice(&buf[..n as usize]);
        }
    }

    fn is_open(fd: c_int) -> bool {
        // SAFETY: integer arguments alone.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        flags >= 0
    }

    #[test]
    fn lines_are_formatted_as_printf_did() {
        let long = vec![b'f'; 200];
        let cut_fence = [b"ERROR ".as_slice(), &[b'f'; 127], b" malformed CLONE"].concat();
        let cases: Vec<(&str, Box<dyn Fn(&mut Line)>, &[u8])> = vec![
            (
                "a bare word",
                Box::new(|l| {
                    l.s(b"READY");
                }),
                b"READY",
            ),
            (
                "a fence and a pid",
                Box::new(|l| {
                    l.s(b"CLONED ").s(b"g/1/7").s(b" ").int(4242);
                }),
                b"CLONED g/1/7 4242",
            ),
            (
                "a negative number",
                Box::new(|l| {
                    l.int(-1);
                }),
                b"-1",
            ),
            (
                "the largest and smallest int",
                Box::new(|l| {
                    l.int(c_int::MAX).s(b" ").int(c_int::MIN);
                }),
                b"2147483647 -2147483648",
            ),
            (
                "a fence cut to 127 as %.*s",
                Box::new(move |l| {
                    l.s(b"ERROR ").cut(&long, 127).s(b" malformed CLONE");
                }),
                &cut_fence,
            ),
            (
                "a short string is not padded by %.*s",
                Box::new(|l| {
                    l.cut(b"ab", 127);
                }),
                b"ab",
            ),
            (
                "a byte as %02x",
                Box::new(|l| {
                    l.s(b"0x").hex2(0x0a).s(b" ").hex2(0xff).s(b" ").hex2(0);
                }),
                b"0x0a ff 00",
            ),
            (
                "a C string",
                Box::new(|l| {
                    // SAFETY: a static NUL-ended string.
                    unsafe { l.cstr(c"deny".as_ptr()) };
                }),
                b"deny",
            ),
        ];
        for (name, build, want) in cases {
            let mut l = Line::new();
            build(&mut l);
            assert_eq!(l.bytes(), want, "{name}");
            assert!(l.fits(), "{name}");
        }
    }

    #[test]
    fn a_line_that_does_not_fit_is_refused_not_cut() {
        let cases: &[(&str, usize, bool)] = &[
            ("the longest line that fits", SEND_MAX - 1, true),
            ("one more is refused", SEND_MAX, false),
            ("far too long", 3 * SEND_MAX, false),
        ];
        for (name, n, want) in cases {
            let [ours, theirs] = pair();
            let mut l = Line::new();
            l.s(&vec![b'x'; *n]);
            assert_eq!(l.fits(), *want, "{name}");
            let rc = l.send(ours);
            let got = drain(theirs);
            if *want {
                assert_eq!(rc, 0, "{name}");
                assert_eq!(got.len(), n + 1, "{name}: the line and its newline");
                assert_eq!(got.last(), Some(&b'\n'), "{name}");
            } else {
                assert_eq!(rc, -1, "{name}");
                assert!(got.is_empty(), "{name}: nothing sent");
            }
            // SAFETY: the pair is the test's own.
            unsafe {
                libc::close(ours);
                libc::close(theirs);
            }
        }
    }

    #[test]
    fn strerror_is_the_c_text() {
        let cases: &[(&str, c_int, &str)] = &[
            ("EPERM", libc::EPERM, "Operation not permitted"),
            ("ENOENT", libc::ENOENT, "No such file or directory"),
            ("EACCES", libc::EACCES, "Permission denied"),
            ("EROFS", libc::EROFS, "Read-only file system"),
            ("an unknown errno", 9999, "Unknown error 9999"),
        ];
        for (name, e, want) in cases {
            let mut buf = [0u8; STRERROR_MAX];
            let got = strerror(*e, &mut buf);
            assert_eq!(got, want.as_bytes(), "{name}");
        }
    }

    #[test]
    fn recv_line_reads_one_line_and_its_descriptors() {
        struct Case {
            name: &'static str,
            send: Vec<(&'static [u8], usize)>, // messages, each with that many descriptors
            eof: bool,
            cap: usize,
            want: isize,
            want_line: &'static [u8],
            want_fds: usize,
            want_errno: c_int,
        }
        let cases = [
            Case {
                name: "one line",
                send: vec![(b"CLONE f e 50 - -\n", 0)],
                eof: false,
                cap: 64,
                want: 17,
                want_line: b"CLONE f e 50 - -",
                want_fds: 0,
                want_errno: 0,
            },
            Case {
                name: "the first of two lines, the second left on the socket",
                send: vec![(b"HIDE /a\nHIDE /b\n", 0)],
                eof: false,
                cap: 64,
                want: 8,
                want_line: b"HIDE /a",
                want_fds: 0,
                want_errno: 0,
            },
            Case {
                name: "a line split across two messages",
                send: vec![(b"RUNDIR /a ", 0), (b"/a/b\n", 0)],
                eof: false,
                cap: 64,
                want: 15,
                want_line: b"RUNDIR /a /a/b",
                want_fds: 0,
                want_errno: 0,
            },
            Case {
                name: "a partial line at EOF, NUL-ended",
                send: vec![(b"PREPARE none", 0)],
                eof: true,
                cap: 64,
                want: 12,
                want_line: b"PREPARE none",
                want_fds: 0,
                want_errno: 0,
            },
            Case {
                name: "EOF alone",
                send: vec![],
                eof: true,
                cap: 64,
                want: 0,
                want_line: b"",
                want_fds: 0,
                want_errno: 0,
            },
            Case {
                name: "two descriptors ride along",
                send: vec![(b"CLONE f e 50 - -\n", 2)],
                eof: false,
                cap: 64,
                want: 17,
                want_line: b"CLONE f e 50 - -",
                want_fds: 2,
                want_errno: 0,
            },
            Case {
                name: "three descriptors ride along",
                send: vec![(b"CLONE f e 50 - - mntns,ws\n", 3)],
                eof: false,
                cap: 64,
                want: 26,
                want_line: b"CLONE f e 50 - - mntns,ws",
                want_fds: 3,
                want_errno: 0,
            },
            Case {
                name: "a fourth descriptor is closed",
                send: vec![(b"CLONE f e 50 - -\n", 4)],
                eof: false,
                cap: 64,
                want: 17,
                want_line: b"CLONE f e 50 - -",
                want_fds: 3,
                want_errno: 0,
            },
            Case {
                name: "a line longer than the buffer is EMSGSIZE",
                send: vec![(b"CLONE ffffffffffffffffffffffffffffffff e 50 - -\n", 0)],
                eof: false,
                cap: 16,
                want: -1,
                want_line: b"",
                want_fds: 0,
                want_errno: libc::EMSGSIZE,
            },
            Case {
                name: "a line of exactly the buffer less one fits",
                send: vec![(b"0123456789abcd\n", 0)],
                eof: false,
                cap: 16,
                want: 15,
                want_line: b"0123456789abcd",
                want_fds: 0,
                want_errno: 0,
            },
            Case {
                name: "a line of the buffer's size does not",
                send: vec![(b"0123456789abcde\n", 0)],
                eof: false,
                cap: 16,
                want: -1,
                want_line: b"",
                want_fds: 0,
                want_errno: libc::EMSGSIZE,
            },
        ];
        for tc in cases {
            let [ours, theirs] = pair();
            let mut sent = Vec::new();
            for (data, n) in &tc.send {
                let fds: Vec<c_int> = (0..*n)
                    .map(|_| {
                        // SAFETY: a static NUL-ended path.
                        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
                        assert!(fd >= 0, "open /dev/null");
                        fd
                    })
                    .collect();
                send_with_fds(theirs, data, &fds);
                sent.extend(fds);
            }
            if tc.eof {
                // SAFETY: an integer argument alone.
                unsafe { libc::shutdown(theirs, libc::SHUT_WR) };
            }
            let mut buf = vec![0xeeu8; tc.cap];
            let mut fds = [-2; MAX_PASSED];
            sys::set_errno(0);
            let r = recv_line(ours, &mut buf, &mut fds);
            assert_eq!(r, tc.want, "{}", tc.name);
            if tc.want_errno != 0 {
                assert_eq!(sys::errno(), tc.want_errno, "{}: errno", tc.name);
            }
            if r >= 0 {
                let line = &buf[..sys::nul_at(&buf)];
                assert_eq!(line, tc.want_line, "{}: the line", tc.name);
            }
            let got: Vec<c_int> = fds.iter().copied().filter(|&fd| fd >= 0).collect();
            assert_eq!(got.len(), tc.want_fds, "{}: descriptors {fds:?}", tc.name);
            for fd in &got {
                assert!(is_open(*fd), "{}: a passed descriptor is open", tc.name);
                // SAFETY: the descriptor the line carried, ours now.
                unsafe { libc::close(*fd) };
            }
            for fd in sent {
                // SAFETY: the test's own copies.
                unsafe { libc::close(fd) };
            }
            // SAFETY: the pair is the test's own.
            unsafe {
                libc::close(ours);
                libc::close(theirs);
            }
        }
    }

    #[test]
    fn deadlines_add_milliseconds_and_carry() {
        let at = |sec: c_long, nsec: c_long| libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let cases: &[(&str, libc::timespec, c_int, (c_long, c_long))] = &[
            ("under a second", at(10, 0), 50, (10, 50_000_000)),
            ("whole seconds", at(10, 0), 3000, (13, 0)),
            ("a carry", at(10, 990_000_000), 20, (11, 10_000_000)),
            (
                "just under a carry",
                at(10, 999_999_999),
                0,
                (10, 999_999_999),
            ),
            (
                "the largest deadline",
                at(0, 0),
                c_int::MAX,
                (2_147_483, 647_000_000),
            ),
        ];
        for (name, now, ms, (sec, nsec)) in cases {
            let d = deadline_of(*now, *ms);
            assert_eq!((d.tv_sec, d.tv_nsec), (*sec, *nsec), "{name}");
        }
    }

    #[test]
    fn ms_until_counts_down() {
        let now = now_ts();
        let cases: &[(&str, c_int, c_long, c_long)] = &[
            ("a second ahead", 1000, 900, 1000),
            ("already past", -1000, -1_000_000, -999),
        ];
        for (name, ms, lo, hi) in cases {
            let t = if *ms >= 0 {
                deadline_of(now, *ms)
            } else {
                libc::timespec {
                    tv_sec: now.tv_sec + c_long::from(*ms / 1000),
                    tv_nsec: now.tv_nsec,
                }
            };
            let left = ms_until(t);
            assert!(left >= *lo && left <= *hi, "{name}: {left}ms");
        }
    }

    #[test]
    fn the_engine_endpoint_is_cut_as_snprintf_cut_it() {
        let long = vec![b'e'; ENGINE_MAX + 10];
        let cases: Vec<(&str, Option<Vec<u8>>, Vec<u8>)> = vec![
            (
                "a path",
                Some(b"/run/e.sock".to_vec()),
                b"/run/e.sock".to_vec(),
            ),
            ("null is empty", None, vec![]),
            ("empty", Some(vec![]), vec![]),
            (
                "cut to ENGINE_MAX - 1",
                Some(long.clone()),
                long[..ENGINE_MAX - 1].to_vec(),
            ),
        ];
        for (name, endpoint, want) in cases {
            let c = endpoint.map(|e| std::ffi::CString::new(e).unwrap());
            // SAFETY: a live C string or null.
            unsafe { fz_set_engine(c.as_ref().map_or(ptr::null(), |c| c.as_ptr())) };
            let got = engine_endpoint();
            assert_eq!(&got[..sys::nul_at(&got)], &want[..], "{name}");
        }
        // SAFETY: null names no engine.
        unsafe { fz_set_engine(ptr::null()) };
    }

    #[test]
    fn report_line_sends_one_whole_line() {
        let _serial = crate::serial();
        let [ours, theirs] = pair();
        let max = vec![b'x'; REPORT_MAX - 1];
        let mut max_sent = max.clone();
        max_sent.push(b'\n');
        let cases: Vec<(&str, c_int, Option<Vec<u8>>, c_int, c_int, Vec<u8>)> = vec![
            (
                "no channel",
                -1,
                Some(b"DEVICE f 1 0".to_vec()),
                -1,
                libc::EBADF,
                vec![],
            ),
            (
                "a line",
                ours,
                Some(b"DEVICE f 1 0".to_vec()),
                0,
                0,
                b"DEVICE f 1 0\n".to_vec(),
            ),
            ("empty", ours, Some(vec![]), 0, 0, b"\n".to_vec()),
            (
                "REPORT_MAX - 1 characters fit",
                ours,
                Some(max.clone()),
                0,
                0,
                max_sent,
            ),
            (
                "REPORT_MAX characters do not",
                ours,
                Some(vec![b'x'; REPORT_MAX]),
                -1,
                libc::EMSGSIZE,
                vec![],
            ),
            (
                "far longer",
                ours,
                Some(vec![b'x'; 3 * REPORT_MAX]),
                -1,
                libc::EMSGSIZE,
                vec![],
            ),
            (
                "a newline",
                ours,
                Some(b"DEVICE f\nEVICT g".to_vec()),
                -1,
                libc::EINVAL,
                vec![],
            ),
            (
                "a trailing newline",
                ours,
                Some(b"DEVICE f 1 0\n".to_vec()),
                -1,
                libc::EINVAL,
                vec![],
            ),
            ("null", ours, None, -1, libc::EINVAL, vec![]),
            (
                "too long beats no channel",
                -1,
                Some(vec![b'x'; REPORT_MAX]),
                -1,
                libc::EMSGSIZE,
                vec![],
            ),
        ];
        for (name, fd, line, want, want_errno, want_sent) in cases {
            set_ctl_fd(fd);
            let c = line.map(|l| std::ffi::CString::new(l).unwrap());
            sys::set_errno(0);
            // SAFETY: a live C string or null.
            let rc = unsafe { fz_report_line(c.as_ref().map_or(ptr::null(), |c| c.as_ptr())) };
            assert_eq!(rc, want, "{name}");
            if want < 0 {
                assert_eq!(sys::errno(), want_errno, "{name}: errno");
            }
            assert_eq!(drain(theirs), want_sent, "{name}: sent");
        }
        // The channel and the handler are statics, so the child's reset
        // is checked here, in the one test that sets them.
        unsafe extern "C" fn on_control(_line: *const c_char) {}
        fz_set_control(Some(on_control));
        assert!(handler().is_some(), "a handler is kept");
        fz_set_control(None);
        assert!(handler().is_none(), "and forgotten");
        set_ctl_fd(ours);
        // SAFETY: the child's reset, which here only clears the statics.
        unsafe { reset_for_child() };
        assert_eq!(ctl_fd(), -1, "the reset forgets the channel");
        // SAFETY: a live C string.
        let rc = unsafe { fz_report_line(c"DEVICE f 1 0".as_ptr()) };
        assert_eq!(
            (rc, sys::errno()),
            (-1, libc::EBADF),
            "a fiber cannot report"
        );
        assert!(drain(theirs).is_empty(), "nothing reached fiberd");
        // SAFETY: the pair is the test's own.
        unsafe {
            libc::close(ours);
            libc::close(theirs);
        }
    }
}
