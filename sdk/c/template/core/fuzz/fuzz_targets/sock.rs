//! Shared by the targets that hand the core a descriptor: a memfd for a
//! file, a socket pair for a peer, messages with descriptors riding
//! along, and the leak check.
#![allow(dead_code)]

use std::ffi::c_int;
use std::mem::size_of;
use std::ptr;

/// A memfd holding data, positioned at its start. A target cannot run
/// without one, so a refusal panics.
pub fn memfd_of(data: &[u8]) -> c_int {
    // SAFETY: a static NUL-ended name.
    let fd = unsafe { libc::memfd_create(c"fuzz".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create");
    let mut off = 0;
    while off < data.len() {
        // SAFETY: write reads the rest of data, which is live.
        let w = unsafe { libc::write(fd, data[off..].as_ptr().cast(), data.len() - off) };
        if w < 0 && errno() == libc::EINTR {
            continue;
        }
        assert!(w > 0, "write to a memfd");
        off += w as usize;
    }
    // SAFETY: an integer call.
    assert!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == 0, "lseek");
    fd
}

/// The thread's errno.
pub fn errno() -> c_int {
    // SAFETY: errno is the thread's own.
    unsafe { *libc::__errno_location() }
}

/// Sets the thread's errno.
pub fn set_errno(e: c_int) {
    // SAFETY: errno is the thread's own.
    unsafe { *libc::__errno_location() = e };
}

/// A connected AF_UNIX pair of the given type.
pub fn pair(ty: c_int) -> [c_int; 2] {
    let mut s = [-1; 2];
    // SAFETY: s is live for the call.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0, s.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair");
    s
}

/// Closes fd, whose answer nobody looks at.
pub fn close(fd: c_int) {
    // SAFETY: an integer call on a descriptor the caller owns.
    unsafe { libc::close(fd) };
}

/// sendmsg of data as one message, with fds in SCM_RIGHTS and extra
/// flags. What sendmsg returns.
pub fn send_fds_flags(sock: c_int, data: &[u8], fds: &[c_int], flags: c_int) -> isize {
    assert!(fds.len() <= 8, "at most eight descriptors");
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut cbuf = [0u64; 8];
    // SAFETY: all zero bits are a msghdr.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_iov = &raw mut iov;
    mh.msg_iovlen = 1;
    if !fds.is_empty() {
        let bytes = (fds.len() * size_of::<c_int>()) as u32;
        mh.msg_control = cbuf.as_mut_ptr().cast();
        // SAFETY: CMSG_SPACE is arithmetic on its argument.
        mh.msg_controllen = unsafe { libc::CMSG_SPACE(bytes) } as usize;
        // SAFETY: mh describes cbuf, which has room for eight descriptors.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&raw const mh);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(bytes) as usize;
            ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(c),
                bytes as usize,
            );
        }
    }
    loop {
        // SAFETY: mh, iov and cbuf are live for the call.
        let r = unsafe { libc::sendmsg(sock, &raw const mh, libc::MSG_NOSIGNAL | flags) };
        if r < 0 && errno() == libc::EINTR {
            continue;
        }
        return r;
    }
}

/// send_fds_flags blocking, and all of data must go.
pub fn send_fds(sock: c_int, data: &[u8], fds: &[c_int]) {
    let r = send_fds_flags(sock, data, fds, 0);
    assert_eq!(r, data.len() as isize, "sendmsg");
}

/// send_fds with n throwaway memfds riding along, closed once in flight.
pub fn send_scratch_fds(sock: c_int, data: &[u8], n: usize) {
    let fds: Vec<c_int> = (0..n).map(|_| memfd_of(&[])).collect();
    send_fds(sock, data, &fds);
    fds.into_iter().for_each(close);
}

/// Which of the first 256 descriptors are open, compared before and
/// after an input to catch a leak.
pub fn open_fds() -> [u64; 4] {
    let mut set = [0u64; 4];
    for fd in 0..256 {
        // SAFETY: an integer call, a query.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            set[fd as usize / 64] |= 1 << (fd % 64);
        }
    }
    set
}
