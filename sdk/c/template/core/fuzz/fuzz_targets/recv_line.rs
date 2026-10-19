//! recv_line (core/src/ctl.rs) fed a stream cut into chunks, with
//! descriptors riding on some. The kernel returns a chunk that carries
//! descriptors on its own, so this exercises the reader's buffering.
//!
//! The input is [cap selector][chunk count and descriptor mask][stream
//! bytes]. No input may leave a descriptor open.
#![no_main]

#[path = "hooks.rs"]
mod hooks;
#[path = "sock.rs"]
mod sock;

use fiberzygote_core::abi::{MAX_LINE, MAX_PASSED};
use fiberzygote_core::ctl::recv_line;
use libfuzzer_sys::fuzz_target;

const CAPS: [usize; 6] = [2, 16, 64, 256, 4096, MAX_LINE];

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let cap = CAPS[usize::from(data[0]) % CAPS.len()];
    let chunks = 1 + usize::from(data[1] & 7);
    let mask = data[1] >> 3;
    let data = &data[2..];
    let before = sock::open_fds();

    let s = sock::pair(libc::SOCK_STREAM);
    let each = data.len() / chunks;
    let mut off = 0;
    for i in 0..chunks {
        if off >= data.len() {
            break;
        }
        let n = if i + 1 == chunks {
            data.len() - off
        } else {
            each
        };
        if n == 0 {
            continue;
        }
        // Chunk i carries one to three descriptors when its mask bit is
        // set, so the reader also sees more than MAX_PASSED at once.
        let nfds = if (mask >> i) & 1 != 0 { 1 + i % 3 } else { 0 };
        sock::send_scratch_fds(s[1], &data[off..off + n], nfds);
        off += n;
    }
    // SAFETY: an integer call on our own socket.
    assert_eq!(unsafe { libc::shutdown(s[1], libc::SHUT_WR) }, 0);

    // Stale bytes, never NULs, so a line recv_line forgot to end shows.
    let mut buf = vec![0xaau8; MAX_LINE];
    loop {
        let mut fds = [-7; MAX_PASSED];
        let n = recv_line(s[0], &mut buf[..cap], &mut fds);
        for fd in fds {
            assert!(fd >= -1, "a slot neither a descriptor nor -1");
            // SAFETY: an integer call on a descriptor recv_line gave us.
            assert!(
                fd < 0 || unsafe { libc::close(fd) } == 0,
                "a dead descriptor"
            );
        }
        if n <= 0 {
            break;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        assert!(n as usize <= cap, "a count past the buffer");
        assert!(len < cap, "a line not NUL-ended inside the buffer");
        assert!(len <= n as usize, "a line longer than its count");
        // Back to stale bytes for the next line, over all it wrote.
        let end = (n as usize).max(len + 1).min(buf.len());
        buf[..end].fill(0xaa);
    }
    sock::close(s[0]);
    sock::close(s[1]);
    assert_eq!(sock::open_fds(), before, "a descriptor leaked");
});
