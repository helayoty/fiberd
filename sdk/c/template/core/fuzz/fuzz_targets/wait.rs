//! fz_incarnation_wait, fz_fiber_ready and fz_accept (core/src/fiber.rs)
//! over a real pair, as a fiber in a park's wait reads its channel. The
//! fuzzshim feature hands out the core's statics, so the target sets the
//! state up and checks it.
//!
//! The input is [served generation][packet count][packet lengths...]
//! [bytes]. Each packet carries a descriptor when its first byte is
//! even, and the rest goes as one last packet. Then fiberd's end is
//! shut, so every wait ends. Ten waits, then up to ten accepts.
#![no_main]

#[path = "hooks.rs"]
mod hooks;
#[path = "sock.rs"]
mod sock;

use fiberzygote_core::abi::{FENCE_MAX, Incarnation, SEED_LEN};
use fiberzygote_core::fiber::fuzz::{fz_rs_fuzz_born, fz_rs_fuzz_polled, fz_rs_fuzz_state};
use fiberzygote_core::fiber::{fz_accept, fz_fiber_ready, fz_incarnation_wait, fz_seed_forget};
use libfuzzer_sys::fuzz_target;
use std::ffi::{CStr, c_char};
use std::ptr;

/// The bytes of a NUL-ended string.
///
/// # Safety
/// p is a live NUL-ended string.
unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    assert!(!p.is_null(), "a null string");
    // SAFETY: by the contract above.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// Every message the fiber sent fiberd, without waiting.
fn answers(fd: i32) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    loop {
        let mut buf = [0u8; FENCE_MAX + 16];
        // SAFETY: buf is live for the call.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n <= 0 {
            return got;
        }
        got.push(buf[..n as usize].to_vec());
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (fst, polled, born) = (fz_rs_fuzz_state(), fz_rs_fuzz_polled(), fz_rs_fuzz_born());
    let npk = usize::from(data[1] % 8);
    let served0 = u32::from(data[0]);
    let rest = &data[2..];
    if rest.len() < npk {
        return;
    }
    let (lens, mut bytes) = rest.split_at(npk);
    let before = sock::open_fds();

    let s = sock::pair(libc::SOCK_SEQPACKET);
    // SAFETY: the statics are the core's, which only the entries below
    // touch in this process, and never while a reference made here
    // lives. All zero bits are a RecordStore.
    unsafe {
        let st = &mut *fst;
        st.served_generation = served0;
        st.park_round = served0;
        st.park_over = false;
        st.channel_fd = s[0];
        st.ack_pending = false;
        st.ready_fd = -1;
        ptr::write_bytes(polled, 0, 1);
    }
    for &l in lens {
        if bytes.is_empty() {
            break;
        }
        let n = (usize::from(l) + 1).min(bytes.len());
        sock::send_scratch_fds(s[1], &bytes[..n], usize::from(bytes[0] % 2 == 0));
        bytes = &bytes[n..];
    }
    if !bytes.is_empty() {
        sock::send_scratch_fds(s[1], bytes, 0);
    }
    // fiberd's end sends nothing more, so every wait ends with EOF once
    // the queue is taken, while the fiber's answers still land there.
    // SAFETY: an integer call on our own socket.
    unsafe { libc::shutdown(s[1], libc::SHUT_WR) };

    let mut served = served0;
    for _ in 0..10 {
        // SAFETY: all zero bits are an Incarnation.
        let mut inc: Incarnation = unsafe { std::mem::zeroed() };
        sock::set_errno(0);
        // SAFETY: inc is ours and writable.
        let rc = unsafe { fz_incarnation_wait(&mut inc) };
        let e = sock::errno();
        // SAFETY: as above, read between the calls alone.
        let (st, pl) = unsafe { (&mut *fst, &*polled) };
        if rc > 0 {
            assert!(rc == 1, "wait gave {rc}");
            assert!(
                inc.generation > served,
                "a record at or below the served generation"
            );
            assert_eq!(
                st.served_generation, inc.generation,
                "served_generation not moved"
            );
            // SAFETY: the record's fields are NUL-ended in polled.
            let (kind, fence, endpoint) =
                unsafe { (cstr(inc.kind), cstr(inc.fence), cstr(inc.endpoint)) };
            // SAFETY: as above.
            assert_eq!(kind, unsafe { cstr(pl.inc.kind) }, "kind not the store's");
            assert_eq!(inc.seed, pl.seed.as_ptr(), "the seed elsewhere");
            assert_eq!(inc.seed_len, SEED_LEN, "a seed of {} bytes", inc.seed_len);
            assert!(
                !fence.is_empty() && fence.len() < FENCE_MAX,
                "a fence of {} bytes",
                fence.len()
            );
            assert!(!endpoint.is_empty(), "an empty endpoint");
            assert!(st.ack_pending, "no ack pending");
            served = inc.generation;
            let fence = fence.to_vec();
            fz_fiber_ready();
            // The wait may have answered a 'p' with a 'q' first. The ack
            // comes last.
            let got = answers(s[1]);
            let (ack, qs) = got.split_last().expect("no ack");
            let mut want = vec![b'a'];
            want.extend_from_slice(&fence);
            want.push(0);
            assert_eq!(*ack, want, "the ack does not name the fence");
            assert!(
                qs.iter().all(|q| q.first() == Some(&b'q')),
                "something else before the ack"
            );
            // SAFETY: as above.
            let (st, pl) = unsafe { (&*fst, &*polled) };
            assert!(!st.ack_pending, "ack still pending");
            assert_eq!(pl.inc.seed_len, 0, "seed_len left after the ack");
            assert!(
                st.ack_fence.iter().all(|&b| b == 0),
                "the fence left after the ack"
            );
        } else if rc < 0 {
            assert!(rc == -1, "wait gave {rc}");
            assert!(e == libc::EPROTO || e == libc::ECONNRESET, "errno {e}");
        } else {
            // A carry-on honoured is a round over.
            assert!(!st.park_over, "park_over left set");
        }
        // SAFETY: as above.
        let (st, pl) = unsafe { (&*fst, &*polled) };
        if rc <= 0 {
            // No seed stays behind after a refusal or a carry-on.
            assert!(pl.seed.iter().all(|&b| b == 0), "seed bytes left");
            assert_eq!(pl.inc.seed_len, 0, "seed_len left");
            assert!(!st.ack_pending, "an ack pending with nothing handed over");
        }
        answers(s[1]);
    }
    for _ in 0..10 {
        let fd = fz_accept();
        let e = sock::errno();
        if fd < 0 {
            if e == libc::EINTR {
                continue; // a park's round, for the loop's flag
            }
            assert!(e == libc::ECONNRESET || e == libc::EPROTO, "errno {e}");
            break;
        }
        sock::close(fd);
    }
    fz_seed_forget();
    // SAFETY: as above.
    unsafe {
        assert!((*polled).seed.iter().all(|&b| b == 0), "polled seed left");
        assert!((*born).seed.iter().all(|&b| b == 0), "born seed left");
        (*fst).channel_fd = -1;
    }
    sock::close(s[0]);
    sock::close(s[1]);
    assert_eq!(sock::open_fds(), before, "a descriptor leaked");
});
