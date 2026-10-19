//! read_incarnation (core/src/child.rs) over one message on a fiber's
//! channel, as fiberd queues the record before the CLONE, with
//! descriptors it must not keep. fz_seed_forget then wipes the seed.
//!
//! The input is [descriptor count][message bytes]. An empty message is a
//! closed channel. A refusal gives a reason, and no descriptor stays
//! open.
#![no_main]

#[path = "hooks.rs"]
mod hooks;
#[path = "sock.rs"]
mod sock;

use fiberzygote_core::abi::{FENCE_MAX, Identity, Incarnation, SEED_LEN};
use fiberzygote_core::child::read_incarnation;
use fiberzygote_core::fiber::{born, fz_seed_forget};
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

/// Where the next field starts.
///
/// # Safety
/// As cstr.
unsafe fn after(p: *const c_char) -> usize {
    // SAFETY: by the contract above.
    p as usize + unsafe { cstr(p) }.len() + 1
}

fuzz_target!(|data: &[u8]| {
    let Some((&head, msg)) = data.split_first() else {
        return;
    };
    let nfds = usize::from(head % 4);
    let before = sock::open_fds();

    let s = sock::pair(libc::SOCK_SEQPACKET);
    if !msg.is_empty() {
        sock::send_scratch_fds(s[1], msg, nfds);
    }
    sock::close(s[1]);

    let st = born();
    // SAFETY: the store is the core's static, which nothing else touches
    // in this process, and all zero bits are an Incarnation and an
    // Identity.
    unsafe {
        ptr::write_bytes(ptr::addr_of_mut!((*st).inc), 0, 1);
        ptr::write_bytes(ptr::addr_of_mut!((*st).identity), 0, 1);
        (*st).seed_hex = ptr::null_mut();
    }
    let mut why: *const c_char = ptr::null();
    // SAFETY: as above, and s[0] is ours.
    let rc = unsafe { read_incarnation(s[0], st, &mut why) };
    if rc != 0 {
        assert!(!why.is_null(), "a refusal without a reason");
    } else {
        // SAFETY: the parser set every pointer below into the store, and
        // each field ends in a NUL there.
        unsafe {
            let b = &*st;
            let inc: &Incarnation = &b.inc;
            let buf = b.buf.as_ptr() as usize;
            let first = b.buf.as_ptr().add(1).cast::<c_char>();
            assert!(inc.generation != 0, "generation 0");
            assert_eq!(
                cstr(first),
                inc.generation.to_string().as_bytes(),
                "the generation read back"
            );
            assert_eq!(inc.kind as usize, after(first), "kind out of place");
            assert!(!cstr(inc.kind).is_empty(), "an empty kind");
            assert_eq!(inc.fence as usize, after(inc.kind), "fence out of place");
            assert_eq!(
                inc.endpoint as usize,
                after(inc.fence),
                "endpoint out of place"
            );
            let fence = cstr(inc.fence);
            assert!(
                !fence.is_empty() && fence.len() < FENCE_MAX,
                "a fence of {} bytes",
                fence.len()
            );
            assert!(!cstr(inc.endpoint).is_empty(), "an empty endpoint");
            assert_eq!(inc.payload, b.payload.as_ptr(), "the payload elsewhere");
            assert!(
                inc.payload_len <= b.payload.len(),
                "a payload past its buffer"
            );
            assert_eq!(
                inc.session,
                b.session.as_ptr().cast(),
                "the session elsewhere"
            );
            assert!(
                cstr(inc.session).len() < b.session.len(),
                "a session past its buffer"
            );
            assert_eq!(inc.seed, b.seed.as_ptr(), "the seed elsewhere");
            assert_eq!(inc.seed_len, SEED_LEN, "a seed of {} bytes", inc.seed_len);
            let hex = b.seed_hex as usize;
            assert!(
                hex >= buf && hex < buf + msg.len(),
                "seed_hex outside the record"
            );
            assert_eq!(
                cstr(b.seed_hex).len(),
                2 * SEED_LEN,
                "a seed field of the wrong length"
            );
            assert_eq!(
                after(b.seed_hex),
                buf + msg.len(),
                "the seed is not the last field"
            );
            if !inc.identity.is_null() {
                let id: &Identity = &*inc.identity;
                assert_eq!(
                    inc.identity, &raw const b.identity,
                    "the identity elsewhere"
                );
                for f in [id.key_pem, id.cert_pem, id.caller, id.caller_pem] {
                    assert!(!cstr(f).is_empty(), "an empty identity field");
                }
                assert_eq!(id.cert_pem as usize, after(id.key_pem), "cert out of place");
                assert_eq!(
                    id.caller as usize,
                    after(id.cert_pem),
                    "caller out of place"
                );
                assert_eq!(
                    id.caller_pem as usize,
                    after(id.caller),
                    "caller_pem out of place"
                );
                assert_ne!(cstr(id.key_pem), b"-", "a key of -");
            }
        }
        fz_seed_forget();
        // SAFETY: as above.
        unsafe {
            let b = &*st;
            assert!(b.seed.iter().all(|&x| x == 0), "seed bytes left");
            let hex = std::slice::from_raw_parts(b.seed_hex.cast::<u8>(), 2 * SEED_LEN);
            assert!(hex.iter().all(|&x| x == 0), "seed hex left in the record");
            assert_eq!(b.inc.seed_len, 0, "seed_len left");
        }
    }
    sock::close(s[0]);
    assert_eq!(sock::open_fds(), before, "a descriptor leaked");
});
