//! The record parser alone, on any input. It is also what a gVisor
//! sandbox runs on what the pool socket hands it. A refusal names a known
//! reason and leaves inc untouched. An accepted record starts with 'i',
//! its fields lie back to back in buf with the seed last, and no
//! identity field is "-".
#![no_main]

#[path = "common.rs"]
mod common;
#[path = "hooks.rs"]
mod hooks;

use common::{REASONS, cstr, store_with};
use fiberzygote_core::abi::{ENV_VALUE_MAX, FENCE_MAX, Incarnation, RECORD_MAX, SEED_LEN};
use fiberzygote_core::record::fz_rs_parse_incarnation;
use libfuzzer_sys::fuzz_target;
use std::ffi::c_char;
use std::mem::size_of;
use std::ptr;

fuzz_target!(|data: &[u8]| {
    let (mut st, n) = store_with(data);
    let mut why: *const c_char = ptr::null();
    // SAFETY: the store is ours and why is a local.
    let rc = unsafe { fz_rs_parse_incarnation(&mut *st, n, &mut why) };
    if rc != 0 {
        assert_eq!(rc, -1);
        // SAFETY: a refusal points why at a static string.
        let reason = unsafe { cstr(why) };
        assert!(
            REASONS.iter().any(|r| r.as_bytes() == reason),
            "unknown reason {:?}",
            String::from_utf8_lossy(reason)
        );
        // SAFETY: inc is plain data within the store.
        let inc = unsafe {
            std::slice::from_raw_parts(ptr::addr_of!(st.inc).cast::<u8>(), size_of::<Incarnation>())
        };
        assert!(inc.iter().all(|&b| b == 0), "inc touched on a refusal");
        return;
    }
    assert!(why.is_null(), "why set on an accepted record");
    assert_eq!(st.buf[0], b'i', "an accepted record not starting with 'i'");
    let buf = st.buf.as_ptr() as usize;
    let inc = &st.inc;
    // SAFETY: every pointer below was set by the parser into this store,
    // which parse checked ends in a NUL.
    let generation = unsafe { cstr(st.buf.as_ptr().add(1).cast()) };
    assert_ne!(inc.generation, 0);
    assert_eq!(generation, inc.generation.to_string().as_bytes());
    let kind = unsafe { cstr(inc.kind) };
    assert_eq!(inc.kind as usize, buf + 1 + generation.len() + 1);
    assert!(!kind.is_empty());
    let fence = unsafe { cstr(inc.fence) };
    assert_eq!(inc.fence as usize, inc.kind as usize + kind.len() + 1);
    assert!(!fence.is_empty() && fence.len() < FENCE_MAX);
    let endpoint = unsafe { cstr(inc.endpoint) };
    assert_eq!(inc.endpoint as usize, inc.fence as usize + fence.len() + 1);
    assert!(!endpoint.is_empty() && endpoint.len() < ENV_VALUE_MAX);
    assert_eq!(inc.payload, st.payload.as_ptr());
    assert!(inc.payload_len <= RECORD_MAX / 2);
    assert_eq!(inc.session, st.session.as_ptr().cast());
    let session = unsafe { cstr(inc.session) };
    assert!(session.len() < ENV_VALUE_MAX);
    assert_eq!(inc.seed, st.seed.as_ptr());
    assert_eq!(inc.seed_len, SEED_LEN);
    let hex = st.seed_hex as usize;
    assert!(hex >= buf && hex < buf + n, "seed_hex outside the record");
    let seed_hex = unsafe { cstr(st.seed_hex) };
    assert_eq!(seed_hex.len(), 2 * SEED_LEN);
    assert_eq!(
        hex + seed_hex.len() + 1,
        buf + n,
        "the seed is the last field"
    );
    if inc.identity.is_null() {
        return;
    }
    assert_eq!(inc.identity, ptr::addr_of!(st.identity));
    let id = &st.identity;
    let key = unsafe { cstr(id.key_pem) };
    let cert = unsafe { cstr(id.cert_pem) };
    let caller = unsafe { cstr(id.caller) };
    let caller_pem = unsafe { cstr(id.caller_pem) };
    assert!(!key.is_empty() && !cert.is_empty() && !caller.is_empty() && !caller_pem.is_empty());
    for f in [key, cert, caller, caller_pem] {
        assert_ne!(f, b"-", "an identity field of -");
    }
    assert_eq!(id.cert_pem as usize, id.key_pem as usize + key.len() + 1);
    assert_eq!(id.caller as usize, id.cert_pem as usize + cert.len() + 1);
    assert_eq!(
        id.caller_pem as usize,
        id.caller as usize + caller.len() + 1
    );
});
