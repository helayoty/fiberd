//! The Rust record parser against the C one of main (csrc/record.c), on
//! every input: the same verdict, the same reason, the same bytes in the
//! store and the same pointers as offsets. The two small entries get the
//! input as a C string too.
#![no_main]

#[path = "common.rs"]
mod common;

use common::{cstr, shape, store_with};
use fiberzygote_core::abi::RecordStore;
use fiberzygote_core::record::{fz_rs_parse_generation, fz_rs_parse_incarnation, fz_rs_unhex};
use libfuzzer_sys::fuzz_target;
use std::ffi::{c_char, c_int, c_uint};
use std::ptr;

unsafe extern "C" {
    fn fz_c_parse_incarnation(st: *mut RecordStore, n: usize, why: *mut *const c_char) -> c_int;
    fn fz_c_parse_generation(s: *const c_char) -> c_uint;
    fn fz_c_unhex(s: *const c_char, out: *mut u8, cap: usize) -> usize;
}

fuzz_target!(|data: &[u8]| {
    let (mut c, n) = store_with(data);
    let (mut r, _) = store_with(data);
    let mut c_why: *const c_char = ptr::null();
    let mut r_why: *const c_char = ptr::null();
    // SAFETY: each store is ours and each why a local.
    let c_rc = unsafe { fz_c_parse_incarnation(&mut *c, n, &mut c_why) };
    let r_rc = unsafe { fz_rs_parse_incarnation(&mut *r, n, &mut r_why) };
    assert_eq!(c_rc, r_rc, "verdict");
    assert_eq!(
        c_why.is_null(),
        r_why.is_null(),
        "a reason on one side only"
    );
    if !c_why.is_null() {
        // SAFETY: both point at static strings.
        let (cw, rw) = unsafe { (cstr(c_why), cstr(r_why)) };
        assert_eq!(
            String::from_utf8_lossy(cw),
            String::from_utf8_lossy(rw),
            "reason"
        );
    }
    assert_eq!(shape(&c), shape(&r), "the store's pointers and numbers");
    assert!(c.session[..] == r.session[..], "session");
    assert_eq!(c.seed, r.seed, "seed");
    if c_rc == 0 {
        let len = c.inc.payload_len;
        assert!(c.payload[..len] == r.payload[..len], "payload");
    }

    // parse_generation and unhex on the input as a C string.
    let mut s = data.to_vec();
    s.push(0);
    // SAFETY: s is NUL-ended and outlives the calls.
    let (cg, rg) = unsafe {
        (
            fz_c_parse_generation(s.as_ptr().cast()),
            fz_rs_parse_generation(s.as_ptr().cast()),
        )
    };
    assert_eq!(cg, rg, "generation");
    for cap in [0, 1, 7, data.len() / 2 + 1] {
        let mut a = vec![0xeeu8; cap];
        let mut b = vec![0xeeu8; cap];
        // SAFETY: each buffer has cap bytes.
        let (x, y) = unsafe {
            (
                fz_c_unhex(s.as_ptr().cast(), a.as_mut_ptr(), cap),
                fz_rs_unhex(s.as_ptr().cast(), b.as_mut_ptr(), cap),
            )
        };
        assert_eq!(x, y, "unhex count at cap {cap}");
        assert_eq!(a, b, "unhex bytes at cap {cap}");
    }
});
