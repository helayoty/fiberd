//! Shared by the record targets: a store to parse into and the view of
//! one that compares across stores.
#![allow(dead_code)]

use fiberzygote_core::abi::{RECORD_MAX, RecordStore};
use std::ffi::{CStr, c_char};
use std::mem::size_of;

/// Every reason the parser can give, as libfiberzygote.c gave them.
pub const REASONS: &[&str] = &[
    "not an incarnation record",
    "record has too few fields",
    "record has an empty field",
    "record has too many fields",
    "record names no generation",
    "record fence too long",
    "record endpoint too long",
    "record session too long",
    "record session holds a NUL",
    "record identity is incomplete",
    "record seed is not 32 bytes",
];

/// A zeroed store with the input in buf, and the byte count the parser
/// is told, at most a record.
pub fn store_with(data: &[u8]) -> (Box<RecordStore>, usize) {
    let n = data.len().min(RECORD_MAX);
    // SAFETY: every field of a record_store is plain data, so all-zero
    // is a valid value, as the core's bss stores start out (fiber.rs).
    let mut st = unsafe { Box::<RecordStore>::new_zeroed().assume_init() };
    st.buf[..n].copy_from_slice(&data[..n]);
    (st, n)
}

/// The bytes of a NUL-ended string.
///
/// # Safety
/// p is null or a live NUL-ended string.
pub unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    assert!(!p.is_null(), "a null string");
    // SAFETY: by the contract above.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// A pointer as its offset into st, None for null. A pointer outside st
/// is a bug on either side.
pub fn rel<T>(p: *const T, st: &RecordStore) -> Option<usize> {
    if p.is_null() {
        return None;
    }
    let base = st as *const RecordStore as usize;
    let off = (p as usize)
        .checked_sub(base)
        .expect("a pointer below the store");
    assert!(off < size_of::<RecordStore>(), "a pointer past the store");
    Some(off)
}

/// What a parse left in a store, with every pointer as an offset, so two
/// stores at different addresses compare.
#[derive(Debug, PartialEq, Eq)]
pub struct Shape {
    pub seed_hex: Option<usize>,
    pub identity: [Option<usize>; 4],
    pub fence: Option<usize>,
    pub endpoint: Option<usize>,
    pub payload: Option<usize>,
    pub payload_len: usize,
    pub session: Option<usize>,
    pub generation: u32,
    pub kind: Option<usize>,
    pub seed: Option<usize>,
    pub seed_len: usize,
    pub inc_identity: Option<usize>,
}

pub fn shape(st: &RecordStore) -> Shape {
    let id = &st.identity;
    let inc = &st.inc;
    Shape {
        seed_hex: rel(st.seed_hex, st),
        identity: [
            rel(id.key_pem, st),
            rel(id.cert_pem, st),
            rel(id.caller, st),
            rel(id.caller_pem, st),
        ],
        fence: rel(inc.fence, st),
        endpoint: rel(inc.endpoint, st),
        payload: rel(inc.payload, st),
        payload_len: inc.payload_len,
        session: rel(inc.session, st),
        generation: inc.generation,
        kind: rel(inc.kind, st),
        seed: rel(inc.seed, st),
        seed_len: inc.seed_len,
        inc_identity: rel(inc.identity, st),
    }
}
