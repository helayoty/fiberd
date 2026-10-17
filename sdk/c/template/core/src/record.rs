//! The incarnation record parser: 'i' then eleven NUL-ended fields, as
//! fiberd's first message on a fiber's channel delivers it, as a gVisor
//! sandbox reads it off the pool socket and as a resume sends it again
//! (libfiberzygote.h). A forked fiber runs it right after its clone, so
//! nothing here allocates, locks or panics. Every index goes through get
//! and every sum is checked.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;

use crate::abi::{
    ENV_VALUE_MAX, FENCE_MAX, Identity, Incarnation, RECORD_FIELDS, RECORD_MAX, RecordStore,
    SEED_LEN,
};
use crate::sys;

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Decodes hex pairs from s into out until a bad digit, an odd tail or
/// out is full, and returns the bytes written.
pub fn unhex(s: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0usize;
    for pair in s.as_chunks::<2>().0 {
        let Some(slot) = out.get_mut(n) else { break };
        let (Some(hi), Some(lo)) = (hexval(pair[0]), hexval(pair[1])) else {
            break;
        };
        *slot = hi << 4 | lo;
        n = n.wrapping_add(1);
    }
    n
}

/// Reads a generation as the record carries it: decimal digits only, 1
/// or more, no leading zero, within unsigned. 0 when it is not one.
pub fn parse_generation(s: &[u8]) -> u32 {
    if s.first().is_none_or(|&c| c == b'0') {
        return 0;
    }
    let mut v = 0u32;
    for &c in s {
        if !c.is_ascii_digit() {
            return 0;
        }
        let Some(next) = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(c.wrapping_sub(b'0'))))
        else {
            return 0;
        };
        v = next;
    }
    v
}

/// One field of the record: where it starts in the record and its
/// length, the NUL not counted.
#[derive(Clone, Copy, Default)]
struct Field {
    off: usize,
    len: usize,
}

/// What a parse yields: the fields as offsets, since the caller turns
/// them into pointers into its own buffer.
pub struct Parsed {
    fields: [Field; RECORD_FIELDS],
    /// The generation, 1 or more.
    pub generation: u32,
    /// The decoded payload's length.
    pub payload_len: usize,
    /// Whether the record carries a handoff identity.
    pub identity: bool,
}

impl Parsed {
    /// The i-th field's bytes of rec, the record it was parsed from.
    pub fn field<'a>(&self, rec: &'a [u8], i: usize) -> &'a [u8] {
        let f = self.fields.get(i).copied().unwrap_or_default();
        f.off
            .checked_add(f.len)
            .and_then(|end| rec.get(f.off..end))
            .unwrap_or(&[])
    }

    /// The i-th field's offset in the record.
    pub fn offset(&self, i: usize) -> usize {
        self.fields.get(i).map_or(0, |f| f.off)
    }
}

/// Takes rec apart, decoding the session, seed and payload into the
/// buffers given, which are a record_store's. Err carries the reason the
/// C file gave, as a C string the caller may keep.
pub fn parse(
    rec: &[u8],
    session: &mut [u8; ENV_VALUE_MAX],
    seed: &mut [u8; SEED_LEN],
    payload: &mut [u8; RECORD_MAX / 2],
) -> Result<Parsed, &'static CStr> {
    if rec.len() < 2 || rec.first() != Some(&b'i') || rec.last() != Some(&0) {
        return Err(c"not an incarnation record");
    }
    let mut fields = [Field::default(); RECORD_FIELDS];
    let mut p = 1usize;
    for f in &mut fields {
        let rest = rec.get(p..).unwrap_or(&[]);
        if rest.is_empty() {
            return Err(c"record has too few fields");
        }
        // rec ends in a NUL, so every field ends.
        let len = sys::nul_at(rest);
        if len == 0 {
            return Err(c"record has an empty field");
        }
        *f = Field { off: p, len };
        let Some(next) = p.checked_add(len).and_then(|p| p.checked_add(1)) else {
            return Err(c"record has too many fields");
        };
        p = next;
    }
    if p != rec.len() {
        return Err(c"record has too many fields");
    }
    let parsed = Parsed {
        fields,
        generation: 0,
        payload_len: 0,
        identity: false,
    };
    let field = |i: usize| parsed.field(rec, i);
    let generation = parse_generation(field(0));
    if generation == 0 {
        return Err(c"record names no generation");
    }
    if field(2).len() >= FENCE_MAX {
        return Err(c"record fence too long");
    }
    if field(3).len() >= ENV_VALUE_MAX {
        return Err(c"record endpoint too long");
    }
    // The session is bounded and NUL-free as on the CLONE line, since it
    // becomes an environment value.
    let mut slen = 0usize;
    if field(5) != b"-" {
        if field(5).len() / 2 >= ENV_VALUE_MAX {
            return Err(c"record session too long");
        }
        slen = unhex(
            field(5),
            session
                .get_mut(..ENV_VALUE_MAX.wrapping_sub(1))
                .unwrap_or(&mut []),
        );
        if session
            .get(..slen)
            .is_some_and(|s| sys::nul_at(s) < s.len())
        {
            return Err(c"record session holds a NUL");
        }
    }
    // A handoff identity is all four fields or none.
    let set = (6..10).filter(|&i| field(i) != b"-").count();
    if set != 0 && set != 4 {
        return Err(c"record identity is incomplete");
    }
    if field(10).len() != 2 * SEED_LEN || unhex(field(10), seed) != SEED_LEN {
        seed.fill(0);
        return Err(c"record seed is not 32 bytes");
    }
    let mut payload_len = 0usize;
    if field(4) != b"-" {
        payload_len = unhex(field(4), payload);
    }
    if let Some(end) = session.get_mut(slen) {
        *end = 0;
    }
    Ok(Parsed {
        generation,
        payload_len,
        identity: set == 4,
        ..parsed
    })
}

/// parse_incarnation in C: takes the record in st->buf, n bytes, apart
/// into the store and fills st->inc from it. Returns 0, or -1 with *why
/// set, and st->inc is then untouched.
///
/// # Safety
/// st points at a live record_store nothing else touches, with n bytes
/// of record in buf, and why is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_parse_incarnation(
    st: *mut RecordStore,
    n: usize,
    why: *mut *const c_char,
) -> c_int {
    // SAFETY: the caller hands a live store nothing else touches.
    let Some(st) = (unsafe { st.as_mut() }) else {
        return -1;
    };
    match parse_store(st, n) {
        Ok(()) => 0,
        Err(reason) => {
            if !why.is_null() {
                // SAFETY: why is writable by the contract above.
                unsafe { *why = reason.as_ptr() };
            }
            -1
        }
    }
}

/// parse_incarnation on a store the caller holds: the record in
/// st.buf, n bytes, taken apart into the store, with st.inc filled from
/// it. Err carries the reason, and st.inc is then untouched. The
/// fiber-side API (fiber.rs) parses a resume's record and a gVisor
/// sandbox's with it.
pub fn parse_store(st: &mut RecordStore, n: usize) -> Result<(), &'static CStr> {
    let n = n.min(RECORD_MAX);
    let parsed = {
        let RecordStore {
            session,
            seed,
            buf,
            payload,
            ..
        } = st;
        parse(buf.get(..n).unwrap_or(&[]), session, seed, payload)
    };
    let parsed = parsed?;
    // Every field lies within buf[..n], which parse checked. The seed's
    // field is written through later (fiber::forget_seed), so its
    // pointer is taken from the buffer as mutable.
    st.seed_hex = st.buf.as_mut_ptr().wrapping_add(parsed.offset(10)).cast();
    let at = |i: usize| -> *const c_char { st.buf.as_ptr().wrapping_add(parsed.offset(i)).cast() };
    if parsed.identity {
        st.identity = Identity {
            key_pem: at(6),
            cert_pem: at(7),
            caller: at(8),
            caller_pem: at(9),
        };
    }
    st.inc = Incarnation {
        fence: at(2),
        endpoint: at(3),
        payload: st.payload.as_ptr(),
        payload_len: parsed.payload_len,
        session: st.session.as_ptr().cast(),
        generation: parsed.generation,
        kind: at(1),
        seed: st.seed.as_ptr(),
        seed_len: SEED_LEN,
        identity: if parsed.identity {
            ptr::addr_of!(st.identity)
        } else {
            ptr::null()
        },
    };
    Ok(())
}

/// parse_generation in C, on a NUL-ended string.
///
/// # Safety
/// s is a live NUL-ended string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_parse_generation(s: *const c_char) -> c_uint {
    // SAFETY: s is NUL-ended by the contract above.
    parse_generation(unsafe { sys::c_bytes(s) })
}

/// unhex in C: decodes the NUL-ended hex string s into out, cap bytes,
/// and returns the bytes written.
///
/// # Safety
/// s is a live NUL-ended string and out has room for cap bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_unhex(s: *const c_char, out: *mut u8, cap: usize) -> usize {
    // SAFETY: both by the contract above.
    let (s, out) = unsafe { (sys::c_bytes(s), core::slice::from_raw_parts_mut(out, cap)) };
    unhex(s, out)
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

    /// A record of the fields given, 'i' then each NUL-ended.
    fn record(fields: &[&[u8]]) -> Vec<u8> {
        let mut rec = vec![b'i'];
        for f in fields {
            rec.extend_from_slice(f);
            rec.push(0);
        }
        rec
    }

    const SEED_HEX: &[u8] = b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// A plain fork record, with one field replaced.
    fn plain_with(i: usize, value: &[u8]) -> Vec<u8> {
        let mut fields: Vec<&[u8]> = vec![
            b"1",
            b"fork",
            b"g/1/1",
            b"/run/f/1.sock",
            b"-",
            b"-",
            b"-",
            b"-",
            b"-",
            b"-",
            SEED_HEX,
        ];
        fields[i] = value;
        record(&fields)
    }

    fn parse_into(
        rec: &[u8],
    ) -> (
        Result<Parsed, &'static CStr>,
        Box<[u8; ENV_VALUE_MAX]>,
        [u8; SEED_LEN],
        Box<[u8; RECORD_MAX / 2]>,
    ) {
        let mut session = Box::new([0u8; ENV_VALUE_MAX]);
        let mut seed = [0u8; SEED_LEN];
        let mut payload = Box::new([0u8; RECORD_MAX / 2]);
        let r = parse(rec, &mut session, &mut seed, &mut payload);
        (r, session, seed, payload)
    }

    #[test]
    fn parse_refuses_what_c_refused() {
        let long_fence = vec![b'f'; FENCE_MAX];
        let long_endpoint = vec![b'e'; ENV_VALUE_MAX];
        let long_session = vec![b'a'; 2 * ENV_VALUE_MAX];
        let mut too_many = plain_with(0, b"1");
        too_many.extend_from_slice(b"extra\0");
        let mut no_nul = plain_with(0, b"1");
        no_nul.pop();
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("empty", vec![], "not an incarnation record"),
            ("one byte", vec![b'i'], "not an incarnation record"),
            (
                "not an i",
                {
                    let mut r = plain_with(0, b"1");
                    r[0] = b'c';
                    r
                },
                "not an incarnation record",
            ),
            ("no NUL at the end", no_nul, "not an incarnation record"),
            (
                "ten fields",
                record(&[
                    b"1", b"fork", b"g/1/1", b"e", b"-", b"-", b"-", b"-", b"-", b"-",
                ]),
                "record has too few fields",
            ),
            (
                "just the i and a NUL",
                vec![b'i', 0],
                "record has an empty field",
            ),
            (
                "an empty field",
                plain_with(3, b""),
                "record has an empty field",
            ),
            ("twelve fields", too_many, "record has too many fields"),
            (
                "generation zero",
                plain_with(0, b"0"),
                "record names no generation",
            ),
            (
                "generation with a leading zero",
                plain_with(0, b"01"),
                "record names no generation",
            ),
            (
                "generation not a number",
                plain_with(0, b"one"),
                "record names no generation",
            ),
            (
                "generation past unsigned",
                plain_with(0, b"4294967296"),
                "record names no generation",
            ),
            (
                "fence of FENCE_MAX",
                plain_with(2, &long_fence),
                "record fence too long",
            ),
            (
                "endpoint of ENV_VALUE_MAX",
                plain_with(3, &long_endpoint),
                "record endpoint too long",
            ),
            (
                "session of ENV_VALUE_MAX bytes",
                plain_with(5, &long_session),
                "record session too long",
            ),
            (
                "session with a NUL",
                plain_with(5, b"6100"),
                "record session holds a NUL",
            ),
            (
                "one identity field",
                plain_with(6, b"key"),
                "record identity is incomplete",
            ),
            (
                "three identity fields",
                {
                    let f: Vec<&[u8]> = vec![
                        b"1", b"fork", b"g", b"e", b"-", b"-", b"k", b"c", b"t", b"-", SEED_HEX,
                    ];
                    record(&f)
                },
                "record identity is incomplete",
            ),
            (
                "seed of 63 digits",
                plain_with(10, &SEED_HEX[..63]),
                "record seed is not 32 bytes",
            ),
            (
                "seed with a bad digit",
                plain_with(
                    10,
                    b"zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                ),
                "record seed is not 32 bytes",
            ),
        ];
        for (name, rec, want) in cases {
            let (r, _, seed, _) = parse_into(&rec);
            let why = r
                .as_ref()
                .err()
                .map(|w| w.to_str().unwrap())
                .unwrap_or("ok");
            assert_eq!(why, want, "{name}");
            if want == "record seed is not 32 bytes" {
                assert_eq!(seed, [0u8; SEED_LEN], "{name}: the seed is zeroed");
            }
        }
    }

    #[test]
    fn parse_takes_a_record_apart() {
        let pem = b"-----BEGIN-----\nabc\n-----END-----";
        let cases: Vec<(&str, Vec<u8>, u32, &[u8], usize, &[u8], bool)> = vec![
            ("a plain fork", plain_with(0, b"1"), 1, b"", 0, b"", false),
            (
                "a payload",
                plain_with(4, b"68656c6c6f"),
                1,
                b"hello",
                0,
                b"",
                false,
            ),
            (
                "a session",
                plain_with(5, b"7365737331"),
                1,
                b"",
                5,
                b"sess1",
                false,
            ),
            (
                "a payload cut at a bad digit",
                plain_with(4, b"6869zz"),
                1,
                b"hi",
                0,
                b"",
                false,
            ),
            (
                "a payload with an odd tail",
                plain_with(4, b"686"),
                1,
                b"h",
                0,
                b"",
                false,
            ),
            (
                "a handoff",
                record(&[
                    b"7", b"resume", b"g/2/9", b"handoff", b"-", b"-", pem, pem, b"thumb", pem,
                    SEED_HEX,
                ]),
                7,
                b"",
                0,
                b"",
                true,
            ),
            (
                "the largest generation",
                plain_with(0, b"4294967295"),
                u32::MAX,
                b"",
                0,
                b"",
                false,
            ),
        ];
        for (name, rec, generation, payload, slen, session, identity) in cases {
            let (r, got_session, seed, got_payload) = parse_into(&rec);
            let p = r.unwrap_or_else(|w| panic!("{name}: {}", w.to_str().unwrap()));
            assert_eq!(p.generation, generation, "{name}");
            assert_eq!(p.identity, identity, "{name}");
            assert_eq!(&got_payload[..p.payload_len], payload, "{name}");
            assert_eq!(&got_session[..slen], session, "{name}");
            assert_eq!(got_session[slen], 0, "{name}: the session is NUL-ended");
            assert_eq!(seed[0..4], [0, 1, 2, 3], "{name}");
            assert_eq!(
                p.field(&rec, 1),
                if identity {
                    &b"resume"[..]
                } else {
                    &b"fork"[..]
                },
                "{name}"
            );
            assert_eq!(p.field(&rec, 10), SEED_HEX, "{name}");
        }
    }

    #[test]
    fn the_c_entry_fills_the_store() {
        let cases: Vec<(&str, Vec<u8>, c_int, bool)> = vec![
            ("a plain fork", plain_with(0, b"3"), 0, false),
            (
                "a handoff",
                record(&[
                    b"3", b"fork", b"g/1/1", b"handoff", b"-", b"-", b"k", b"c", b"t", b"p",
                    SEED_HEX,
                ]),
                0,
                true,
            ),
            ("a refusal", plain_with(0, b"0"), -1, false),
        ];
        for (name, rec, want, identity) in cases {
            let mut st: Box<RecordStore> = Box::new(unsafe { core::mem::zeroed() });
            st.buf[..rec.len()].copy_from_slice(&rec);
            let mut why: *const c_char = ptr::null();
            let rc = unsafe { fz_rs_parse_incarnation(&mut *st, rec.len(), &mut why) };
            assert_eq!(rc, want, "{name}");
            if rc != 0 {
                assert!(!why.is_null(), "{name}: a refusal names a reason");
                assert!(st.inc.fence.is_null(), "{name}: inc is untouched");
                continue;
            }
            let base = st.buf.as_ptr() as usize;
            let field = |p: *const c_char| unsafe { CStr::from_ptr(p) }.to_bytes();
            assert_eq!(st.inc.generation, 3, "{name}");
            assert_eq!(field(st.inc.kind), b"fork", "{name}");
            assert_eq!(
                st.inc.kind as usize - base,
                3,
                "{name}: kind follows the generation"
            );
            assert_eq!(field(st.inc.fence), b"g/1/1", "{name}");
            assert_eq!(st.inc.payload, st.payload.as_ptr(), "{name}");
            assert_eq!(st.inc.session, st.session.as_ptr().cast(), "{name}");
            assert_eq!(st.inc.seed, st.seed.as_ptr(), "{name}");
            assert_eq!(st.inc.seed_len, SEED_LEN, "{name}");
            assert_eq!(field(st.seed_hex), SEED_HEX, "{name}");
            assert_eq!(st.inc.identity.is_null(), !identity, "{name}");
            if identity {
                assert_eq!(st.inc.identity, ptr::addr_of!(st.identity), "{name}");
                assert_eq!(field(st.identity.caller), b"t", "{name}");
            }
        }
    }

    #[test]
    fn parse_generation_reads_decimals_only() {
        let cases: &[(&str, &[u8], u32)] = &[
            ("empty", b"", 0),
            ("zero", b"0", 0),
            ("leading zero", b"07", 0),
            ("one", b"1", 1),
            ("many digits", b"123456", 123456),
            ("a sign", b"+1", 0),
            ("a letter", b"1a", 0),
            ("the largest", b"4294967295", u32::MAX),
            ("one past", b"4294967296", 0),
            ("far past", b"99999999999999999999", 0),
        ];
        for (name, s, want) in cases {
            assert_eq!(parse_generation(s), *want, "{name}");
        }
    }

    #[test]
    fn unhex_decodes_pairs() {
        let cases: &[(&str, &[u8], usize, &[u8])] = &[
            ("empty", b"", 4, b""),
            ("lower", b"0aff", 4, b"\x0a\xff"),
            ("upper", b"0AFF", 4, b"\x0a\xff"),
            ("odd tail dropped", b"0af", 4, b"\x0a"),
            ("bad digit stops", b"0axx10", 4, b"\x0a"),
            ("full out", b"01020304", 2, b"\x01\x02"),
            ("no room", b"0102", 0, b""),
        ];
        for (name, s, cap, want) in cases {
            let mut out = [0xeeu8; 8];
            let n = unhex(s, &mut out[..*cap]);
            assert_eq!(&out[..n], *want, "{name}");
            assert_eq!(out[n], 0xee, "{name}: nothing past the count");
        }
    }

    #[test]
    fn the_corpus_parses_as_c_did() {
        // The verdict the C parser of main 4afa97c gave each seed, recorded
        // once with bin/rust-core's oracle. A bare `cargo fuzz run` adds
        // what it finds beside the seeds, with no verdict recorded.
        let cases: &[(&str, &str)] = &[
            ("clone", "ok"),
            ("fork-plain", "ok"),
            ("half-identity", "record identity is incomplete"),
            ("resume-tls", "ok"),
            ("session-nul", "record session holds a NUL"),
            ("short-seed", "record seed is not 32 bytes"),
            ("ten-fields", "record has too few fields"),
        ];
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/record");
        for (name, want) in cases {
            let rec =
                std::fs::read(format!("{dir}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"));
            let (r, ..) = parse_into(&rec);
            let got = r
                .as_ref()
                .err()
                .map(|w| w.to_str().unwrap())
                .unwrap_or("ok");
            assert_eq!(got, *want, "{name}");
        }
    }
}
