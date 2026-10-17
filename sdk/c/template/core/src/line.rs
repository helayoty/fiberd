//! The lines fiberd sends the zygote on its control socket, and the park
//! messages it sends a fiber, taken apart as the C file took them apart.
//! Only the parsing is here. The replies, the mounts and every error
//! line stay in C, which chooses them from what these return. A line is
//! cut up in place as strtok_r cut it, so the C side keeps its fields as
//! C strings. A fiber runs take_round, so the child-path rules hold
//! throughout: nothing allocates, every index goes through get and
//! every sum is checked.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;

use crate::abi::{CloneOut, FENCE_MAX, RUNDIR_MAX};
use crate::record::{parse_generation, unhex};
use crate::sys;

/// A token's place in the line it was cut from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// Where it starts.
    pub off: usize,
    /// Its length, the NUL after it not counted.
    pub len: usize,
}

impl Span {
    /// The token's bytes of line.
    pub fn of(self, line: &[u8]) -> &[u8] {
        self.off
            .checked_add(self.len)
            .and_then(|end| line.get(self.off..end))
            .unwrap_or(&[])
    }
}

/// strtok_r on one separator byte, over a line read up to its first NUL
/// or its end. A run of separators counts as one, a token is never
/// empty, and the separator after a token becomes a NUL, as strtok_r
/// leaves it. The line is handed to each call, so the caller keeps it.
pub(crate) struct Tokens {
    pos: usize,
    end: usize,
    sep: u8,
}

impl Tokens {
    /// Over all of line.
    pub(crate) fn new(line: &[u8], sep: u8) -> Self {
        Tokens::within(0, sys::nul_at(line), sep)
    }

    /// Over line[from..to], which strtok_r on a token already cut out
    /// of the line sees, since that token ends in a NUL.
    pub(crate) fn within(from: usize, to: usize, sep: u8) -> Self {
        Tokens {
            pos: from,
            end: to,
            sep,
        }
    }

    pub(crate) fn next(&mut self, line: &mut [u8]) -> Option<Span> {
        // The run of separators before the token. strspn in C, a short
        // loop here, since a line has one space between its fields.
        while self.pos < self.end && line.get(self.pos) == Some(&self.sep) {
            self.pos = self.pos.wrapping_add(1);
        }
        if self.pos >= self.end {
            return None;
        }
        let len = sys::byte_at(line.get(self.pos..self.end)?, self.sep);
        let span = Span { off: self.pos, len };
        let after = self.pos.wrapping_add(len);
        if after < self.end {
            if let Some(b) = line.get_mut(after) {
                *b = 0;
            }
            self.pos = after.wrapping_add(1);
        } else {
            self.pos = self.end;
        }
        Some(span)
    }
}

/// isspace in the C locale, what strtol and scanf skip.
pub(crate) fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// atoi in C, which is strtol in base 10 cut to int: leading white
/// space, a sign, then digits, clamped at the ends of long before the
/// cut, so "2147483648" is -2147483648 and "9223372036854775808" is -1.
pub fn atoi(s: &[u8]) -> i32 {
    let mut i = 0usize;
    while s.get(i).is_some_and(|&c| is_space(c)) {
        i = i.wrapping_add(1);
    }
    let negative = match s.get(i) {
        Some(b'-') => {
            i = i.wrapping_add(1);
            true
        }
        Some(b'+') => {
            i = i.wrapping_add(1);
            false
        }
        _ => false,
    };
    let limit = if negative {
        (i64::MAX as u64).wrapping_add(1)
    } else {
        i64::MAX as u64
    };
    let mut v = 0u64;
    let mut over = false;
    while let Some(&c) = s.get(i)
        && c.is_ascii_digit()
    {
        i = i.wrapping_add(1);
        match v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c.wrapping_sub(b'0'))))
        {
            Some(next) if next <= limit => v = next,
            _ => {
                over = true;
                break;
            }
        }
    }
    let long = if over {
        if negative { i64::MIN } else { i64::MAX }
    } else if negative {
        (v as i64).wrapping_neg()
    } else {
        v as i64
    };
    long as i32
}

/// Why handle_clone refuses a CLONE line before it looks at the
/// zygote's own state. The C side sends the ERROR line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum CloneRefusal {
    /// A field is missing. "ERROR %.*s malformed CLONE", with the fence
    /// cut to FENCE_MAX - 1 characters, or "?" when there is none.
    Malformed = 1,
    /// "ERROR %.*s fence too long (at most 127 characters)".
    FenceTooLong = 2,
    /// "ERROR %s session too long (at most 1023 bytes)".
    SessionTooLong = 3,
    /// "ERROR %s session holds a NUL byte".
    SessionNul = 4,
}

/// What handle_clone made of a CLONE line, up to the session's NUL
/// check. The zygote's state checks (a refused mount namespace, the
/// channel, the pending table) and the endpoint's length come after,
/// in C, in the order they always had.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CloneLine {
    /// Why the line is refused, or None when the state checks are next.
    pub refusal: Option<CloneRefusal>,
    /// The fence, when the line has one.
    pub fence: Option<Span>,
    /// The endpoint, when the line has one.
    pub endpoint: Option<Span>,
    /// The deadline in ms with the default of 50, set once the fence
    /// fits, else 0.
    pub deadline_ms: i32,
    /// The pidns option.
    pub pidns: bool,
    /// The mntns option.
    pub mntns: bool,
    /// The nocaps option.
    pub nocaps: bool,
    /// The decoded session's length in the session buffer, set once the
    /// session is decoded.
    pub session_len: usize,
}

/// Takes a CLONE line apart. `CLONE <fence> <endpoint> <deadline_ms>
/// <hexpayload|-> <hexsession|-> [opt,opt...]`, read up to its first
/// NUL and cut up in place on spaces. Unknown options are ignored. The
/// session is decoded into session, ENV_VALUE_MAX bytes in the library,
/// at most session.len() - 1 of them, and NUL-ended when it passes.
pub fn parse_clone(line: &mut [u8], session: &mut [u8]) -> CloneLine {
    let mut out = CloneLine::default();
    let mut t = Tokens::new(line, b' ');
    t.next(line); // CLONE
    let fence = t.next(line);
    let endpoint = t.next(line);
    let dl = t.next(line);
    let hex = t.next(line);
    let shex = t.next(line);
    let opts = t.next(line);
    if let Some(o) = opts {
        let mut ot = Tokens::within(o.off, o.off.wrapping_add(o.len), b',');
        while let Some(opt) = ot.next(line) {
            match opt.of(line) {
                b"pidns" => out.pidns = true,
                b"mntns" => out.mntns = true,
                b"nocaps" => out.nocaps = true,
                _ => {}
            }
        }
    }
    out.fence = fence;
    out.endpoint = endpoint;
    let (Some(fence), Some(_), Some(dl), Some(_), Some(shex)) = (fence, endpoint, dl, hex, shex)
    else {
        out.refusal = Some(CloneRefusal::Malformed);
        return out;
    };
    if fence.len >= FENCE_MAX {
        out.refusal = Some(CloneRefusal::FenceTooLong);
        return out;
    }
    let deadline_ms = atoi(dl.of(line));
    out.deadline_ms = if deadline_ms <= 0 { 50 } else { deadline_ms };
    // The session becomes an environment value, so a NUL inside it, or
    // more than fits, is refused rather than cut.
    let mut slen = 0usize;
    if shex.of(line) != b"-" {
        if shex.len / 2 >= session.len() {
            out.refusal = Some(CloneRefusal::SessionTooLong);
            return out;
        }
        let cap = session.len().saturating_sub(1);
        slen = unhex(shex.of(line), session.get_mut(..cap).unwrap_or(&mut []));
        out.session_len = slen;
        if session
            .get(..slen)
            .is_some_and(|s| sys::nul_at(s) < s.len())
        {
            out.refusal = Some(CloneRefusal::SessionNul);
            return out;
        }
    }
    if let Some(end) = session.get_mut(slen) {
        *end = 0;
    }
    out
}

/// Whether s holds "//".
fn has_double_slash(s: &[u8]) -> bool {
    let mut i = 0usize;
    while let Some(rest) = s.get(i..) {
        let at = sys::byte_at(rest, b'/');
        if at >= rest.len() {
            return false;
        }
        i = i.wrapping_add(at).wrapping_add(1);
        if s.get(i) == Some(&b'/') {
            return true;
        }
    }
    false
}

/// set_rundir in C: takes "RUNDIR <parent> <own>" apart, cutting the line
/// up in place, and keeps the two paths, NUL-ended, in parent and own
/// (RUNDIR_MAX bytes each in the library). Both must be absolute and
/// clean, and own must be a direct child of parent (one name, not "."
/// or ".."). Err carries the reason the C file gave.
pub fn parse_rundir(
    line: &mut [u8],
    parent: &mut [u8],
    own: &mut [u8],
) -> Result<(), &'static CStr> {
    let mut t = Tokens::new(line, b' ');
    t.next(line); // RUNDIR
    let p = t.next(line);
    let o = t.next(line);
    let (Some(p), Some(o)) = (p, o) else {
        return Err(c"want RUNDIR <parent> <own>");
    };
    if t.next(line).is_some() {
        return Err(c"want RUNDIR <parent> <own>");
    }
    let (pl, ol) = (p.len, o.len);
    if pl >= RUNDIR_MAX || ol >= RUNDIR_MAX {
        return Err(c"path too long");
    }
    let (pb, ob) = (p.of(line), o.of(line));
    if pb.first() != Some(&b'/') || ob.first() != Some(&b'/') {
        return Err(c"want absolute paths");
    }
    if pl == 1 {
        return Err(c"parent must not be /");
    }
    if pb.last() == Some(&b'/')
        || ob.last() == Some(&b'/')
        || has_double_slash(pb)
        || has_double_slash(ob)
    {
        return Err(c"want clean paths");
    }
    if ol <= pl.wrapping_add(1) || ob.get(..pl) != Some(pb) || ob.get(pl) != Some(&b'/') {
        return Err(c"own must be under parent");
    }
    let name = ob.get(pl.wrapping_add(1)..).unwrap_or(&[]);
    if sys::byte_at(name, b'/') < name.len() || name == b"." || name == b".." {
        return Err(c"own must be a direct child of parent");
    }
    let n = sys::append(parent, 0, pb);
    sys::append(parent, n, b"\0");
    let n = sys::append(own, 0, ob);
    sys::append(own, n, b"\0");
    Ok(())
}

/// What read_setup does with a line before READY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Setup {
    /// "HIDE /...", kept for the mount namespace.
    Hide = 0,
    /// "DROP /...", kept for the mount namespace.
    Drop = 1,
    /// "RUNDIR ...", to set_rundir.
    Rundir = 2,
    /// "PREPARE mntns", which ends the setup and prepares the namespace.
    PrepareMntns = 3,
    /// "PREPARE none", which ends the setup.
    PrepareNone = 4,
    /// Anything else, a protocol error before READY.
    Other = 5,
}

/// read_setup's choice for a line, read up to its first NUL.
pub fn setup_kind(line: &[u8]) -> Setup {
    let line = line.get(..sys::nul_at(line)).unwrap_or(&[]);
    if line.starts_with(b"HIDE /") {
        Setup::Hide
    } else if line.starts_with(b"DROP /") {
        Setup::Drop
    } else if line.starts_with(b"RUNDIR ") {
        Setup::Rundir
    } else if line == b"PREPARE mntns" {
        Setup::PrepareMntns
    } else if line == b"PREPARE none" {
        Setup::PrepareNone
    } else {
        Setup::Other
    }
}

/// Whether a line, read up to its first NUL, is the REBIND rebind_ctl
/// takes.
pub fn is_rebind(line: &[u8]) -> bool {
    line.get(..sys::nul_at(line)) == Some(b"REBIND")
}

/// record_round in C: the one decimal field of a 'p' or 'c' message,
/// msg as it arrived, or 0 for none.
pub fn record_round(msg: &[u8]) -> u32 {
    if msg.len() < 3 || msg.last() != Some(&0) {
        return 0;
    }
    let s = msg.get(1..).unwrap_or(&[]);
    parse_generation(s.get(..sys::nul_at(s)).unwrap_or(&[]))
}

/// take_round in C: notes a park message in round and over, the
/// fiber's park state. 'p' names the round to answer, and 'c' ends the
/// round it names. True when the message was one of those. msg is at
/// least one byte, since the fiber received it.
pub fn take_round(msg: &[u8], round: &mut u32, over: &mut bool) -> bool {
    match msg.first() {
        Some(b'p') => {
            *round = record_round(msg);
            *over = false;
            true
        }
        Some(b'c') => {
            if record_round(msg) == *round {
                *over = true;
            }
            true
        }
        _ => false,
    }
}

/// The pointer to a token of line, NUL-ended there, or null.
fn at(line: &mut [u8], span: Option<Span>) -> *const c_char {
    span.map_or(ptr::null(), |s| line.as_ptr().wrapping_add(s.off).cast())
}

/// handle_clone's parsing in C: takes the CLONE line apart in place,
/// decodes the session into session (cap bytes) and fills *out. Returns
/// 0 when the state checks are next, or the CloneRefusal the C side
/// answers with. out is filled either way.
///
/// # Safety
/// line is a live NUL-ended string nothing else touches, session has
/// room for cap bytes and out is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_parse_clone(
    line: *mut c_char,
    session: *mut c_char,
    cap: usize,
    out: *mut CloneOut,
) -> c_int {
    // SAFETY: all three by the contract above.
    let (line, session, out) = unsafe {
        (
            sys::c_bytes_mut(line),
            core::slice::from_raw_parts_mut(session.cast::<u8>(), cap),
            &mut *out,
        )
    };
    let c = parse_clone(line, session);
    *out = CloneOut {
        fence: at(line, c.fence),
        endpoint: at(line, c.endpoint),
        endpoint_len: c.endpoint.map_or(0, |e| e.len),
        deadline_ms: c.deadline_ms,
        pidns: c_int::from(c.pidns),
        mntns: c_int::from(c.mntns),
        nocaps: c_int::from(c.nocaps),
        session_len: c.session_len,
    };
    c.refusal.map_or(0, |r| r as c_int)
}

/// set_rundir in C: takes the RUNDIR line apart in place and copies the
/// paths, NUL-ended, into parent and own, RUNDIR_MAX bytes each.
/// Returns 0, or -1 with *why set.
///
/// # Safety
/// line is a live NUL-ended string nothing else touches, parent and
/// own have room for RUNDIR_MAX bytes, and why is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_set_rundir(
    line: *mut c_char,
    parent: *mut c_char,
    own: *mut c_char,
    why: *mut *const c_char,
) -> c_int {
    // SAFETY: all three by the contract above.
    let (line, parent, own) = unsafe {
        (
            sys::c_bytes_mut(line),
            core::slice::from_raw_parts_mut(parent.cast::<u8>(), RUNDIR_MAX),
            core::slice::from_raw_parts_mut(own.cast::<u8>(), RUNDIR_MAX),
        )
    };
    match parse_rundir(line, parent, own) {
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

/// read_setup's choice for a line, as a Setup discriminant.
///
/// # Safety
/// line is a live NUL-ended string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_setup_kind(line: *const c_char) -> c_int {
    // SAFETY: line is NUL-ended by the contract above.
    setup_kind(unsafe { sys::c_bytes(line) }) as c_int
}

/// rebind_ctl's match: 1 when line is "REBIND", else 0.
///
/// # Safety
/// line is a live NUL-ended string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_is_rebind(line: *const c_char) -> c_int {
    // SAFETY: line is NUL-ended by the contract above.
    c_int::from(is_rebind(unsafe { sys::c_bytes(line) }))
}

/// take_round in C, on the n bytes of msg and the fiber's park_round
/// and park_over. Returns 1 for a 'p' or 'c' message, else 0. Only the
/// tests and the line_diff fuzz target call it, since fiber.rs calls
/// take_round directly.
///
/// # Safety
/// msg holds n live bytes, n at least 1, and round and over are
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_take_round(
    msg: *const c_char,
    n: usize,
    round: *mut c_uint,
    over: *mut c_int,
) -> c_int {
    // SAFETY: all three by the contract above.
    let (msg, round, over) = unsafe {
        (
            core::slice::from_raw_parts(msg.cast::<u8>(), n),
            &mut *round,
            &mut *over,
        )
    };
    let mut is_over = *over != 0;
    let taken = take_round(msg, round, &mut is_over);
    *over = c_int::from(is_over);
    c_int::from(taken)
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
    use crate::abi::ENV_VALUE_MAX;

    /// The C string a line is, cut up as strtok_r left it.
    fn cut(line: &[u8]) -> Vec<u8> {
        line.to_vec()
    }

    #[test]
    fn tokens_cut_as_strtok_r_does() {
        let cases: &[(&str, &[u8], u8, &[&[u8]], &[u8])] = &[
            ("empty", b"", b' ', &[], b""),
            ("only separators", b"   ", b' ', &[], b"   "),
            ("one token", b"abc", b' ', &[b"abc"], b"abc"),
            ("two tokens", b"a b", b' ', &[b"a", b"b"], b"a\0b"),
            (
                "a run of separators is one",
                b"a   b",
                b' ',
                &[b"a", b"b"],
                b"a\0  b",
            ),
            ("leading separators", b"  a", b' ', &[b"a"], b"  a"),
            ("trailing separators", b"a  ", b' ', &[b"a"], b"a\0 "),
            (
                "stops at the first NUL",
                b"a b\0c d",
                b' ',
                &[b"a", b"b"],
                b"a\0b\0c d",
            ),
            (
                "another separator",
                b"pidns,,mntns",
                b',',
                &[b"pidns", b"mntns"],
                b"pidns\0,mntns",
            ),
        ];
        for (name, line, sep, want, left) in cases {
            let mut line = cut(line);
            let mut t = Tokens::new(&line, *sep);
            let mut got: Vec<Vec<u8>> = Vec::new();
            while let Some(s) = t.next(&mut line) {
                got.push(s.of(&line).to_vec());
            }
            assert_eq!(got, want.to_vec(), "{name}");
            assert_eq!(&line, left, "{name}: the line as strtok_r left it");
            assert!(t.next(&mut line).is_none(), "{name}: stays at the end");
        }
    }

    #[test]
    fn atoi_reads_as_glibc_does() {
        let cases: &[(&str, &[u8], i32)] = &[
            ("empty", b"", 0),
            ("zero", b"0", 0),
            ("plain", b"50", 50),
            ("a sign", b"-7", -7),
            ("a plus", b"+7", 7),
            ("leading white space", b"\t\n 12", 12),
            ("white space after the sign", b"- 5", 0),
            ("a letter stops it", b"12ab", 12),
            ("not a number", b"abc", 0),
            ("leading zeros", b"0012", 12),
            ("int max", b"2147483647", i32::MAX),
            ("one past int wraps", b"2147483648", i32::MIN),
            ("wraps around to 50", b"4294967346", 50),
            ("long max cut to int", b"9223372036854775807", -1),
            ("past long max clamps then cuts", b"9223372036854775808", -1),
            ("far past long max", b"99999999999999999999999", -1),
            ("long min cut to int", b"-9223372036854775808", 0),
            ("past long min clamps then cuts", b"-9223372036854775809", 0),
            ("far past long min", b"-99999999999999999999999", 0),
        ];
        for (name, s, want) in cases {
            assert_eq!(atoi(s), *want, "{name}");
        }
    }

    /// The line parsed and the session buffer after it.
    fn clone_of(line: &[u8]) -> (CloneLine, Vec<u8>, Vec<u8>) {
        let mut line = cut(line);
        let mut session = vec![0xeeu8; ENV_VALUE_MAX];
        let c = parse_clone(&mut line, &mut session);
        (c, line, session)
    }

    #[test]
    fn parse_clone_refuses_what_c_refused() {
        let long_fence = [b"CLONE ".as_slice(), &[b'f'; FENCE_MAX], b" e 50 - -"].concat();
        let long_session = [b"CLONE f e 50 - ".as_slice(), &[b'a'; 2 * ENV_VALUE_MAX]].concat();
        let cases: Vec<(&str, Vec<u8>, Option<CloneRefusal>, Option<&[u8]>)> = vec![
            ("empty", b"".to_vec(), Some(CloneRefusal::Malformed), None),
            (
                "the word alone",
                b"CLONE".to_vec(),
                Some(CloneRefusal::Malformed),
                None,
            ),
            (
                "a fence alone",
                b"CLONE f1".to_vec(),
                Some(CloneRefusal::Malformed),
                Some(b"f1"),
            ),
            (
                "no session",
                b"CLONE f2 e 50 -".to_vec(),
                Some(CloneRefusal::Malformed),
                Some(b"f2"),
            ),
            (
                "trailing space is no field",
                b"CLONE f3 e 50 - ".to_vec(),
                Some(CloneRefusal::Malformed),
                Some(b"f3"),
            ),
            (
                "a NUL cuts the line",
                b"CLONE f4 e\0 50 - -".to_vec(),
                Some(CloneRefusal::Malformed),
                Some(b"f4"),
            ),
            (
                "fence of FENCE_MAX",
                long_fence,
                Some(CloneRefusal::FenceTooLong),
                Some(&[b'f'; FENCE_MAX]),
            ),
            (
                "session of ENV_VALUE_MAX bytes",
                long_session,
                Some(CloneRefusal::SessionTooLong),
                Some(b"f"),
            ),
            (
                "session with a NUL",
                b"CLONE s4 e 50 - 6100".to_vec(),
                Some(CloneRefusal::SessionNul),
                Some(b"s4"),
            ),
            (
                "session with a NUL first",
                b"CLONE s5 e 50 - 0061".to_vec(),
                Some(CloneRefusal::SessionNul),
                Some(b"s5"),
            ),
            (
                "the least line",
                b"CLONE f e 1 - -".to_vec(),
                None,
                Some(b"f"),
            ),
        ];
        for (name, line, refusal, fence) in cases {
            let (c, line, _) = clone_of(&line);
            assert_eq!(c.refusal, refusal, "{name}");
            assert_eq!(c.fence.map(|f| f.of(&line)), fence, "{name}: the fence");
        }
    }

    #[test]
    fn parse_clone_takes_a_line_apart() {
        struct Want {
            fence: &'static [u8],
            endpoint: &'static [u8],
            deadline_ms: i32,
            opts: (bool, bool, bool),
            session: &'static [u8],
        }
        let longest_fence = [b"CLONE ".as_slice(), &[b'f'; FENCE_MAX - 1], b" e 50 - -"].concat();
        let cases: Vec<(&str, &[u8], Want)> = vec![
            (
                "a storm clone",
                b"CLONE g/1/7 /run/f/7.sock 50 - -",
                Want {
                    fence: b"g/1/7",
                    endpoint: b"/run/f/7.sock",
                    deadline_ms: 50,
                    opts: (false, false, false),
                    session: b"",
                },
            ),
            (
                "every option",
                b"CLONE f e 250 68690a 7365737331 pidns,mntns,nocaps",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 250,
                    opts: (true, true, true),
                    session: b"sess1",
                },
            ),
            (
                "unknown options are ignored",
                b"CLONE f e 50 - - foo,mntns,,bar",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, true, false),
                    session: b"",
                },
            ),
            (
                "a seventh field is not options",
                b"CLONE f e 50 - - pidns mntns",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (true, false, false),
                    session: b"",
                },
            ),
            (
                "repeated spaces",
                b"CLONE  f   e  50  -  -   nocaps",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, false, true),
                    session: b"",
                },
            ),
            (
                "a deadline of zero takes the default",
                b"CLONE f e 0 - -",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, false, false),
                    session: b"",
                },
            ),
            (
                "a negative deadline takes the default",
                b"CLONE f e -3 - -",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, false, false),
                    session: b"",
                },
            ),
            (
                "a deadline that is no number takes the default",
                b"CLONE f e soon - -",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, false, false),
                    session: b"",
                },
            ),
            (
                "a deadline that wraps int",
                b"CLONE f e 4294967396 - -",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 100,
                    opts: (false, false, false),
                    session: b"",
                },
            ),
            (
                "a session cut at a bad digit",
                b"CLONE f e 50 - 6869zz",
                Want {
                    fence: b"f",
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, false, false),
                    session: b"hi",
                },
            ),
            (
                "a fence of FENCE_MAX - 1",
                &longest_fence,
                Want {
                    fence: &[b'f'; FENCE_MAX - 1],
                    endpoint: b"e",
                    deadline_ms: 50,
                    opts: (false, false, false),
                    session: b"",
                },
            ),
        ];
        for (name, line, want) in cases {
            let (c, line, session) = clone_of(line);
            assert_eq!(c.refusal, None, "{name}");
            assert_eq!(c.fence.unwrap().of(&line), want.fence, "{name}: fence");
            assert_eq!(
                c.endpoint.unwrap().of(&line),
                want.endpoint,
                "{name}: endpoint"
            );
            assert_eq!(c.deadline_ms, want.deadline_ms, "{name}: deadline");
            assert_eq!((c.pidns, c.mntns, c.nocaps), want.opts, "{name}: options");
            assert_eq!(c.session_len, want.session.len(), "{name}: session length");
            assert_eq!(&session[..c.session_len], want.session, "{name}: session");
            assert_eq!(
                session[c.session_len], 0,
                "{name}: the session is NUL-ended"
            );
        }
    }

    #[test]
    fn the_clone_entry_fills_the_out_struct() {
        let cases: Vec<(&str, &[u8], c_int, bool, usize)> = vec![
            ("a plain line", b"CLONE f e 50 - - mntns", 0, true, 0),
            ("a session", b"CLONE f e 50 - 6869", 0, true, 2),
            ("malformed with a fence", b"CLONE f", 1, true, 0),
            ("malformed without one", b"CLONE", 1, false, 0),
            ("session with a NUL", b"CLONE f e 50 - 00", 4, true, 0),
        ];
        for (name, line, want, has_fence, slen) in cases {
            let mut line = [line, b"\0".as_slice()].concat();
            let mut session = [0u8; ENV_VALUE_MAX];
            let mut out: CloneOut = unsafe { core::mem::zeroed() };
            let rc = unsafe {
                fz_rs_parse_clone(
                    line.as_mut_ptr().cast(),
                    session.as_mut_ptr().cast(),
                    session.len(),
                    &mut out,
                )
            };
            assert_eq!(rc, want, "{name}");
            assert_eq!(out.fence.is_null(), !has_fence, "{name}: the fence");
            if has_fence {
                let f = unsafe { CStr::from_ptr(out.fence) }.to_bytes();
                assert_eq!(f, b"f", "{name}: the fence is a C string");
                assert_eq!(out.fence as usize - line.as_ptr() as usize, 6, "{name}");
            }
            if rc == 0 {
                assert_eq!(out.endpoint_len, 1, "{name}");
                assert_eq!(out.deadline_ms, 50, "{name}");
                assert_eq!(out.session_len, slen, "{name}");
                assert_eq!(out.mntns, c_int::from(name == "a plain line"), "{name}");
            }
        }
    }

    /// The paths a RUNDIR line left in its two buffers.
    fn rundir_of(line: &[u8]) -> (Result<(), &'static CStr>, Vec<u8>, Vec<u8>) {
        let mut line = cut(line);
        let mut parent = vec![0xeeu8; RUNDIR_MAX];
        let mut own = vec![0xeeu8; RUNDIR_MAX];
        let r = parse_rundir(&mut line, &mut parent, &mut own);
        (r, parent, own)
    }

    #[test]
    fn parse_rundir_refuses_what_c_refused() {
        let long_parent = [b"RUNDIR /".as_slice(), &[b'p'; RUNDIR_MAX], b" /p/x"].concat();
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("empty", b"".to_vec(), "want RUNDIR <parent> <own>"),
            (
                "the word alone",
                b"RUNDIR".to_vec(),
                "want RUNDIR <parent> <own>",
            ),
            (
                "one path",
                b"RUNDIR /a".to_vec(),
                "want RUNDIR <parent> <own>",
            ),
            (
                "three paths",
                b"RUNDIR /a /a/b /c".to_vec(),
                "want RUNDIR <parent> <own>",
            ),
            (
                "a NUL cuts the line",
                b"RUNDIR /a\0 /a/b".to_vec(),
                "want RUNDIR <parent> <own>",
            ),
            ("parent of RUNDIR_MAX", long_parent, "path too long"),
            (
                "relative parent",
                b"RUNDIR a /a/b".to_vec(),
                "want absolute paths",
            ),
            (
                "relative own",
                b"RUNDIR /a a/b".to_vec(),
                "want absolute paths",
            ),
            (
                "parent is the root",
                b"RUNDIR / /a".to_vec(),
                "parent must not be /",
            ),
            (
                "parent with a trailing slash",
                b"RUNDIR /a/ /a/b".to_vec(),
                "want clean paths",
            ),
            (
                "own with a trailing slash",
                b"RUNDIR /a /a/b/".to_vec(),
                "want clean paths",
            ),
            (
                "parent with a double slash",
                b"RUNDIR /a//c /a//c/b".to_vec(),
                "want clean paths",
            ),
            (
                "own with a double slash",
                b"RUNDIR /a /a//b".to_vec(),
                "want clean paths",
            ),
            (
                "own is the parent",
                b"RUNDIR /a /a".to_vec(),
                "own must be under parent",
            ),
            (
                "own elsewhere",
                b"RUNDIR /a /b/c".to_vec(),
                "own must be under parent",
            ),
            (
                "own only shares a prefix",
                b"RUNDIR /a /ab/c".to_vec(),
                "own must be under parent",
            ),
            (
                "own two levels down",
                b"RUNDIR /a /a/b/c".to_vec(),
                "own must be a direct child of parent",
            ),
            (
                "own is dot",
                b"RUNDIR /a /a/.".to_vec(),
                "own must be a direct child of parent",
            ),
            (
                "own is dot dot",
                b"RUNDIR /a /a/..".to_vec(),
                "own must be a direct child of parent",
            ),
        ];
        for (name, line, want) in cases {
            let (r, parent, own) = rundir_of(&line);
            let why = r.err().map(|w| w.to_str().unwrap()).unwrap_or("ok");
            assert_eq!(why, want, "{name}");
            assert_eq!(parent[0], 0xee, "{name}: parent untouched");
            assert_eq!(own[0], 0xee, "{name}: own untouched");
        }
    }

    #[test]
    fn parse_rundir_keeps_both_paths() {
        // own is RUNDIR_MAX - 1 characters, the longest that fits.
        let deep = [
            b"RUNDIR /".as_slice(),
            &[b'p'; RUNDIR_MAX - 4],
            b" /",
            &[b'p'; RUNDIR_MAX - 4],
            b"/x",
        ]
        .concat();
        let deep_parent = [b"/".as_slice(), &[b'p'; RUNDIR_MAX - 4]].concat();
        let deep_own = [b"/".as_slice(), &[b'p'; RUNDIR_MAX - 4], b"/x"].concat();
        assert_eq!(deep_own.len(), RUNDIR_MAX - 1);
        let cases: Vec<(&str, Vec<u8>, &[u8], &[u8])> = vec![
            (
                "the usual",
                b"RUNDIR /run/fiberd /run/fiberd/g1".to_vec(),
                b"/run/fiberd",
                b"/run/fiberd/g1",
            ),
            (
                "repeated spaces",
                b"RUNDIR   /a   /a/b".to_vec(),
                b"/a",
                b"/a/b",
            ),
            (
                "a name with dots",
                b"RUNDIR /a /a/...".to_vec(),
                b"/a",
                b"/a/...",
            ),
            (
                "a parent just under the bound",
                deep,
                &deep_parent,
                &deep_own,
            ),
        ];
        for (name, line, parent, own) in cases {
            let (r, got_parent, got_own) = rundir_of(&line);
            assert_eq!(r, Ok(()), "{name}");
            assert_eq!(&got_parent[..parent.len()], parent, "{name}: parent");
            assert_eq!(got_parent[parent.len()], 0, "{name}: parent NUL-ended");
            assert_eq!(&got_own[..own.len()], own, "{name}: own");
            assert_eq!(got_own[own.len()], 0, "{name}: own NUL-ended");
        }
    }

    #[test]
    fn setup_kind_sorts_as_read_setup_did() {
        let cases: &[(&str, &[u8], Setup)] = &[
            ("a hide", b"HIDE /proc/kcore", Setup::Hide),
            ("a drop", b"DROP /run/fiberd", Setup::Drop),
            ("a relative hide", b"HIDE proc", Setup::Other),
            ("the word alone", b"HIDE", Setup::Other),
            ("a rundir", b"RUNDIR /a /a/b", Setup::Rundir),
            ("a rundir with nothing after", b"RUNDIR ", Setup::Rundir),
            ("rundir alone", b"RUNDIR", Setup::Other),
            ("prepare mntns", b"PREPARE mntns", Setup::PrepareMntns),
            ("prepare none", b"PREPARE none", Setup::PrepareNone),
            ("prepare with a tail", b"PREPARE none ", Setup::Other),
            ("prepare else", b"PREPARE pidns", Setup::Other),
            ("a clone", b"CLONE f e 50 - -", Setup::Other),
            ("empty", b"", Setup::Other),
            (
                "a NUL cuts the line",
                b"PREPARE none\0x",
                Setup::PrepareNone,
            ),
            ("lower case", b"hide /x", Setup::Other),
        ];
        for (name, line, want) in cases {
            assert_eq!(setup_kind(line), *want, "{name}");
        }
    }

    #[test]
    fn is_rebind_matches_the_word_alone() {
        let cases: &[(&str, &[u8], bool)] = &[
            ("the word", b"REBIND", true),
            ("with a tail", b"REBIND ", false),
            ("a prefix", b"REBIN", false),
            ("empty", b"", false),
            ("a NUL cuts the line", b"REBIND\0x", true),
        ];
        for (name, line, want) in cases {
            assert_eq!(is_rebind(line), *want, "{name}");
        }
    }

    #[test]
    fn record_round_reads_the_one_field() {
        let cases: &[(&str, &[u8], u32)] = &[
            ("empty", b"", 0),
            ("too short", b"p\0", 0),
            ("no NUL at the end", b"p12", 0),
            ("a round", b"p12\0", 12),
            ("a carry-on", b"c7\0", 7),
            ("zero is none", b"p0\0", 0),
            ("a leading zero is none", b"p07\0", 0),
            ("a NUL inside cuts it", b"p1\0\0", 1),
            ("the largest", b"p4294967295\0", u32::MAX),
            ("one past", b"p4294967296\0", 0),
            ("not a number", b"pabc\0", 0),
        ];
        for (name, msg, want) in cases {
            assert_eq!(record_round(msg), *want, "{name}");
        }
    }

    #[test]
    fn take_round_notes_the_park_state() {
        // Each case starts from round 1 and not over.
        let cases: &[(&str, &[u8], bool, u32, bool)] = &[
            ("a round", b"p3\0", true, 3, false),
            ("a round resets over", b"p1\0", true, 1, false),
            ("an unreadable round is 0", b"px\0", true, 0, false),
            ("the carry-on of the round", b"c1\0", true, 1, true),
            ("a stale carry-on", b"c2\0", true, 1, false),
            ("an unreadable carry-on", b"c\0", true, 1, false),
            ("a record", b"i1\0fork\0", false, 1, false),
            ("a quiesce", b"q1\0", false, 1, false),
            ("empty", b"", false, 1, false),
        ];
        for (name, msg, taken, round, over) in cases {
            let (mut r, mut o) = (1u32, false);
            assert_eq!(take_round(msg, &mut r, &mut o), *taken, "{name}");
            assert_eq!((r, o), (*round, *over), "{name}: the state after");
            // The C entry does the same on the C side's int.
            let (mut cr, mut co): (c_uint, c_int) = (1, 0);
            let rc = unsafe { fz_rs_take_round(msg.as_ptr().cast(), msg.len(), &mut cr, &mut co) };
            assert_eq!(
                (rc != 0, cr, co != 0),
                (*taken, *round, *over),
                "{name}: the entry"
            );
        }
    }

    #[test]
    fn the_rundir_entry_copies_and_names_a_reason() {
        let cases: &[(&str, &[u8], c_int, &str)] = &[
            ("kept", b"RUNDIR /a /a/b", 0, ""),
            ("refused", b"RUNDIR /a /b", -1, "own must be under parent"),
        ];
        for (name, line, want, why) in cases {
            let mut line = [line, b"\0".as_slice()].concat();
            let mut parent = [0u8; RUNDIR_MAX];
            let mut own = [0u8; RUNDIR_MAX];
            let mut got_why: *const c_char = ptr::null();
            let rc = unsafe {
                fz_rs_set_rundir(
                    line.as_mut_ptr().cast(),
                    parent.as_mut_ptr().cast(),
                    own.as_mut_ptr().cast(),
                    &mut got_why,
                )
            };
            assert_eq!(rc, *want, "{name}");
            if rc == 0 {
                assert!(got_why.is_null(), "{name}");
                assert_eq!(&parent[..3], b"/a\0", "{name}");
                assert_eq!(&own[..5], b"/a/b\0", "{name}");
            } else {
                let w = unsafe { CStr::from_ptr(got_why) }.to_str().unwrap();
                assert_eq!(w, *why, "{name}");
            }
        }
    }

    #[test]
    fn the_small_entries_read_c_strings() {
        let cases: &[(&str, &[u8], c_int, c_int)] = &[
            ("a hide", b"HIDE /x\0", Setup::Hide as c_int, 0),
            ("rebind", b"REBIND\0", Setup::Other as c_int, 1),
        ];
        for (name, line, kind, rebind) in cases {
            let p = line.as_ptr().cast();
            assert_eq!(unsafe { fz_rs_setup_kind(p) }, *kind, "{name}");
            assert_eq!(unsafe { fz_rs_is_rebind(p) }, *rebind, "{name}");
        }
    }
}
