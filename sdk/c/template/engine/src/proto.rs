//! The fiber's side of the protocol (bin/gpu-poc/PROTOCOL.md). One
//! request line per connection on engine.sock and one reply line, each
//! at most 256 bytes and ending in a newline. Only the grammar, the fill
//! pattern and the hash live here. Who may name which fence is peer.rs,
//! and what a request does to the pool is main.rs and pool.rs.

// ---- bounds and tokens ----

use fiberzygote_core::line::{Span, Tokens};

/// Longest line either way, its newline counted.
pub const LINE_MAX: usize = 256;
/// Longest fence, in bytes. A DEVICE or ERROR line with one still fits.
pub const FENCE_MAX: usize = 128;
/// Most tokens any line of either protocol has.
const TOKENS_MAX: usize = 3;

/// The tokens of line, split on single spaces with the core's
/// tokenizer, which leaves a NUL after each one. A line with a NUL of
/// its own or more than TOKENS_MAX tokens is None, since the tokenizer
/// would stop at the NUL and hide the rest.
pub fn tokens(line: &mut [u8]) -> Option<([Span; TOKENS_MAX], usize)> {
    if line.contains(&0) {
        return None;
    }
    let mut spans = [Span::default(); TOKENS_MAX];
    let mut n = 0usize;
    let mut t = Tokens::new(line, b' ');
    while let Some(s) = t.next(line) {
        *spans.get_mut(n)? = s;
        n = n.checked_add(1)?;
    }
    Some((spans, n))
}

// ---- fences and numbers ----

/// Whether f can be a fence. One to FENCE_MAX bytes of printable ASCII
/// with no space, and not the "-" a DEVICE line uses for the whole pool.
/// fiberd prints fences as `<grant>/<epoch>/<seq>`, but the engine only
/// compares them, so it asks no more than that.
pub fn valid_fence(f: &[u8]) -> bool {
    !f.is_empty()
        && f.len() <= FENCE_MAX
        && f != b"-"
        && f.iter().all(|&b| (0x21..=0x7e).contains(&b))
}

/// A decimal u64. Digits only, at least one, with no sign and no
/// overflow.
pub fn dec_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v = 0u64;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(v)
}

// ---- requests ----

/// One fiber request. The fence is the line's, not yet checked against
/// the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// `reserve <fence> <bytes>`
    Reserve {
        /// The fence named.
        fence: &'a [u8],
        /// The size asked for, before rounding.
        bytes: u64,
    },
    /// `release <fence>`
    Release {
        /// The fence named.
        fence: &'a [u8],
    },
    /// `fill <fence> <seed>`
    Fill {
        /// The fence named.
        fence: &'a [u8],
        /// The pattern's seed.
        seed: u64,
    },
    /// `sum <fence>`
    Sum {
        /// The fence named.
        fence: &'a [u8],
    },
    /// `stat`
    Stat,
}

impl<'a> Request<'a> {
    /// The fence the request names, None for stat.
    pub fn fence(&self) -> Option<&'a [u8]> {
        match *self {
            Request::Reserve { fence, .. }
            | Request::Release { fence }
            | Request::Fill { fence, .. }
            | Request::Sum { fence } => Some(fence),
            Request::Stat => None,
        }
    }
}

/// parse reads one request line, its newline already cut off. None is
/// `err proto`. The fence is left as it came, since a fence that is not
/// a valid one never has a LEAF and so gets `err fence`.
pub fn parse(line: &mut [u8]) -> Option<Request<'_>> {
    let (spans, n) = tokens(line)?;
    let line: &[u8] = line;
    let [a, b, c] = spans.map(|s| s.of(line));
    Some(match (a, n) {
        (b"reserve", 3) => Request::Reserve {
            fence: b,
            bytes: dec_u64(c)?,
        },
        (b"release", 2) => Request::Release { fence: b },
        (b"fill", 3) => Request::Fill {
            fence: b,
            seed: dec_u64(c)?,
        },
        (b"sum", 2) => Request::Sum { fence: b },
        (b"stat", 1) => Request::Stat,
        _ => return None,
    })
}

// ---- replies ----

/// One reply line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `ok`
    Ok,
    /// `ok <hash>`, 16 lowercase hex digits.
    Hash(u64),
    /// `<used> <capacity>`, for stat.
    Stat(u64, u64),
    /// `err <reason>`, one of fence, capacity, none, proto and device.
    Err(&'static str),
}

impl Reply {
    /// The line on the wire, newline included. The longest, a stat of
    /// two 20-digit numbers, is far under LINE_MAX.
    pub fn line(self) -> String {
        match self {
            Reply::Ok => "ok\n".to_owned(),
            Reply::Hash(h) => format!("ok {h:016x}\n"),
            Reply::Stat(used, cap) => format!("{used} {cap}\n"),
            Reply::Err(why) => format!("err {why}\n"),
        }
    }
}

// ---- fill pattern and hash ----

/// What the fill pattern starts from when seed ^ o is 0, since xorshift
/// keeps 0 at 0.
const FILL_ZERO: u64 = 0x9E37_79B9_7F4A_7C15;

/// The fill pattern's word at byte offset o of a slice. x is seed ^ o,
/// or FILL_ZERO when that is 0, then one xorshift64 round (13, 7, 17).
/// The word goes into the slice little-endian.
pub fn fill_word(seed: u64, o: u64) -> u64 {
    let mut x = seed ^ o;
    if x == 0 {
        x = FILL_ZERO;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// fill_into writes the pattern over buf, which starts at byte offset
/// at of its slice. at and buf's length are multiples of 8, since a
/// slice is a whole number of 256-byte units and callers chunk it on
/// those bounds. A short tail, which never happens, is left as it was.
pub fn fill_into(buf: &mut [u8], seed: u64, at: u64) {
    let mut o = at;
    for word in buf.as_chunks_mut::<8>().0 {
        *word = fill_word(seed, o).to_le_bytes();
        o = o.wrapping_add(8);
    }
}

/// FNV-1a 64 over a slice's bytes, fed in any number of pieces.
#[derive(Clone, Copy, Debug)]
pub struct Fnv(u64);

impl Fnv {
    /// The offset basis.
    pub fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }

    /// Feeds bytes, in order.
    pub fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    /// The hash so far.
    pub fn finish(self) -> u64 {
        self.0
    }
}

impl Default for Fnv {
    fn default() -> Self {
        Fnv::new()
    }
}
