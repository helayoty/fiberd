//! Parsers for files the kernel and the sandbox hand the zygote:
//! /proc/self/mountinfo, /proc/self/uid_map and the gVisor spec
//! environment. Only buffer logic is here. The open, the read and every
//! mount are the callers' (prepare.rs, fiber.rs). The child-path rules of
//! line.rs hold.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::line::{Span, Tokens, is_space};
use crate::sys;

/// The one octal escape mountinfo writes, \ooo, at s[at], as its byte.
fn octal_at(s: &[u8], at: usize) -> Option<u8> {
    let digit = |k: usize| -> Option<u16> {
        match s.get(at.checked_add(k)?) {
            Some(&c @ b'0'..=b'7') => Some(u16::from(c.wrapping_sub(b'0'))),
            _ => None,
        }
    };
    if s.get(at) != Some(&b'\\') {
        return None;
    }
    let v = digit(1)?
        .wrapping_mul(64)
        .wrapping_add(digit(2)?.wrapping_mul(8))
        .wrapping_add(digit(3)?);
    // Escapes past \377 keep their low 8 bits.
    Some(v as u8)
}

/// Undoes mountinfo's octal escapes (\040 for a space) in place, up to
/// s's first NUL, and NUL-ends the result. Returns the new length. A
/// backslash that starts no escape stays.
pub fn unescape_mount(s: &mut [u8]) -> usize {
    let end = sys::nul_at(s);
    let (mut r, mut w) = (0usize, 0usize);
    loop {
        let rest = s.get(r..end).unwrap_or(&[]);
        let run = sys::byte_at(rest, b'\\');
        // The common line has no escape, so nothing moves.
        if w != r
            && let Some(stop) = r.checked_add(run)
        {
            s.copy_within(r..stop, w);
        }
        r = r.wrapping_add(run);
        w = w.wrapping_add(run);
        if r >= end {
            break;
        }
        let (byte, took) = match octal_at(s.get(..end).unwrap_or(&[]), r) {
            Some(b) => (b, 4),
            None => (b'\\', 1),
        };
        if let Some(slot) = s.get_mut(w) {
            *slot = byte;
        }
        w = w.wrapping_add(1);
        r = r.wrapping_add(took);
    }
    if let Some(slot) = s.get_mut(w) {
        *slot = 0;
    }
    w
}

/// The fields of one mountinfo line the zygote reads, as spans of the
/// buffer. The mount point is unescaped and NUL-ended, ready for mount.
/// The others are as the kernel wrote them, since they are only
/// compared with each other.
pub struct MountLine {
    /// The third field, the device as major:minor.
    pub dev: Span,
    /// The fourth field, the mount's root within its file system.
    pub root: Span,
    /// The fifth field, the mount point.
    pub point: Span,
    /// The source, the field after the file system type past the "-"
    /// separator. Empty when the line has none.
    pub source: Span,
}

/// The fields of the line at buf[line_start..line_end], whose newline
/// is already a NUL. None for fewer than five fields. With whole false
/// the line is cut at line_end rather than ended there, and the fields
/// count only when the source token ended before the cut, so that no
/// field is read short. The mount point is unescaped in place.
fn line_fields(
    buf: &mut [u8],
    line_start: usize,
    line_end: usize,
    whole: bool,
) -> Option<MountLine> {
    // 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
    // (0)(1)(2)  (3)   (4)   (5)        (6...)   -  type source opts
    // A NUL inside the line ends it.
    let line = buf.get(line_start..line_end).unwrap_or(&[]);
    let nul = line_start.wrapping_add(sys::nul_at(line));
    let mut t = Tokens::within(line_start, nul, b' ');
    let (Some(_), Some(_), Some(dev), Some(root), Some(mp)) = (
        t.next(buf),
        t.next(buf),
        t.next(buf),
        t.next(buf),
        t.next(buf),
    ) else {
        return None;
    };
    let mut source = None;
    while let Some(tok) = t.next(buf) {
        if tok.of(buf) == b"-" {
            if let (Some(_), Some(src)) = (t.next(buf), t.next(buf)) {
                source = Some(src);
            }
            break;
        }
    }
    let source = match source {
        Some(src) => {
            // A cut line's source is whole only when a separator
            // followed it inside the buffer.
            if !whole && src.off.wrapping_add(src.len) >= nul {
                return None;
            }
            src
        }
        None if whole => Span {
            off: mp.off,
            len: 0,
        },
        None => return None,
    };
    // The token ends in a NUL, the tokenizer's or the line's.
    let field = buf.get_mut(mp.off..).unwrap_or(&mut []);
    let len = unescape_mount(field);
    // An escaped NUL cuts the path the mount sees.
    let len = sys::nul_at(field.get(..len).unwrap_or(&[]));
    Some(MountLine {
        dev,
        root,
        point: Span { off: mp.off, len },
        source,
    })
}

/// The next complete line of buf[..have] from *start, which moves past
/// it, as its fields. None when no complete line is left. A line with
/// fewer than five fields is skipped. Every newline passed becomes a
/// NUL. A line that began before the buffer (*skipping) is dropped and
/// clears the flag.
pub fn mountinfo_next(
    buf: &mut [u8],
    have: usize,
    start: &mut usize,
    skipping: &mut bool,
) -> Option<MountLine> {
    let have = have.min(buf.len());
    loop {
        let rest = buf.get(*start..have)?;
        let nl = sys::byte_at(rest, b'\n');
        if nl >= rest.len() {
            return None;
        }
        let line_start = *start;
        let line_end = line_start.wrapping_add(nl);
        if let Some(b) = buf.get_mut(line_end) {
            *b = 0;
        }
        *start = line_end.wrapping_add(1);
        if *skipping {
            *skipping = false;
            continue;
        }
        if let Some(m) = line_fields(buf, line_start, line_end, true) {
            return Some(m);
        }
    }
}

/// The fields of a line longer than the buffer, read from the buffer it
/// fills with no newline. Every field read here comes before the
/// superoptions, which is what makes an overlay root's line long, so
/// the fields are there unless the root and mount point paths alone
/// fill the buffer. None then, and the caller treats the line as
/// unreadable. The byte at have is overwritten with a NUL, so have is
/// at most buf.len() - 1.
pub fn mountinfo_long(buf: &mut [u8], have: usize) -> Option<MountLine> {
    let end = have.min(buf.len().saturating_sub(1));
    if let Some(b) = buf.get_mut(end) {
        *b = 0;
    }
    line_fields(buf, 0, end, false)
}

/// Why stream_mounts could not read the whole table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unread {
    /// read failed.
    Read,
    /// A line's fields did not fit the buffer.
    Line,
}

/// Streams a mountinfo table through buf, calling f with each line's
/// fields until f returns true, and reports whether it did. read fills
/// a slice and returns the count, 0 at the end, or a negative value on
/// failure. A line longer than the buffer is read as far as its source
/// field (mountinfo_long) and the rest of it dropped. Err when read
/// fails or a line's fields do not fit the buffer, so a caller that
/// decides by every line fails closed rather than miss one.
pub fn stream_mounts(
    buf: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> isize,
    mut f: impl FnMut(&mut [u8], &MountLine) -> bool,
) -> Result<bool, Unread> {
    let cap = buf.len();
    let mut have = 0usize;
    let mut skipping = false;
    loop {
        let room = buf.get_mut(have..).unwrap_or(&mut []);
        let n = read(room);
        if n < 0 {
            return Err(Unread::Read);
        }
        let Some(n) = usize::try_from(n).ok().filter(|&n| n > 0) else {
            return Ok(false); // the end. mountinfo ends every line with '\n'
        };
        have = have.wrapping_add(n);
        let mut start = 0usize;
        while let Some(m) = mountinfo_next(buf, have, &mut start, &mut skipping) {
            if f(buf, &m) {
                return Ok(true);
            }
        }
        if start == 0 && have == cap && !skipping {
            // A line longer than the buffer. Its fields are read from
            // the buffer it fills, and the carry drops the rest.
            let Some(m) = mountinfo_long(buf, have) else {
                return Err(Unread::Line);
            };
            if f(buf, &m) {
                return Ok(true);
            }
        }
        have = mountinfo_carry(buf, have, start, &mut skipping);
    }
}

/// The next mount point under /sys among the complete lines of
/// buf[..have] from *start, which moves past them, as mountinfo_next
/// reads them.
pub fn mountinfo_next_sys(
    buf: &mut [u8],
    have: usize,
    start: &mut usize,
    skipping: &mut bool,
) -> Option<Span> {
    loop {
        let m = mountinfo_next(buf, have, start, skipping)?;
        let path = m.point.of(buf);
        if path == b"/sys" || path.starts_with(b"/sys/") {
            return Some(m.point);
        }
    }
}

/// What a mount fiberd made is named by: the source of every file system
/// fiberd mounts starts with it (the gVisor backend's templates tmpfs is
/// fiberd-templates). pkg/backend names the same prefix.
pub const FIBERD_SOURCE: &[u8] = b"fiberd-";

/// The largest major:minor the dev field can hold.
const DEV_MAX: usize = 24;

/// The root mount of a namespace, by the dev and root fields of the
/// last mountinfo line at /. A bind of / repeats both at another mount
/// point, which is how a proc home's restore root is known.
pub struct RootId {
    dev: [u8; DEV_MAX],
    dev_len: usize,
    root: [u8; crate::abi::KEEP_MAX],
    root_len: usize,
    /// Whether a line at / was seen at all.
    pub found: bool,
}

impl RootId {
    /// No line at / seen yet.
    pub const fn new() -> Self {
        RootId {
            dev: [0; DEV_MAX],
            dev_len: 0,
            root: [0; crate::abi::KEEP_MAX],
            root_len: 0,
            found: false,
        }
    }

    /// Keeps m's dev and root when m is at /. A later line at / replaces
    /// an earlier one, since the last is the one a path lookup sees.
    pub fn note(&mut self, buf: &[u8], m: &MountLine) {
        if m.point.of(buf) != b"/" {
            return;
        }
        let dev = m.dev.of(buf);
        let root = m.root.of(buf);
        if dev.len() > DEV_MAX || root.len() > self.root.len() {
            return;
        }
        self.dev_len = sys::append(&mut self.dev, 0, dev);
        self.root_len = sys::append(&mut self.root, 0, root);
        self.found = true;
    }

    /// Whether m shows the same directory as / does.
    fn is_bind_of_root(&self, buf: &[u8], m: &MountLine) -> bool {
        self.found
            && m.dev.of(buf) == self.dev.get(..self.dev_len).unwrap_or(&[])
            && m.root.of(buf) == self.root.get(..self.root_len).unwrap_or(&[])
    }
}

impl Default for RootId {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether m is a mount some fiberd home made, which no fiber needs and
/// which goes away with that home: a file system whose source names
/// fiberd (FIBERD_SOURCE), or a bind of / (a proc home's restore root,
/// which besides shows every hidden path uncovered). The root mount
/// itself is never one.
pub fn fiberd_mount(buf: &[u8], m: &MountLine, root: &RootId) -> bool {
    if m.point.of(buf) == b"/" {
        return false;
    }
    m.source.of(buf).starts_with(FIBERD_SOURCE) || root.is_bind_of_root(buf, m)
}

/// Moves the partial line left at start of buf[..have] to the front and
/// returns its length. A full buffer with no newline is dropped instead,
/// with *skipping set, so the rest of that line is skipped rather than
/// read as lines of its own. stream_mounts reads such a line's head
/// (mountinfo_long) before it lets the carry drop it.
pub fn mountinfo_carry(buf: &mut [u8], have: usize, start: usize, skipping: &mut bool) -> usize {
    let have = have.min(buf.len());
    if start == 0 && have == buf.len() {
        *skipping = true;
        return 0;
    }
    let start = start.min(have);
    buf.copy_within(start..have, 0);
    have.wrapping_sub(start)
}

/// One number as sscanf's %lu reads it: white space, a sign, digits. The
/// magnitude clamps at ULONG_MAX before the sign applies, so "-1" is
/// ULONG_MAX. None when there is no number.
pub(crate) fn scan_ulong(s: &[u8], i: &mut usize) -> Option<u64> {
    while s.get(*i).is_some_and(|&c| is_space(c)) {
        *i = i.wrapping_add(1);
    }
    let negative = match s.get(*i) {
        Some(b'-') => {
            *i = i.wrapping_add(1);
            true
        }
        Some(b'+') => {
            *i = i.wrapping_add(1);
            false
        }
        _ => false,
    };
    let mut v = 0u64;
    let mut digits = 0usize;
    let mut over = false;
    while let Some(&c) = s.get(*i)
        && c.is_ascii_digit()
    {
        *i = i.wrapping_add(1);
        digits = digits.wrapping_add(1);
        if over {
            continue;
        }
        match v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c.wrapping_sub(b'0'))))
        {
            Some(next) => v = next,
            None => over = true,
        }
    }
    if digits == 0 {
        return None;
    }
    Some(if over {
        u64::MAX
    } else if negative {
        v.wrapping_neg()
    } else {
        v
    })
}

/// The first three numbers of a uid_map, up to its first NUL, as
/// sscanf("%lu %lu %lu") reads them. None when fewer convert.
pub fn uid_map(s: &[u8]) -> Option<[u64; 3]> {
    let s = s.get(..sys::nul_at(s)).unwrap_or(&[]);
    let mut i = 0usize;
    let inside = scan_ulong(s, &mut i)?;
    let outside = scan_ulong(s, &mut i)?;
    let count = scan_ulong(s, &mut i)?;
    Some([inside, outside, count])
}

/// Whether /proc/self/uid_map names a user namespace other than the
/// initial one, which maps everything to itself in one line. False when
/// it does not parse.
pub fn in_child_userns(s: &[u8]) -> bool {
    uid_map(s).is_some_and(|[inside, outside, count]| {
        !(inside == 0 && outside == 0 && count == 4_294_967_295)
    })
}

/// Finds FIBERD_TOKEN in the spec environment, KEY=VALUE entries split
/// by NUL or newline. Every newline becomes a NUL. True with the token
/// NUL-ended in out. False when it is missing, empty or too long, and
/// the first FIBERD_TOKEN entry ends the search either way.
pub fn spec_token(env: &mut [u8], out: &mut [u8]) -> bool {
    let mut i = 0usize;
    while let Some(rest) = env.get(i..) {
        let at = sys::byte_at(rest, b'\n');
        if at >= rest.len() {
            break;
        }
        i = i.wrapping_add(at);
        if let Some(b) = env.get_mut(i) {
            *b = 0;
        }
        i = i.wrapping_add(1);
    }
    let mut p = 0usize;
    while p < env.len() {
        let rest = env.get(p..).unwrap_or(&[]);
        let len = sys::nul_at(rest);
        let entry = rest.get(..len).unwrap_or(&[]);
        if let Some(token) = entry.strip_prefix(b"FIBERD_TOKEN=") {
            if token.is_empty() || token.len() >= out.len() {
                return false;
            }
            let n = sys::append(out, 0, token);
            sys::append(out, n, b"\0");
            return true;
        }
        p = p.wrapping_add(len).wrapping_add(1);
    }
    false
}

/// mountinfo_next_sys over a raw buffer. Null when no mount is left.
///
/// # Safety
/// buf holds have live bytes nothing else touches, and start and
/// skipping are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_mountinfo_sys_mount(
    buf: *mut c_char,
    have: usize,
    start: *mut usize,
    skipping: *mut c_int,
) -> *mut c_char {
    // SAFETY: all three by the contract above.
    let (buf, start, skipping) = unsafe {
        (
            core::slice::from_raw_parts_mut(buf.cast::<u8>(), have),
            &mut *start,
            &mut *skipping,
        )
    };
    let mut skip = *skipping != 0;
    let found = mountinfo_next_sys(buf, have, start, &mut skip);
    *skipping = c_int::from(skip);
    found.map_or(ptr::null_mut(), |s| {
        buf.as_mut_ptr().wrapping_add(s.off).cast()
    })
}

/// mountinfo_carry over a raw buffer of cap bytes.
///
/// # Safety
/// buf holds cap live bytes nothing else touches, and skipping is
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_mountinfo_carry(
    buf: *mut c_char,
    cap: usize,
    have: usize,
    start: usize,
    skipping: *mut c_int,
) -> usize {
    // SAFETY: both by the contract above.
    let (buf, skipping) = unsafe {
        (
            core::slice::from_raw_parts_mut(buf.cast::<u8>(), cap),
            &mut *skipping,
        )
    };
    let mut skip = *skipping != 0;
    let left = mountinfo_carry(buf, have, start, &mut skip);
    *skipping = c_int::from(skip);
    left
}

/// in_child_userns on a NUL-ended uid_map. 1 for a child namespace,
/// else 0.
///
/// # Safety
/// s is a live NUL-ended string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_in_child_userns(s: *const c_char) -> c_int {
    // SAFETY: s is NUL-ended by the contract above.
    c_int::from(in_child_userns(unsafe { sys::c_bytes(s) }))
}

/// spec_token over got bytes of env and n bytes of out. Returns 1 or 0.
/// Only the tests and the line fuzz targets call it.
///
/// # Safety
/// env holds got live bytes nothing else touches, and out has room for
/// n bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_spec_token(
    env: *mut c_char,
    got: usize,
    out: *mut c_char,
    n: usize,
) -> c_int {
    // SAFETY: both by the contract above.
    let (env, out) = unsafe {
        (
            core::slice::from_raw_parts_mut(env.cast::<u8>(), got),
            core::slice::from_raw_parts_mut(out.cast::<u8>(), n),
        )
    };
    c_int::from(spec_token(env, out))
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

    #[test]
    fn unescape_mount_undoes_octal_escapes() {
        let cases: &[(&str, &[u8], &[u8])] = &[
            ("empty", b"", b""),
            ("nothing to do", b"/sys/fs/cgroup", b"/sys/fs/cgroup"),
            ("a space", b"/mnt/my\\040disk", b"/mnt/my disk"),
            ("two escapes", b"/a\\040b\\011c", b"/a b\tc"),
            ("escapes side by side", b"\\040\\040", b"  "),
            ("a lone backslash stays", b"/a\\b", b"/a\\b"),
            ("a backslash at the end stays", b"/a\\", b"/a\\"),
            ("two digits are not an escape", b"/a\\04", b"/a\\04"),
            ("a digit past 7 is not an escape", b"/a\\048", b"/a\\048"),
            ("a doubled backslash then an escape", b"\\\\040", b"\\ "),
            ("the top of the range wraps as a char", b"\\777x", b"\xffx"),
            ("an escaped NUL is a byte here", b"/sys\\000x", b"/sys\0x"),
            ("stops at the first NUL", b"/a\\040\0\\040", b"/a "),
        ];
        for (name, input, want) in cases {
            let mut s = [input, b"\0".as_slice()].concat();
            let n = unescape_mount(&mut s);
            assert_eq!(&s[..n], *want, "{name}");
            assert_eq!(s[n], 0, "{name}: NUL-ended");
        }
    }

    /// lock_sys's loop over data read chunk bytes at a time into a buffer
    /// of cap bytes. Returns the mount points it would remount, in order.
    fn mountinfo_mounts(data: &[u8], chunk: usize, cap: usize) -> Vec<Vec<u8>> {
        let mut buf = vec![0u8; cap];
        let mut have = 0usize;
        let mut skipping = false;
        let mut fed = 0usize;
        let mut got = Vec::new();
        loop {
            let room = cap - have;
            let n = (data.len() - fed).min(room).min(chunk);
            if n == 0 {
                break;
            }
            buf[have..have + n].copy_from_slice(&data[fed..fed + n]);
            fed += n;
            have += n;
            let mut start = 0usize;
            while let Some(mp) = mountinfo_next_sys(&mut buf, have, &mut start, &mut skipping) {
                assert_eq!(buf[mp.off + mp.len], 0, "the mount point is NUL-ended");
                got.push(mp.of(&buf).to_vec());
            }
            have = mountinfo_carry(&mut buf, have, start, &mut skipping);
        }
        got
    }

    #[test]
    fn mountinfo_finds_the_mounts_under_sys() {
        let lines: &[u8] = b"22 1 0:21 / /proc rw,nosuid - proc proc rw\n\
            23 1 0:22 / /sys rw,nosuid - sysfs sysfs rw\n\
            24 23 0:23 / /sys/kernel/security rw - securityfs securityfs rw\n\
            25 23 0:24 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n\
            26 1 0:25 / /system rw - tmpfs tmpfs rw\n\
            27 1 0:26 / /sysx rw - tmpfs tmpfs rw\n\
            28 23 0:27 / /sys/my\\040mount rw - tmpfs tmpfs rw\n\
            29 1 0:28 / /mnt rw - tmpfs tmpfs rw\n";
        let want: Vec<&[u8]> = vec![
            b"/sys",
            b"/sys/kernel/security",
            b"/sys/fs/cgroup",
            b"/sys/my mount",
        ];
        let cases: &[(&str, usize)] = &[
            ("one read", 8192),
            ("a line per read, nearly", 60),
            ("seven bytes a read", 7),
            ("one byte a read", 1),
        ];
        for (name, chunk) in cases {
            assert_eq!(mountinfo_mounts(lines, *chunk, 8192), want, "{name}");
        }
    }

    #[test]
    fn mountinfo_handles_odd_lines() {
        let cases: &[(&str, &[u8], &[&[u8]])] = &[
            ("empty", b"", &[]),
            ("no newline at the end is no line", b"1 2 3 4 /sys rw", &[]),
            ("fewer than five fields", b"1 2 3 4\n", &[]),
            ("exactly five fields", b"1 2 3 4 /sys\n", &[b"/sys"]),
            ("repeated spaces", b"1  2  3  4   /sys  rw\n", &[b"/sys"]),
            ("leading spaces", b"  1 2 3 4 /sys\n", &[b"/sys"]),
            ("an empty line", b"\n1 2 3 4 /sys\n", &[b"/sys"]),
            (
                "a NUL in the line ends it",
                b"1 2 3\0 4 /sys\n1 2 3 4 /sys/a\n",
                &[b"/sys/a"],
            ),
            (
                "an escaped NUL cuts the mount point",
                b"1 2 3 4 /sys\\000x\n",
                &[b"/sys"],
            ),
            (
                "an escape that makes it match",
                b"1 2 3 4 /sys\\057a\n",
                &[b"/sys/a"],
            ),
            ("only a prefix", b"1 2 3 4 /sysfs\n", &[]),
            ("the root", b"1 2 3 4 /\n", &[]),
            ("tabs are not separators", b"1\t2\t3\t4\t/sys\n", &[]),
        ];
        for (name, data, want) in cases {
            let want: Vec<Vec<u8>> = want.iter().map(|w| w.to_vec()).collect();
            assert_eq!(mountinfo_mounts(data, 8192, 8192), want, "{name}");
            assert_eq!(
                mountinfo_mounts(data, 3, 8192),
                want,
                "{name}: three bytes a read"
            );
        }
    }

    /// Every line of data as mountinfo_next reads it, read chunk bytes
    /// at a time into a buffer of cap bytes: (dev, root, point, source).
    fn mountinfo_lines(data: &[u8], chunk: usize, cap: usize) -> Vec<[Vec<u8>; 4]> {
        let mut buf = vec![0u8; cap];
        let mut have = 0usize;
        let mut skipping = false;
        let mut fed = 0usize;
        let mut got = Vec::new();
        loop {
            let room = cap - have;
            let n = (data.len() - fed).min(room).min(chunk);
            if n == 0 {
                break;
            }
            buf[have..have + n].copy_from_slice(&data[fed..fed + n]);
            fed += n;
            have += n;
            let mut start = 0usize;
            while let Some(m) = mountinfo_next(&mut buf, have, &mut start, &mut skipping) {
                assert_eq!(
                    buf[m.point.off + m.point.len],
                    0,
                    "the mount point is NUL-ended"
                );
                got.push([
                    m.dev.of(&buf).to_vec(),
                    m.root.of(&buf).to_vec(),
                    m.point.of(&buf).to_vec(),
                    m.source.of(&buf).to_vec(),
                ]);
            }
            have = mountinfo_carry(&mut buf, have, start, &mut skipping);
        }
        got
    }

    #[test]
    fn mountinfo_next_reads_the_fields() {
        fn row(f: [&str; 4]) -> [Vec<u8>; 4] {
            f.map(|s| s.as_bytes().to_vec())
        }
        let cases: &[(&str, &[u8], Vec<[Vec<u8>; 4]>)] = &[
            (
                "a full line",
                b"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw\n",
                vec![row(["98:0", "/mnt1", "/mnt2", "/dev/root"])],
            ),
            (
                "the gVisor templates tmpfs",
                b"233 232 0:66 / /var/lib/fiberd/gvisor/templates rw,nosuid,nodev,relatime - tmpfs fiberd-templates rw,mode=700\n",
                vec![row(["0:66", "/", "/var/lib/fiberd/gvisor/templates", "fiberd-templates"])],
            ),
            (
                "no optional fields",
                b"1 0 0:64 / / rw - overlay overlay rw,lowerdir=/a\n",
                vec![row(["0:64", "/", "/", "overlay"])],
            ),
            (
                "two optional fields",
                b"1 0 0:64 / / rw shared:1 master:2 - overlay overlay rw\n",
                vec![row(["0:64", "/", "/", "overlay"])],
            ),
            (
                "no separator leaves the source empty",
                b"1 2 3:4 /r /p rw\n",
                vec![row(["3:4", "/r", "/p", ""])],
            ),
            (
                "a separator with the type alone leaves the source empty",
                b"1 2 3:4 /r /p rw - tmpfs\n",
                vec![row(["3:4", "/r", "/p", ""])],
            ),
            (
                "exactly five fields",
                b"1 2 3:4 /r /p\n",
                vec![row(["3:4", "/r", "/p", ""])],
            ),
            ("fewer than five fields is no line", b"1 2 3:4 /r\n", vec![]),
            (
                "an escaped mount point, the source as written",
                b"1 2 3:4 /r /my\\040dir rw - tmpfs my\\040src rw\n",
                vec![row(["3:4", "/r", "/my dir", "my\\040src"])],
            ),
            (
                "two lines",
                b"1 0 0:64 / / rw - overlay overlay rw\n2 1 0:64 / /root-bind rw - overlay overlay rw\n",
                vec![
                    row(["0:64", "/", "/", "overlay"]),
                    row(["0:64", "/", "/root-bind", "overlay"]),
                ],
            ),
        ];
        for (name, data, want) in cases {
            for chunk in [8192usize, 7, 1] {
                assert_eq!(
                    mountinfo_lines(data, chunk, 8192),
                    *want,
                    "{name}, {chunk} bytes a read"
                );
            }
        }
    }

    /// stream_mounts over data fed chunk bytes a read through a buffer of
    /// cap bytes, as each_mount runs it, collecting every line's fields.
    fn streamed(data: &[u8], chunk: usize, cap: usize) -> Result<Vec<[Vec<u8>; 4]>, Unread> {
        let mut buf = vec![0u8; cap];
        let mut fed = 0usize;
        let mut got = Vec::new();
        stream_mounts(
            &mut buf,
            |room| {
                let n = (data.len() - fed).min(room.len()).min(chunk);
                room[..n].copy_from_slice(&data[fed..fed + n]);
                fed += n;
                n as isize
            },
            |buf, m| {
                got.push([
                    m.dev.of(buf).to_vec(),
                    m.root.of(buf).to_vec(),
                    m.point.of(buf).to_vec(),
                    m.source.of(buf).to_vec(),
                ]);
                false
            },
        )?;
        Ok(got)
    }

    /// An overlay line's superoptions, lowerdir of n bytes.
    fn lowerdir(n: usize) -> String {
        format!("rw,lowerdir={}", "x".repeat(n))
    }

    #[test]
    fn stream_mounts_reads_a_line_longer_than_its_buffer() {
        fn row(f: [&str; 4]) -> [Vec<u8>; 4] {
            f.map(|s| s.as_bytes().to_vec())
        }
        let long = format!("1 0 0:64 / / rw - overlay overlay {}\n", lowerdir(9000));
        let bind = format!(
            "2 1 0:64 / /var/lib/fiberd/private/root rw - overlay overlay {}\n",
            lowerdir(9000)
        );
        let short = "3 1 0:66 / /x rw - tmpfs fiberd-templates rw\n";
        let wide_root = format!(
            "1 0 0:64 /{} /{} rw - ext4 /dev/sda1 rw\n",
            "r".repeat(4100),
            "p".repeat(4100)
        );
        let cases: &[(&str, String, Result<Vec<[Vec<u8>; 4]>, Unread>)] = &[
            (
                "a / line of 9 KiB",
                long.clone(),
                Ok(vec![row(["0:64", "/", "/", "overlay"])]),
            ),
            (
                "a long / line, a long bind of /, a short line",
                [long.as_str(), bind.as_str(), short].concat(),
                Ok(vec![
                    row(["0:64", "/", "/", "overlay"]),
                    row(["0:64", "/", "/var/lib/fiberd/private/root", "overlay"]),
                    row(["0:66", "/", "/x", "fiberd-templates"]),
                ]),
            ),
            (
                "a short line, then a long one",
                [short, long.as_str()].concat(),
                Ok(vec![
                    row(["0:66", "/", "/x", "fiberd-templates"]),
                    row(["0:64", "/", "/", "overlay"]),
                ]),
            ),
            (
                "a long line with no newline at the end",
                long[..long.len() - 1].to_string(),
                Ok(vec![row(["0:64", "/", "/", "overlay"])]),
            ),
            (
                "paths alone fill the buffer",
                [wide_root.as_str(), short].concat(),
                Err(Unread::Line),
            ),
            (
                "the source cut by the buffer",
                format!("1 0 0:64 / / {} - overlay overlay rw\n", "o".repeat(8170)),
                Err(Unread::Line),
            ),
            (
                "no separator inside the buffer",
                format!("1 0 0:64 / / {} - overlay overlay rw\n", "o".repeat(9000)),
                Err(Unread::Line),
            ),
        ];
        for (name, data, want) in cases {
            for chunk in [8192usize, 4096, 1000, 7] {
                assert_eq!(
                    streamed(data.as_bytes(), chunk, 8192),
                    *want,
                    "{name}, {chunk} bytes a read"
                );
            }
        }
        let mut buf = [0u8; 16];
        assert_eq!(
            stream_mounts(&mut buf, |_| -1, |_, _| false),
            Err(Unread::Read),
            "a failed read"
        );
    }

    /// The mount points of lines fiberd_mount says are another home's,
    /// with the root known from the lines at /, read as
    /// drop_fiberd_mounts reads them, through an 8 KiB buffer.
    fn foreign_points(data: &[u8]) -> Result<Vec<Vec<u8>>, Unread> {
        let mut root = RootId::new();
        let mut buf = [0u8; 8192];
        let mut fed = 0usize;
        stream_mounts(
            &mut buf,
            |room| {
                let n = (data.len() - fed).min(room.len());
                room[..n].copy_from_slice(&data[fed..fed + n]);
                fed += n;
                n as isize
            },
            |buf, m| {
                root.note(buf, m);
                false
            },
        )?;
        let mut got = Vec::new();
        let mut fed = 0usize;
        stream_mounts(
            &mut buf,
            |room| {
                let n = (data.len() - fed).min(room.len());
                room[..n].copy_from_slice(&data[fed..fed + n]);
                fed += n;
                n as isize
            },
            |buf, m| {
                if fiberd_mount(buf, m, &root) {
                    got.push(m.point.of(buf).to_vec());
                }
                false
            },
        )?;
        Ok(got)
    }

    #[test]
    fn fiberd_mount_knows_other_homes_mounts() {
        const ROOT: &[u8] = b"1 0 0:64 / / rw - overlay overlay rw\n";
        let cases: &[(&str, Vec<u8>, &[&[u8]])] = &[
            ("the root alone", ROOT.to_vec(), &[]),
            (
                "the gVisor templates tmpfs, by its source",
                [ROOT, b"2 1 0:66 / /var/lib/fiberd/gvisor/templates rw - tmpfs fiberd-templates rw\n"].concat(),
                &[b"/var/lib/fiberd/gvisor/templates"],
            ),
            (
                "any source fiberd names",
                [ROOT, b"2 1 0:66 / /x rw - tmpfs fiberd-anything rw\n"].concat(),
                &[b"/x"],
            ),
            (
                "a tmpfs of anyone else is kept",
                [ROOT, b"2 1 0:66 / /tmp rw - tmpfs tmpfs rw\n3 1 0:67 / /run rw - tmpfs none rw\n"].concat(),
                &[],
            ),
            (
                "the prefix inside the source is not the prefix",
                [ROOT, b"2 1 0:66 / /x rw - tmpfs my-fiberd-thing rw\n"].concat(),
                &[],
            ),
            (
                "a restore root, a bind of / in the test's name",
                [ROOT, b"2 1 0:64 / /tmp/fiberd-root-4242 rw - overlay overlay rw\n"].concat(),
                &[b"/tmp/fiberd-root-4242"],
            ),
            (
                "a restore root in production's name",
                [ROOT, b"2 1 0:64 / /var/lib/fiberd/private/root rw - overlay overlay rw\n"].concat(),
                &[b"/var/lib/fiberd/private/root"],
            ),
            (
                "a bind of a directory of / is kept",
                [ROOT, b"2 1 0:64 /srv /mnt/srv rw - overlay overlay rw\n"].concat(),
                &[],
            ),
            (
                "the same root path on another device is kept",
                [ROOT, b"2 1 8:1 / /mnt/disk rw - ext4 /dev/sda1 rw\n"].concat(),
                &[],
            ),
            (
                "a root with a subvolume, and its bind",
                b"1 0 0:30 /@ / rw - btrfs /dev/sda2 rw\n2 1 0:30 /@ /tmp/fiberd-root-1 rw - btrfs /dev/sda2 rw\n3 1 0:30 /@home /home rw - btrfs /dev/sda2 rw\n".to_vec(),
                &[b"/tmp/fiberd-root-1"],
            ),
            (
                "an overmounted root, the last line at / is the root",
                b"1 0 0:64 / / rw - overlay overlay rw\n2 1 8:1 / / rw - ext4 /dev/sda1 rw\n3 2 8:1 / /mnt/bind rw - ext4 /dev/sda1 rw\n4 2 0:64 / /mnt/old rw - overlay overlay rw\n".to_vec(),
                &[b"/mnt/bind"],
            ),
            (
                "no line at / leaves only the sources",
                b"2 1 0:64 / /tmp/fiberd-root-1 rw - overlay overlay rw\n3 1 0:66 / /x rw - tmpfs fiberd-templates rw\n".to_vec(),
                &[b"/x"],
            ),
            (
                "a root with escapes in its path matches as written",
                b"1 0 0:30 /my\\040vol / rw - btrfs /dev/sda2 rw\n2 1 0:30 /my\\040vol /tmp/r rw - btrfs /dev/sda2 rw\n".to_vec(),
                &[b"/tmp/r"],
            ),
            (
                "the zygote's own covers are kept",
                [ROOT, b"2 1 0:70 / /var/lib/fiberd/private rw - tmpfs tmpfs ro\n3 1 0:71 / /run/fiberd rw - tmpfs tmpfs ro\n"].concat(),
                &[],
            ),
            (
                "an overlay root whose line passes 8 KiB, and a bind of it",
                format!(
                    "1 0 0:64 / / rw - overlay overlay {}\n2 1 0:64 / /var/lib/fiberd/private/root rw - overlay overlay rw\n",
                    lowerdir(9000)
                )
                .into_bytes(),
                &[b"/var/lib/fiberd/private/root"],
            ),
            (
                "a bind of / whose own line passes 8 KiB",
                format!(
                    "1 0 0:64 / / rw - overlay overlay rw\n2 1 0:64 / /tmp/fiberd-root-7 rw - overlay overlay {}\n3 1 0:64 /srv /mnt/srv rw - overlay overlay {}\n",
                    lowerdir(9000),
                    lowerdir(9000)
                )
                .into_bytes(),
                &[b"/tmp/fiberd-root-7"],
            ),
            (
                "a fiberd source whose line passes 8 KiB",
                format!("{}2 1 0:66 / /x rw - tmpfs fiberd-templates {}\n", String::from_utf8_lossy(ROOT), lowerdir(9000)).into_bytes(),
                &[b"/x"],
            ),
        ];
        for (name, data, want) in cases {
            let want: Vec<Vec<u8>> = want.iter().map(|w| w.to_vec()).collect();
            assert_eq!(foreign_points(data), Ok(want), "{name}");
        }
        let wide = format!(
            "1 0 0:64 /{} /{} rw - ext4 /dev/sda1 rw\n",
            "r".repeat(4100),
            "p".repeat(4100)
        );
        assert_eq!(
            foreign_points(wide.as_bytes()),
            Err(Unread::Line),
            "a line whose fields do not fit fails closed"
        );
    }

    #[test]
    fn mountinfo_skips_a_line_longer_than_the_buffer() {
        // A buffer of 64 bytes, lines around it. A line fits when its
        // newline lands inside the buffer, so 64 bytes with the newline
        // is read and 65 is dropped.
        let long = [b"1 2 3 4 /sys/".as_slice(), &[b'x'; 100], b" rw\n"].concat();
        let exact = [b"1 2 3 4 /sys/".as_slice(), &[b'y'; 64 - 13 - 3], b" r\n"].concat();
        assert_eq!(exact.len(), 64);
        let over = [b"1 2 3 4 /sys/".as_slice(), &[b'y'; 65 - 13 - 3], b" r\n"].concat();
        let exact_mp = &exact[8..61];
        assert_eq!(&exact_mp[..5], b"/sys/");
        let cases: Vec<(&str, Vec<u8>, Vec<&[u8]>)> = vec![
            (
                "a long line between two short ones",
                [b"1 2 3 4 /sys/a\n".as_slice(), &long, b"1 2 3 4 /sys/b\n"].concat(),
                vec![b"/sys/a", b"/sys/b"],
            ),
            (
                "a long line first",
                [long.as_slice(), b"1 2 3 4 /sys/b\n"].concat(),
                vec![b"/sys/b"],
            ),
            (
                "a long line last, unfinished",
                [b"1 2 3 4 /sys/a\n".as_slice(), &long[..long.len() - 1]].concat(),
                vec![b"/sys/a"],
            ),
            (
                "a line of exactly the buffer is read",
                [exact.as_slice(), b"1 2 3 4 /sys/b\n"].concat(),
                vec![exact_mp, b"/sys/b"],
            ),
            (
                "a line one past the buffer is dropped",
                [over.as_slice(), b"1 2 3 4 /sys/b\n"].concat(),
                vec![b"/sys/b"],
            ),
            (
                "a line one short of the buffer is read",
                [&exact[..62], b"\n1 2 3 4 /sys/b\n"].concat(),
                vec![exact_mp, b"/sys/b"],
            ),
        ];
        for (name, data, want) in cases {
            let want: Vec<Vec<u8>> = want.iter().map(|w| w.to_vec()).collect();
            for chunk in [64usize, 17, 1] {
                assert_eq!(
                    mountinfo_mounts(&data, chunk, 64),
                    want,
                    "{name}, {chunk} bytes a read"
                );
            }
        }
    }

    #[test]
    fn the_mountinfo_entries_drive_a_c_buffer() {
        let mut buf = [0u8; 64];
        let data = b"1 2 3 4 /sys\n1 2 3 4 /proc\n1 2 3 4 /sys/fs/cg";
        buf[..data.len()].copy_from_slice(data);
        let have = data.len();
        let mut start = 0usize;
        let mut skipping: c_int = 0;
        let p = buf.as_mut_ptr().cast::<c_char>();
        let mp = unsafe { fz_rs_mountinfo_sys_mount(p, have, &mut start, &mut skipping) };
        assert!(!mp.is_null());
        assert_eq!(unsafe { core::ffi::CStr::from_ptr(mp) }.to_bytes(), b"/sys");
        let mp = unsafe { fz_rs_mountinfo_sys_mount(p, have, &mut start, &mut skipping) };
        assert!(mp.is_null(), "the partial line is not a line yet");
        assert_eq!(start, 27);
        let left = unsafe { fz_rs_mountinfo_carry(p, buf.len(), have, start, &mut skipping) };
        assert_eq!(left, 18);
        assert_eq!(&buf[..left], b"1 2 3 4 /sys/fs/cg");
        assert_eq!(skipping, 0);
        // A full buffer with no newline is dropped and skipped.
        let left = unsafe { fz_rs_mountinfo_carry(p, buf.len(), buf.len(), 0, &mut skipping) };
        assert_eq!((left, skipping), (0, 1));
    }

    #[test]
    fn uid_map_scans_as_sscanf_does() {
        let cases: &[(&str, &[u8], Option<[u64; 3]>)] = &[
            (
                "the initial namespace",
                b"         0          0 4294967295\n",
                Some([0, 0, 4294967295]),
            ),
            ("a child", b"0 1000 1\n", Some([0, 1000, 1])),
            (
                "tabs and newlines between",
                b"\t0\n1000\r\n1",
                Some([0, 1000, 1]),
            ),
            (
                "no white space at the end",
                b"0 0 4294967295",
                Some([0, 0, 4294967295]),
            ),
            ("empty", b"", None),
            ("two numbers", b"0 0", None),
            ("two numbers and a word", b"0 0 many", None),
            ("a sign alone", b"0 0 -", None),
            ("a sign then a space", b"0 0 - 1", None),
            ("a plus", b"+0 +0 +4294967295", Some([0, 0, 4294967295])),
            ("a minus wraps", b"-1 0 0", Some([u64::MAX, 0, 0])),
            ("minus zero", b"-0 0 4294967295", Some([0, 0, 4294967295])),
            (
                "overflow clamps",
                b"99999999999999999999 0 0",
                Some([u64::MAX, 0, 0]),
            ),
            (
                "the largest",
                b"18446744073709551615 0 0",
                Some([u64::MAX, 0, 0]),
            ),
            (
                "one past clamps",
                b"18446744073709551616 0 0",
                Some([u64::MAX, 0, 0]),
            ),
            (
                "a negative past the range clamps too",
                b"-18446744073709551616 0 0",
                Some([u64::MAX, 0, 0]),
            ),
            (
                "the most negative",
                b"-18446744073709551615 0 0",
                Some([1, 0, 0]),
            ),
            (
                "a letter stops a number and fails the next",
                b"0x1 0 0",
                None,
            ),
            (
                "a letter after the last number is left",
                b"0 0 1x",
                Some([0, 0, 1]),
            ),
            ("a NUL cuts it", b"0 0\0 4294967295", None),
            (
                "more lines are not read",
                b"0 0 1\n1000 1000 1\n",
                Some([0, 0, 1]),
            ),
        ];
        for (name, s, want) in cases {
            assert_eq!(uid_map(s), *want, "{name}");
        }
    }

    #[test]
    fn in_child_userns_knows_the_initial_map() {
        let cases: &[(&str, &[u8], bool)] = &[
            (
                "the initial namespace",
                b"         0          0 4294967295\n",
                false,
            ),
            ("a child", b"         0       1000          1\n", true),
            (
                "a shifted root",
                b"         0     100000      65536\n",
                true,
            ),
            ("a count short of the whole", b"0 0 4294967294", true),
            ("unreadable is the initial one", b"", false),
            ("two numbers are unreadable", b"0 0", false),
            ("the whole range from one", b"1 0 4294967295", true),
        ];
        for (name, s, want) in cases {
            assert_eq!(in_child_userns(s), *want, "{name}");
            let c = [s, b"\0".as_slice()].concat();
            assert_eq!(
                unsafe { fz_rs_in_child_userns(c.as_ptr().cast()) },
                c_int::from(*want),
                "{name}: the entry"
            );
        }
    }

    #[test]
    fn spec_token_finds_fiberd_token() {
        let long = [b"FIBERD_TOKEN=".as_slice(), &[b't'; 65]].concat();
        let fits = [b"FIBERD_TOKEN=".as_slice(), &[b't'; 64]].concat();
        let cases: Vec<(&str, Vec<u8>, Option<&[u8]>)> = vec![
            ("empty", b"".to_vec(), None),
            (
                "NUL separated",
                b"PATH=/bin\0FIBERD_TOKEN=abc\0HOME=/\0".to_vec(),
                Some(b"abc"),
            ),
            (
                "newline separated",
                b"PATH=/bin\nFIBERD_TOKEN=abc\nHOME=/\n".to_vec(),
                Some(b"abc"),
            ),
            (
                "no separator at the end",
                b"FIBERD_TOKEN=abc".to_vec(),
                Some(b"abc"),
            ),
            ("not there", b"PATH=/bin\0HOME=/\0".to_vec(), None),
            ("a prefix of the name", b"FIBERD_TOKE=abc\0".to_vec(), None),
            (
                "the name inside a value",
                b"X=FIBERD_TOKEN=abc\0".to_vec(),
                None,
            ),
            (
                "empty ends the search",
                b"FIBERD_TOKEN=\0FIBERD_TOKEN=abc\0".to_vec(),
                None,
            ),
            (
                "too long ends the search",
                [long.as_slice(), b"\0FIBERD_TOKEN=abc\0"].concat(),
                None,
            ),
            ("the longest that fits", fits.clone(), Some(&fits[13..])),
            (
                "empty entries between",
                b"\0\0\n\nFIBERD_TOKEN=abc\0".to_vec(),
                Some(b"abc"),
            ),
            (
                "the first of two",
                b"FIBERD_TOKEN=one\0FIBERD_TOKEN=two\0".to_vec(),
                Some(b"one"),
            ),
            (
                "a token with a newline is cut there",
                b"FIBERD_TOKEN=ab\nc\0".to_vec(),
                Some(b"ab"),
            ),
        ];
        for (name, env, want) in cases {
            let mut env = env.clone();
            let mut out = [0xeeu8; 65];
            let got = spec_token(&mut env, &mut out);
            assert_eq!(got, want.is_some(), "{name}");
            if let Some(w) = want {
                assert_eq!(&out[..w.len()], w, "{name}: the token");
                assert_eq!(out[w.len()], 0, "{name}: NUL-ended");
            } else {
                assert_eq!(out[0], 0xee, "{name}: out untouched");
            }
            assert!(!env.contains(&b'\n'), "{name}: every newline became a NUL");
        }
    }

    #[test]
    fn the_spec_token_entry_copies_into_c_storage() {
        let cases: &[(&str, &[u8], c_int, &[u8])] = &[
            ("found", b"A=1\nFIBERD_TOKEN=t0k\n", 1, b"t0k\0"),
            ("missing", b"A=1\n", 0, b"\xee\xee\xee\xee"),
        ];
        for (name, env, want, out_want) in cases {
            let mut env = env.to_vec();
            let mut out = [0xeeu8; 65];
            let rc = unsafe {
                fz_rs_spec_token(
                    env.as_mut_ptr().cast(),
                    env.len(),
                    out.as_mut_ptr().cast(),
                    out.len(),
                )
            };
            assert_eq!(rc, *want, "{name}");
            assert_eq!(&out[..4], *out_want, "{name}");
        }
    }
}
