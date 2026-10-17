//! What the zygote reads out of files the kernel and the sandbox hand
//! it, taken apart as the C file took them apart: the mount points of
//! /proc/self/mountinfo for lock_sys, /proc/self/uid_map for
//! in_child_userns and the gVisor spec environment for spec_token. The
//! open, the read and every mount stay in C. Only buffer logic is here,
//! and the child-path rules hold as in line.rs.
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
    // C stores it through a char, so 8 bits of it.
    Some(v as u8)
}

/// unescape_mount in C: undoes mountinfo's octal escapes (\040 for a
/// space) in place, over s up to its first NUL, and NUL-ends the result.
/// Returns the new length, the NUL not counted. A backslash that starts
/// no escape stays.
pub fn unescape_mount(s: &mut [u8]) -> usize {
    let end = sys::nul_at(s);
    let (mut r, mut w) = (0usize, 0usize);
    loop {
        let rest = s.get(r..end).unwrap_or(&[]);
        let run = sys::byte_at(rest, b'\\');
        // The bytes before the backslash move down as one, which the
        // common line, with no escape at all, never needs.
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

/// lock_sys's line loop in C: the next mount point under /sys among the
/// complete lines of buf[..have] from *start, which it moves past them.
/// The mount point is the fifth field, unescaped in place and NUL-ended,
/// so the caller hands it to mount as a C string. None when no complete
/// line is left. Every newline passed becomes a NUL, and a line that
/// began before the buffer (*skipping) is dropped and clears the flag.
pub fn mountinfo_next_sys(
    buf: &mut [u8],
    have: usize,
    start: &mut usize,
    skipping: &mut bool,
) -> Option<Span> {
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
        // 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
        // (0)(1)(2)  (3)   (4) is the mount point. strtok_r stops at a
        // NUL inside the line, as it did.
        let line = buf.get(line_start..line_end).unwrap_or(&[]);
        let nul = line_start.wrapping_add(sys::nul_at(line));
        let mut t = Tokens::within(line_start, nul, b' ');
        let mut mp = None;
        for _ in 0..5 {
            mp = t.next(buf);
            if mp.is_none() {
                break;
            }
        }
        let Some(mp) = mp else { continue };
        // The token ends in a NUL, the one strtok_r wrote or the line's.
        let field = buf.get_mut(mp.off..).unwrap_or(&mut []);
        let len = unescape_mount(field);
        // An escaped NUL cuts the C string the mount sees.
        let len = sys::nul_at(field.get(..len).unwrap_or(&[]));
        let path = field.get(..len).unwrap_or(&[]);
        if path == b"/sys" || path.starts_with(b"/sys/") {
            return Some(Span { off: mp.off, len });
        }
    }
}

/// lock_sys's carry in C, after the complete lines of buf[..have] are
/// done at start. The partial line left moves to the front and its
/// length is returned. A full buffer with no newline in it is dropped
/// instead, with *skipping set, so the rest of that line is skipped to
/// its newline rather than read as lines of its own.
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

/// One %lu of sscanf in C: white space, a sign, digits, read as strtoul
/// reads them. The magnitude clamps at ULONG_MAX before the sign is
/// applied, so "-1" is ULONG_MAX. None when there is no number there.
fn scan_ulong(s: &[u8], i: &mut usize) -> Option<u64> {
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

/// sscanf(buf, "%lu %lu %lu") in C over a uid_map read up to its first
/// NUL: the three numbers, or None when fewer convert.
pub fn uid_map(s: &[u8]) -> Option<[u64; 3]> {
    let s = s.get(..sys::nul_at(s)).unwrap_or(&[]);
    let mut i = 0usize;
    let inside = scan_ulong(s, &mut i)?;
    let outside = scan_ulong(s, &mut i)?;
    let count = scan_ulong(s, &mut i)?;
    Some([inside, outside, count])
}

/// in_child_userns in C, on the bytes read from /proc/self/uid_map:
/// whether they name a user namespace other than the initial one, which
/// maps everything to itself in one line. False when they do not parse.
pub fn in_child_userns(s: &[u8]) -> bool {
    uid_map(s).is_some_and(|[inside, outside, count]| {
        !(inside == 0 && outside == 0 && count == 4_294_967_295)
    })
}

/// spec_token in C: finds FIBERD_TOKEN in env, the spec environment as
/// read, KEY=VALUE entries separated by NUL or newline. Every newline
/// becomes a NUL. True with the token NUL-ended in out, or false when it
/// is not there, is empty or does not fit, which ends the search as it
/// did in C.
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

/// lock_sys's line loop in C: the next mount point under /sys among the
/// complete lines of buf[..have] from *start, unescaped in place and
/// NUL-ended, or null when none is left. See mountinfo_next_sys.
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

/// lock_sys's carry in C: moves the partial line at start of buf[..have]
/// (cap bytes) to the front and returns its length, or drops a full
/// buffer with no newline, sets *skipping and returns 0.
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

/// in_child_userns in C, on uid_map as a C string: 1 for a user
/// namespace other than the initial one, else 0.
///
/// # Safety
/// s is a live NUL-ended string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_rs_in_child_userns(s: *const c_char) -> c_int {
    // SAFETY: s is NUL-ended by the contract above.
    c_int::from(in_child_userns(unsafe { sys::c_bytes(s) }))
}

/// spec_token in C: finds FIBERD_TOKEN in the got bytes of env, which it
/// cuts up in place, and copies it NUL-ended into out, n bytes. Returns
/// 1, or 0 when it is not there, is empty or does not fit.
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
    /// of cap bytes, as the C did: the mount points it would remount, in
    /// order.
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
