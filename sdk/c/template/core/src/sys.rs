//! The libc calls the core makes, each behind a safe shape. Byte scans go
//! through libc, whose memchr and strlen are the SIMD loops the C file
//! had. A Rust byte loop measured 8x slower on a 4 KB handoff record
//! (bin/rust-core/DESIGN.md, section 5).

use core::ffi::c_char;

/// The index of the first NUL in s, or s.len() when there is none.
pub fn nul_at(s: &[u8]) -> usize {
    if s.is_empty() {
        return 0;
    }
    // SAFETY: memchr reads at most s.len() bytes of s, which is live.
    let p = unsafe { libc::memchr(s.as_ptr().cast(), 0, s.len()) };
    if p.is_null() {
        s.len()
    } else {
        (p as usize).wrapping_sub(s.as_ptr() as usize)
    }
}

/// The bytes of a C string, the NUL not included.
///
/// # Safety
/// s is a NUL-ended string that stays live and unchanged for 'a.
pub unsafe fn c_bytes<'a>(s: *const c_char) -> &'a [u8] {
    // SAFETY: strlen reads s up to its NUL, and the slice covers the same
    // bytes, which the caller keeps live.
    unsafe { core::slice::from_raw_parts(s.cast(), libc::strlen(s)) }
}

/// Copies src into buf at off, as far as it fits, and returns the new
/// offset.
pub fn append(buf: &mut [u8], off: usize, src: &[u8]) -> usize {
    let Some(room) = buf.get_mut(off..) else {
        return off;
    };
    let n = src.len().min(room.len());
    if let (Some(dst), Some(src)) = (room.get_mut(..n), src.get(..n)) {
        dst.copy_from_slice(src);
    }
    off.wrapping_add(n)
}

/// Writes v in decimal into buf at off, as far as it fits, and returns
/// the new offset. No formatting machinery, as child_say in C.
pub fn append_decimal(buf: &mut [u8], off: usize, v: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    let mut v = v;
    loop {
        i = i.wrapping_sub(1);
        if let Some(d) = digits.get_mut(i) {
            *d = b'0'.wrapping_add((v % 10) as u8);
        }
        v /= 10;
        if v == 0 {
            break;
        }
    }
    append(buf, off, digits.get(i..).unwrap_or(&[]))
}

/// Writes all of buf to fd, retrying on EINTR, and gives up on any other
/// error. For the panic line, where nothing can be done about one.
pub fn write_all(fd: i32, buf: &[u8]) {
    let mut rest = buf;
    while !rest.is_empty() {
        // SAFETY: write reads at most rest.len() bytes of rest, which is live.
        let n = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if n < 0 {
            // SAFETY: errno is the thread's own.
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return;
        }
        let Some(left) = usize::try_from(n).ok().and_then(|n| rest.get(n..)) else {
            return;
        };
        rest = left;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]
    use super::*;

    #[test]
    fn nul_at_finds_the_first_nul() {
        let cases: &[(&str, &[u8], usize)] = &[
            ("empty", b"", 0),
            ("no NUL", b"abc", 3),
            ("NUL at the end", b"abc\0", 3),
            ("NUL first", b"\0abc", 0),
            ("the first of two", b"a\0b\0", 1),
        ];
        for (name, input, want) in cases {
            assert_eq!(nul_at(input), *want, "{name}");
        }
    }

    #[test]
    fn append_decimal_formats_like_c() {
        let cases: &[(&str, u32, &str)] = &[
            ("zero", 0, "0"),
            ("one digit", 7, "7"),
            ("many digits", 1234, "1234"),
            ("the largest", u32::MAX, "4294967295"),
        ];
        for (name, v, want) in cases {
            let mut buf = [0u8; 16];
            let n = append_decimal(&mut buf, 0, *v);
            assert_eq!(&buf[..n], want.as_bytes(), "{name}");
        }
    }

    #[test]
    fn append_stops_at_the_buffer() {
        let cases: &[(&str, usize, &[u8], usize, &[u8])] = &[
            ("fits", 0, b"abc", 3, b"abc\0"),
            ("fills", 1, b"abc", 4, b"\0abc"),
            ("cut", 2, b"abc", 4, b"\0\0ab"),
            ("past the end", 9, b"abc", 9, b"\0\0\0\0"),
        ];
        for (name, off, src, want_off, want) in cases {
            let mut buf = [0u8; 4];
            assert_eq!(append(&mut buf, *off, src), *want_off, "{name}");
            assert_eq!(&buf, want, "{name}");
        }
    }
}
