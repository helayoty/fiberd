//! The libc calls the core makes, each behind a safe shape. Byte scans go
//! through libc, whose memchr and strlen are the SIMD loops the C file
//! had. A Rust byte loop measured 8x slower on a 4 KB handoff record
//! (bin/rust-core/DESIGN.md, section 5).
//!
//! The second half is the seam for the calls the C fuzz harnesses shim
//! with a #define (fuzz/fuzz_control.c, fuzz/fuzz_procfiles.c). With the
//! `fuzzshim` feature each one calls the `fz_fuzz_*` hook a harness
//! defines, with the C signature the harness gives it, so no harness
//! really clones or mounts. Without the feature each is the libc call.
//! Every mount, umount2, mkdir, open and raw syscall of the core goes
//! through here, so one feature flag covers them all.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

/// The hooks the harnesses define, with exactly their C signatures.
#[cfg(feature = "fuzzshim")]
mod hook {
    use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

    unsafe extern "C" {
        pub fn fz_fuzz_syscall(nr: c_long, ...) -> c_long;
        pub fn fz_fuzz_mount(
            src: *const c_char,
            target: *const c_char,
            fstype: *const c_char,
            flags: c_ulong,
            data: *const c_void,
        ) -> c_int;
        pub fn fz_fuzz_umount2(target: *const c_char, flags: c_int) -> c_int;
        pub fn fz_fuzz_mkdir(path: *const c_char, mode: libc::mode_t) -> c_int;
        pub fn fz_fuzz_open(path: *const c_char, flags: c_int, ...) -> c_int;
    }
}

/// syscall(2) with up to five arguments, as the C file makes its raw
/// calls (clone3, clone, capset, unshare, close_range). The wrapper sets
/// errno and returns -1 as glibc's does. Missing arguments are zero,
/// which the kernel ignores and the C passed for clone's tids and tls.
///
/// # Safety
/// The arguments must be what system call nr takes, pointers live for
/// the call, and the caller must know what the call does to the process
/// (clone returns twice).
pub unsafe fn syscall(nr: c_long, args: [c_long; 5]) -> c_long {
    let [a, b, c, d, e] = args;
    #[cfg(feature = "fuzzshim")]
    // SAFETY: by the contract above, and the hook takes what syscall takes.
    unsafe {
        hook::fz_fuzz_syscall(nr, a, b, c, d, e)
    }
    #[cfg(not(feature = "fuzzshim"))]
    // SAFETY: by the contract above.
    unsafe {
        libc::syscall(nr, a, b, c, d, e)
    }
}

/// mount(2).
///
/// # Safety
/// The strings are NUL-ended and live for the call, data is what the
/// filesystem type takes or null.
pub unsafe fn mount(
    src: *const c_char,
    target: *const c_char,
    fstype: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_int {
    #[cfg(feature = "fuzzshim")]
    // SAFETY: by the contract above.
    unsafe {
        hook::fz_fuzz_mount(src, target, fstype, flags, data)
    }
    #[cfg(not(feature = "fuzzshim"))]
    // SAFETY: by the contract above.
    unsafe {
        libc::mount(src, target, fstype, flags, data)
    }
}

/// umount2(2).
///
/// # Safety
/// target is NUL-ended and live for the call.
pub unsafe fn umount2(target: *const c_char, flags: c_int) -> c_int {
    #[cfg(feature = "fuzzshim")]
    // SAFETY: by the contract above.
    unsafe {
        hook::fz_fuzz_umount2(target, flags)
    }
    #[cfg(not(feature = "fuzzshim"))]
    // SAFETY: by the contract above.
    unsafe {
        libc::umount2(target, flags)
    }
}

/// mkdir(2).
///
/// # Safety
/// path is NUL-ended and live for the call.
pub unsafe fn mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    #[cfg(feature = "fuzzshim")]
    // SAFETY: by the contract above.
    unsafe {
        hook::fz_fuzz_mkdir(path, mode)
    }
    #[cfg(not(feature = "fuzzshim"))]
    // SAFETY: by the contract above.
    unsafe {
        libc::mkdir(path, mode)
    }
}

/// open(2) without a mode, for flags that create nothing.
///
/// # Safety
/// path is NUL-ended and live for the call.
pub unsafe fn open(path: *const c_char, flags: c_int) -> c_int {
    #[cfg(feature = "fuzzshim")]
    // SAFETY: by the contract above.
    unsafe {
        hook::fz_fuzz_open(path, flags)
    }
    #[cfg(not(feature = "fuzzshim"))]
    // SAFETY: by the contract above.
    unsafe {
        libc::open(path, flags)
    }
}

/// open(2) with a mode, for O_CREAT.
///
/// # Safety
/// path is NUL-ended and live for the call.
pub unsafe fn open_mode(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    #[cfg(feature = "fuzzshim")]
    // SAFETY: by the contract above, and a mode is what the hook's
    // variadic tail takes.
    unsafe {
        hook::fz_fuzz_open(path, flags, mode as c_int)
    }
    #[cfg(not(feature = "fuzzshim"))]
    // SAFETY: by the contract above.
    unsafe {
        libc::open(path, flags, mode as c_int)
    }
}

/// The thread's errno.
pub fn errno() -> c_int {
    // SAFETY: errno is the thread's own.
    unsafe { *libc::__errno_location() }
}

/// Sets the thread's errno, once, at the boundary.
pub fn set_errno(e: c_int) {
    // SAFETY: errno is the thread's own.
    unsafe { *libc::__errno_location() = e }
}

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

/// The index of the first c in s, or s.len() when there is none.
pub fn byte_at(s: &[u8], c: u8) -> usize {
    if s.is_empty() {
        return 0;
    }
    // SAFETY: memchr reads at most s.len() bytes of s, which is live.
    let p = unsafe { libc::memchr(s.as_ptr().cast(), i32::from(c), s.len()) };
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

/// The bytes of a C string the caller may cut up, the NUL not included.
///
/// # Safety
/// s is a NUL-ended string nothing else touches for 'a.
pub unsafe fn c_bytes_mut<'a>(s: *mut c_char) -> &'a mut [u8] {
    // SAFETY: strlen reads s up to its NUL, and the slice covers the same
    // bytes, which the caller keeps live and ours.
    unsafe { core::slice::from_raw_parts_mut(s.cast(), libc::strlen(s)) }
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
    fn byte_at_finds_the_first_match() {
        let cases: &[(&str, &[u8], u8, usize)] = &[
            ("empty", b"", b' ', 0),
            ("none", b"abc", b' ', 3),
            ("first", b" abc", b' ', 0),
            ("the first of two", b"a b c", b' ', 1),
            ("a NUL is a byte like any other", b"ab\0c", 0, 2),
        ];
        for (name, input, c, want) in cases {
            assert_eq!(byte_at(input, *c), *want, "{name}");
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
