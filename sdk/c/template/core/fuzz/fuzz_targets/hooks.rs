//! The fz_fuzz_* hooks the fuzzshim core calls in place of syscall,
//! mount, umount2, mkdir and open (core/src/sys.rs). Every target
//! includes this file. Each hook is the real call until a target
//! installs a Shim, once, before its first input.
#![allow(dead_code)]

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use std::sync::OnceLock;

/// What a target puts in place of each call. None keeps the real one.
#[derive(Default)]
pub struct Shim {
    /// syscall(2) with the five arguments the core always passes.
    pub syscall: Option<fn(c_long, [c_long; 5]) -> c_long>,
    /// mount(2).
    pub mount:
        Option<fn(*const c_char, *const c_char, *const c_char, c_ulong, *const c_void) -> c_int>,
    /// umount2(2).
    pub umount2: Option<fn(*const c_char, c_int) -> c_int>,
    /// mkdir(2).
    pub mkdir: Option<fn(*const c_char, libc::mode_t) -> c_int>,
    /// open(2), with the mode the core passed or 0.
    pub open: Option<fn(*const c_char, c_int, libc::mode_t) -> c_int>,
}

static SHIM: OnceLock<Shim> = OnceLock::new();

/// Installs the target's shim. Once, before the first input.
pub fn install(s: Shim) {
    assert!(SHIM.set(s).is_ok(), "a second shim");
}

fn shim() -> Option<&'static Shim> {
    SHIM.get()
}

/// A refusal with errno e, as a libc call gives one.
pub fn fail(e: c_int) -> c_int {
    // SAFETY: errno is the thread's own.
    unsafe { *libc::__errno_location() = e };
    -1
}

/// The core's sys::syscall always passes five arguments, zero past what
/// the call takes, so five are read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_fuzz_syscall(nr: c_long, mut args: ...) -> c_long {
    // SAFETY: five longs follow, by the comment above.
    let a = unsafe {
        [
            args.next_arg::<c_long>(),
            args.next_arg::<c_long>(),
            args.next_arg::<c_long>(),
            args.next_arg::<c_long>(),
            args.next_arg::<c_long>(),
        ]
    };
    if let Some(f) = shim().and_then(|s| s.syscall) {
        return f(nr, a);
    }
    // SAFETY: what the core asked for, passed on as it was.
    unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4]) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_fuzz_mount(
    src: *const c_char,
    target: *const c_char,
    fstype: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_int {
    if let Some(f) = shim().and_then(|s| s.mount) {
        return f(src, target, fstype, flags, data);
    }
    // SAFETY: what the core asked for, passed on as it was.
    unsafe { libc::mount(src, target, fstype, flags, data) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_fuzz_umount2(target: *const c_char, flags: c_int) -> c_int {
    if let Some(f) = shim().and_then(|s| s.umount2) {
        return f(target, flags);
    }
    // SAFETY: what the core asked for, passed on as it was.
    unsafe { libc::umount2(target, flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_fuzz_mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    if let Some(f) = shim().and_then(|s| s.mkdir) {
        return f(path, mode);
    }
    // SAFETY: what the core asked for, passed on as it was.
    unsafe { libc::mkdir(path, mode) }
}

/// open reads a mode only when the flags ask to create a file.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_fuzz_open(path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    let mut mode: libc::mode_t = 0;
    if flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE {
        // SAFETY: the core passes a mode with these flags (sys::open_mode).
        mode = unsafe { args.next_arg::<c_int>() } as libc::mode_t;
    }
    if let Some(f) = shim().and_then(|s| s.open) {
        return f(path, flags, mode);
    }
    // SAFETY: what the core asked for, passed on as it was.
    unsafe { libc::open(path, flags, mode as c_int) }
}
