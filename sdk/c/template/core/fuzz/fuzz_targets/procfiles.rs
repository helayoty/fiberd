//! lock_sys over /proc/self/mountinfo and in_child_userns over
//! /proc/self/uid_map (core/src/prepare.rs), with the fuzz input as the
//! file. open hands out a memfd for that one path, and mount answers as
//! told, so nothing is mounted.
//!
//! The input is [mode and mount verdict][file bytes]. Bit 0 picks the
//! reader, bit 1 has every mount refused.
#![no_main]

#[path = "hooks.rs"]
mod hooks;
#[path = "sock.rs"]
mod sock;

use fiberzygote_core::prepare::{in_child_userns, lock_sys};
use libfuzzer_sys::fuzz_target;
use std::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

/// The one path the reader may open: 0 mountinfo, 1 uid_map.
static MODE: AtomicUsize = AtomicUsize::new(0);
/// What it gets, once.
static PROC_FD: AtomicI32 = AtomicI32::new(-1);
/// What the mount shim answers.
static REFUSED: AtomicBool = AtomicBool::new(false);
static MOUNTS: AtomicUsize = AtomicUsize::new(0);

const PATHS: [&CStr; 2] = [c"/proc/self/mountinfo", c"/proc/self/uid_map"];

fn open(path: *const c_char, flags: c_int, _mode: libc::mode_t) -> c_int {
    // SAFETY: the core passes a NUL-ended path.
    let path = unsafe { CStr::from_ptr(path) };
    let fd = PROC_FD.load(Ordering::Relaxed);
    if fd >= 0
        && path == PATHS[MODE.load(Ordering::Relaxed)]
        && flags & libc::O_ACCMODE == libc::O_RDONLY
    {
        PROC_FD.store(-1, Ordering::Relaxed);
        return fd;
    }
    panic!("an open of {path:?} with flags {flags:#x}, nothing else may be opened here");
}

fn mount(
    _src: *const c_char,
    target: *const c_char,
    _ty: *const c_char,
    _flags: c_ulong,
    _data: *const c_void,
) -> c_int {
    MOUNTS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the core passes a NUL-ended target.
    let target = unsafe { CStr::from_ptr(target) }.to_bytes();
    // lock_sys remounts under /sys and nowhere else.
    assert!(
        target == b"/sys" || target.starts_with(b"/sys/"),
        "a mount outside /sys"
    );
    if REFUSED.load(Ordering::Relaxed) {
        return hooks::fail(libc::EPERM);
    }
    0
}

fuzz_target!(
    init: {
        hooks::install(hooks::Shim {
            open: Some(open),
            mount: Some(mount),
            ..Default::default()
        });
    },
    |data: &[u8]| {
        let Some((&head, file)) = data.split_first() else {
            return;
        };
        let mode = usize::from(head & 1);
        let refused = head & 2 != 0;
        MODE.store(mode, Ordering::Relaxed);
        REFUSED.store(refused, Ordering::Relaxed);
        MOUNTS.store(0, Ordering::Relaxed);
        let given = sock::memfd_of(file);
        PROC_FD.store(given, Ordering::Relaxed);
        if mode == 0 {
            let rc = lock_sys();
            let mounts = MOUNTS.load(Ordering::Relaxed);
            // The file's contents cannot fail lock_sys, only the mounts.
            assert!(mounts > 0 || rc == 0, "a failure with nothing mounted");
            assert!(mounts == 0 || (rc == 0) == !refused, "an answer against the verdict");
        } else {
            in_child_userns();
            assert_eq!(MOUNTS.load(Ordering::Relaxed), 0, "in_child_userns mounted");
        }
        let fd = PROC_FD.swap(-1, Ordering::Relaxed);
        if fd >= 0 {
            sock::close(fd);
            panic!("the reader never opened its file");
        }
        // SAFETY: an integer call, a query.
        assert!(unsafe { libc::fcntl(given, libc::F_GETFD) } < 0, "the file left open");
    }
);
