//! libfiberzygote, the zygote side of fiberd's process runtime. It
//! exports every `fz_*` entry of libfiberzygote.h.
//!
//! Modules: record, line and procfiles parse. child and mounts are the
//! child's path. fiber is the fiber-side API and gVisor. ctl is the
//! control channel. prepare sets up the namespace before READY. zygote
//! is the serving loop. sys is the one seam for system calls.
//!
//! No std, no allocator and one lock, the fz_report_line mutex. The
//! child never takes it before on_fiber. Tests and fuzz targets link std.
#![cfg_attr(not(any(test, fuzzing)), no_std)]
#![deny(unsafe_op_in_unsafe_fn, missing_docs)]

pub mod abi;
pub mod child;
pub mod ctl;
pub mod fiber;
pub mod line;
pub mod mounts;
pub mod prepare;
pub mod procfiles;
pub mod record;
pub mod sys;
pub mod zygote;

/// Runs the unit tests that make or reap child processes, or set the
/// process-wide control channel, one at a time. reap takes any child
/// with waitpid(-1), so beside a test that forks it would answer for
/// that test's children, and fz_report_line writes to whatever channel
/// the last test set. Every such test holds this guard for its whole
/// run. A test that panics while holding it leaves it usable.
#[cfg(test)]
pub(crate) fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The ABI the core is written for. The header's own number is read by
/// build.rs, and the two must agree.
pub const ABI_VERSION: u32 = 10;

const _: () = assert!(
    parse_decimal(env!("FZ_HEADER_ABI_VERSION")) == ABI_VERSION,
    "libfiberzygote.h moved FZ_ABI_VERSION, the core is written for 10"
);

/// A non-negative decimal, as a const for the assert above.
const fn parse_decimal(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut v = 0u32;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "FZ_ABI_VERSION is not a number");
        v = v * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    v
}

/// The prebuilt core is compiled with unwinding and keeps a reference to
/// the personality routine in its debug frames. With panic=abort it is
/// never called, so an empty symbol satisfies the link on stable.
#[cfg(not(any(test, fuzzing)))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

/// A panic is a bug. One line names where, then the process aborts. In a
/// fiber that is "died before ready: signal:6", in the zygote it ends the
/// template loudly. Nothing is formatted, since formatting could run
/// under a lock the child does not own.
#[cfg(not(any(test, fuzzing)))]
#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut line = [0u8; 512];
    let mut n = sys::append(&mut line, 0, b"libfiberzygote: panic in the Rust core at ");
    if let Some(at) = info.location() {
        n = sys::append(&mut line, n, at.file().as_bytes());
        n = sys::append(&mut line, n, b":");
        n = sys::append_decimal(&mut line, n, at.line());
    }
    n = sys::append(&mut line, n, b"\n");
    sys::write_all(2, line.get(..n).unwrap_or(&[]));
    // SAFETY: abort takes nothing and never returns.
    unsafe { libc::abort() }
}
