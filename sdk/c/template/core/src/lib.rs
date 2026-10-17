//! The core of libfiberzygote, the zygote side of fiberd's process
//! runtime, behind the C ABI of libfiberzygote.h. The C file calls the
//! `fz_rs_*` entries for what has moved here, one concern per stage
//! (bin/rust-core/DESIGN.md). The record parser came first, then the
//! line parsers (line, procfiles), then the child's path (child, with
//! its mount steps in mounts), whose system calls go through the sys
//! seam, then the fiber-side API (fiber), whose fz_* entries are
//! exported from here directly.
//!
//! No standard library, no allocator and no lock. A fiber runs this code
//! right after its clone, where C's rule is the same. The unit tests and
//! the fuzz targets (fuzz/) link std, since their harness owns the panic,
//! and the archive check.sh guards the product build.
#![cfg_attr(not(any(test, fuzzing)), no_std)]
#![deny(unsafe_op_in_unsafe_fn, missing_docs)]

pub mod abi;
pub mod child;
pub mod fiber;
pub mod line;
pub mod mounts;
pub mod procfiles;
pub mod record;
pub mod sys;

/// The ABI the core is written for. The header's own number is read by
/// build.rs, and the two must agree.
pub const ABI_VERSION: u32 = 9;

const _: () = assert!(
    parse_decimal(env!("FZ_HEADER_ABI_VERSION")) == ABI_VERSION,
    "libfiberzygote.h moved FZ_ABI_VERSION, the core is written for 9"
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
