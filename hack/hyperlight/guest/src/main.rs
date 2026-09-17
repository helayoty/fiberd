//! The reference workload (hack/zygote/refzygote.c) as a Hyperlight guest.
//!
//! The helper (hack/hyperlight/helper) calls `Init` once in the warm
//! sandbox and snapshots it; every fiber is a sandbox restored from that
//! snapshot, and the helper maps the fiber's line protocol (ping, incr,
//! get, dirty) onto the guest functions below. State lives in guest
//! memory, so it travels with a snapshot: that is what park and resume
//! move.
//!
//! Build: `cargo hyperlight build --release` (hack/hyperlight/build.sh).
#![no_std]
#![no_main]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI64, Ordering};

use hyperlight_guest_bin::error::Result;
use hyperlight_guest_bin::guest_function;

static COUNTER: AtomicI64 = AtomicI64::new(0);

/// Allocations kept on purpose: the working set the guest has dirtied.
/// The guest is single-threaded, so an UnsafeCell is enough.
struct Kept(UnsafeCell<Vec<Vec<u8>>>);
// SAFETY: guest functions run one at a time on one vCPU.
unsafe impl Sync for Kept {}
static KEPT: Kept = Kept(UnsafeCell::new(Vec::new()));

fn touch(bytes: usize) -> usize {
    let mut v: Vec<u8> = Vec::with_capacity(bytes);
    // SAFETY: capacity is bytes; every page is written below.
    unsafe { v.set_len(bytes) };
    let mut i = 0;
    while i < bytes {
        v[i] = (i >> 12) as u8;
        i += 4096;
    }
    // SAFETY: single-threaded guest, see Kept.
    unsafe { (*KEPT.0.get()).push(v) };
    bytes
}

/// Init is the expensive part, paid once in the warm sandbox: a heap of
/// `mb` MiB touched page by page.
#[guest_function("Init")]
fn init(mb: i64) -> Result<i64> {
    let bytes = touch((mb.max(0) as usize) << 20);
    // Stand in for a JIT or a graph build.
    let mut x: u32 = 1;
    for _ in 0..2_000_000u32 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
    }
    core::hint::black_box(x);
    Ok(bytes as i64)
}

#[guest_function("Ping")]
fn ping() -> Result<String> {
    Ok(String::from("pong"))
}

#[guest_function("Incr")]
fn incr() -> Result<i64> {
    Ok(COUNTER.fetch_add(1, Ordering::Relaxed) + 1)
}

#[guest_function("Get")]
fn get() -> Result<i64> {
    Ok(COUNTER.load(Ordering::Relaxed))
}

/// Dirty grows the working set by `bytes`: new pages, touched and kept,
/// which is what a restored sandbox can do (there is no inherited heap
/// to break copy-on-write on).
#[guest_function("Dirty")]
fn dirty(bytes: i64) -> Result<i64> {
    Ok(touch(bytes.max(0) as usize) as i64)
}
