//! The reference workload (sdk/c/template/refzygote.c) as a Hyperlight guest.
//!
//! The helper (hack/hyperlight/helper) calls `Init` once in the warm
//! sandbox and snapshots it; every fiber is a sandbox restored from that
//! snapshot, told who it is with `Incarnate` before it serves, and the
//! helper maps the fiber's line protocol (ping, incr, get, dirty, random,
//! generation, fence, gpufill, gpucheck, gpuopen) onto the guest functions
//! below. State lives in guest memory, so it travels with a snapshot: that
//! is what park and resume move, and why every incarnation is reseeded.
//!
//! The guest reaches the grant's device engine only through the helper's
//! `Engine` host function, which puts the fiber's own fence in each line.
//!
//! Build: `cargo hyperlight build --release` (hack/hyperlight/build.sh).
#![no_std]
#![no_main]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI64, Ordering};

use hyperlight_guest_bin::error::Result;
use hyperlight_guest_bin::{guest_function, host_function};

static COUNTER: AtomicI64 = AtomicI64::new(0);

/// Guest state the helper may read back. The guest is single-threaded,
/// so an UnsafeCell is enough.
struct Cell<T>(UnsafeCell<T>);
// SAFETY: guest functions run one at a time on one vCPU.
unsafe impl<T> Sync for Cell<T> {}

/// Allocations kept on purpose: the working set the guest has dirtied.
static KEPT: Cell<Vec<Vec<u8>>> = Cell(UnsafeCell::new(Vec::new()));

/// What `Incarnate` told this sandbox: the host's count of its lineage,
/// its fence, and the generator seeded from the host's 32 bytes.
/// Everything here travels with a snapshot, so a resume replaces it.
struct Incarnation {
    generation: i64,
    fence: String,
    rng: [u64; 4],
}
static INC: Cell<Incarnation> = Cell(UnsafeCell::new(Incarnation { generation: 0, fence: String::new(), rng: [0; 4] }));

fn touch(bytes: usize) -> usize {
    let mut v: Vec<u8> = Vec::with_capacity(bytes);
    // SAFETY: capacity is bytes; every page is written below.
    unsafe { v.set_len(bytes) };
    let mut i = 0;
    while i < bytes {
        v[i] = (i >> 12) as u8;
        i += 4096;
    }
    // SAFETY: single-threaded guest, see Cell.
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

/// Incarnate is the first call into every fiber, before it serves: the
/// host's generation, the fence it serves as, and 32 fresh bytes the
/// generator is seeded from. The seed is the generator's whole state, so
/// nothing of it is kept apart from the stream it drives, and a sandbox
/// restored from a park keeps serving its old stream only until this
/// call. Returns the generation it took.
#[guest_function("Incarnate")]
fn incarnate(generation: i64, fence: String, seed: Vec<u8>) -> Result<i64> {
    let mut rng = [0u64; 4];
    for (i, word) in rng.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        if seed.len() >= 8 * (i + 1) {
            b.copy_from_slice(&seed[8 * i..8 * i + 8]);
        }
        *word = u64::from_le_bytes(b) ^ hardware_random();
    }
    if rng == [0; 4] {
        // xoshiro's one fixed point. A 32-byte host seed never lands here.
        rng[0] = 1;
    }
    // SAFETY: single-threaded guest, see Cell.
    unsafe { *INC.0.get() = Incarnation { generation, fence, rng } };
    Ok(generation)
}

/// One word from the CPU's own generator where the guest has one, so the
/// stream mixes what the host sent with what the host cannot know. On
/// x86_64 that is rdrand, when CPUID says it exists. aarch64 has RNDR
/// behind a feature register this guest does not probe, so the stream
/// there is the host's seed alone.
fn hardware_random() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let has_rdrand = core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0;
        if has_rdrand {
            // SAFETY: the feature was checked just above.
            return unsafe { rdrand() };
        }
    }
    0
}

/// Inline asm, because the hyperlight target refuses the rdrnd feature
/// the intrinsic needs.
#[cfg(target_arch = "x86_64")]
unsafe fn rdrand() -> u64 {
    for _ in 0..10 {
        let (v, ok): (u64, u8);
        // SAFETY: the caller checked CPUID for rdrand, which writes only
        // its register and the carry flag.
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok == 1 {
            return v;
        }
    }
    0
}

/// Random is the next word of xoshiro256** over the incarnation's state.
#[guest_function("Random")]
fn random() -> Result<u64> {
    // SAFETY: single-threaded guest, see Cell.
    let s = unsafe { &mut (*INC.0.get()).rng };
    let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
    let t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = s[3].rotate_left(45);
    Ok(result)
}

/// Generation is what Incarnate was given, 0 before the first call.
#[guest_function("Generation")]
fn generation() -> Result<i64> {
    // SAFETY: single-threaded guest, see Cell.
    Ok(unsafe { (*INC.0.get()).generation })
}

/// Fence is what Incarnate was given, empty before the first call.
#[guest_function("Fence")]
fn fence() -> Result<String> {
    // SAFETY: single-threaded guest, see Cell.
    Ok(unsafe { (*INC.0.get()).fence.clone() })
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

/// Engine sends one request to the grant's device engine and returns its
/// reply. The guest names the verb and at most one number. The helper
/// puts this fiber's fence in and refuses anything else with `err proto`.
#[host_function("Engine")]
fn engine(line: String) -> Result<String>;

/// The hash of the slice the last GpuFill filled, empty before one. It
/// lives in guest memory, so a park carries it to the resumed fiber.
static GPU_HASH: Cell<String> = Cell(UnsafeCell::new(String::new()));

/// GpuFill reserves `bytes` of the device under this fiber's fence, fills
/// them from `seed` and keeps the hash. Returns the fill's reply, `ok
/// <hash>`, or the first reply that was not ok.
#[guest_function("GpuFill")]
fn gpu_fill(seed: u64, bytes: u64) -> Result<String> {
    // SAFETY: single-threaded guest, see Cell.
    let kept = unsafe { &mut *GPU_HASH.0.get() };
    // A failed fill may have zeroed the slice, so the old hash goes first.
    kept.clear();
    let reserved = engine(format!("reserve {bytes}"))?;
    if reserved != "ok" {
        return Ok(reserved);
    }
    let filled = engine(format!("fill {seed}"))?;
    if let Some(hash) = filled.strip_prefix("ok ") {
        kept.push_str(hash);
    }
    Ok(filled)
}

/// GpuCheck asks the engine for the slice's hash now. Returns `ok` when it
/// is the kept one, `mismatch <kept> <now>` when not, `err none` before
/// any fill, or the engine's own error.
#[guest_function("GpuCheck")]
fn gpu_check() -> Result<String> {
    // SAFETY: single-threaded guest, see Cell.
    let kept = unsafe { (*GPU_HASH.0.get()).clone() };
    if kept.is_empty() {
        return Ok(String::from("err none"));
    }
    let sum = engine(String::from("sum"))?;
    if let Some(now) = sum.strip_prefix("ok ") {
        if now == kept {
            return Ok(String::from("ok"));
        }
        return Ok(format!("mismatch {kept} {now}"));
    }
    Ok(sum)
}

/// GpuOpen is the fiber's attempt to open a GPU node. A Hyperlight guest
/// has no file system and no device, so every path is missing.
#[guest_function("GpuOpen")]
fn gpu_open(_path: String) -> Result<String> {
    Ok(String::from("ENOENT"))
}
