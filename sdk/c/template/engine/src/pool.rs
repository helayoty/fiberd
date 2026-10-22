//! The pool, the engine's whole device budget allocated once at start,
//! and the slices fibers reserve in it. Pool keeps the slice table and
//! the accounting, and a Device does the bytes. Sim is the device for
//! `--sim-mb`, host memory. The CUDA device (M6, cuda.rs) implements the
//! same trait over one device allocation. A slice is a fence, an offset
//! and a length, so a later SAVE can read it out and a RESTORE can place
//! one and write it back (M5).

// ---- the device trait ----

use std::io;
use std::ptr;

use crate::proto::{self, Fnv};

/// A device error, named by one word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The engine exits, since the fault may have poisoned the pool for
    /// every fiber. A sticky driver error, a half-done move or a bug.
    Fatal(&'static str),
    /// The one request fails with `err device` and the engine serves on.
    /// A driver error that leaves the context usable.
    Soft(&'static str),
}

/// A range past the pool, which only a bug in Pool could ask for.
const RANGE: Fault = Fault::Fatal("range");
/// Slice sums that do not add up, a bug.
const ACCOUNTING: Fault = Fault::Fatal("accounting");

/// The bytes of one pool. The engine opens the device, sends ENGINE
/// and GPU, then calls allocate once before READY. Offsets and lengths
/// are in bytes from the pool's start, and Pool only passes ranges
/// inside capacity that are whole 256-byte units.
pub trait Device {
    /// The class ENGINE declares, `sim` or `gpu`.
    fn class(&self) -> &'static str;
    /// The GPU line's name, cc and driver, as the driver gives them.
    fn gpu(&self) -> (String, String, String);
    /// The pool's size in bytes.
    fn capacity(&self) -> u64;
    /// Allocates the whole pool and zeroes it.
    fn allocate(&mut self) -> Result<(), String>;
    /// Zeroes len bytes at off.
    fn zero(&mut self, off: u64, len: u64) -> Result<(), Fault>;
    /// Writes the fill pattern (proto::fill_word) over len bytes at
    /// off, with offsets counted from off, the slice's start.
    fn fill(&mut self, off: u64, len: u64, seed: u64) -> Result<(), Fault>;
    /// FNV-1a 64 over len bytes at off.
    fn hash(&mut self, off: u64, len: u64) -> Result<u64, Fault>;
    /// Moves len bytes from from to to, ranges that may overlap, so the
    /// pool can close its gaps. Any failure is Fatal, since a half-done
    /// move leaves another fiber's slice torn.
    fn copy(&mut self, from: u64, to: u64, len: u64) -> Result<(), Fault>;
}

// ---- the simulated device ----

/// The simulated device, one anonymous mapping of host memory that
/// lives as long as the engine. mem is empty until allocate.
pub struct Sim {
    cap: u64,
    mem: &'static mut [u8],
}

impl Sim {
    /// A device of capacity bytes, not yet allocated.
    pub fn new(capacity: u64) -> Sim {
        Sim {
            cap: capacity,
            mem: Default::default(),
        }
    }

    /// map maps cap bytes and touches every page, so the pool is
    /// resident and zeroed before READY. A leaf whose memory.max cannot
    /// hold it fails here, at start, and not under a fiber's request.
    fn map(&mut self) -> io::Result<()> {
        let len = usize::try_from(self.cap)
            .ok()
            .filter(|&n| n > 0)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: an anonymous private mapping at an address the kernel
        // picks touches no memory the program owns.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = p.cast::<u8>();
        // SAFETY: the mapping is len bytes, readable and writable, zeroed
        // by the kernel, and never unmapped, so it is valid for 'static
        // and this is its one reference.
        let mem: &'static mut [u8] = unsafe { std::slice::from_raw_parts_mut(base, len) };
        // A volatile write per page, so the compiler keeps the stores
        // although the bytes are already zero.
        for i in (0..len).step_by(4096) {
            if let Some(b) = mem.get_mut(i) {
                // SAFETY: b is a valid, aligned, exclusive byte.
                unsafe { ptr::write_volatile(b, 0) };
            }
        }
        self.mem = mem;
        Ok(())
    }

    /// The bytes [off, off+len), or a fault for a range past the pool,
    /// which only a bug in Pool could ask for.
    fn range(&mut self, off: u64, len: u64) -> Result<&mut [u8], Fault> {
        let (a, n) = span(off, len)?;
        let end = a.checked_add(n).ok_or(RANGE)?;
        self.mem.get_mut(a..end).ok_or(RANGE)
    }
}

/// off and len as usize.
fn span(off: u64, len: u64) -> Result<(usize, usize), Fault> {
    let a = usize::try_from(off).map_err(|_| RANGE)?;
    let n = usize::try_from(len).map_err(|_| RANGE)?;
    Ok((a, n))
}

impl Device for Sim {
    fn class(&self) -> &'static str {
        "sim"
    }

    fn gpu(&self) -> (String, String, String) {
        ("sim".to_owned(), "0.0".to_owned(), "0".to_owned())
    }

    fn capacity(&self) -> u64 {
        self.cap
    }

    fn allocate(&mut self) -> Result<(), String> {
        self.map()
            .map_err(|e| format!("sim pool of {} bytes: {e}", self.cap))
    }

    fn zero(&mut self, off: u64, len: u64) -> Result<(), Fault> {
        self.range(off, len)?.fill(0);
        Ok(())
    }

    fn fill(&mut self, off: u64, len: u64, seed: u64) -> Result<(), Fault> {
        proto::fill_into(self.range(off, len)?, seed, 0);
        Ok(())
    }

    fn hash(&mut self, off: u64, len: u64) -> Result<u64, Fault> {
        let mut h = Fnv::new();
        h.update(self.range(off, len)?);
        Ok(h.finish())
    }

    fn copy(&mut self, from: u64, to: u64, len: u64) -> Result<(), Fault> {
        // Both ranges are checked first, since copy_within panics on
        // one past the end.
        self.range(from, len)?;
        self.range(to, len)?;
        let (a, n) = span(from, len)?;
        let (b, _) = span(to, len)?;
        let end = a.checked_add(n).ok_or(RANGE)?;
        self.mem.copy_within(a..end, b);
        Ok(())
    }
}

// ---- slices and accounting ----

/// The unit a slice is rounded up to, the `raw256` layout's.
pub const UNIT: u64 = 256;
/// Most slices at once, as the zygote engine had.
pub const SLICES_MAX: usize = 4096;

/// One fiber's slice.
struct Slice {
    fence: Vec<u8>,
    off: u64,
    len: u64,
}

/// What a reserve did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserved {
    /// The fence's slice is replaced, all zero.
    Done,
    /// The pool cannot hold it. The old slice, if any, is untouched.
    Capacity,
}

/// The slice table over one device. Slices are kept sorted by offset
/// and never overlap. used is the sum of their lengths and never passes
/// capacity.
pub struct Pool {
    dev: Box<dyn Device>,
    cap: u64,
    used: u64,
    slices: Vec<Slice>,
}

impl Pool {
    /// An empty pool over dev, allocated and zeroed.
    pub fn new(dev: Box<dyn Device>) -> Pool {
        let cap = dev.capacity();
        Pool {
            dev,
            cap,
            used: 0,
            slices: Vec::new(),
        }
    }

    /// Bytes held by every slice.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// The pool's size.
    pub fn capacity(&self) -> u64 {
        self.cap
    }

    /// The fence's slice size, 0 for none.
    pub fn bytes(&self, fence: &[u8]) -> u64 {
        self.find(fence)
            .and_then(|i| self.slices.get(i))
            .map_or(0, |s| s.len)
    }

    fn find(&self, fence: &[u8]) -> Option<usize> {
        self.slices.iter().position(|s| s.fence == fence)
    }

    /// The fence's offset and length, for fill and sum, and for SAVE
    /// later.
    fn slice(&self, fence: &[u8]) -> Option<(u64, u64)> {
        let s = self.slices.get(self.find(fence)?)?;
        Some((s.off, s.len))
    }

    /// reserve replaces the fence's slice with a zeroed one of bytes,
    /// rounded up to UNIT. 0 drops it, as release does. The check counts
    /// the old slice as freed, so a fiber can always shrink or keep its
    /// size. A Soft fault from the zeroing leaves the fence with no slice.
    pub fn reserve(&mut self, fence: &[u8], bytes: u64) -> Result<Reserved, Fault> {
        if bytes == 0 {
            self.release(fence);
            return Ok(Reserved::Done);
        }
        let Some(len) = bytes.div_ceil(UNIT).checked_mul(UNIT) else {
            return Ok(Reserved::Capacity);
        };
        let had = self.bytes(fence);
        let rest = self.used.checked_sub(had).ok_or(ACCOUNTING)?;
        if rest.checked_add(len).is_none_or(|t| t > self.cap) {
            return Ok(Reserved::Capacity);
        }
        if had == 0 && self.slices.len() >= SLICES_MAX {
            return Ok(Reserved::Capacity);
        }
        self.release(fence);
        let off = self.place(len)?;
        self.dev.zero(off, len)?;
        let at = self.slices.partition_point(|s| s.off < off);
        self.slices.insert(
            at,
            Slice {
                fence: fence.to_vec(),
                off,
                len,
            },
        );
        self.used = self.used.checked_add(len).ok_or(ACCOUNTING)?;
        Ok(Reserved::Done)
    }

    /// release drops the fence's slice, if it has one. Its bytes stay
    /// until the next reserve over them zeroes them.
    pub fn release(&mut self, fence: &[u8]) {
        if let Some(i) = self.find(fence) {
            let s = self.slices.remove(i);
            self.used = self.used.saturating_sub(s.len);
        }
    }

    /// fill writes the pattern over the fence's slice and gives its
    /// hash, None for no slice.
    pub fn fill(&mut self, fence: &[u8], seed: u64) -> Result<Option<u64>, Fault> {
        let Some((off, len)) = self.slice(fence) else {
            return Ok(None);
        };
        self.dev.fill(off, len, seed)?;
        self.dev.hash(off, len).map(Some)
    }

    /// sum gives the hash of the fence's slice, None for no slice.
    pub fn sum(&mut self, fence: &[u8]) -> Result<Option<u64>, Fault> {
        let Some((off, len)) = self.slice(fence) else {
            return Ok(None);
        };
        self.dev.hash(off, len).map(Some)
    }

    /// place finds len free bytes, the first gap that fits, else the
    /// tail after closing every gap. reserve checked used, so the tail
    /// always fits then, and a miss is an accounting fault.
    fn place(&mut self, len: u64) -> Result<u64, Fault> {
        let mut at = 0u64;
        for s in &self.slices {
            if s.off.saturating_sub(at) >= len {
                return Ok(at);
            }
            at = s.off.checked_add(s.len).ok_or(ACCOUNTING)?;
        }
        if self.cap.saturating_sub(at) >= len {
            return Ok(at);
        }
        let at = self.compact()?;
        if self.cap.saturating_sub(at) >= len {
            return Ok(at);
        }
        Err(ACCOUNTING)
    }

    /// compact moves every slice down to close the gaps, in offset
    /// order, so no move overwrites a slice not yet moved. It gives
    /// where the free tail starts.
    fn compact(&mut self) -> Result<u64, Fault> {
        let mut at = 0u64;
        for s in &mut self.slices {
            if s.off != at {
                self.dev.copy(s.off, at, s.len)?;
                s.off = at;
            }
            at = at.checked_add(s.len).ok_or(ACCOUNTING)?;
        }
        Ok(at)
    }
}
