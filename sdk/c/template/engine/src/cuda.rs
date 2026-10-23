//! The CUDA device, class gpu. The engine loads libcuda.so.1 with
//! dlopen, so it has no link-time tie to CUDA, and resolves every entry
//! point by the driver's own versioned name, all before the seccomp
//! seal. The pool is one cuMemAlloc_v2 in the device's primary context,
//! current on the one serving thread. fill, hash and moves go through
//! one host buffer of CHUNK bytes, so a slice of any size costs that
//! much host memory and no more. SAVE and RESTORE copy through a bounded
//! buffer of their own (slice.rs), one piece per call. A sticky driver
//! error ends the engine, and any other fails the one request.
//!
//! After the seal the driver makes ioctls on the /dev/nvidia* files it
//! opened at cuInit, maps and unmaps memory, waits on futexes and may
//! start a helper thread through clone, since clone3 is ENOSYS and libc
//! falls back. The Engine program allows all of those.

// ---- the driver's types and entry points ----

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::fmt::Write as _;
use std::ptr;

use crate::pool::{Device, Fault};
use crate::proto::{self, Fnv};

/// CUresult, a C enum, int-sized.
type CuResult = c_int;
/// CUdevice_v1.
type CuDevice = c_int;
/// CUdeviceptr_v2, a 64-bit device address.
type CuPtr = u64;
/// CUcontext, opaque.
type CuContext = *mut c_void;

const CUDA_SUCCESS: CuResult = 0;
/// CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR.
const CC_MAJOR: c_int = 75;
/// CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR.
const CC_MINOR: c_int = 76;

/// The CUresults after which the context is lost for good, since every
/// later call in the process fails the same way. They are the codes
/// cuda.h calls sticky, for which the process must be restarted, and
/// the ones that say the context or the driver is gone.
const STICKY: [CuResult; 15] = [
    3,   // CUDA_ERROR_NOT_INITIALIZED, the driver lost its state
    4,   // CUDA_ERROR_DEINITIALIZED
    201, // CUDA_ERROR_INVALID_CONTEXT, the pool's context is gone
    214, // CUDA_ERROR_ECC_UNCORRECTABLE
    700, // CUDA_ERROR_ILLEGAL_ADDRESS
    702, // CUDA_ERROR_LAUNCH_TIMEOUT
    709, // CUDA_ERROR_CONTEXT_IS_DESTROYED
    710, // CUDA_ERROR_ASSERT
    714, // CUDA_ERROR_HARDWARE_STACK_ERROR
    715, // CUDA_ERROR_ILLEGAL_INSTRUCTION
    716, // CUDA_ERROR_MISALIGNED_ADDRESS
    717, // CUDA_ERROR_INVALID_ADDRESS_SPACE
    718, // CUDA_ERROR_INVALID_PC
    719, // CUDA_ERROR_LAUNCH_FAILED
    999, // CUDA_ERROR_UNKNOWN
];

type FnInit = unsafe extern "C" fn(c_uint) -> CuResult;
type FnVersion = unsafe extern "C" fn(*mut c_int) -> CuResult;
type FnDeviceGet = unsafe extern "C" fn(*mut CuDevice, c_int) -> CuResult;
type FnName = unsafe extern "C" fn(*mut c_char, c_int, CuDevice) -> CuResult;
type FnAttribute = unsafe extern "C" fn(*mut c_int, c_int, CuDevice) -> CuResult;
type FnUuid = unsafe extern "C" fn(*mut u8, CuDevice) -> CuResult;
type FnTotalMem = unsafe extern "C" fn(*mut usize, CuDevice) -> CuResult;
type FnRetain = unsafe extern "C" fn(*mut CuContext, CuDevice) -> CuResult;
type FnSetCurrent = unsafe extern "C" fn(CuContext) -> CuResult;
type FnSync = unsafe extern "C" fn() -> CuResult;
type FnAlloc = unsafe extern "C" fn(*mut CuPtr, usize) -> CuResult;
type FnMemset = unsafe extern "C" fn(CuPtr, u8, usize) -> CuResult;
type FnHtoD = unsafe extern "C" fn(CuPtr, *const c_void, usize) -> CuResult;
type FnDtoH = unsafe extern "C" fn(*mut c_void, CuPtr, usize) -> CuResult;
type FnErrorName = unsafe extern "C" fn(CuResult, *mut *const c_char) -> CuResult;

/// The library's name, for messages.
const LIBCUDA: &str = "libcuda.so.1";

// ---- device selection ----

/// The device the first FIBERD_DEVICES entry names.
enum Select {
    /// A CUDA ordinal, from `N` or `/dev/nvidiaN`.
    Ordinal(u32),
    /// A `GPU-` or `MIG-` UUID, as its text and as its 16 bytes.
    Uuid(String, [u8; 16]),
}

impl Select {
    /// parse reads one entry. Anything else, `/dev/nvidiactl` and a
    /// `MIG-GPU-.../gi/ci` name from before driver 470 included, is
    /// refused by name.
    fn parse(entry: &str) -> Result<Select, String> {
        let bad = || format!("FIBERD_DEVICES entry {entry} is malformed");
        if let Some(n) = entry.strip_prefix("/dev/nvidia") {
            return ordinal(n).map(Select::Ordinal).ok_or_else(bad);
        }
        if entry.starts_with("GPU-") || entry.starts_with("MIG-") {
            let bytes = uuid(entry).ok_or_else(bad)?;
            return Ok(Select::Uuid(entry.to_owned(), bytes));
        }
        ordinal(entry).map(Select::Ordinal).ok_or_else(bad)
    }

    /// What CUDA_VISIBLE_DEVICES is set to, so the driver shows this
    /// device alone, as its device 0.
    fn visible(&self) -> String {
        match self {
            Select::Ordinal(n) => n.to_string(),
            Select::Uuid(text, _) => text.clone(),
        }
    }
}

/// A CUDA ordinal, decimal digits only.
fn ordinal(s: &str) -> Option<u32> {
    let n = proto::dec_u64(s.as_bytes())?;
    u32::try_from(n).ok()
}

/// The 16 bytes of a 4-byte prefix and xxxxxxxx-xxxx-xxxx-xxxx-
/// xxxxxxxxxxxx, as nvidia-smi -L prints a GPU or MIG UUID.
fn uuid(text: &str) -> Option<[u8; 16]> {
    let body = text.get(4..)?.as_bytes();
    if body.len() != 36 {
        return None;
    }
    let mut digits = Vec::with_capacity(32);
    for (i, &c) in body.iter().enumerate() {
        let dash = matches!(i, 8 | 13 | 18 | 23);
        if dash != (c == b'-') {
            return None;
        }
        if !dash {
            digits.push(hex(c)?);
        }
    }
    let mut out = [0u8; 16];
    for (b, &[hi, lo]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *b = (hi << 4) | lo;
    }
    Some(out)
}

/// One hex digit's value.
fn hex(c: u8) -> Option<u8> {
    let d = char::from(c).to_digit(16)?;
    u8::try_from(d).ok()
}

/// bytes as a UUID after prefix, for a refusal's message.
fn uuid_text(prefix: &str, bytes: &[u8; 16]) -> String {
    let mut s = prefix.to_owned();
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---- loading libcuda ----

/// The driver's entry points. They stay valid for the life of the
/// process, since the library is never closed.
struct Api {
    cu_init: FnInit,
    cu_driver_get_version: FnVersion,
    cu_device_get: FnDeviceGet,
    cu_device_get_name: FnName,
    cu_device_get_attribute: FnAttribute,
    cu_device_get_uuid: FnUuid,
    cu_device_total_mem: FnTotalMem,
    cu_primary_ctx_retain: FnRetain,
    cu_ctx_set_current: FnSetCurrent,
    cu_ctx_synchronize: FnSync,
    cu_mem_alloc: FnAlloc,
    cu_memset_d8: FnMemset,
    cu_memcpy_htod: FnHtoD,
    cu_memcpy_dtoh: FnDtoH,
    cu_get_error_name: FnErrorName,
}

/// load resolves the entry point name in lib as the function type ty,
/// or returns the start-up error that names it.
macro_rules! load {
    ($lib:expr, $name:literal, $ty:ty) => {{
        let p = sym($lib, $name)?;
        // SAFETY: p is the driver's entry point of that name, and $ty is
        // its C signature as cuda.h declares it.
        unsafe { std::mem::transmute::<*mut c_void, $ty>(p) }
    }};
}

/// sym finds name in lib.
fn sym(lib: *mut c_void, name: &CStr) -> Result<*mut c_void, String> {
    // SAFETY: lib is a live dlopen handle and name ends in a nul.
    let p = unsafe { libc::dlsym(lib, name.as_ptr()) };
    if p.is_null() {
        let name = name.to_string_lossy();
        return Err(format!("{LIBCUDA} has no {name}"));
    }
    Ok(p)
}

/// The last dl error, read at once since the next dl call may free it.
fn dl_error() -> String {
    // SAFETY: dlerror takes no argument.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        return "no reason given".to_owned();
    }
    // SAFETY: p is dlerror's nul-terminated message, live until the next
    // dl call.
    let why = unsafe { CStr::from_ptr(p) };
    why.to_string_lossy().into_owned()
}

impl Api {
    /// open loads libcuda.so.1 and resolves every entry point the engine
    /// calls. RTLD_NOW binds the library's own symbols now, so a broken
    /// install fails here and not under the seal, and RTLD_LOCAL keeps
    /// its symbols out of the engine's lookups.
    fn open() -> Result<Api, String> {
        let flags = libc::RTLD_NOW | libc::RTLD_LOCAL;
        // SAFETY: the name is a nul-terminated literal. The library's
        // constructors run here, on the engine's one thread, unsealed.
        let lib = unsafe { libc::dlopen(c"libcuda.so.1".as_ptr(), flags) };
        if lib.is_null() {
            let why = dl_error();
            return Err(format!("dlopen {LIBCUDA}: {why}"));
        }
        Ok(Api {
            cu_init: load!(lib, c"cuInit", FnInit),
            cu_driver_get_version: load!(lib, c"cuDriverGetVersion", FnVersion),
            cu_device_get: load!(lib, c"cuDeviceGet", FnDeviceGet),
            cu_device_get_name: load!(lib, c"cuDeviceGetName", FnName),
            cu_device_get_attribute: load!(lib, c"cuDeviceGetAttribute", FnAttribute),
            cu_device_get_uuid: load!(lib, c"cuDeviceGetUuid_v2", FnUuid),
            cu_device_total_mem: load!(lib, c"cuDeviceTotalMem_v2", FnTotalMem),
            cu_primary_ctx_retain: load!(lib, c"cuDevicePrimaryCtxRetain", FnRetain),
            cu_ctx_set_current: load!(lib, c"cuCtxSetCurrent", FnSetCurrent),
            cu_ctx_synchronize: load!(lib, c"cuCtxSynchronize", FnSync),
            cu_mem_alloc: load!(lib, c"cuMemAlloc_v2", FnAlloc),
            cu_memset_d8: load!(lib, c"cuMemsetD8_v2", FnMemset),
            cu_memcpy_htod: load!(lib, c"cuMemcpyHtoD_v2", FnHtoD),
            cu_memcpy_dtoh: load!(lib, c"cuMemcpyDtoH_v2", FnDtoH),
            cu_get_error_name: load!(lib, c"cuGetErrorName", FnErrorName),
        })
    }

    /// word is rc's name by cuGetErrorName, which works even before
    /// cuInit and after a sticky error.
    fn word(&self, rc: CuResult) -> &'static str {
        let mut p: *const c_char = ptr::null();
        // SAFETY: p is a live local the driver points at the name.
        let r = unsafe { (self.cu_get_error_name)(rc, &raw mut p) };
        if r != CUDA_SUCCESS || p.is_null() {
            return "CUDA_ERROR_unnamed";
        }
        // SAFETY: the driver's names are nul-terminated static strings
        // in the library, which is never unloaded.
        let name: &'static CStr = unsafe { CStr::from_ptr(p) };
        name.to_str().unwrap_or("CUDA_ERROR_unnamed")
    }

    /// check fails start-up on any error, naming the call and the error.
    fn check(&self, call: &str, rc: CuResult) -> Result<(), String> {
        if rc == CUDA_SUCCESS {
            return Ok(());
        }
        let word = self.word(rc);
        Err(format!("{call}: {word} ({rc})"))
    }

    /// after sorts an error once the engine serves. A sticky one is
    /// fatal, and any other fails the one request.
    fn after(&self, rc: CuResult) -> Result<(), Fault> {
        if rc == CUDA_SUCCESS {
            return Ok(());
        }
        let word = self.word(rc);
        if STICKY.contains(&rc) {
            return Err(Fault::Fatal(word));
        }
        Err(Fault::Soft(word))
    }

    /// The device's name, as cuDeviceGetName gives it.
    fn name(&self, dev: CuDevice) -> Result<String, String> {
        let mut buf = [0u8; 256];
        let at = buf.as_mut_ptr().cast::<c_char>();
        // SAFETY: at is buf's 256 bytes, the length passed.
        let rc = unsafe { (self.cu_device_get_name)(at, 256, dev) };
        self.check("cuDeviceGetName", rc)?;
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = buf.get(..end).unwrap_or_default();
        Ok(String::from_utf8_lossy(name).into_owned())
    }

    /// One integer attribute of the device.
    fn attribute(&self, dev: CuDevice, which: c_int) -> Result<c_int, String> {
        let mut v: c_int = 0;
        // SAFETY: v is a live local the driver writes one int to.
        let rc = unsafe { (self.cu_device_get_attribute)(&raw mut v, which, dev) };
        self.check("cuDeviceGetAttribute", rc)?;
        Ok(v)
    }

    /// The device's UUID by cuDeviceGetUuid_v2, which names a MIG
    /// instance where the first version names its parent GPU.
    fn uuid(&self, dev: CuDevice) -> Result<[u8; 16], String> {
        let mut u = [0u8; 16];
        // SAFETY: u is the 16-byte CUuuid the driver writes.
        let rc = unsafe { (self.cu_device_get_uuid)(u.as_mut_ptr(), dev) };
        self.check("cuDeviceGetUuid_v2", rc)?;
        Ok(u)
    }

    /// The device's memory in bytes, a MIG instance's own on MIG.
    fn total_mem(&self, dev: CuDevice) -> Result<u64, String> {
        let mut n: usize = 0;
        // SAFETY: n is a live local the driver writes one size_t to.
        let rc = unsafe { (self.cu_device_total_mem)(&raw mut n, dev) };
        self.check("cuDeviceTotalMem_v2", rc)?;
        Ok(n as u64)
    }
}

// ---- the device ----

/// The host buffer every fill, hash and move goes through. A multiple of
/// 8, so each piece of a fill starts on a pattern word.
const CHUNK: usize = 1 << 20;
/// Bytes in a MiB.
const MIB: u64 = 1 << 20;
/// A range past the pool, which only a bug in Pool could ask for.
const RANGE: Fault = Fault::Fatal("range");

/// The GPU pool, one allocation in the primary context.
pub struct Cuda {
    api: Api,
    /// The pool's device address, 0 until allocate.
    base: CuPtr,
    cap: u64,
    name: String,
    cc: String,
    driver: String,
    /// CHUNK bytes, taken before the seal.
    buf: Vec<u8>,
}

impl Cuda {
    /// open starts the driver on the device entry names and makes its
    /// primary context current on this thread, all before the seal. The
    /// pool is pool_mb MiB, or three quarters of the device's memory.
    /// The quarter left holds the context, the driver's staging buffers
    /// and its own allocations, so a default pool allocates on a fresh
    /// GPU or MIG instance without a guess at those sizes.
    pub fn open(entry: &str, pool_mb: Option<u64>) -> Result<Cuda, String> {
        let select = Select::parse(entry)?;
        // The driver reads both at cuInit. With the entry as its only
        // visible device it is device 0, and no other GPU is opened or
        // can be fallen back to. An ordinal counts in PCI bus order, as
        // nvidia-smi and the /dev/nvidiaN minors usually do.
        // SAFETY: the engine has one thread here, so nothing reads the
        // environment while it changes.
        unsafe {
            std::env::set_var("CUDA_VISIBLE_DEVICES", select.visible());
            std::env::set_var("CUDA_DEVICE_ORDER", "PCI_BUS_ID");
        }
        let api = Api::open()?;
        let mut version: c_int = 0;
        // SAFETY: version is a live local the driver writes one int to.
        let rc = unsafe { (api.cu_driver_get_version)(&raw mut version) };
        api.check("cuDriverGetVersion", rc)?;
        // SAFETY: an integer argument alone.
        let rc = unsafe { (api.cu_init)(0) };
        api.check("cuInit", rc)?;
        let mut dev: CuDevice = 0;
        // SAFETY: dev is a live local the driver writes to.
        let rc = unsafe { (api.cu_device_get)(&raw mut dev, 0) };
        api.check("cuDeviceGet", rc)?;
        if let Select::Uuid(text, want) = &select {
            let got = api.uuid(dev)?;
            if got != *want {
                let got = uuid_text(text.get(..4).unwrap_or_default(), &got);
                return Err(format!("device 0 is {got}, not {text}"));
            }
        }
        let name = api.name(dev)?;
        let major = api.attribute(dev, CC_MAJOR)?;
        let minor = api.attribute(dev, CC_MINOR)?;
        let cap = pool_size(pool_mb, api.total_mem(dev)?)?;
        let mut ctx: CuContext = ptr::null_mut();
        // SAFETY: ctx is a live local the driver writes the context to.
        let rc = unsafe { (api.cu_primary_ctx_retain)(&raw mut ctx, dev) };
        api.check("cuDevicePrimaryCtxRetain", rc)?;
        // SAFETY: ctx is the primary context just retained, and it is
        // never released.
        let rc = unsafe { (api.cu_ctx_set_current)(ctx) };
        api.check("cuCtxSetCurrent", rc)?;
        Ok(Cuda {
            api,
            base: 0,
            cap,
            name,
            cc: format!("{major}.{minor}"),
            driver: format!("{}.{}", version / 1000, (version % 1000) / 10),
            buf: vec![0; CHUNK],
        })
    }

    /// The device address off bytes into the pool, for len bytes that
    /// must lie inside it.
    fn at(&self, off: u64, len: u64) -> Result<CuPtr, Fault> {
        let end = off.checked_add(len).ok_or(RANGE)?;
        if end > self.cap {
            return Err(RANGE);
        }
        self.base.checked_add(off).ok_or(RANGE)
    }

    /// bounce moves n bytes, at most CHUNK, from from to to through the
    /// host buffer.
    fn bounce(&mut self, from: CuPtr, to: CuPtr, n: usize) -> Result<(), Fault> {
        let piece = self.buf.get_mut(..n).ok_or(RANGE)?;
        // SAFETY: piece is n live bytes, and at checked from..from+n.
        let rc = unsafe { (self.api.cu_memcpy_dtoh)(piece.as_mut_ptr().cast(), from, n) };
        self.api.after(rc)?;
        // SAFETY: piece is n live bytes, and at checked to..to+n.
        let rc = unsafe { (self.api.cu_memcpy_htod)(to, piece.as_ptr().cast(), n) };
        self.api.after(rc)
    }
}

/// pool_size is pool_mb MiB, or three quarters of total in whole MiB.
/// A pool larger than the device is refused here, by name.
fn pool_size(pool_mb: Option<u64>, total: u64) -> Result<u64, String> {
    let total_mb = total / MIB;
    let mb = pool_mb.unwrap_or(total_mb / 4 * 3);
    if mb == 0 || mb > total_mb {
        let why = format!("a {mb} MiB pool does not fit the device's {total_mb} MiB");
        return Err(why);
    }
    mb.checked_mul(MIB)
        .ok_or_else(|| "the pool is too large".to_owned())
}

/// fatal makes any fault fatal.
fn fatal(f: Fault) -> Fault {
    match f {
        Fault::Fatal(w) | Fault::Soft(w) => Fault::Fatal(w),
    }
}

impl Device for Cuda {
    fn class(&self) -> &'static str {
        "gpu"
    }

    fn gpu(&self) -> (String, String, String) {
        (self.name.clone(), self.cc.clone(), self.driver.clone())
    }

    fn capacity(&self) -> u64 {
        self.cap
    }

    fn allocate(&mut self) -> Result<(), String> {
        let n = usize::try_from(self.cap);
        let n = n.map_err(|_| "the pool is too large".to_owned())?;
        let mut base: CuPtr = 0;
        // SAFETY: base is a live local the driver writes the address to.
        let rc = unsafe { (self.api.cu_mem_alloc)(&raw mut base, n) };
        self.api.check("cuMemAlloc_v2", rc)?;
        // SAFETY: base..base+n is the allocation just made.
        let rc = unsafe { (self.api.cu_memset_d8)(base, 0, n) };
        self.api.check("cuMemsetD8_v2", rc)?;
        // SAFETY: no arguments.
        let rc = unsafe { (self.api.cu_ctx_synchronize)() };
        self.api.check("cuCtxSynchronize", rc)?;
        self.base = base;
        Ok(())
    }

    fn zero(&mut self, off: u64, len: u64) -> Result<(), Fault> {
        let dst = self.at(off, len)?;
        let n = usize::try_from(len).map_err(|_| RANGE)?;
        // SAFETY: at checked dst..dst+n.
        let rc = unsafe { (self.api.cu_memset_d8)(dst, 0, n) };
        self.api.after(rc)?;
        // The memset may finish after the call returns, so its error
        // shows here, on the reserve that asked for it.
        // SAFETY: no arguments.
        let rc = unsafe { (self.api.cu_ctx_synchronize)() };
        self.api.after(rc)
    }

    fn fill(&mut self, off: u64, len: u64, seed: u64) -> Result<(), Fault> {
        let dst = self.at(off, len)?;
        let len = usize::try_from(len).map_err(|_| RANGE)?;
        let mut done = 0usize;
        while done < len {
            let n = CHUNK.min(len - done);
            let piece = self.buf.get_mut(..n).ok_or(RANGE)?;
            proto::fill_into(piece, seed, done as u64);
            let to = dst + done as u64;
            // SAFETY: piece is n live bytes, and at checked to..to+n. A
            // copy from pageable memory has staged the bytes when it
            // returns, so the buffer is free for the next piece.
            let rc = unsafe { (self.api.cu_memcpy_htod)(to, piece.as_ptr().cast(), n) };
            self.api.after(rc)?;
            done += n;
        }
        Ok(())
    }

    fn hash(&mut self, off: u64, len: u64) -> Result<u64, Fault> {
        let src = self.at(off, len)?;
        let len = usize::try_from(len).map_err(|_| RANGE)?;
        let mut h = Fnv::new();
        let mut done = 0usize;
        while done < len {
            let n = CHUNK.min(len - done);
            let piece = self.buf.get_mut(..n).ok_or(RANGE)?;
            let from = src + done as u64;
            // SAFETY: piece is n live bytes the driver writes, and at
            // checked from..from+n. A copy to pageable memory is done
            // when it returns.
            let rc = unsafe { (self.api.cu_memcpy_dtoh)(piece.as_mut_ptr().cast(), from, n) };
            self.api.after(rc)?;
            h.update(piece);
            done += n;
        }
        Ok(h.finish())
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), Fault> {
        let n = buf.len();
        let src = self.at(off, n as u64)?;
        // SAFETY: buf is n live bytes the driver writes, and at checked
        // src..src+n. A copy to pageable memory is done when it returns.
        let rc = unsafe { (self.api.cu_memcpy_dtoh)(buf.as_mut_ptr().cast(), src, n) };
        self.api.after(rc)
    }

    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), Fault> {
        let n = buf.len();
        let dst = self.at(off, n as u64)?;
        // SAFETY: buf is n live bytes, and at checked dst..dst+n. A copy
        // from pageable memory has staged the bytes when it returns.
        let rc = unsafe { (self.api.cu_memcpy_htod)(dst, buf.as_ptr().cast(), n) };
        self.api.after(rc)
    }

    /// A move down goes front to back and a move up back to front, so no
    /// piece overwrites bytes not yet read. Every failure is fatal, even
    /// one the driver would survive, since the slices are half moved.
    fn copy(&mut self, from: u64, to: u64, len: u64) -> Result<(), Fault> {
        let src = self.at(from, len)?;
        let dst = self.at(to, len)?;
        let len = usize::try_from(len).map_err(|_| RANGE)?;
        let mut done = 0usize;
        while done < len {
            let n = CHUNK.min(len - done);
            let at = if dst <= src { done } else { len - done - n };
            let at = at as u64;
            self.bounce(src + at, dst + at, n).map_err(fatal)?;
            done += n;
        }
        Ok(())
    }
}
