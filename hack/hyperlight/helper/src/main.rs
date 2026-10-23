//! fiberd's Hyperlight helper: hack/hyperlight/PROTOCOL.md over fd 3.
//!
//! One helper per warm template. Warm builds a sandbox from the guest
//! binary, calls `Init`, and snapshots it; every fiber is a sandbox built
//! from that snapshot, told its generation, fence and seed through
//! `Incarnate` before its endpoint exists, and owned by a thread that
//! serves the fiber's unix socket (the reference workload's line
//! protocol) and takes commands from the control loop. Park is
//! `Snapshot::save` into the directory fiberd gave (an OCI image layout);
//! resume is `Snapshot::load`, a sandbox built from it and `Incarnate`
//! again. W is what the guest dirtied through `Dirty`, which the helper
//! tracks and reports. The command log never shows a seed or a payload.
//!
//! A guest reaches the grant's device engine only through the `Engine`
//! host function, which each sandbox gets bound to the fence fiberd named
//! for it. The helper puts that fence in every line, so a guest can act on
//! its own slice alone. fiberd sends the engine RELAY for the helper's
//! cgroup, which lets it name the fences of its fibers.
//!
//!   hyperlight-helper --guest <path> [--heap-mb N] [--engine <sock>]  (fd 3 = control)
//!   hyperlight-helper --guest <path> --check           (self-test, no fd 3)
//!   hyperlight-helper --version                        (the snapshot facts)

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use hyperlight_host::func::Registerable;
use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
use hyperlight_host::{HostFunctions, MultiUseSandbox, SandboxBuilder};

/// The facts a snapshot made here depends on, one token each. This
/// helper's version (its park layout), the hyperlight_host crate (its
/// snapshot format, from Cargo.lock through build.rs), the hypervisor in
/// use and the CPU vendor. Hyperlight refuses to load a snapshot from
/// another crate version, hypervisor or vendor, so fiberd records these as
/// the platform of every park and the refusal happens before a resume.
fn facts() -> String {
    format!(
        "fiberd-hyperlight-helper/{} hyperlight_host/{} {} {}",
        env!("CARGO_PKG_VERSION"),
        env!("HYPERLIGHT_HOST_VERSION"),
        hypervisor(),
        cpu_vendor()
    )
}

/// The hypervisor Hyperlight picks on Linux, by its device, in the
/// order Hyperlight probes them (mshv before kvm).
fn hypervisor() -> &'static str {
    if Path::new("/dev/mshv").exists() {
        "mshv"
    } else if Path::new("/dev/kvm").exists() {
        "kvm"
    } else {
        "none"
    }
}

/// The CPU vendor as Hyperlight tags it. CPUID leaf 0 on x86_64
/// ("GenuineIntel", "AuthenticAMD"), the MIDR_EL1 implementer on
/// aarch64 ("0x41").
fn cpu_vendor() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        let r = unsafe { core::arch::x86_64::__cpuid(0) };
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&r.ebx.to_le_bytes());
        bytes[4..8].copy_from_slice(&r.edx.to_le_bytes());
        bytes[8..12].copy_from_slice(&r.ecx.to_le_bytes());
        let s = String::from_utf8_lossy(&bytes).replace(char::is_whitespace, "_");
        if s.is_empty() { "unknown".to_string() } else { s }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let midr: u64;
        unsafe { core::arch::asm!("mrs {}, MIDR_EL1", out(reg) midr) };
        format!("{:#04x}", (midr >> 24) & 0xff)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unknown".to_string()
    }
}

/// The control channel back to fiberd, shared by every fiber thread.
#[derive(Clone)]
struct Ctl(Arc<Mutex<File>>);

impl Ctl {
    fn say(&self, line: impl AsRef<str>) {
        if let Ok(mut f) = self.0.lock() {
            let _ = writeln!(f, "{}", line.as_ref());
            let _ = f.flush();
        }
    }
}

enum Cmd {
    Park { dir: PathBuf, sync: bool },
    Kill,
}

struct Args {
    guest: PathBuf,
    heap_mb: u64,
    check: bool,
    /// The grant's engine socket, None when the grant has no engine.
    engine: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut a = Args { guest: PathBuf::new(), heap_mb: 32, check: false, engine: None };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        match k.as_str() {
            "--version" => {
                println!("{}", facts());
                std::process::exit(0);
            }
            "--guest" => a.guest = PathBuf::from(it.next().context("--guest needs a path")?),
            "--heap-mb" => a.heap_mb = it.next().context("--heap-mb needs a number")?.parse()?,
            "--check" => a.check = true,
            "--engine" => a.engine = Some(PathBuf::from(it.next().context("--engine needs a path")?)),
            // The template command's first word names the guest for
            // fiberd's benefit; anything else is unknown.
            "guest" => {}
            other => return Err(anyhow!("unknown argument {other}")),
        }
    }
    if a.guest.as_os_str().is_empty() {
        return Err(anyhow!("--guest is required"));
    }
    Ok(a)
}

/// Build the warm sandbox and take the template snapshot.
fn warm(args: &Args) -> Result<Arc<Snapshot>> {
    // The heap the guest gets is the template's plus room to grow W.
    // Scratch is the guest's writable physical memory: every heap page
    // it touches is allocated from it (the guest aborts with "Out of
    // physical memory" otherwise), plus page tables and its stacks, so
    // it is the heap with a margin, page-aligned.
    let heap: u64 = (args.heap_mb + 96) << 20;
    let scratch: usize = ((heap + (8 << 20)) as usize + 0xfff) & !0xfff;
    let mut sb = SandboxBuilder::from_file(&args.guest)
        .heap_size(heap)
        .scratch_size(scratch)
        .build()
        .context("build warm sandbox")?;
    let bytes: i64 = sb.call("Init", args.heap_mb as i64).context("Init")?;
    if bytes < 0 {
        return Err(anyhow!("Init returned {bytes}"));
    }
    sb.snapshot().context("warm snapshot")
}

fn from_snapshot(s: Arc<Snapshot>, hf: HostFunctions) -> Result<MultiUseSandbox> {
    MultiUseSandbox::from_snapshot(s, hf, None).context("sandbox from snapshot")
}

/// The host functions of a fiber's sandbox. `Engine` is bound here to the
/// fence fiberd named on CLONE or RESUME, never to one the guest gives.
fn host_functions(engine: Option<&Path>, fence: &str) -> Result<HostFunctions> {
    let mut hf = HostFunctions::default();
    let engine = engine.map(Path::to_path_buf);
    let fence = fence.to_string();
    hf.register_host_function("Engine", move |line: String| -> hyperlight_host::Result<String> {
        Ok(engine_call(engine.as_deref(), &fence, &line))
    })
    .context("register Engine")?;
    Ok(hf)
}

/// Longest line to or from the engine, its newline counted.
const ENGINE_LINE_MAX: usize = 256;

/// How long one engine request may take, so a stuck engine cannot hold
/// the fiber's thread, and with it a park.
const ENGINE_TIMEOUT: Duration = Duration::from_secs(10);

/// What `Engine` answers the guest for line: the engine's reply to the
/// request engine_line makes of it, or an `err` of the helper's own.
fn engine_call(engine: Option<&Path>, fence: &str, line: &str) -> String {
    let Some(req) = engine_line(fence, line) else {
        return "err proto".to_string();
    };
    let Some(path) = engine else {
        return "err no engine".to_string();
    };
    match ask_engine(path, &req) {
        Ok(reply) if !reply.is_empty() => reply,
        Ok(_) => "err no reply".to_string(),
        Err(_) => "err engine unreachable".to_string(),
    }
}

/// The engine request for a guest's line, with the fiber's fence put in
/// by the helper. The guest gives `reserve <n>`, `fill <n>`, `release` or
/// `sum`, one space apart, with n decimal digits. Nothing it can send
/// holds a fence, a second line or another token, so the request names
/// this fiber alone. Anything else is None.
fn engine_line(fence: &str, line: &str) -> Option<String> {
    if !valid_fence(fence) {
        return None;
    }
    let mut words = line.split(' ');
    let verb = words.next()?;
    let arg = words.next();
    if words.next().is_some() {
        return None;
    }
    let req = match (verb, arg) {
        ("reserve" | "fill", Some(n)) if is_decimal(n) => format!("{verb} {fence} {n}"),
        ("release" | "sum", None) => format!("{verb} {fence}"),
        _ => return None,
    };
    (req.len() < ENGINE_LINE_MAX).then_some(req)
}

/// Whether f is a fence as the engine takes one. Printable ASCII with no
/// space, and not the `-` its DEVICE lines use for the pool.
fn valid_fence(f: &str) -> bool {
    !f.is_empty() && f != "-" && f.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Whether s is one to twenty decimal digits, a u64's longest.
fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

/// One request on a fresh connection to the engine, and its reply line.
fn ask_engine(path: &Path, req: &str) -> std::io::Result<String> {
    let mut s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(ENGINE_TIMEOUT))?;
    s.set_write_timeout(Some(ENGINE_TIMEOUT))?;
    s.write_all(format!("{req}\n").as_bytes())?;
    let mut reply = String::new();
    BufReader::new(s.take(ENGINE_LINE_MAX as u64)).read_line(&mut reply)?;
    Ok(reply.trim_end().to_string())
}

/// The fiber's `gpufill <seed> <bytes>`, through the guest's GpuFill.
fn gpu_fill(sb: &mut MultiUseSandbox, args: &str) -> String {
    let mut words = args.split(' ');
    let (Some(seed), Some(bytes), None) = (words.next(), words.next(), words.next()) else {
        return "err usage: gpufill <seed> <bytes>".to_string();
    };
    let (Ok(seed), Ok(bytes)) = (seed.parse::<u64>(), bytes.parse::<u64>()) else {
        return "err usage: gpufill <seed> <bytes>".to_string();
    };
    sb.call::<String>("GpuFill", (seed, bytes)).unwrap_or_else(|e| format!("err {e}"))
}

fn payload_num(payload: &[u8], key: &str) -> u64 {
    let s = String::from_utf8_lossy(payload);
    let Some(i) = s.find(key) else { return 0 };
    let rest = &s[i + key.len()..];
    let Some(j) = rest.find(':') else { return 0 };
    rest[j + 1..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0)
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2).filter_map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()).collect()
}

/// What CLONE and RESUME carry for the guest: the host's generation and
/// 32 seed bytes, fields 5 and 6 of either line. A line the guest would
/// be wrong to take is refused here by name.
fn parse_incarnation(f: &[&str]) -> Result<(u64, Vec<u8>)> {
    if f.len() < 7 {
        return Err(anyhow!("{} needs 6 fields, got {}", f[0], f.len() - 1));
    }
    let generation: u64 = f[5].parse().context("generation")?;
    if generation < 1 {
        return Err(anyhow!("generation {generation} is not an incarnation"));
    }
    let seed = unhex(f[6]);
    if f[6].len() != 2 * SEED_BYTES || seed.len() != SEED_BYTES {
        return Err(anyhow!("seed is not {SEED_BYTES} hex bytes"));
    }
    Ok((generation, seed))
}

const SEED_BYTES: usize = 32;

/// The command line as the log shows it. A CLONE or RESUME carries the
/// fiber's seed, which belongs to the fiber alone, and a CLONE its
/// payload, which is the caller's; both are shown by size. Every other
/// line is shown whole.
fn log_line(f: &[&str]) -> String {
    let (payload, seed) = match f[0] {
        "CLONE" => (Some(4), Some(6)),
        "RESUME" => (None, Some(6)),
        _ => (None, None),
    };
    f.iter()
        .enumerate()
        .map(|(i, v)| match (Some(i) == payload, Some(i) == seed) {
            (true, _) if *v != "-" => format!("payload:{}B", v.len() / 2),
            (_, true) => format!("seed:{}B", v.len() / 2),
            _ => v.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// What a fiber is born as: the kind of copy, the host's generation and
/// the seed, which the guest takes through `Incarnate` and the helper
/// then zeroes. The seed's hex is kept only under the payload's
/// "keep_seed" key, for the tests that look for it in the logs. A
/// resume carries no payload, so its park notes the flag instead.
struct Birth {
    kind: &'static str,
    generation: u64,
    seed: Vec<u8>,
    keep_seed: bool,
}

/// The park's note that its fiber kept its seed: an empty file beside
/// the snapshot, so a resumed sandbox honours the clone's payload as the
/// fake does through its state. The flag alone is written, never the seed.
const KEEP_SEED_NOTE: &str = "keep_seed";

fn note_keep_seed(dir: &Path, keep: bool) -> Result<()> {
    if keep {
        File::create(dir.join(KEEP_SEED_NOTE)).context("note keep_seed")?;
    }
    Ok(())
}

fn keep_seed_noted(dir: &Path) -> bool {
    dir.join(KEEP_SEED_NOTE).is_file()
}

/// One fiber: a sandbox, its endpoint and its command channel, on its
/// own thread. The line answered once serving is CLONED, or an ERROR.
fn fiber_thread(ctl: Ctl, fence: String, endpoint: PathBuf, mut sb: MultiUseSandbox, payload: Vec<u8>, mut birth: Birth, cmds: Receiver<Cmd>) {
    let mut dirtied: u64 = 0;
    let delay = payload_num(&payload, "\"ready_delay_ms\"");
    if delay > 0 {
        thread::sleep(Duration::from_millis(delay));
    }
    // The guest learns who it is before anything can reach it.
    let kept_seed = (birth.keep_seed || payload_num(&payload, "\"keep_seed\"") > 0).then(|| birth.seed.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let took = sb.call::<i64>("Incarnate", (birth.generation as i64, fence.clone(), birth.seed.clone()));
    birth.seed.fill(0);
    match took {
        Ok(g) if g == birth.generation as i64 => {}
        Ok(g) => {
            ctl.say(format!("ERROR {fence} incarnate: the guest took generation {g}, not {}", birth.generation));
            return;
        }
        Err(e) => {
            ctl.say(format!("ERROR {fence} incarnate: {e}"));
            return;
        }
    }
    let _ = std::fs::remove_file(&endpoint);
    let listener = match UnixListener::bind(&endpoint) {
        Ok(l) => l,
        Err(e) => {
            ctl.say(format!("ERROR {fence} bind: {e}"));
            return;
        }
    };
    let _ = listener.set_nonblocking(true);
    ctl.say(format!("CLONED {fence}"));
    let db = payload_num(&payload, "\"dirty_bytes\"");
    if db > 0 && let Ok(n) = sb.call::<i64>("Dirty", db as i64) {
        dirtied += n.max(0) as u64;
    }
    ctl.say(format!("W {fence} {dirtied}"));

    let mut serving = true;
    loop {
        // Commands from fiberd first.
        match cmds.try_recv() {
            Ok(Cmd::Kill) => {
                let _ = std::fs::remove_file(&endpoint);
                ctl.say(format!("EXITED {fence} exit:137"));
                return;
            }
            Ok(Cmd::Park { dir, sync }) => {
                serving = false;
                let _ = std::fs::remove_file(&endpoint);
                eprintln!("helper: {fence} parking into {}", dir.display());
                match park(&mut sb, &dir, kept_seed.is_some()) {
                    Ok(bytes) => {
                        eprintln!("helper: {fence} parked, {bytes} bytes");
                        ctl.say(format!("PARKED {fence} {bytes}"))
                    }
                    Err(e) => {
                        eprintln!("helper: {fence} park failed: {e:#}");
                        ctl.say(format!("ERROR {fence} park: {e:#}"))
                    }
                }
                if !sync {
                    ctl.say(format!("EXITED {fence} exit:0"));
                    return;
                }
            }
            Err(_) => {}
        }
        if !serving {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut w = stream;
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let l = line.trim();
                    let reply = match l {
                        "ping" => sb.call::<String>("Ping", ()).unwrap_or_else(|e| format!("err {e}")),
                        "incr" => sb.call::<i64>("Incr", ()).map(|n| n.to_string()).unwrap_or_else(|e| format!("err {e}")),
                        "get" => sb.call::<i64>("Get", ()).map(|n| n.to_string()).unwrap_or_else(|e| format!("err {e}")),
                        "fence" => sb.call::<String>("Fence", ()).unwrap_or_else(|e| format!("err {e}")),
                        "random" => sb.call::<u64>("Random", ()).map(|n| n.to_string()).unwrap_or_else(|e| format!("err {e}")),
                        "generation" => sb.call::<i64>("Generation", ()).map(|n| n.to_string()).unwrap_or_else(|e| format!("err {e}")),
                        "kind" => birth.kind.to_string(),
                        "seed" => kept_seed.clone().unwrap_or_else(|| "-".to_string()),
                        "pid" => "0".to_string(),
                        "rss" => dirtied.to_string(),
                        "gpucheck" => sb.call::<String>("GpuCheck", ()).unwrap_or_else(|e| format!("err {e}")),
                        _ if l.starts_with("gpufill ") => gpu_fill(&mut sb, &l[8..]),
                        _ if l.starts_with("gpuopen ") => {
                            sb.call::<String>("GpuOpen", l[8..].to_string()).unwrap_or_else(|e| format!("err {e}"))
                        }
                        "quit" => break,
                        _ if l.starts_with("dirty ") => {
                            let n: i64 = l[6..].trim().parse().unwrap_or(0);
                            match sb.call::<i64>("Dirty", n) {
                                Ok(got) => {
                                    dirtied += got.max(0) as u64;
                                    ctl.say(format!("W {fence} {dirtied}"));
                                    format!("ok {got}")
                                }
                                Err(e) => format!("err {e}"),
                            }
                        }
                        _ if l.starts_with("getenv ") => "-".to_string(),
                        _ => "err unknown command".to_string(),
                    };
                    if writeln!(w, "{reply}").is_err() {
                        break;
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// Park: snapshot the sandbox and save it as an OCI image layout in dir,
/// with the keep_seed note when the fiber kept its seed. Returns the
/// bytes on disk.
fn park(sb: &mut MultiUseSandbox, dir: &Path, keep_seed: bool) -> Result<u64> {
    std::fs::create_dir_all(dir)?;
    let snap = sb.snapshot().context("snapshot")?;
    let tag = OciTag::new("park").map_err(|e| anyhow!("{e}"))?;
    snap.save(dir, &tag).map_err(|e| anyhow!("save: {e}"))?;
    note_keep_seed(dir, keep_seed)?;
    Ok(dir_bytes(dir))
}

fn dir_bytes(dir: &Path) -> u64 {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += dir_bytes(&p);
            } else if let Ok(m) = e.metadata() {
                n += m.len();
            }
        }
    }
    n
}

fn resume_snapshot(dir: &Path) -> Result<Arc<Snapshot>> {
    let tag = OciTag::new("park").map_err(|e| anyhow!("{e}"))?;
    let s = Snapshot::load(dir, tag).map_err(|e| anyhow!("load: {e}"))?;
    Ok(Arc::new(s))
}

/// --check: the whole mechanism once, with timings, for hosts to prove
/// their hypervisor before fiberd is pointed at them.
fn check(args: &Args) -> Result<()> {
    let t = Instant::now();
    let snap = warm(args)?;
    eprintln!("warm sandbox + Init({} MiB) + snapshot: {:?}", args.heap_mb, t.elapsed());
    let t = Instant::now();
    let mut sb = from_snapshot(snap.clone(), host_functions(None, "check/1")?)?;
    let pong: String = sb.call("Ping", ())?;
    eprintln!("sandbox from snapshot + Ping = {pong}: {:?}", t.elapsed());
    let t = Instant::now();
    let g: i64 = sb.call("Incarnate", (1i64, "check/1".to_string(), vec![1u8; SEED_BYTES]))?;
    eprintln!("Incarnate(1, check/1, seed): {:?}, generation = {g}", t.elapsed());
    let r1: u64 = sb.call("Random", ())?;
    let mut other = from_snapshot(snap.clone(), HostFunctions::default())?;
    let _: i64 = other.call("Incarnate", (1i64, "check/2".to_string(), vec![2u8; SEED_BYTES]))?;
    let r2: u64 = other.call("Random", ())?;
    if r1 == r2 {
        return Err(anyhow!("two sandboxes with different seeds drew the same word {r1}"));
    }
    eprintln!("Random under two seeds: {r1} and {r2}");
    let n: i64 = sb.call("Incr", ())?;
    let d: i64 = sb.call("Dirty", 1i64 << 20)?;
    eprintln!("Incr = {n}, Dirty(1 MiB) = {d}");
    // The GPU probes with no engine. Each must answer, never fail.
    let probes: [(&str, String); 3] = [
        ("GpuCheck", sb.call("GpuCheck", ())?),
        ("GpuFill", sb.call("GpuFill", (1u64, 4096u64))?),
        ("GpuOpen", sb.call("GpuOpen", "/dev/nvidia0".to_string())?),
    ];
    let want = ["err none", "err no engine", "ENOENT"];
    for ((name, got), want) in probes.iter().zip(want) {
        if got != want {
            return Err(anyhow!("{name} without an engine = {got:?}, want {want:?}"));
        }
    }
    eprintln!("GpuCheck, GpuFill and GpuOpen without an engine: {want:?}");
    let dir = std::env::temp_dir().join(format!("fiberd-hl-check-{}", std::process::id()));
    let t = Instant::now();
    let bytes = park(&mut sb, &dir, false)?;
    eprintln!("park (Snapshot::save): {:?}, {} bytes", t.elapsed(), bytes);
    let t = Instant::now();
    let mut back = from_snapshot(resume_snapshot(&dir)?, host_functions(None, "check/2")?)?;
    let n2: i64 = back.call("Get", ())?;
    eprintln!("resume (Snapshot::load + sandbox): {:?}, counter = {n2}", t.elapsed());
    let _ = std::fs::remove_dir_all(&dir);
    if n2 != 1 {
        return Err(anyhow!("counter after resume = {n2}, want 1"));
    }
    println!("ok: {}", facts());
    Ok(())
}

fn main() -> Result<()> {
    let args = parse_args()?;
    if args.check {
        return check(&args);
    }
    // fd 3: fiberd's control socket.
    let ctl_file = unsafe { File::from_raw_fd(3) };
    let reader = BufReader::new(ctl_file.try_clone().context("fd 3")?);
    let ctl = Ctl(Arc::new(Mutex::new(ctl_file)));

    let snap = match warm(&args) {
        Ok(s) => s,
        Err(e) => {
            ctl.say(format!("ERROR warm {e:#}"));
            return Err(e);
        }
    };
    ctl.say(format!("READY {}", facts()));

    let mut fibers: HashMap<String, Sender<Cmd>> = HashMap::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // fiberd closed the channel: exit, and every sandbox with us
        };
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        // stderr is the helper's log (the backend points it at the
        // grant's zygote.log): one line per command, so a park that
        // never comes back can be told from one that never arrived.
        eprintln!("helper: < {}", log_line(&f));
        match f[0] {
            "CLONE" | "RESUME" if f.len() >= 2 => {
                let fence = f[1].to_string();
                let (generation, seed) = match parse_incarnation(&f) {
                    Ok(v) => v,
                    Err(e) => {
                        ctl.say(format!("ERROR {fence} {e:#}"));
                        continue;
                    }
                };
                // The sandbox's Engine is bound to the line's fence alone.
                let hf = host_functions(args.engine.as_deref(), &fence);
                let (endpoint, payload, sb, kind, keep_seed) = if f[0] == "CLONE" {
                    let sb = hf.and_then(|hf| from_snapshot(snap.clone(), hf));
                    (PathBuf::from(f[2]), if f[4] == "-" { Vec::new() } else { unhex(f[4]) }, sb, "clone", false)
                } else {
                    let park = Path::new(f[2]);
                    let sb = hf.and_then(|hf| resume_snapshot(park).and_then(|s| from_snapshot(s, hf)));
                    (PathBuf::from(f[3]), Vec::new(), sb, "resume", keep_seed_noted(park))
                };
                match sb {
                    Ok(sb) => {
                        let (tx, rx) = channel();
                        fibers.insert(fence.clone(), tx);
                        let c = ctl.clone();
                        let birth = Birth { kind, generation, seed, keep_seed };
                        thread::spawn(move || fiber_thread(c, fence, endpoint, sb, payload, birth, rx));
                    }
                    Err(e) => ctl.say(format!("ERROR {fence} {e:#}")),
                }
            }
            "PARK" if f.len() >= 4 => {
                if let Some(tx) = fibers.get(f[1]) {
                    let _ = tx.send(Cmd::Park { dir: PathBuf::from(f[2]), sync: f[3] == "1" });
                } else {
                    ctl.say(format!("ERROR {} unknown fiber", f[1]));
                }
            }
            "KILL" if f.len() >= 2 => {
                if let Some(tx) = fibers.remove(f[1]) {
                    let _ = tx.send(Cmd::Kill);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// Keep Read in scope for BufReader::lines on a File clone.
#[allow(dead_code)]
fn _read_marker(_: &dyn Read) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_are_four_tokens_fiberd_can_parse() {
        let line = facts();
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 4, "{line:?}");
        assert!(f.iter().all(|t| !t.is_empty()), "{line:?}");
        assert!(f[0].starts_with("fiberd-hyperlight-helper/"), "{line:?}");
        assert_eq!(f[1], concat!("hyperlight_host/", env!("HYPERLIGHT_HOST_VERSION")));
        assert!(matches!(f[2], "kvm" | "mshv" | "none"), "{line:?}");
    }

    const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn a_park_notes_the_flag_and_nothing_else() {
        let cases: &[(&str, bool)] = &[("a fiber that kept its seed", true), ("a fiber that did not", false)];
        for (name, keep) in cases {
            let dir = std::env::temp_dir().join(format!("fiberd-hl-note-{}-{keep}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            note_keep_seed(&dir, *keep).unwrap();
            assert_eq!(keep_seed_noted(&dir), *keep, "{name}");
            let files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
            assert_eq!(files.len(), usize::from(*keep), "{name}");
            for f in files {
                assert!(std::fs::read(f.path()).unwrap().is_empty(), "{name}: the note holds bytes");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn the_log_shows_no_seed_and_no_payload() {
        let cases: &[(&str, &str)] = &[
            (&format!("CLONE f /ep 500 6869 1 {SEED}"), "CLONE f /ep 500 payload:2B 1 seed:32B"),
            (&format!("CLONE f /ep 500 - 3 {SEED}"), "CLONE f /ep 500 - 3 seed:32B"),
            (&format!("RESUME f /park /ep 2000 2 {SEED}"), "RESUME f /park /ep 2000 2 seed:32B"),
            ("CLONE f /ep 500 -", "CLONE f /ep 500 -"),
            ("PARK f /park 1", "PARK f /park 1"),
            ("KILL f", "KILL f"),
        ];
        for (line, want) in cases {
            let f: Vec<&str> = line.split_whitespace().collect();
            let got = log_line(&f);
            assert_eq!(&got, want, "{line}");
            assert!(!got.contains(SEED), "{got}");
        }
    }

    #[test]
    fn an_incarnation_is_a_generation_and_32_seed_bytes() {
        let cases: &[(&str, Option<u64>)] = &[
            (&format!("CLONE f /ep 500 - 1 {SEED}"), Some(1)),
            (&format!("RESUME f /park /ep 2000 7 {SEED}"), Some(7)),
            ("CLONE f /ep 500 -", None),
            (&format!("CLONE f /ep 500 - 0 {SEED}"), None),
            (&format!("CLONE f /ep 500 - x {SEED}"), None),
            ("CLONE f /ep 500 - 1 0011", None),
            (&format!("CLONE f /ep 500 - 1 {SEED}zz"), None),
        ];
        for (line, want) in cases {
            let f: Vec<&str> = line.split_whitespace().collect();
            match (parse_incarnation(&f), want) {
                (Ok((g, seed)), Some(w)) => {
                    assert_eq!(g, *w, "{line}");
                    assert_eq!(seed.len(), SEED_BYTES, "{line}");
                    assert_eq!(seed[1], 1, "{line}");
                }
                (Err(_), None) => {}
                (got, want) => panic!("{line}: {got:?}, want {want:?}"),
            }
        }
    }
}
