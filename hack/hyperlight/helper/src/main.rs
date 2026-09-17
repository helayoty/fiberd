//! fiberd's Hyperlight helper: hack/hyperlight/PROTOCOL.md over fd 3.
//!
//! One helper per warm template. Warm builds a sandbox from the guest
//! binary, calls `Init`, and snapshots it; every fiber is a sandbox built
//! from that snapshot, owned by a thread that serves the fiber's unix
//! socket (the reference workload's line protocol) and takes commands
//! from the control loop. Park is `Snapshot::save` into the directory
//! fiberd gave (an OCI image layout); resume is `Snapshot::load` and a
//! sandbox built from it. W is what the guest dirtied through `Dirty`,
//! which the helper tracks and reports.
//!
//!   hyperlight-helper --guest <path> [--heap-mb N]     (fd 3 = control)
//!   hyperlight-helper --guest <path> --check           (self-test, no fd 3)

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
use hyperlight_host::{HostFunctions, MultiUseSandbox, SandboxBuilder};

const VERSION: &str = concat!("hyperlight-helper/", env!("CARGO_PKG_VERSION"), "+hyperlight_host-0.17.0");

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
}

fn parse_args() -> Result<Args> {
    let mut a = Args { guest: PathBuf::new(), heap_mb: 32, check: false };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        match k.as_str() {
            "--guest" => a.guest = PathBuf::from(it.next().context("--guest needs a path")?),
            "--heap-mb" => a.heap_mb = it.next().context("--heap-mb needs a number")?.parse()?,
            "--check" => a.check = true,
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

fn from_snapshot(s: Arc<Snapshot>) -> Result<MultiUseSandbox> {
    MultiUseSandbox::from_snapshot(s, HostFunctions::default(), None).context("sandbox from snapshot")
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

/// One fiber: a sandbox, its endpoint and its command channel, on its
/// own thread. `start` is the line answered once serving: CLONED, or an
/// ERROR.
fn fiber_thread(ctl: Ctl, fence: String, endpoint: PathBuf, mut sb: MultiUseSandbox, mut dirtied: u64, payload: Vec<u8>, cmds: Receiver<Cmd>) {
    let delay = payload_num(&payload, "\"ready_delay_ms\"");
    if delay > 0 {
        thread::sleep(Duration::from_millis(delay));
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
    if db > 0 {
        if let Ok(n) = sb.call::<i64>("Dirty", db as i64) {
            dirtied += n.max(0) as u64;
        }
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
                match park(&mut sb, &dir) {
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
                        "fence" => fence.clone(),
                        "pid" => "0".to_string(),
                        "rss" => dirtied.to_string(),
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

/// Park: snapshot the sandbox and save it as an OCI image layout in dir.
/// Returns the bytes on disk.
fn park(sb: &mut MultiUseSandbox, dir: &Path) -> Result<u64> {
    std::fs::create_dir_all(dir)?;
    let snap = sb.snapshot().context("snapshot")?;
    let tag = OciTag::new("park").map_err(|e| anyhow!("{e}"))?;
    snap.save(dir, &tag).map_err(|e| anyhow!("save: {e}"))?;
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
    let mut sb = from_snapshot(snap.clone())?;
    let pong: String = sb.call("Ping", ())?;
    eprintln!("sandbox from snapshot + Ping = {pong}: {:?}", t.elapsed());
    let n: i64 = sb.call("Incr", ())?;
    let d: i64 = sb.call("Dirty", 1i64 << 20)?;
    eprintln!("Incr = {n}, Dirty(1 MiB) = {d}");
    let dir = std::env::temp_dir().join(format!("fiberd-hl-check-{}", std::process::id()));
    let t = Instant::now();
    let bytes = park(&mut sb, &dir)?;
    eprintln!("park (Snapshot::save): {:?}, {} bytes", t.elapsed(), bytes);
    let t = Instant::now();
    let mut back = from_snapshot(resume_snapshot(&dir)?)?;
    let n2: i64 = back.call("Get", ())?;
    eprintln!("resume (Snapshot::load + sandbox): {:?}, counter = {n2}", t.elapsed());
    let _ = std::fs::remove_dir_all(&dir);
    if n2 != 1 {
        return Err(anyhow!("counter after resume = {n2}, want 1"));
    }
    println!("ok: {VERSION}");
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
    ctl.say(format!("READY {VERSION}"));

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
        eprintln!("helper: < {}", line.trim());
        match f[0] {
            "CLONE" if f.len() >= 5 => {
                let (fence, endpoint, payload) = (f[1].to_string(), PathBuf::from(f[2]), if f[4] == "-" { Vec::new() } else { unhex(f[4]) });
                match from_snapshot(snap.clone()) {
                    Ok(sb) => {
                        let (tx, rx) = channel();
                        fibers.insert(fence.clone(), tx);
                        let c = ctl.clone();
                        thread::spawn(move || fiber_thread(c, fence, endpoint, sb, 0, payload, rx));
                    }
                    Err(e) => ctl.say(format!("ERROR {fence} {e:#}")),
                }
            }
            "RESUME" if f.len() >= 5 => {
                let (fence, dir, endpoint) = (f[1].to_string(), PathBuf::from(f[2]), PathBuf::from(f[3]));
                match resume_snapshot(&dir).and_then(from_snapshot) {
                    Ok(sb) => {
                        let (tx, rx) = channel();
                        fibers.insert(fence.clone(), tx);
                        let c = ctl.clone();
                        thread::spawn(move || fiber_thread(c, fence, endpoint, sb, 0, Vec::new(), rx));
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
