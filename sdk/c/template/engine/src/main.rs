//! refengine, the reference device engine. fiberd starts one per grant
//! with a device budget, in the grant's own engine cgroup leaf, as its
//! own uid. It holds the grant's whole device pool and serves every
//! fiber of the grant over engine.sock, one request line per connection,
//! so no fiber ever opens the device. It learns which fiber is asking
//! from the kernel and from fiberd's LEAF lines, never from the request,
//! and it reports every slice to fiberd on fd 3. The protocol is
//! bin/gpu-poc/PROTOCOL.md. With `--sim-mb` the pool is host memory,
//! and without it the pool is GPU memory through libcuda (cuda.rs).
//!
//! One thread serves everything. A poll loop watches fd 3 and the
//! listening socket, takes every pending fd 3 line first, then answers
//! one connection at a time. Nothing needs a lock, and the seccomp
//! program covers the one thread it is installed on.

// ---- modules and bounds ----

mod ctl;
mod cuda;
mod peer;
mod pool;
mod proto;

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::ctl::{Control, Ctl, Recv};
use crate::cuda::Cuda;
use crate::peer::Map;
use crate::pool::{Device, Fault, Pool, Reserved, Sim};
use crate::proto::{LINE_MAX, Reply, Request};

/// How long a fiber has to send its request line once connected. One
/// thread serves every fiber, so a slow one delays the rest by at most
/// this.
const REQUEST_WAIT: Duration = Duration::from_secs(2);
/// How long the reply may take to go out. It is one short line into an
/// empty socket, so this only bounds a peer that is gone.
const REPLY_WAIT: Duration = Duration::from_secs(1);
/// Longest GPU name the GPU line carries.
const NAME_MAX: usize = 64;

/// die ends a start that cannot go on, naming why. fiberd fails the
/// warm with it.
fn die(why: &str) -> ! {
    eprintln!("refengine: {why}");
    std::process::exit(2)
}

/// failed turns a device error into the request's reply. A fatal one
/// ends the engine, since the pool may be poisoned for every fiber, and
/// fiberd sets every slice to zero. A soft one fails this request alone
/// with `err device`.
fn failed(f: Fault) -> Reply {
    match f {
        Fault::Fatal(word) => {
            eprintln!("refengine: device fault: {word}");
            std::process::exit(1)
        }
        Fault::Soft(word) => {
            eprintln!("refengine: device error: {word}");
            Reply::Err("device")
        }
    }
}

// ---- arguments ----

/// The command line, `--grant <grant> --socket <path> [--sim-mb N]
/// [--pool-mb N]`. `--pool-mb` sizes a CUDA pool, so it goes without
/// `--sim-mb`.
struct Args {
    grant: String,
    socket: PathBuf,
    sim_mb: Option<u64>,
    pool_mb: Option<u64>,
}

impl Args {
    /// parse reads each flag once, with its value as the next argument.
    fn parse(mut it: impl Iterator<Item = OsString>) -> Result<Args, String> {
        let (mut grant, mut socket, mut sim_mb, mut pool_mb) = (None, None, None, None);
        while let Some(flag) = it.next() {
            let flag = flag.to_string_lossy().into_owned();
            let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            let text = value.to_string_lossy().into_owned();
            let seen = match flag.as_str() {
                "--grant" => grant.replace(text).is_some(),
                "--socket" => socket.replace(PathBuf::from(value)).is_some(),
                "--sim-mb" => {
                    let mb = proto::dec_u64(text.as_bytes()).filter(|&mb| mb > 0);
                    let mb = mb.ok_or("--sim-mb needs a whole number of MiB, at least 1")?;
                    sim_mb.replace(mb).is_some()
                }
                "--pool-mb" => {
                    let mb = proto::dec_u64(text.as_bytes()).filter(|&mb| mb > 0);
                    let mb = mb.ok_or("--pool-mb needs a whole number of MiB, at least 1")?;
                    pool_mb.replace(mb).is_some()
                }
                _ => return Err(format!("unknown flag {flag}")),
            };
            if seen {
                return Err(format!("{flag} given twice"));
            }
        }
        let grant: String = grant.ok_or("--grant is required")?;
        if grant.is_empty() || !grant.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err("--grant must be printable with no space".to_owned());
        }
        Ok(Args {
            grant,
            socket: socket.ok_or("--socket is required")?,
            sim_mb,
            pool_mb,
        })
    }
}

// ---- start ----

/// Start-up runs in the protocol's order. ENGINE and GPU, then the pool
/// allocated and zeroed, the socket bound, the seccomp program on, and
/// READY last. Every start failure exits before READY, so fiberd fails
/// the warm with the reason on stderr.
fn main() {
    let argv = std::env::args_os().skip(1);
    let args = Args::parse(argv).unwrap_or_else(|e| die(&e));
    let ctl = Ctl::open().unwrap_or_else(|e| die(&e));
    let mut dev = open_device(&args).unwrap_or_else(|e| die(&e));
    let (class, cap) = (dev.class(), dev.capacity());
    ctl.send(&format!("ENGINE {class} {cap} 1 raw256"));
    let (name, cc, driver) = dev.gpu();
    let gpu = format!("GPU {} {} {}", word(&name), word(&cc), word(&driver));
    ctl.send(&gpu);
    dev.allocate().unwrap_or_else(|e| die(&e));
    let pool = Pool::new(dev);
    // The map's tables take their random hash keys here, before the
    // seal, so nothing after it asks the kernel for randomness.
    let map = Map::default();
    let listener = bind(&args.socket).unwrap_or_else(|e| die(&e));
    if let Err(e) = peer::seal() {
        die(&format!("seccomp: {e}"));
    }
    ctl.send("READY");
    let (grant, at) = (&args.grant, args.socket.display());
    eprintln!("refengine: {grant} ready, {cap} bytes {class} on {at}");
    let engine = Engine {
        ctl,
        map,
        pool,
        listener,
    };
    engine.serve()
}

/// open_device opens the device the arguments name, not yet allocated.
/// `--sim-mb` is the simulated one. Without it the class is gpu, the
/// first FIBERD_DEVICES entry is the device, and libcuda drives it. It
/// never falls back to another device.
fn open_device(args: &Args) -> Result<Box<dyn Device>, String> {
    let first = first_device();
    let Some(mb) = args.sim_mb else {
        let Some(entry) = first else {
            let none = "FIBERD_DEVICES names no device and --sim-mb is not set";
            return Err(none.to_owned());
        };
        let cuda = Cuda::open(&entry, args.pool_mb)?;
        return Ok(Box::new(cuda));
    };
    if args.pool_mb.is_some() {
        return Err("--pool-mb sizes a CUDA pool, not a --sim-mb one".to_owned());
    }
    let cap = mb.checked_mul(1 << 20).ok_or("--sim-mb is too large")?;
    if let Some(d) = first {
        eprintln!("refengine: simulated pool, device {d} is not opened");
    }
    Ok(Box::new(Sim::new(cap)))
}

/// The first entry of FIBERD_DEVICES, a comma-separated list.
fn first_device() -> Option<String> {
    let all = std::env::var("FIBERD_DEVICES").ok()?;
    let first = all.split(',').next()?;
    (!first.is_empty()).then(|| first.to_owned())
}

/// word makes one token of a GPU line field. Spaces and every other
/// byte that is not printable ASCII become `_`, and it is cut to
/// NAME_MAX, so the line stays one line under 256 bytes.
fn word(s: &str) -> String {
    let w: String = s.bytes().take(NAME_MAX).map(graphic).collect();
    if w.is_empty() {
        return "_".to_owned();
    }
    w
}

/// b as a char when it is printable ASCII other than space, else `_`.
fn graphic(b: u8) -> char {
    if b.is_ascii_graphic() {
        char::from(b)
    } else {
        '_'
    }
}

/// bind listens on path with mode 0666, so fibers of any uid connect. A
/// socket left by an engine before this one is removed first. fiberd
/// made the directory the engine's own, so nothing else can have put a
/// file there.
fn bind(path: &Path) -> Result<UnixListener, String> {
    let at = path.display();
    let meta = fs::symlink_metadata(path);
    if meta.is_ok_and(|m| m.file_type().is_socket()) {
        let gone = fs::remove_file(path);
        gone.map_err(|e| format!("remove {at}: {e}"))?;
    }
    let listener = UnixListener::bind(path);
    let listener = listener.map_err(|e| format!("bind {at}: {e}"))?;
    let mode = fs::Permissions::from_mode(0o666);
    let set = fs::set_permissions(path, mode);
    set.map_err(|e| format!("chmod {at}: {e}"))?;
    let nb = listener.set_nonblocking(true);
    nb.map_err(|e| format!("listen {at}: {e}"))?;
    Ok(listener)
}

// ---- fd 3 lines ----

/// Everything the serving thread owns.
struct Engine {
    ctl: Ctl,
    map: Map,
    pool: Pool,
    listener: UnixListener,
}

impl Engine {
    /// drain takes every pending fd 3 line, without blocking. The poll
    /// loop calls it when fd 3 is readable, and a request calls it on a
    /// miss, so a LEAF fiberd wrote before the fiber ran is always seen
    /// before the fiber is refused. fiberd closing fd 3 ends the engine.
    fn drain(&mut self) {
        loop {
            match self.ctl.recv() {
                Recv::Line(mut line) => self.control(&mut line),
                Recv::Bad => self.ctl.error(b"-", "proto"),
                Recv::Empty => return,
                Recv::Closed => ctl::gone("closed"),
            }
        }
    }

    /// control does one line from fiberd. A refusal is an ERROR line.
    fn control(&mut self, line: &mut [u8]) {
        match ctl::parse(line) {
            None => self.ctl.error(b"-", "proto"),
            Some(Control::Leaf { fence, cgroup }) => {
                if let Err(why) = self.map.leaf(fence, cgroup) {
                    self.ctl.error(fence, why.token());
                }
            }
            Some(Control::Unleaf { fence }) => self.map.unleaf(fence),
            Some(Control::Relay { cgroup }) => {
                if let Err(why) = self.map.relay(cgroup) {
                    self.ctl.error(b"-", why.token());
                }
            }
            Some(Control::Evict { fence }) => {
                self.pool.release(fence);
                self.report(fence);
            }
        }
    }

    /// report sends the fence's slice and then the whole pool, the two
    /// DEVICE lines back to back, after every change to a slice.
    fn report(&self, fence: &[u8]) {
        let bytes = self.pool.bytes(fence);
        let fence = String::from_utf8_lossy(fence);
        self.ctl.send(&format!("DEVICE {fence} {bytes} 0"));
        let (used, cap) = (self.pool.used(), self.pool.capacity());
        self.ctl.send(&format!("DEVICE - {used} {cap}"));
    }
}

// ---- serving ----

impl Engine {
    /// serve is the poll loop. fd 3 goes first on every wake, then one
    /// connection is answered. It never returns.
    fn serve(mut self) -> ! {
        loop {
            let mut fds = [
                pollin(self.ctl.as_fd().as_raw_fd()),
                pollin(self.listener.as_raw_fd()),
            ];
            // SAFETY: fds is a live local array and the count passed is
            // its length.
            let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                die(&format!("poll: {err}"));
            }
            let [c, l] = fds;
            if c.revents != 0 {
                self.drain();
            }
            if l.revents & libc::POLLIN != 0 {
                self.accept();
            }
        }
    }

    /// accept answers one connection, one line in and one line out, and
    /// closes it. A failed accept, such as a peer that already left, is
    /// skipped.
    fn accept(&mut self) {
        let Ok((conn, _)) = self.listener.accept() else {
            return;
        };
        let reply = self.answer(&conn).line();
        let mut out = &conn;
        if out.set_write_timeout(Some(REPLY_WAIT)).is_ok() {
            let _ = out.write_all(reply.as_bytes());
        }
    }

    /// answer reads the peer's identity first, then its line, and checks
    /// the fence the line names against the peer's mapping. Any miss
    /// drains fd 3 and looks again before it refuses, which covers a
    /// fiber's first request after its LEAF, a later LEAF for its
    /// cgroup and a relay naming a fence whose LEAF is still pending.
    fn answer(&mut self, conn: &UnixStream) -> Reply {
        let cgroup = peer::cgroup_of(conn.as_fd());
        // The line is read even for a refused peer, so the reply is not
        // lost to a reset from unread bytes at close.
        let line = read_line(conn);
        let Ok(cgroup) = cgroup else {
            return Reply::Err("fence");
        };
        let Some(mut line) = line else {
            return Reply::Err("proto");
        };
        if !self.map.known(&cgroup) {
            self.drain();
            if !self.map.known(&cgroup) {
                return Reply::Err("fence");
            }
        }
        let Some(req) = proto::parse(&mut line) else {
            return Reply::Err("proto");
        };
        let named = req.fence();
        if named.is_some_and(|f| !self.map.may_name(&cgroup, f)) {
            self.drain();
            if named.is_some_and(|f| !self.map.may_name(&cgroup, f)) {
                return Reply::Err("fence");
            }
        }
        self.request(req)
    }

    /// request does what an allowed request asks of the pool.
    fn request(&mut self, req: Request<'_>) -> Reply {
        match req {
            Request::Stat => Reply::Stat(self.pool.used(), self.pool.capacity()),
            Request::Reserve { fence, bytes } => match self.pool.reserve(fence, bytes) {
                Ok(Reserved::Done) => {
                    self.report(fence);
                    Reply::Ok
                }
                Ok(Reserved::Capacity) => Reply::Err("capacity"),
                Err(f) => {
                    // A soft fault dropped the old slice, so fiberd
                    // hears the fence is down to none.
                    let reply = failed(f);
                    self.report(fence);
                    reply
                }
            },
            Request::Release { fence } => {
                self.pool.release(fence);
                self.report(fence);
                Reply::Ok
            }
            Request::Fill { fence, seed } => hashed(self.pool.fill(fence, seed)),
            Request::Sum { fence } => hashed(self.pool.sum(fence)),
        }
    }
}

/// A pollfd that waits for input on fd.
fn pollin(fd: i32) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// hashed turns a fill or sum into its reply. No slice is `err none`,
/// and a device error is failed's.
fn hashed(r: Result<Option<u64>, Fault>) -> Reply {
    match r {
        Ok(Some(h)) => Reply::Hash(h),
        Ok(None) => Reply::Err("none"),
        Err(f) => failed(f),
    }
}

/// read_line reads one request line, at most LINE_MAX bytes with its
/// newline, within REQUEST_WAIT of the first read. It gives the line
/// without the newline, or None for a peer that closed, stalled or sent
/// a line too long. Bytes after the newline are ignored.
fn read_line(conn: &UnixStream) -> Option<Vec<u8>> {
    let deadline = Instant::now().checked_add(REQUEST_WAIT)?;
    let mut buf = [0u8; LINE_MAX];
    let mut got = 0usize;
    let mut stream = conn;
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        if left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        let room = buf.get_mut(got..).filter(|r| !r.is_empty())?;
        let n = match stream.read(room) {
            Ok(0) => return None,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        let start = got;
        got = got.checked_add(n)?;
        let fresh = buf.get(start..got)?;
        if let Some(nl) = fresh.iter().position(|&b| b == b'\n') {
            return buf.get(..start.checked_add(nl)?).map(<[u8]>::to_vec);
        }
    }
}
