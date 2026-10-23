//! The slice file, what SAVE writes and RESTORE reads. One header line,
//! `fiberd-slice 1 <class> <layout> <bytes> <hash>`, then exactly bytes
//! raw bytes, with hash their FNV-1a 64. fiberd opens the file and hands
//! the engine its descriptor on fd 3, so the engine needs no path and
//! no write access to any directory. Everything here goes through
//! positional reads and writes from the file's start, in pieces of at
//! most CHUNK bytes, so a slice of any size costs that much host memory.
//! The header is parsed strictly under a hard length cap, and its byte
//! count is never trusted past the engine's own capacity.

// ---- bounds and reasons ----

use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::FileExt;

use crate::pool::{Fault, LAYOUT, Pool, Reserved, UNIT};
use crate::proto::{self, Fnv};

/// The first word of a header.
const MAGIC: &[u8] = b"fiberd-slice";
/// The format's version, the header's second word.
const VERSION: &[u8] = b"1";
/// Longest header read. The longest one the engine writes, with a
/// 20-digit byte count, is under 90 bytes, so a file whose first line
/// outgrows this is not a slice file.
const HEADER_MAX: usize = 128;
/// The host buffer a copy goes through, a multiple of UNIT.
const CHUNK: usize = 1 << 20;
/// A range past the slice or the buffer, which only a bug here could ask
/// for.
const RANGE: Fault = Fault::Fatal("range");

/// Why a SAVE or RESTORE failed, the one token of its ERROR line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The header is malformed, or names a size the layout cannot have.
    Header,
    /// The header's class is not the engine's.
    Class,
    /// The header's layout is not the engine's.
    Layout,
    /// The file ended before the header's byte count.
    Short,
    /// The bytes do not hash to the header's hash.
    Hash,
    /// The pool cannot hold the slice.
    Capacity,
    /// The file could not be read or written.
    Io,
    /// The fence has no slice to save.
    None,
    /// The device failed. main.rs ends the engine on a fatal one.
    Device(Fault),
}

impl Why {
    /// The token, as PROTOCOL.md lists them. Device is `device`, though
    /// main.rs sorts a fatal one out first.
    pub fn token(self) -> &'static str {
        match self {
            Why::Header => "header",
            Why::Class => "class",
            Why::Layout => "layout",
            Why::Short => "short",
            Why::Hash => "hash",
            Why::Capacity => "capacity",
            Why::Io => "io",
            Why::None => "none",
            Why::Device(_) => "device",
        }
    }
}

// ---- the header ----

/// A parsed header the engine can take, class and layout its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Where the bytes start, just after the header's newline.
    data: u64,
    /// How many bytes follow, a whole number of UNITs within capacity.
    bytes: u64,
    /// Their FNV-1a 64, as the header claims it.
    hash: u64,
}

/// line is the header for a slice of bytes with hash, newline included.
/// Its length does not depend on the hash, so save knows where the
/// bytes go before it has hashed them.
fn line(class: &str, bytes: u64, hash: u64) -> String {
    format!("fiberd-slice 1 {class} {LAYOUT} {bytes} {hash:016x}\n")
}

/// header reads and checks the file's header against class, the
/// engine's own, and capacity, the pool's. The order of the checks is
/// the order of the reasons. A line that is not six words of the right
/// shape is `header`, then class, layout, and a byte count the pool
/// could never hold is `capacity`. A zero count, or one that is not
/// whole UNITs, is `header`, since the engine never writes one.
pub fn header(file: &File, class: &str, capacity: u64) -> Result<Header, Why> {
    let mut buf = [0u8; HEADER_MAX];
    let got = read_head(file, &mut buf)?;
    let head = buf.get(..got).ok_or(Why::Header)?;
    let nl = head.iter().position(|&b| b == b'\n').ok_or(Why::Header)?;
    let text = head.get(..nl).ok_or(Why::Header)?;
    let mut words = text.split(|&b| b == b' ');
    let mut next = || words.next().ok_or(Why::Header);
    let magic = next()?;
    let version = next()?;
    let kind = next()?;
    let layout = next()?;
    let bytes = next()?;
    let hash = next()?;
    if words.next().is_some() || magic != MAGIC || version != VERSION {
        return Err(Why::Header);
    }
    if kind != class.as_bytes() {
        return Err(Why::Class);
    }
    if layout != LAYOUT.as_bytes() {
        return Err(Why::Layout);
    }
    let bytes = proto::dec_u64(bytes).ok_or(Why::Header)?;
    let hash = hex_u64(hash).ok_or(Why::Header)?;
    if bytes == 0 || !bytes.is_multiple_of(UNIT) {
        return Err(Why::Header);
    }
    if bytes > capacity {
        return Err(Why::Capacity);
    }
    let data = nl.checked_add(1).ok_or(Why::Header)?;
    let data = u64::try_from(data).map_err(|_| Why::Header)?;
    // The file's end must fit the offsets the reads use.
    data.checked_add(bytes).ok_or(Why::Header)?;
    Ok(Header { data, bytes, hash })
}

/// A hash as the header carries it, exactly 16 lowercase hex digits.
fn hex_u64(s: &[u8]) -> Option<u64> {
    if s.len() != 16 || !s.iter().all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok()
}

// ---- save ----

/// save writes the fence's slice to file as a slice file and gives its
/// size and hash. The bytes go first, piece by piece from the device
/// through the host buffer, hashed as they pass, and the header last,
/// at the start, since its length is known before its hash is. The
/// file is then cut to exactly the header and the bytes. The slice is
/// untouched, held or not.
pub fn save(file: &File, pool: &mut Pool, fence: &[u8]) -> Result<(u64, u64), Why> {
    let bytes = pool.bytes(fence);
    if bytes == 0 {
        return Err(Why::None);
    }
    let class = pool.class();
    let data = u64::try_from(line(class, bytes, 0).len()).map_err(|_| Why::Io)?;
    let end = data.checked_add(bytes).ok_or(Why::Io)?;
    let mut buf = vec![0u8; CHUNK];
    let mut h = Fnv::new();
    let mut done = 0u64;
    while done < bytes {
        let n = piece(bytes.saturating_sub(done));
        let part = buf.get_mut(..n).ok_or(Why::Device(RANGE))?;
        pool.read(fence, done, part).map_err(Why::Device)?;
        h.update(part);
        let at = data.checked_add(done).ok_or(Why::Io)?;
        file.write_all_at(part, at).map_err(|_| Why::Io)?;
        done = done.checked_add(n as u64).ok_or(Why::Io)?;
    }
    let hash = h.finish();
    let head = line(class, bytes, hash);
    file.write_all_at(head.as_bytes(), 0).map_err(|_| Why::Io)?;
    file.set_len(end).map_err(|_| Why::Io)?;
    Ok((bytes, hash))
}

/// The next piece of a copy with left bytes to go, at most CHUNK.
fn piece(left: u64) -> usize {
    usize::try_from(left).map_or(CHUNK, |l| l.min(CHUNK))
}

// ---- restore ----

/// restore reserves header's byte count under fence and reads the
/// file's bytes into it, piece by piece, hashed as they pass. It gives
/// the slice's size. On any failure the fence is left with no slice, an
/// old one of its included, so the caller's DEVICE pair reports none.
pub fn restore(file: &File, header: &Header, pool: &mut Pool, fence: &[u8]) -> Result<u64, Why> {
    let placed = place(file, header, pool, fence);
    if placed.is_err() {
        pool.release(fence);
    }
    placed
}

/// place does restore's work, and leaves the slice to its caller on a
/// failure. The hash is checked after the last piece is on the device,
/// so a torn file costs one slice's worth of copying and nothing else.
fn place(file: &File, header: &Header, pool: &mut Pool, fence: &[u8]) -> Result<u64, Why> {
    match pool.reserve(fence, header.bytes).map_err(Why::Device)? {
        Reserved::Done => {}
        Reserved::Capacity => return Err(Why::Capacity),
    }
    let mut buf = vec![0u8; CHUNK];
    let mut h = Fnv::new();
    let mut done = 0u64;
    while done < header.bytes {
        let n = piece(header.bytes.saturating_sub(done));
        let part = buf.get_mut(..n).ok_or(Why::Device(RANGE))?;
        let at = header.data.checked_add(done).ok_or(Why::Io)?;
        read_full(file, at, part)?;
        h.update(part);
        pool.write(fence, done, part).map_err(Why::Device)?;
        done = done.checked_add(n as u64).ok_or(Why::Io)?;
    }
    if h.finish() != header.hash {
        return Err(Why::Hash);
    }
    Ok(header.bytes)
}

// ---- the file ----

/// read_head fills buf from the file's start, until buf is full or the
/// file ends, and gives how much it holds. A short file is not an error
/// here, since header decides whether a newline arrived.
fn read_head(file: &File, buf: &mut [u8]) -> Result<usize, Why> {
    let mut got = 0usize;
    while let Some(room) = buf.get_mut(got..).filter(|r| !r.is_empty()) {
        match file.read_at(room, got as u64) {
            Ok(0) => break,
            Ok(n) => got = got.checked_add(n).ok_or(Why::Io)?,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(Why::Io),
        }
    }
    Ok(got)
}

/// read_full fills buf from the file at at. A file that ends first is
/// `short`, and any other failure is `io`.
fn read_full(file: &File, at: u64, buf: &mut [u8]) -> Result<(), Why> {
    match file.read_exact_at(buf, at) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(Why::Short),
        Err(_) => Err(Why::Io),
    }
}
