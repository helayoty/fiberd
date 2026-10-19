//! The types the entries take, laid out as libfiberzygote.h lays them
//! out, and the sizes of the library's fixed storage. Const asserts at
//! the end pin the layout.

use core::ffi::{c_char, c_int, c_uint};
use core::mem::{offset_of, size_of};

/// A fence is at most FENCE_MAX - 1 characters.
pub const FENCE_MAX: usize = 128;
/// A session, an endpoint and a fence as the fiber's environment carries
/// them are at most ENV_VALUE_MAX - 1 characters.
pub const ENV_VALUE_MAX: usize = 1024;
/// The longest incarnation record, with a payload and a caller
/// certificate of any key size.
pub const RECORD_MAX: usize = 65536;
/// The fields of a record after its 'i'.
pub const RECORD_FIELDS: usize = 11;
/// The seed's length in bytes, 32 bytes of fresh entropy from the host.
pub const SEED_LEN: usize = 32;
/// A RUNDIR path is at most RUNDIR_MAX - 1 characters, the size of the
/// static storage the child reads it from.
pub const RUNDIR_MAX: usize = 4096;
/// The lines HIDE and DROP may keep, each kind.
pub const MAX_PATHS: usize = 16;
/// A kept HIDE or DROP path's storage, PATH_MAX. A longer path is
/// refused, never cut, since a cut path names another file. The tables
/// stay small because under THP=always a write faults in a whole 2 MiB
/// bss window, which a park then writes out.
pub const KEEP_MAX: usize = 4096;
/// The fiber's channel to fiberd, FZ_CHANNEL_FD in the header.
pub const FZ_CHANNEL_FD: c_int = 4;
/// The peer of the pair a non-handoff fiber makes, FZ_CHANNEL_PEER_FD.
pub const FZ_CHANNEL_PEER_FD: c_int = 5;
/// A control line is at most MAX_LINE - 1 characters.
pub const MAX_LINE: usize = 65536;
/// How many fibers that reported ready the zygote remembers for their
/// EXITED lines.
pub const MAX_KIDS: usize = 4096;
/// How many children may be forked and not yet ready at once.
pub const MAX_PENDING: usize = 1024;
/// How many descriptors a control line may carry, the cgroup's and the
/// channel.
pub const MAX_PASSED: usize = 2;
/// A line the zygote sends is at most SEND_MAX - 1 characters. The
/// longest is the ERROR naming a HIDE path that could not be covered
/// (prepare_why), which must reach fiberd whole rather than be dropped.
pub const SEND_MAX: usize = RUNDIR_MAX + 512;
/// The engine's endpoint (fz_set_engine) is at most ENGINE_MAX - 1
/// characters.
pub const ENGINE_MAX: usize = 256;
/// A reported line (fz_report_line) is at most REPORT_MAX bytes with its
/// newline, FZ_REPORT_MAX in the header.
pub const REPORT_MAX: usize = 1024;
/// A kept HIDE or DROP path, NUL-ended in KEEP_MAX bytes.
pub type Kept = [u8; KEEP_MAX];

/// fz_on_fiber in the header: the template's entry, which returns the
/// fiber's exit code.
pub type OnFiber = Option<unsafe extern "C" fn(*const Incarnation) -> c_int>;

/// What the line parser made of a CLONE line, for handle_clone to
/// answer from. The pointers point into the line, which the parser cuts
/// up in place.
#[repr(C)]
pub struct CloneOut {
    /// The fence, NUL-ended, or null when the line has none.
    pub fence: *const c_char,
    /// The endpoint, NUL-ended, or null when the line has none.
    pub endpoint: *const c_char,
    /// The endpoint's length, for the check against ENV_VALUE_MAX.
    pub endpoint_len: usize,
    /// The deadline in ms, with the default of 50, once the fence fits.
    pub deadline_ms: c_int,
    /// The pidns option.
    pub pidns: c_int,
    /// The mntns option.
    pub mntns: c_int,
    /// The nocaps option.
    pub nocaps: c_int,
    /// The decoded session's length in the session buffer.
    pub session_len: usize,
}

/// fz_identity_t.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Identity {
    /// The grant's PKCS #8 private key.
    pub key_pem: *const c_char,
    /// Its self-signed certificate.
    pub cert_pem: *const c_char,
    /// The thumbprint of the one client certificate the fiber accepts.
    pub caller: *const c_char,
    /// That certificate.
    pub caller_pem: *const c_char,
}

/// fz_incarnation_t.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Incarnation {
    /// The fiber's identity, "grant/epoch/seq".
    pub fence: *const c_char,
    /// Where the fiber serves, or "handoff".
    pub endpoint: *const c_char,
    /// Opaque data delivered at birth.
    pub payload: *const u8,
    /// Its length.
    pub payload_len: usize,
    /// The session the caller named, "" for an anonymous fiber.
    pub session: *const c_char,
    /// fiberd's count of the lineage, 1 for a fork of the warm template.
    pub generation: c_uint,
    /// "fork", "clone" or "resume".
    pub kind: *const c_char,
    /// 32 bytes of fresh entropy, zeroed once ready.
    pub seed: *const u8,
    /// Its length while it is there.
    pub seed_len: usize,
    /// A handoff fiber's TLS identity, null on every other fiber.
    pub identity: *const Identity,
}

/// A record as it arrived and what is parsed out of it, in the fiber's
/// memory.
#[repr(C)]
pub struct RecordStore {
    /// The decoded session, NUL-ended.
    pub session: [u8; ENV_VALUE_MAX],
    /// The decoded seed.
    pub seed: [u8; SEED_LEN],
    /// The seed's field in buf, zeroed with seed.
    pub seed_hex: *mut c_char,
    /// A handoff fiber's identity, pointing into buf.
    pub identity: Identity,
    /// What the fiber learns at birth.
    pub inc: Incarnation,
    /// The record as it arrived.
    pub buf: [u8; RECORD_MAX],
    /// The decoded payload.
    pub payload: [u8; RECORD_MAX / 2],
}

const _: () = {
    assert!(size_of::<usize>() == 8, "the library runs on 64-bit Linux");
    assert!(size_of::<Identity>() == 32);
    assert!(offset_of!(Identity, key_pem) == 0);
    assert!(offset_of!(Identity, cert_pem) == 8);
    assert!(offset_of!(Identity, caller) == 16);
    assert!(offset_of!(Identity, caller_pem) == 24);
    assert!(size_of::<Incarnation>() == 80);
    assert!(offset_of!(Incarnation, fence) == 0);
    assert!(offset_of!(Incarnation, endpoint) == 8);
    assert!(offset_of!(Incarnation, payload) == 16);
    assert!(offset_of!(Incarnation, payload_len) == 24);
    assert!(offset_of!(Incarnation, session) == 32);
    assert!(offset_of!(Incarnation, generation) == 40);
    assert!(offset_of!(Incarnation, kind) == 48);
    assert!(offset_of!(Incarnation, seed) == 56);
    assert!(offset_of!(Incarnation, seed_len) == 64);
    assert!(offset_of!(Incarnation, identity) == 72);
    assert!(size_of::<RecordStore>() == 99480);
    assert!(offset_of!(RecordStore, session) == 0);
    assert!(offset_of!(RecordStore, seed) == 1024);
    assert!(offset_of!(RecordStore, seed_hex) == 1056);
    assert!(offset_of!(RecordStore, identity) == 1064);
    assert!(offset_of!(RecordStore, inc) == 1096);
    assert!(offset_of!(RecordStore, buf) == 1176);
    assert!(offset_of!(RecordStore, payload) == 66712);
    assert!(size_of::<CloneOut>() == 48);
    assert!(offset_of!(CloneOut, fence) == 0);
    assert!(offset_of!(CloneOut, endpoint) == 8);
    assert!(offset_of!(CloneOut, endpoint_len) == 16);
    assert!(offset_of!(CloneOut, deadline_ms) == 24);
    assert!(offset_of!(CloneOut, pidns) == 28);
    assert!(offset_of!(CloneOut, mntns) == 32);
    assert!(offset_of!(CloneOut, nocaps) == 36);
    assert!(offset_of!(CloneOut, session_len) == 40);
    assert!(
        KEEP_MAX >= 4096,
        "a realpath result (PATH_MAX) must fit a kept path"
    );
};
