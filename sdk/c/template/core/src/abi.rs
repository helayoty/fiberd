//! Mirrors of the C types the entries take, laid out as libfiberzygote.h
//! and libfiberzygote.c lay them out. The numbers are pinned here and
//! with _Static_assert in the C file, so a field moved on one side fails
//! to compile on the other.

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
/// A kept HIDE or DROP path's storage, the size of a control line
/// (MAX_LINE in C). A line is at most MAX_LINE - 1 characters, so the
/// path after its five-character prefix always fits whole, as strdup
/// kept it. A smaller table would cut a long path, and stat would then
/// answer for another name than the one fiberd sent. Untouched bss
/// costs nothing and a checkpoint skips untouched pages.
pub const KEEP_MAX: usize = 65536;
/// The fiber's channel to fiberd, FZ_CHANNEL_FD in the header.
pub const FZ_CHANNEL_FD: c_int = 4;
/// The peer of the pair a non-handoff fiber makes, FZ_CHANNEL_PEER_FD.
pub const FZ_CHANNEL_PEER_FD: c_int = 5;

/// fz_on_fiber in the header: the template's entry, which returns the
/// fiber's exit code.
pub type OnFiber = Option<unsafe extern "C" fn(*const Incarnation) -> c_int>;

/// struct fz_rs_child in libfiberzygote.c: what the child's path needs
/// from the zygote, built by handle_clone before the clone. The zygote's
/// statics the child resets stay C until stage 5, and the C resets them
/// with plain stores before the one call into the core. The fiber's
/// state, the birth record's store among it, is the core's own
/// (fiber.rs), so the core resets it and reads the record into it with
/// no pointer from C.
#[repr(C)]
pub struct Child {
    /// The ready pipe's read end, the zygote's, closed first.
    pub ready_r: c_int,
    /// The ready pipe's write end, moved to fd 3.
    pub ready_w: c_int,
    /// fiberd's channel end as passed on the CLONE line.
    pub channel: c_int,
    /// The zygote's SIGCHLD descriptor, or -1.
    pub sigchld_fd: c_int,
    /// The pidns option.
    pub pidns: c_int,
    /// The mntns option.
    pub mntns: c_int,
    /// The nocaps option.
    pub nocaps: c_int,
    /// FIBERD_USERNS_NESTED=deny was given.
    pub deny_nested_userns: c_int,
    /// How many HIDE paths hide holds.
    pub nhide: c_int,
    /// How many DROP paths drop holds.
    pub ndrop: c_int,
    /// The fence the CLONE named, NUL-ended.
    pub fence: *const c_char,
    /// The template's entry.
    pub on_fiber: OnFiber,
    /// The zygote's own executable as /proc/self/exe named it, NUL-ended,
    /// empty when it could not be read.
    pub self_exe: *const c_char,
    /// The HIDE paths, nhide of them, each NUL-ended in KEEP_MAX bytes.
    pub hide: *const [c_char; KEEP_MAX],
    /// Which HIDE paths prepare_ns covered, one byte each.
    pub hide_covered: *const u8,
    /// The DROP paths, ndrop of them.
    pub drop: *const [c_char; KEEP_MAX],
}

/// struct fz_rs_clone in libfiberzygote.c: what the Rust parser made of
/// a CLONE line, for handle_clone to answer from. The pointers point
/// into the line, which the parser cut up in place as strtok_r did.
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

/// struct record_store in libfiberzygote.c: a record as it arrived and
/// what is parsed out of it, in the fiber's memory.
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
    assert!(size_of::<Child>() == 88);
    assert!(offset_of!(Child, ready_r) == 0);
    assert!(offset_of!(Child, ready_w) == 4);
    assert!(offset_of!(Child, channel) == 8);
    assert!(offset_of!(Child, sigchld_fd) == 12);
    assert!(offset_of!(Child, pidns) == 16);
    assert!(offset_of!(Child, mntns) == 20);
    assert!(offset_of!(Child, nocaps) == 24);
    assert!(offset_of!(Child, deny_nested_userns) == 28);
    assert!(offset_of!(Child, nhide) == 32);
    assert!(offset_of!(Child, ndrop) == 36);
    assert!(offset_of!(Child, fence) == 40);
    assert!(offset_of!(Child, on_fiber) == 48);
    assert!(offset_of!(Child, self_exe) == 56);
    assert!(offset_of!(Child, hide) == 64);
    assert!(offset_of!(Child, hide_covered) == 72);
    assert!(offset_of!(Child, drop) == 80);
    assert!(
        KEEP_MAX >= 4096,
        "a realpath result (PATH_MAX) must fit a kept path"
    );
};
