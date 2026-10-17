//! The Rust line parsers against the C ones of main (csrc/line.c), on
//! every input in the format line.c's header defines. Each side gets the
//! same bytes and must give the same answer, cut its line up the same
//! way and keep the same bytes.
#![no_main]

#[path = "line_common.rs"]
mod common;

use common::{
    Input, MAX_LINE, cbytes, decode, off_in, rs_clone, rs_mountinfo, rs_rundir, rs_spec_token,
    rs_uid_map,
};
use fiberzygote_core::abi::{ENV_VALUE_MAX, RECORD_MAX, RUNDIR_MAX};
use fiberzygote_core::line::{
    Setup, fz_rs_is_rebind, fz_rs_setup_kind, fz_rs_take_round, record_round,
};
use libfuzzer_sys::fuzz_target;
use std::ffi::{c_char, c_int, c_uint, c_void};

#[repr(C)]
struct CField {
    off: isize,
    len: usize,
}

#[repr(C)]
struct CClone {
    reason: c_int,
    pidns: c_int,
    mntns: c_int,
    nocaps: c_int,
    deadline_ms: c_int,
    fence: CField,
    endpoint: CField,
    deadline: CField,
    payload: CField,
    session_hex: CField,
    slen: usize,
    session: [u8; ENV_VALUE_MAX],
}

#[repr(C)]
struct CRundir {
    why: *const c_char,
    parent: [u8; RUNDIR_MAX],
    own: [u8; RUNDIR_MAX],
}

// C_SETUP_* in line.c.
const C_SETUP_PATH: c_int = 0;
const C_SETUP_RUNDIR: c_int = 1;
const C_SETUP_PREPARE_MNTNS: c_int = 2;
const C_SETUP_PREPARE_NONE: c_int = 3;
const C_SETUP_OTHER: c_int = 4;

type Remount = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;

unsafe extern "C" {
    fn c_line_cut(data: *const u8, n: usize, out: *mut c_char, cap: usize) -> usize;
    fn c_line_chunk(b: u8) -> usize;
    fn c_line_clone(line: *mut c_char, out: *mut CClone);
    fn c_line_rundir(line: *mut c_char, out: *mut CRundir) -> c_int;
    fn c_line_setup_kind(line: *const c_char) -> c_int;
    fn c_line_rebind(line: *const c_char) -> c_int;
    fn c_line_round(msg: *const u8, n: usize) -> c_uint;
    fn c_line_take_round(msg: *const u8, n: usize, round: *mut c_uint, over: *mut c_int) -> c_int;
    fn c_line_mountinfo(
        data: *const u8,
        n: usize,
        chunk: usize,
        remount: Remount,
        ctx: *mut c_void,
    ) -> c_int;
    fn c_line_uid_map(data: *const u8, n: usize) -> c_int;
    fn c_line_spec_token(data: *const u8, n: usize, out: *mut c_char, cap: usize) -> c_int;
}

/// What the C remount callback saw, and how it answers.
struct Seen {
    mounts: Vec<Vec<u8>>,
    refuse: bool,
}

unsafe extern "C" fn remount(ctx: *mut c_void, mp: *const c_char) -> c_int {
    // SAFETY: ctx is the Seen c_mountinfo was handed, mp a C string.
    let seen = unsafe { &mut *ctx.cast::<Seen>() };
    seen.mounts.push(unsafe { cbytes(mp) }.to_vec());
    if seen.refuse { -1 } else { 0 }
}

fn span(off: Option<usize>, len: usize) -> (isize, usize) {
    off.map_or((-1, 0), |o| (o as isize, len))
}

fn diff_clone(line: Vec<u8>) {
    let mut cl = line.clone();
    let mut rl = line;
    // SAFETY: CClone is plain data, all-zero is valid, and c_line_clone
    // zeroes it again before it fills it.
    let mut c: Box<CClone> = unsafe { Box::new_zeroed().assume_init() };
    unsafe { c_line_clone(cl.as_mut_ptr().cast(), &mut *c) };
    let r = rs_clone(&mut rl);
    assert_eq!(c.reason, r.rc, "refusal");
    // SAFETY: each pointer is null or a token NUL-ended in rl.
    let rf = span(
        off_in(r.out.fence, &rl),
        unsafe { cbytes(r.out.fence) }.len(),
    );
    let re = span(
        off_in(r.out.endpoint, &rl),
        unsafe { cbytes(r.out.endpoint) }.len(),
    );
    assert_eq!((c.fence.off, c.fence.len), rf, "fence");
    assert_eq!((c.endpoint.off, c.endpoint.len), re, "endpoint");
    if c.endpoint.off >= 0 {
        assert_eq!(c.endpoint.len, r.out.endpoint_len, "endpoint_len");
    }
    assert_eq!(c.deadline_ms, r.out.deadline_ms, "deadline_ms");
    assert_eq!(
        (c.pidns, c.mntns, c.nocaps),
        (r.out.pidns, r.out.mntns, r.out.nocaps),
        "options"
    );
    assert_eq!(c.slen, r.out.session_len, "session length");
    assert!(c.session[..c.slen] == r.session[..c.slen], "session bytes");
    if c.reason == 0 {
        assert_eq!(r.session[r.out.session_len], 0, "session NUL-ended");
    }
    assert_eq!(cl, rl, "the line as each side cut it up");
}

fn diff_rundir(line: Vec<u8>) {
    let mut cl = line.clone();
    let mut rl = line;
    // SAFETY: CRundir is plain data, a null why and zero paths are valid.
    let mut c: Box<CRundir> = unsafe { Box::new_zeroed().assume_init() };
    let crc = unsafe { c_line_rundir(cl.as_mut_ptr().cast(), &mut *c) };
    let r = rs_rundir(&mut rl);
    assert_eq!(crc, r.rc, "verdict");
    // SAFETY: why is null or static, and both paths are NUL-ended.
    let cwhy = (!c.why.is_null()).then(|| unsafe { cbytes(c.why) }.to_vec());
    assert_eq!(
        cwhy.as_deref().map(String::from_utf8_lossy),
        r.why.as_deref().map(String::from_utf8_lossy),
        "reason"
    );
    assert_eq!(
        unsafe { cbytes(c.parent.as_ptr().cast()) },
        &r.parent[..],
        "parent"
    );
    assert_eq!(unsafe { cbytes(c.own.as_ptr().cast()) }, &r.own[..], "own");
    assert_eq!(cl, rl, "the line as each side cut it up");
}

fn diff_classify(line: Vec<u8>) {
    let p = line.as_ptr().cast::<c_char>();
    // SAFETY: line is NUL-ended.
    let (ck, rk) = unsafe { (c_line_setup_kind(p), fz_rs_setup_kind(p)) };
    let want = match ck {
        C_SETUP_PATH if line[0] == b'H' => Setup::Hide,
        C_SETUP_PATH => Setup::Drop,
        C_SETUP_RUNDIR => Setup::Rundir,
        C_SETUP_PREPARE_MNTNS => Setup::PrepareMntns,
        C_SETUP_PREPARE_NONE => Setup::PrepareNone,
        C_SETUP_OTHER => Setup::Other,
        k => panic!("C setup kind {k}"),
    };
    assert_eq!(want as c_int, rk, "setup kind");
    // SAFETY: line is NUL-ended.
    let (cr, rr) = unsafe { (c_line_rebind(p), fz_rs_is_rebind(p)) };
    assert_eq!(cr, rr, "REBIND");
}

fn diff_round(msg: &[u8]) {
    // SAFETY: msg has its length.
    let c = unsafe { c_line_round(msg.as_ptr(), msg.len()) };
    assert_eq!(c, record_round(msg), "record_round");
    for (round, over) in [(1, 0), (0, 1), (c, 0)] {
        let (mut cr, mut co) = (round, over);
        let (mut rr, mut ro) = (round, over);
        // SAFETY: msg has its length and the state is local. The Rust
        // entry wants a message of one byte at least, as a fiber
        // receives it.
        let ct = unsafe { c_line_take_round(msg.as_ptr(), msg.len(), &mut cr, &mut co) };
        let rt = if msg.is_empty() {
            0
        } else {
            unsafe { fz_rs_take_round(msg.as_ptr().cast(), msg.len(), &mut rr, &mut ro) }
        };
        assert_eq!((ct, cr, co), (rt, rr, ro), "take_round from {round},{over}");
    }
}

fn diff_mountinfo(chunk: usize, refuse: bool, file: &[u8]) {
    let mut seen = Seen {
        mounts: Vec::new(),
        refuse,
    };
    // SAFETY: file has its length and seen outlives the call.
    let crc = unsafe {
        c_line_mountinfo(
            file.as_ptr(),
            file.len(),
            chunk,
            remount,
            (&mut seen as *mut Seen).cast(),
        )
    };
    let (mounts, rrc) = rs_mountinfo(file, chunk, refuse);
    assert_eq!(seen.mounts, mounts, "mount points");
    assert_eq!(crc, rrc, "rc");
}

fuzz_target!(|data: &[u8]| {
    // The format helpers agree first.
    if let Some((&sel, rest)) = data.split_first() {
        let mut out = vec![0u8; MAX_LINE];
        // SAFETY: out has MAX_LINE bytes.
        let n = unsafe {
            c_line_cut(
                rest.as_ptr(),
                rest.len(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        assert_eq!(&out[..=n], &common::cut(rest)[..], "cut");
        assert_eq!(unsafe { c_line_chunk(sel) }, common::chunk(sel), "chunk");
    }
    match decode(data) {
        None => {}
        Some(Input::Clone(line)) => diff_clone(line),
        Some(Input::Rundir(line)) => diff_rundir(line),
        Some(Input::Classify(line)) => diff_classify(line),
        Some(Input::Round(msg)) => {
            assert!(msg.len() <= RECORD_MAX);
            diff_round(msg)
        }
        Some(Input::Mountinfo {
            chunk,
            refuse,
            file,
        }) => diff_mountinfo(chunk, refuse, file),
        Some(Input::UidMap(file)) => {
            // SAFETY: file has its length.
            let c = unsafe { c_line_uid_map(file.as_ptr(), file.len()) };
            assert_eq!(c, rs_uid_map(file), "in_child_userns");
        }
        Some(Input::Spec(file)) => {
            let mut c = [0x33u8; common::TOKEN_CAP];
            let mut r = [0x33u8; common::TOKEN_CAP];
            // SAFETY: file and c have their lengths.
            let crc = unsafe {
                c_line_spec_token(file.as_ptr(), file.len(), c.as_mut_ptr().cast(), c.len())
            };
            let rrc = rs_spec_token(file, &mut r);
            assert_eq!(crc, rrc, "found");
            assert_eq!(c, r, "token");
        }
    }
});
