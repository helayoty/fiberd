//! The line parsers alone, on inputs in the format csrc/line.c's header
//! defines, checked for what each answer promises.
#![no_main]

#[path = "line_common.rs"]
mod common;
#[path = "hooks.rs"]
mod hooks;

use common::{
    Input, MOUNTINFO_BUF, TOKEN_CAP, cbytes, decode, off_in, rs_clone, rs_mountinfo, rs_rundir,
    rs_spec_token, rs_uid_map,
};
use fiberzygote_core::abi::{ENV_VALUE_MAX, FENCE_MAX, RUNDIR_MAX};
use fiberzygote_core::line::{Setup, fz_rs_is_rebind, fz_rs_setup_kind, record_round, take_round};
use fiberzygote_core::procfiles::{in_child_userns, uid_map};
use libfuzzer_sys::fuzz_target;

/// The reasons set_rundir gives.
const RUNDIR_REASONS: &[&str] = &[
    "want RUNDIR <parent> <own>",
    "path too long",
    "want absolute paths",
    "parent must not be /",
    "want clean paths",
    "own must be under parent",
    "own must be a direct child of parent",
];

fn has(s: &[u8], pat: &[u8]) -> bool {
    s.windows(pat.len()).any(|w| w == pat)
}

fn check_clone(line: Vec<u8>) {
    let before = line.clone();
    let mut line = line;
    let r = rs_clone(&mut line);
    // The cut only turns separators into NULs.
    assert_eq!(line.len(), before.len());
    for (a, b) in before.iter().zip(&line) {
        assert!(
            a == b || (*b == 0 && (*a == b' ' || *a == b',')),
            "a byte changed"
        );
    }
    assert!((0..=4).contains(&r.rc), "refusal {}", r.rc);
    // SAFETY: each pointer is null or a token NUL-ended in line.
    let fence = unsafe { cbytes(r.out.fence) };
    let endpoint = unsafe { cbytes(r.out.endpoint) };
    for (p, tok) in [(r.out.fence, fence), (r.out.endpoint, endpoint)] {
        if off_in(p, &line).is_some() {
            assert!(
                !tok.is_empty() && !tok.contains(&b' '),
                "a token with a space or none"
            );
        }
    }
    if !r.out.endpoint.is_null() {
        assert_eq!(r.out.endpoint_len, endpoint.len());
        assert!(!r.out.fence.is_null(), "an endpoint without a fence");
    }
    match r.rc {
        1 => assert_eq!(r.out.deadline_ms, 0),
        2 => {
            assert!(fence.len() >= FENCE_MAX);
            assert_eq!(r.out.deadline_ms, 0);
        }
        _ => {
            assert!(!fence.is_empty() && fence.len() < FENCE_MAX);
            assert!(!endpoint.is_empty());
            assert!(r.out.deadline_ms > 0, "deadline {}", r.out.deadline_ms);
        }
    }
    let slen = r.out.session_len;
    assert!(slen < ENV_VALUE_MAX, "session length {slen}");
    match r.rc {
        0 => {
            assert!(!r.session[..slen].contains(&0), "a NUL in a passed session");
            assert_eq!(r.session[slen], 0, "session NUL-ended");
        }
        4 => assert!(
            r.session[..slen].contains(&0),
            "a NUL refusal without a NUL"
        ),
        _ => assert_eq!(slen, 0),
    }
}

fn check_rundir(line: Vec<u8>) {
    let mut line = line;
    let r = rs_rundir(&mut line);
    if r.rc != 0 {
        assert_eq!(r.rc, -1);
        let why = r.why.expect("a refusal without a reason");
        assert!(
            RUNDIR_REASONS.iter().any(|w| w.as_bytes() == why),
            "unknown reason"
        );
        assert!(
            r.parent.is_empty() && r.own.is_empty(),
            "paths kept on a refusal"
        );
        return;
    }
    assert!(r.why.is_none());
    let (p, o) = (&r.parent[..], &r.own[..]);
    let (pl, ol) = (p.len(), o.len());
    assert!(pl < RUNDIR_MAX && ol < RUNDIR_MAX && pl >= 2 && ol > pl + 1);
    assert!(p[0] == b'/' && p[pl - 1] != b'/' && !has(p, b"//"));
    assert!(o.starts_with(p) && o[pl] == b'/');
    let name = &o[pl + 1..];
    assert!(!name.is_empty() && !name.contains(&b'/') && name != b"." && name != b"..");
    assert!(!p.contains(&b' ') && !o.contains(&b' '));
}

fn check_classify(line: Vec<u8>) {
    let p = line.as_ptr().cast();
    let s = &line[..line.len() - 1];
    // SAFETY: line is NUL-ended.
    let kind = unsafe { fz_rs_setup_kind(p) };
    let want = if s.starts_with(b"HIDE /") {
        Setup::Hide
    } else if s.starts_with(b"DROP /") {
        Setup::Drop
    } else if s.starts_with(b"RUNDIR ") {
        Setup::Rundir
    } else if s == b"PREPARE mntns" {
        Setup::PrepareMntns
    } else if s == b"PREPARE none" {
        Setup::PrepareNone
    } else {
        Setup::Other
    };
    assert_eq!(kind, want as i32);
    // SAFETY: line is NUL-ended.
    assert_eq!(unsafe { fz_rs_is_rebind(p) } != 0, s == b"REBIND");
}

fn check_round(msg: &[u8]) {
    let round = record_round(msg);
    if round != 0 {
        assert!(msg.len() >= 3 && msg[msg.len() - 1] == 0);
        let digits = &msg[1..];
        let digits = &digits[..digits.iter().position(|&b| b == 0).unwrap()];
        assert_eq!(digits, round.to_string().as_bytes(), "a round read back");
    }
    let (mut r, mut over) = (7u32, false);
    let taken = take_round(msg, &mut r, &mut over);
    match msg.first() {
        Some(b'p') => assert!(taken && r == round && !over),
        Some(b'c') => assert!(taken && r == 7 && over == (round == 7)),
        _ => assert!(!taken && r == 7 && !over),
    }
}

fn check_mountinfo(chunk: usize, refuse: bool, file: &[u8]) {
    let (mounts, rc) = rs_mountinfo(file, chunk, refuse);
    for m in &mounts {
        assert!(
            m == b"/sys" || m.starts_with(b"/sys/"),
            "a mount outside /sys"
        );
    }
    assert!(mounts.len() <= file.iter().filter(|&&b| b == b'\n').count());
    assert_eq!(rc == -1, refuse && !mounts.is_empty(), "rc");
    // The buffer fills before a line is dropped, whatever the read size.
    let (whole, _) = rs_mountinfo(file, MOUNTINFO_BUF, false);
    assert_eq!(mounts, whole, "the read size changed the mounts");
}

fn check_uid_map(file: &[u8]) {
    let child = rs_uid_map(file);
    assert!(child == 0 || child == 1);
    let n = file.len().min(127);
    let s = &file[..n];
    assert_eq!(child == 1, in_child_userns(s));
    if let Some(v) = uid_map(s) {
        let again = format!("{} {} {}", v[0], v[1], v[2]);
        assert_eq!(uid_map(again.as_bytes()), Some(v), "a map read back");
        assert_eq!(in_child_userns(s), v != [0, 0, 4_294_967_295]);
    } else {
        assert_eq!(child, 0);
    }
}

fn check_spec(file: &[u8]) {
    let mut out = [0x33u8; TOKEN_CAP];
    let found = rs_spec_token(file, &mut out);
    // The first FIBERD_TOKEN entry decides, NUL or newline ending entries.
    let file = &file[..file.len().min(65535)];
    let first = file
        .split(|&b| b == 0 || b == b'\n')
        .find_map(|e| e.strip_prefix(b"FIBERD_TOKEN="));
    match first {
        Some(t) if !t.is_empty() && t.len() < TOKEN_CAP => {
            assert_eq!(found, 1, "a token missed");
            assert_eq!(&out[..t.len()], t);
            assert_eq!(out[t.len()], 0);
        }
        _ => {
            assert_eq!(found, 0, "a token found where none fits");
            assert!(out.iter().all(|&b| b == 0x33), "out touched");
        }
    }
}

fuzz_target!(|data: &[u8]| match decode(data) {
    None => {}
    Some(Input::Clone(line)) => check_clone(line),
    Some(Input::Rundir(line)) => check_rundir(line),
    Some(Input::Classify(line)) => check_classify(line),
    Some(Input::Round(msg)) => check_round(msg),
    Some(Input::Mountinfo {
        chunk,
        refuse,
        file,
    }) => check_mountinfo(chunk, refuse, file),
    Some(Input::UidMap(file)) => check_uid_map(file),
    Some(Input::Spec(file)) => check_spec(file),
});
