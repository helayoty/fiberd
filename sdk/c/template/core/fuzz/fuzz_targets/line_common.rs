//! Shared by the line targets. The input format is the one csrc/line.c's
//! header defines, and each parser is driven through its fz_rs_* entry
//! as the library drives it.
#![allow(dead_code)]

use fiberzygote_core::abi::{CloneOut, ENV_VALUE_MAX, RECORD_MAX, RUNDIR_MAX};
use fiberzygote_core::line::{fz_rs_parse_clone, fz_rs_set_rundir};
use fiberzygote_core::procfiles::{
    fz_rs_in_child_userns, fz_rs_mountinfo_carry, fz_rs_mountinfo_sys_mount, fz_rs_spec_token,
};
use std::ffi::{CStr, c_char, c_int};
use std::ptr;

/// The parsers the first byte picks from.
pub const PARSERS: u8 = 7;
/// recv_line's buffer, so a line is at most MAX_LINE - 1 bytes.
pub const MAX_LINE: usize = 65536;
/// lock_sys's buffer.
pub const MOUNTINFO_BUF: usize = 8192;
/// What fz_gvisor_identity hands spec_token.
pub const TOKEN_CAP: usize = 64 + 1;

/// One input, taken apart by its selector byte.
pub enum Input<'a> {
    /// A CLONE line, NUL-ended.
    Clone(Vec<u8>),
    /// A RUNDIR line, NUL-ended.
    Rundir(Vec<u8>),
    /// Any line for the classifiers, NUL-ended.
    Classify(Vec<u8>),
    /// A park message, at most RECORD_MAX bytes.
    Round(&'a [u8]),
    /// mountinfo, its read size and whether the remount refuses.
    Mountinfo {
        chunk: usize,
        refuse: bool,
        file: &'a [u8],
    },
    /// uid_map as it is in the file.
    UidMap(&'a [u8]),
    /// The spec environment as it is in the file.
    Spec(&'a [u8]),
}

/// A line as recv_line hands it over, the bytes before the first newline
/// or NUL, at most MAX_LINE - 1 of them, then a NUL.
pub fn cut(data: &[u8]) -> Vec<u8> {
    let end = data
        .iter()
        .take(MAX_LINE - 1)
        .position(|&b| b == b'\n' || b == 0)
        .unwrap_or(data.len().min(MAX_LINE - 1));
    let mut line = data[..end].to_vec();
    line.push(0);
    line
}

/// The read size the chunk byte's low 7 bits give.
pub fn chunk(b: u8) -> usize {
    let c = usize::from(b & 0x7f);
    if c < 64 { c + 1 } else { (c - 63) * 128 }
}

pub fn decode(data: &[u8]) -> Option<Input<'_>> {
    let (&sel, rest) = data.split_first()?;
    Some(match sel % PARSERS {
        0 => Input::Clone(cut(rest)),
        1 => Input::Rundir(cut(rest)),
        2 => Input::Classify(cut(rest)),
        3 => Input::Round(&rest[..rest.len().min(RECORD_MAX)]),
        4 => {
            let (&b, file) = rest.split_first().unwrap_or((&0, &[]));
            Input::Mountinfo {
                chunk: chunk(b),
                refuse: b & 0x80 != 0,
                file,
            }
        }
        5 => Input::UidMap(rest),
        _ => Input::Spec(rest),
    })
}

/// The bytes of a NUL-ended string, empty for null.
///
/// # Safety
/// p is null or a live NUL-ended string.
pub unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    // SAFETY: by the contract above.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// A pointer into line as its offset, None for null.
pub fn off_in(p: *const c_char, line: &[u8]) -> Option<usize> {
    if p.is_null() {
        return None;
    }
    let off = (p as usize)
        .checked_sub(line.as_ptr() as usize)
        .expect("a pointer below the line");
    assert!(off < line.len(), "a pointer past the line");
    Some(off)
}

/// What fz_rs_parse_clone made of a line, into a session buffer of
/// ENV_VALUE_MAX bytes as handle_clone passes session_buf.
pub struct RsClone {
    pub rc: c_int,
    pub out: CloneOut,
    pub session: Box<[u8; ENV_VALUE_MAX]>,
}

pub fn rs_clone(line: &mut [u8]) -> RsClone {
    let mut session = Box::new([0xeeu8; ENV_VALUE_MAX]);
    let mut out = CloneOut {
        fence: ptr::null(),
        endpoint: ptr::null(),
        endpoint_len: usize::MAX,
        deadline_ms: -7,
        pidns: -1,
        mntns: -1,
        nocaps: -1,
        ws: -1,
        session_len: usize::MAX,
    };
    // SAFETY: line is NUL-ended and ours, session has its length, out is
    // a local.
    let rc = unsafe {
        fz_rs_parse_clone(
            line.as_mut_ptr().cast(),
            session.as_mut_ptr().cast(),
            session.len(),
            &mut out,
        )
    };
    RsClone { rc, out, session }
}

/// What fz_rs_set_rundir made of a line, into rundir_parent and
/// rundir_own as set_rundir passes them, both empty before.
pub struct RsRundir {
    pub rc: c_int,
    pub why: Option<Vec<u8>>,
    pub parent: Vec<u8>,
    pub own: Vec<u8>,
}

pub fn rs_rundir(line: &mut [u8]) -> RsRundir {
    let mut parent = vec![0u8; RUNDIR_MAX];
    let mut own = vec![0u8; RUNDIR_MAX];
    let mut why: *const c_char = ptr::null();
    // SAFETY: line is NUL-ended and ours, both paths have RUNDIR_MAX
    // bytes, why is a local.
    let rc = unsafe {
        fz_rs_set_rundir(
            line.as_mut_ptr().cast(),
            parent.as_mut_ptr().cast(),
            own.as_mut_ptr().cast(),
            &mut why,
        )
    };
    // SAFETY: why is null or a static string, and both paths NUL-ended
    // in their buffers, which start zeroed.
    let why = (!why.is_null()).then(|| unsafe { cbytes(why) }.to_vec());
    let parent = unsafe { cbytes(parent.as_ptr().cast()) }.to_vec();
    let own = unsafe { cbytes(own.as_ptr().cast()) }.to_vec();
    RsRundir {
        rc,
        why,
        parent,
        own,
    }
}

/// lock_sys's loop over file read chunk bytes at a time. Every mount
/// point it would remount, in order, and its rc.
pub fn rs_mountinfo(file: &[u8], chunk: usize, refuse: bool) -> (Vec<Vec<u8>>, c_int) {
    let mut buf = [0u8; MOUNTINFO_BUF];
    let mut have = 0usize;
    let mut skipping: c_int = 0;
    let mut fed = 0usize;
    let mut mounts = Vec::new();
    let mut rc = 0;
    loop {
        let n = (file.len() - fed).min(buf.len() - have).min(chunk.max(1));
        if n == 0 {
            break;
        }
        buf[have..have + n].copy_from_slice(&file[fed..fed + n]);
        fed += n;
        have += n;
        let mut start = 0usize;
        loop {
            // SAFETY: buf holds have live bytes, start and skipping are
            // locals.
            let mp = unsafe {
                fz_rs_mountinfo_sys_mount(buf.as_mut_ptr().cast(), have, &mut start, &mut skipping)
            };
            if mp.is_null() {
                break;
            }
            assert!(off_in(mp, &buf[..have]).is_some());
            // SAFETY: the mount point is NUL-ended within buf.
            mounts.push(unsafe { cbytes(mp) }.to_vec());
            if refuse {
                rc = -1;
            }
        }
        // SAFETY: buf has its length in live bytes.
        have = unsafe {
            fz_rs_mountinfo_carry(
                buf.as_mut_ptr().cast(),
                buf.len(),
                have,
                start,
                &mut skipping,
            )
        };
        assert!(have < buf.len(), "a carry fills the buffer");
    }
    (mounts, rc)
}

/// in_child_userns as prepare.rs drives it, one read of at most 127
/// bytes, NUL-ended.
pub fn rs_uid_map(file: &[u8]) -> c_int {
    let mut buf = [0u8; 128];
    let n = file.len().min(buf.len() - 1);
    if n == 0 {
        return 0;
    }
    buf[..n].copy_from_slice(&file[..n]);
    buf[n] = 0;
    // SAFETY: buf is NUL-ended.
    unsafe { fz_rs_in_child_userns(buf.as_ptr().cast()) }
}

/// spec_token as fz_gvisor_identity drives it (fiber.rs). Its static
/// buffer keeps what an earlier read left past the bytes read.
pub fn rs_spec_token(file: &[u8], out: &mut [u8]) -> c_int {
    let mut buf = vec![0x5au8; 65536];
    let got = file.len().min(buf.len() - 1);
    if got == 0 {
        return 0;
    }
    buf[..got].copy_from_slice(&file[..got]);
    // SAFETY: buf holds got live bytes and out has its length.
    unsafe {
        fz_rs_spec_token(
            buf.as_mut_ptr().cast(),
            got,
            out.as_mut_ptr().cast(),
            out.len(),
        )
    }
}
