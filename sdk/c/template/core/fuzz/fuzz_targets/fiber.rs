//! The fiber side's state machine (core/src/fiber.rs) against a model,
//! its entries called in any order between the messages fiberd queues
//! on a real SOCK_SEQPACKET pair. The fuzzshim feature hands out the
//! core's statics, so the target checks all of them after every call.
//!
//! The input is [served generation][park round][ops...]. Each op is one
//! byte, its low four bits the op and bit 4 a descriptor riding along
//! on what it sends, with the arguments after it.
//!
//!   0  a resume record: [generation][fence length][payload length/64]
//!   1  raw bytes: [length][bytes]
//!   2  'p' and a round: [round]
//!   3  'c' and a round: [round]
//!   4  a connection, one byte with a descriptor: [byte]
//!   5  a zero-length message
//!   6  a message longer than a record: [first byte]
//!   7  fiberd's end shut for writing, so the queue ends in EOF
//!   8, 13, 15  fz_incarnation_wait
//!   9  fz_fiber_ready
//!   10 fz_accept
//!   11 fz_quiesce
//!   12 fz_seed_forget
//!   14 fz_fiber_ready as a born fiber, on its readiness pipe, with a
//!      birth record of [generation]
//!
//! A call the model says would block gets fiberd's end shut first, so
//! none ever does. The message buffer must hold nothing but round
//! messages, since any other may be a record with a seed.
#![no_main]

#[path = "hooks.rs"]
mod hooks;
#[path = "sock.rs"]
mod sock;

use fiberzygote_core::abi::{FENCE_MAX, Incarnation, RECORD_MAX, RecordStore, SEED_LEN};
use fiberzygote_core::fiber::fuzz::{
    fz_rs_fuzz_born, fz_rs_fuzz_msg, fz_rs_fuzz_polled, fz_rs_fuzz_state,
};
use fiberzygote_core::fiber::{
    fz_accept, fz_fiber_ready, fz_incarnation_wait, fz_quiesce, fz_seed_forget,
};
use fiberzygote_core::line::take_round;
use fiberzygote_core::record::parse_store;
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::ffi::{CStr, c_int};
use std::ptr;

/// At most this many messages wait in the queue.
const QUEUE_MAX: usize = 32;

/// A message fiberd queued. One longer than RECORD_MAX does not fit the
/// fiber's buffer.
#[derive(Clone)]
struct Msg {
    bytes: Vec<u8>,
    fd: bool,
}

/// What a call answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Got {
    /// A value, 0 or 1.
    Val(c_int),
    /// A descriptor, from fz_accept.
    Fd,
    /// -1 with this errno.
    Err(c_int),
    /// The call would wait for fiberd.
    Block,
}

/// What one read off the channel gives.
enum Read {
    /// EOF, or a zero-length message, which reads as one.
    Eof,
    /// A message longer than the buffer, EPROTO.
    TooLong(Msg),
    Msg(Msg),
}

/// The generation and the fence of a record the core's parser takes.
fn parse(bytes: &[u8]) -> Option<(u32, Vec<u8>)> {
    if bytes.first() != Some(&b'i') || bytes.len() > RECORD_MAX {
        return None;
    }
    // SAFETY: all zero bits are a RecordStore.
    let mut st = unsafe { Box::<RecordStore>::new_zeroed().assume_init() };
    st.buf[..bytes.len()].copy_from_slice(bytes);
    parse_store(&mut st, bytes.len()).ok()?;
    // SAFETY: the parser points the fence at a NUL-ended field of buf.
    let fence = unsafe { CStr::from_ptr(st.inc.fence) }.to_bytes().to_vec();
    Some((st.inc.generation, fence))
}

/// The fiber as the model sees it.
#[derive(Clone)]
struct Model {
    queue: VecDeque<Msg>,
    eof: bool,
    served: u32,
    round: u32,
    over: bool,
    ack_pending: bool,
    ack_fence: Vec<u8>,
    /// The seed of the record a wait handed over is still in polled.
    polled_live: bool,
    /// What the fiber has sent fiberd since the last look.
    out: Vec<Vec<u8>>,
    /// The message buffer as it must be: zero but for round messages.
    msg: Vec<u8>,
}

impl Model {
    fn recv(&mut self) -> Option<Read> {
        let Some(m) = self.queue.pop_front() else {
            return self.eof.then_some(Read::Eof);
        };
        if m.bytes.is_empty() {
            return Some(Read::Eof);
        }
        if m.bytes.len() > RECORD_MAX {
            return Some(Read::TooLong(m));
        }
        Some(Read::Msg(m))
    }

    /// A message read into the buffer and then kept or wiped.
    fn landed(&mut self, m: &Msg, keep: bool) {
        let n = m.bytes.len().min(RECORD_MAX);
        if keep {
            self.msg[..n].copy_from_slice(&m.bytes[..n]);
        } else {
            self.msg[..n].fill(0);
        }
    }

    fn quiesce_message(&self) -> Vec<u8> {
        format!("q{}\0", self.round).into_bytes()
    }

    fn wait(&mut self) -> Got {
        self.polled_live = false;
        loop {
            if self.over {
                self.over = false;
                return Got::Val(0);
            }
            let m = match self.recv() {
                None => return Got::Block,
                Some(Read::Eof) => return Got::Err(libc::ECONNRESET),
                Some(Read::TooLong(m)) => {
                    self.landed(&m, false);
                    return Got::Err(libc::EPROTO);
                }
                Some(Read::Msg(m)) => m,
            };
            if m.fd {
                self.landed(&m, false);
                continue;
            }
            if take_round(&m.bytes, &mut self.round, &mut self.over) {
                self.landed(&m, true);
                if m.bytes[0] == b'p' {
                    let q = self.quiesce_message();
                    self.out.push(q);
                }
                continue;
            }
            self.landed(&m, false);
            let Some((generation, fence)) = parse(&m.bytes) else {
                return Got::Err(libc::EPROTO);
            };
            if generation <= self.served {
                continue; // a replay
            }
            self.served = generation;
            self.ack_pending = true;
            self.ack_fence = fence;
            self.polled_live = true;
            return Got::Val(1);
        }
    }

    fn accept(&mut self) -> Got {
        loop {
            let m = match self.recv() {
                None => return Got::Block,
                Some(Read::Eof) => return Got::Err(libc::ECONNRESET),
                Some(Read::TooLong(m)) => {
                    self.landed(&m, false);
                    return Got::Err(libc::EPROTO);
                }
                Some(Read::Msg(m)) => m,
            };
            self.landed(&m, false);
            if m.fd {
                return Got::Fd;
            }
            if take_round(&m.bytes, &mut self.round, &mut self.over) && m.bytes[0] == b'p' {
                return Got::Err(libc::EINTR);
            }
        }
    }

    fn quiesce(&mut self) -> Got {
        while let Some(r) = self.recv() {
            let m = match r {
                Read::Eof => return Got::Err(libc::ECONNRESET),
                Read::TooLong(m) => {
                    self.landed(&m, false);
                    return Got::Err(libc::EPROTO);
                }
                Read::Msg(m) => m,
            };
            let round = !m.fd && take_round(&m.bytes, &mut self.round, &mut self.over);
            self.landed(&m, round);
        }
        let q = self.quiesce_message();
        self.out.push(q);
        Got::Val(0)
    }

    fn ready(&mut self) {
        if !self.ack_pending {
            return;
        }
        self.ack_pending = false;
        let mut ack = vec![b'a'];
        ack.extend_from_slice(&self.ack_fence);
        ack.push(0);
        self.out.push(ack);
        self.ack_fence.clear();
        self.polled_live = false;
    }
}

/// A resume's record as fiberd sends it, its seed made from the
/// generation so it is never zero.
fn record(generation: u8, fence_len: u8, payload_64: u8) -> Vec<u8> {
    let fence: Vec<u8> = (0..usize::from(fence_len) % (FENCE_MAX + 2))
        .map(|i| b'a' + (i % 26) as u8)
        .collect();
    let payload: Vec<u8> = if payload_64 == 0 {
        b"-".to_vec()
    } else {
        (0..usize::from(payload_64) * 64)
            .flat_map(|i| format!("{:02x}", i as u8).into_bytes())
            .collect()
    };
    let seed: Vec<u8> = (0..SEED_LEN)
        .flat_map(|i| format!("{:02x}", 0x80 | (generation ^ i as u8)).into_bytes())
        .collect();
    let decimal = generation.to_string().into_bytes();
    let fields: [&[u8]; 11] = [
        &decimal,
        b"resume",
        &fence,
        b"/run/g/ep.sock",
        &payload,
        b"-",
        b"-",
        b"-",
        b"-",
        b"-",
        &seed,
    ];
    let mut r = vec![b'i'];
    for f in fields {
        r.extend_from_slice(f);
        r.push(0);
    }
    r
}

/// Every message the fiber sent fiberd, without waiting.
fn answers(fd: c_int) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    loop {
        let mut buf = [0u8; 256];
        // SAFETY: buf is live for the call.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n <= 0 {
            return got;
        }
        got.push(buf[..n as usize].to_vec());
    }
}

/// The input, a byte at a time.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let (a, b) = self.0.split_at(n.min(self.0.len()));
        self.0 = b;
        a
    }
}

/// The rig: the pair and the model.
struct Rig {
    fiber: c_int,
    fiberd: c_int,
    m: Model,
}

impl Rig {
    /// Queues one message, unless the queue is full, fiberd's end is
    /// shut, or the socket has no room.
    fn send(&mut self, bytes: Vec<u8>, fd: bool) {
        if self.m.eof || self.m.queue.len() >= QUEUE_MAX {
            return;
        }
        let scratch = fd.then(|| sock::memfd_of(&[]));
        let fds: Vec<c_int> = scratch.into_iter().collect();
        let r = sock::send_fds_flags(self.fiberd, &bytes, &fds, libc::MSG_DONTWAIT);
        fds.into_iter().for_each(sock::close);
        if r < 0 {
            assert_eq!(sock::errno(), libc::EAGAIN, "sendmsg");
            return;
        }
        assert_eq!(r, bytes.len() as isize, "a short sendmsg");
        self.m.queue.push_back(Msg { bytes, fd });
    }

    fn shut(&mut self) {
        if !self.m.eof {
            // SAFETY: an integer call on our own socket.
            assert_eq!(unsafe { libc::shutdown(self.fiberd, libc::SHUT_WR) }, 0);
            self.m.eof = true;
        }
    }

    /// The model's answer to a call that may wait, with fiberd's end
    /// shut first when it would block.
    fn predict(&mut self, call: fn(&mut Model) -> Got) -> Got {
        let mut next = self.m.clone();
        let mut want = call(&mut next);
        if want == Got::Block {
            self.shut();
            next = self.m.clone();
            want = call(&mut next);
            assert_ne!(want, Got::Block, "the model blocks at EOF");
        }
        self.m = next;
        want
    }

    /// Everything after a call, against the model.
    fn check(&mut self, what: &str) {
        let got = answers(self.fiberd);
        assert_eq!(got, self.m.out, "{what}: what the fiber sent fiberd");
        self.m.out.clear();
        // SAFETY: the statics are the core's, which only the entries
        // touch, and no call runs while these references live.
        let (st, polled, msg) = unsafe {
            (
                &*fz_rs_fuzz_state(),
                &*fz_rs_fuzz_polled(),
                &*fz_rs_fuzz_msg(),
            )
        };
        assert_eq!(
            st.served_generation, self.m.served,
            "{what}: served_generation"
        );
        assert_eq!(st.park_round, self.m.round, "{what}: park_round");
        assert_eq!(st.park_over, self.m.over, "{what}: park_over");
        assert_eq!(st.ack_pending, self.m.ack_pending, "{what}: ack_pending");
        let mut fence = self.m.ack_fence.clone();
        fence.resize(FENCE_MAX, 0);
        assert_eq!(st.ack_fence[..], fence[..], "{what}: ack_fence");
        assert_eq!(st.channel_fd, self.fiber, "{what}: channel_fd");
        if self.m.polled_live {
            assert_eq!(
                polled.inc.seed_len, SEED_LEN,
                "{what}: the seed handed over is gone"
            );
        } else {
            assert!(
                polled.seed.iter().all(|&b| b == 0),
                "{what}: seed bytes left in polled"
            );
            assert_eq!(polled.inc.seed_len, 0, "{what}: seed_len left in polled");
            if !polled.seed_hex.is_null() {
                let off = polled.seed_hex as usize - polled.buf.as_ptr() as usize;
                let hex = &polled.buf[off..(off + 2 * SEED_LEN).min(RECORD_MAX)];
                assert!(
                    hex.iter().all(|&b| b == 0),
                    "{what}: seed hex left in polled"
                );
            }
        }
        if msg[..] != self.m.msg[..] {
            let at = msg
                .iter()
                .zip(&self.m.msg)
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            panic!(
                "{what}: the message buffer holds a byte of a message that was not a round, at {at}"
            );
        }
    }

    fn wait(&mut self) {
        let want = self.predict(Model::wait);
        // SAFETY: all zero bits are an Incarnation.
        let mut inc: Incarnation = unsafe { std::mem::zeroed() };
        sock::set_errno(0);
        // SAFETY: inc is ours and writable.
        let rc = unsafe { fz_incarnation_wait(&mut inc) };
        let got = if rc < 0 {
            Got::Err(sock::errno())
        } else {
            Got::Val(rc)
        };
        assert_eq!(got, want, "fz_incarnation_wait");
        if rc == 1 {
            // SAFETY: as in check, and the record's fields are NUL-ended
            // in polled.
            unsafe {
                let polled = &*fz_rs_fuzz_polled();
                assert_eq!(inc.generation, self.m.served, "the generation handed over");
                assert_eq!(
                    CStr::from_ptr(inc.fence).to_bytes(),
                    &self.m.ack_fence[..],
                    "the fence handed over"
                );
                let fence = inc.fence as usize - polled.buf.as_ptr() as usize;
                assert!(fence < RECORD_MAX, "the fence outside polled");
                assert_eq!(inc.seed, polled.seed.as_ptr(), "the seed elsewhere");
                assert_eq!(inc.seed_len, SEED_LEN, "a seed of {} bytes", inc.seed_len);
                assert!(
                    !CStr::from_ptr(inc.endpoint).to_bytes().is_empty(),
                    "an empty endpoint"
                );
            }
        }
        self.check("fz_incarnation_wait");
    }

    fn accept(&mut self) {
        let want = self.predict(Model::accept);
        sock::set_errno(0);
        let fd = fz_accept();
        let got = if fd < 0 {
            Got::Err(sock::errno())
        } else {
            Got::Fd
        };
        assert_eq!(got, want, "fz_accept");
        if fd >= 0 {
            sock::close(fd);
        }
        self.check("fz_accept");
    }

    fn quiesce(&mut self) {
        let want = self.m.quiesce();
        sock::set_errno(0);
        let rc = fz_quiesce();
        let got = if rc < 0 {
            Got::Err(sock::errno())
        } else {
            Got::Val(rc)
        };
        assert_eq!(got, want, "fz_quiesce");
        self.check("fz_quiesce");
    }

    fn ready(&mut self) {
        self.m.ready();
        fz_fiber_ready();
        self.check("fz_fiber_ready");
    }

    fn forget(&mut self) {
        self.m.polled_live = false;
        fz_seed_forget();
        self.check("fz_seed_forget");
        // SAFETY: as in check.
        let born = unsafe { &*fz_rs_fuzz_born() };
        assert!(born.seed.iter().all(|&b| b == 0), "born seed left");
        assert_eq!(born.inc.seed_len, 0, "born seed_len left");
    }

    /// fz_fiber_ready in a born fiber: 'r' on its readiness pipe, the
    /// pipe closed, the birth seed gone, and nothing sent on the channel.
    /// It points stderr at stdin, so the target's is kept aside.
    fn born_ready(&mut self, generation: u8) {
        let rec = record(generation.max(1), 8, 0);
        // SAFETY: as in check.
        unsafe {
            let born = &mut *fz_rs_fuzz_born();
            born.buf[..rec.len()].copy_from_slice(&rec);
            assert!(
                parse_store(born, rec.len()).is_ok(),
                "a birth record refused"
            );
        }
        let mut p = [-1; 2];
        // SAFETY: p is live for the call.
        assert_eq!(
            unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2"
        );
        // SAFETY: as in check, and an integer call.
        let saved = unsafe {
            (*fz_rs_fuzz_state()).ready_fd = p[1];
            libc::dup(2)
        };
        fz_fiber_ready();
        // SAFETY: integer calls on our own descriptors.
        unsafe {
            libc::dup2(saved, 2);
            libc::close(saved);
        }
        let mut buf = [0u8; 4];
        // SAFETY: buf is live for the call.
        let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(&buf[..n.max(0) as usize], b"r", "the ready record");
        // SAFETY: as above.
        let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(n, 0, "the readiness pipe left open");
        sock::close(p[0]);
        // SAFETY: as in check.
        unsafe {
            let st = &*fz_rs_fuzz_state();
            assert_eq!(st.ready_fd, -1, "ready_fd left");
            let born = &*fz_rs_fuzz_born();
            assert!(born.seed.iter().all(|&b| b == 0), "born seed left");
            assert_eq!(born.inc.seed_len, 0, "born seed_len left");
        }
        self.check("fz_fiber_ready as a born fiber");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut d = Bytes(data);
    let (Some(served), Some(round)) = (d.byte(), d.byte()) else {
        return;
    };
    let before = sock::open_fds();
    let s = sock::pair(libc::SOCK_SEQPACKET);
    // Room for every message the queue may hold, the long ones too.
    let sndbuf: c_int = 4 << 20;
    // SAFETY: sndbuf is live for the call and an int long.
    unsafe {
        libc::setsockopt(
            s[1],
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            (&raw const sndbuf).cast(),
            size_of::<c_int>() as libc::socklen_t,
        )
    };
    // SAFETY: the statics are the core's, which only the entries touch,
    // and none runs now. All zero bits are a RecordStore.
    unsafe {
        let st = &mut *fz_rs_fuzz_state();
        st.channel_fd = s[0];
        st.ready_fd = -1;
        st.served_generation = u32::from(served);
        st.park_round = u32::from(round);
        st.park_over = false;
        st.ack_pending = false;
        st.ack_fence = [0; FENCE_MAX];
        ptr::write_bytes(fz_rs_fuzz_polled(), 0, 1);
        ptr::write_bytes(fz_rs_fuzz_born(), 0, 1);
        ptr::write_bytes(fz_rs_fuzz_msg(), 0, 1);
    }
    let mut rig = Rig {
        fiber: s[0],
        fiberd: s[1],
        m: Model {
            queue: VecDeque::new(),
            eof: false,
            served: u32::from(served),
            round: u32::from(round),
            over: false,
            ack_pending: false,
            ack_fence: Vec::new(),
            polled_live: false,
            out: Vec::new(),
            msg: vec![0; RECORD_MAX],
        },
    };
    while let Some(op) = d.byte() {
        let fd = op & 0x10 != 0;
        match op & 0x0f {
            0 => {
                let (g, f, p) = (
                    d.byte().unwrap_or(1),
                    d.byte().unwrap_or(8),
                    d.byte().unwrap_or(0),
                );
                rig.send(record(g, f, p), fd);
            }
            1 => {
                let n = usize::from(d.byte().unwrap_or(0));
                let raw = d.take(n).to_vec();
                if !raw.is_empty() {
                    rig.send(raw, fd);
                }
            }
            2 => rig.send(format!("p{}\0", d.byte().unwrap_or(0)).into_bytes(), fd),
            3 => rig.send(format!("c{}\0", d.byte().unwrap_or(0)).into_bytes(), fd),
            4 => rig.send(vec![d.byte().unwrap_or(b'x')], true),
            5 => rig.send(Vec::new(), fd),
            6 => {
                let mut long = vec![b'i'; RECORD_MAX + 1];
                long[0] = d.byte().unwrap_or(b'i');
                rig.send(long, fd);
            }
            7 => rig.shut(),
            9 => rig.ready(),
            10 => rig.accept(),
            11 => rig.quiesce(),
            12 => rig.forget(),
            14 => rig.born_ready(d.byte().unwrap_or(1)),
            _ => rig.wait(),
        }
    }
    // SAFETY: as above.
    unsafe { (*fz_rs_fuzz_state()).channel_fd = -1 };
    sock::close(s[0]);
    sock::close(s[1]);
    assert_eq!(sock::open_fds(), before, "a descriptor leaked");
});
