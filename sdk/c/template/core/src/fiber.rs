//! The fiber-side API, what a fiber calls once on_fiber runs, and the
//! gVisor side, what a sandbox calls in place of a birth. fz_fiber_ready,
//! fz_accept, fz_quiesce, fz_incarnation_wait and fz_seed_forget, then
//! fz_gvisor_identity and fz_gvisor_ack, each with the signature
//! libfiberzygote.h gives it.
//!
//! They run in a fiber, after scrub_and_run, on the fiber's one thread
//! or the template's, never two at once, which is the header's rule. A
//! park's SIGUSR1 may interrupt them. The library installs no handler,
//! so a poll the signal ends returns EINTR, and the entry hands it to
//! the template's loop as the C did. Every entry sets errno once, at the
//! boundary, to what the header promises (EBADF, EPROTO, ECONNRESET,
//! EINTR, EMSGSIZE, ENOENT) or to what the failing call left.
//!
//! The state is the core's own and nothing in C touches it. The small
//! fields are one State. The two record stores, the message buffer and
//! the spec environment's read buffer are zero statics, so they sit in
//! bss as the C's did, and a fiber's copy-on-write cost is the pages a
//! record touches. The child's path (child.rs) resets State and reads
//! the birth record into its store, through reset_for_child and born.
//!
//! The functions take the state as a Fiber of references, so the unit
//! tests drive them over a socketpair with state of their own. The
//! entries build that Fiber from the statics, once per call.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::abi::{FENCE_MAX, FZ_CHANNEL_FD, Incarnation, RECORD_MAX, RecordStore};
use crate::child::{channel_recv, zeroed};
use crate::line::take_round;
use crate::procfiles::spec_token;
use crate::record::parse_store;
use crate::sys::{self, Errno};

/// The ready record is the one byte 'r'. The zygote takes anything else
/// on the pipe as a fiber that misused it.
pub const READY_BYTE: u8 = b'r';
/// The longest FIBERD_TOKEN a sandbox claims with.
pub const GVISOR_TOKEN_MAX: usize = 64;
/// The spec environment's read buffer, 64 KiB as the C's was.
pub const SPEC_ENV_MAX: usize = 65536;
/// The sandbox's spec environment, KEY=VALUE entries.
const GVISOR_SPEC_ENV: &CStr = c"/proc/gvisor/spec_environ";
/// The pool socket a sandbox claims its record on.
const GVISOR_POOL_SOCKET: &[u8] = b"/fiberd/channel/pool.sock";
/// How often fz_gvisor_identity looks for a fresh token, and connects,
/// 1 ms apart.
const TOKEN_TRIES: u32 = 3000;
const CONNECT_TRIES: u32 = 2000;
const TRY_EVERY_US: libc::useconds_t = 1000;

/// A static the C ABI's rule guards: the fiber-side API runs on one
/// thread at a time, and the child's path runs before any of it.
pub struct Global<T>(UnsafeCell<T>);

// SAFETY: every access is from the one thread the header allows at a
// time (see the module comment), so no two threads share the value.
unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    /// A static holding v.
    pub const fn new(v: T) -> Self {
        Global(UnsafeCell::new(v))
    }

    /// The value's address. Writing through it needs the rule above.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// The fiber's small state, the C file's statics of the same names.
#[repr(C)]
pub struct State {
    /// FZ_CHANNEL_FD in a fiber, -1 in the zygote and in a gVisor
    /// sandbox.
    pub channel_fd: c_int,
    /// The readiness pipe, fd 3 until fz_fiber_ready, else -1.
    pub ready_fd: c_int,
    /// The generation this process serves, the birth record's and then
    /// each resume's. A record at or below it is a replay and is dropped.
    pub served_generation: c_uint,
    /// The park round the fiber answers, from the last 'p' fiberd queued
    /// before its signal.
    pub park_round: c_uint,
    /// The sandbox's pool connection between fz_gvisor_identity and
    /// fz_gvisor_ack, else -1.
    pub gv_channel: c_int,
    /// Set once fz_incarnation_wait handed over a resume's record, until
    /// fz_fiber_ready acks it.
    pub ack_pending: bool,
    /// Whether the round's carry-on was already there when the fiber
    /// quiesced, so the wait answers 0 at once. A carry-on for any other
    /// round is stale and dropped, so one left by a park that gave up
    /// never undoes a later park's dump.
    pub park_over: bool,
    /// The token this process last claimed with, NUL-ended. The spec
    /// environment can still show the previous restore's for a moment
    /// after a restore returns, and a restored copy keeps this memory,
    /// so a token already used is waited out.
    pub gv_last_token: [u8; GVISOR_TOKEN_MAX + 1],
}

const _: () = {
    assert!(size_of::<State>() == 88);
    assert!(offset_of!(State, channel_fd) == 0);
    assert!(offset_of!(State, ready_fd) == 4);
    assert!(offset_of!(State, served_generation) == 8);
    assert!(offset_of!(State, park_round) == 12);
    assert!(offset_of!(State, gv_channel) == 16);
    assert!(offset_of!(State, ack_pending) == 20);
    assert!(offset_of!(State, park_over) == 21);
    assert!(offset_of!(State, gv_last_token) == 22);
};

impl State {
    /// The state of the zygote, and of a sandbox before its identity.
    pub const fn new() -> State {
        State {
            channel_fd: -1,
            ready_fd: -1,
            served_generation: 0,
            park_round: 0,
            gv_channel: -1,
            ack_pending: false,
            park_over: false,
            gv_last_token: [0; GVISOR_TOKEN_MAX + 1],
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::new()
    }
}

static STATE: Global<State> = Global::new(State::new());
/// The birth record's store. It stays for the fiber's life, since a
/// handoff fiber's TLS library points into it, and a sandbox's record
/// lands here too.
// SAFETY: a RecordStore is integers, byte arrays and raw pointers, for
// which all zero bits are a value (null for the pointers), as C's bss
// gave it.
static BORN: Global<RecordStore> = Global::new(unsafe { core::mem::zeroed() });
/// A record that arrives later, a resume's.
// SAFETY: as BORN.
static POLLED: Global<RecordStore> = Global::new(unsafe { core::mem::zeroed() });
/// Messages after the birth record are read here first, so a connection
/// that arrives behind a record never touches the record's store.
static CHANNEL_MSG: Global<[u8; RECORD_MAX]> = Global::new([0; RECORD_MAX]);
/// The spec environment as read, for spec_token.
static SPEC_ENV: Global<[u8; SPEC_ENV_MAX]> = Global::new([0; SPEC_ENV_MAX]);

/// The fiber's state, the references each entry works on.
pub struct Fiber<'a> {
    /// The small fields.
    pub st: &'a mut State,
    /// The birth record's store.
    pub born: &'a mut RecordStore,
    /// A resume's record's store.
    pub polled: &'a mut RecordStore,
    /// Where a channel message lands first.
    pub msg: &'a mut [u8; RECORD_MAX],
}

/// The Fiber of the statics.
///
/// # Safety
/// The caller is an entry on the one thread the header allows, and
/// holds no other reference into the statics while this one lives.
unsafe fn global<'a>() -> Fiber<'a> {
    // SAFETY: by the contract above, each static is referenced once.
    unsafe {
        Fiber {
            st: &mut *STATE.get(),
            born: &mut *BORN.get(),
            polled: &mut *POLLED.get(),
            msg: &mut *CHANNEL_MSG.get(),
        }
    }
}

/// The child's reset, made by scrub_and_run before its first system
/// call. The readiness pipe is fd 3 and the channel FZ_CHANNEL_FD from
/// here on, and no park or resume is under way. Plain stores, which
/// nothing reads before on_fiber.
///
/// # Safety
/// The caller is the child of birth, the only thread of the process.
pub unsafe fn reset_for_child() {
    // SAFETY: by the contract above.
    let st = unsafe { &mut *STATE.get() };
    st.channel_fd = FZ_CHANNEL_FD;
    st.ack_pending = false;
    st.park_round = 0;
    st.park_over = false;
    st.ready_fd = 3;
}

/// The birth record's store, which the child reads its record into.
pub fn born() -> *mut RecordStore {
    BORN.get()
}

/// Notes the generation the child's birth record names.
///
/// # Safety
/// As reset_for_child.
pub unsafe fn set_served_generation(generation: c_uint) {
    // SAFETY: by the contract above.
    unsafe { (*STATE.get()).served_generation = generation };
}

/// Zeroes buf so the stores are not optimised out. Volatile writes, one
/// byte each, then a compiler fence, so no later access moves above
/// them. A secret wiped here is never read again, which is exactly the
/// store a compiler may drop, and a volatile write it may not.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: b is a live, aligned byte of buf.
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// forget_seed zeroes a store's seed, in its decoded form and in the
/// record, once nothing should be reseeded from it again. The record's
/// copy is found by its offset in buf, so the write stays inside buf
/// and is made through it.
pub fn forget_seed(st: &mut RecordStore) {
    wipe(&mut st.seed);
    if !st.seed_hex.is_null() {
        let off = (st.seed_hex as usize).wrapping_sub(st.buf.as_ptr() as usize);
        if let Some(rest) = st.buf.get_mut(off..) {
            let n = sys::nul_at(rest);
            wipe(rest.get_mut(..n).unwrap_or(&mut []));
        }
    }
    st.inc.seed_len = 0;
}

/// The fence a store's record names, from its NUL-ended field in buf,
/// at most FENCE_MAX bytes. The parser keeps it shorter. A store whose
/// buf was overwritten after its parse (a refused record) is cut there,
/// where the C read on and overflowed its ack buffer.
fn fence_of(st: &RecordStore) -> &[u8] {
    let off = (st.inc.fence as usize).wrapping_sub(st.buf.as_ptr() as usize);
    let Some(rest) = st.buf.get(off..) else {
        return &[];
    };
    let rest = rest.get(..FENCE_MAX).unwrap_or(rest);
    rest.get(..sys::nul_at(rest)).unwrap_or(&[])
}

/// The ack a resumed fiber and a sandbox send: 'a', the fence and its
/// NUL, with the byte count.
pub fn ack_message(fence: &[u8]) -> ([u8; FENCE_MAX + 2], usize) {
    let mut ack = [0u8; FENCE_MAX + 2];
    let n = sys::append(&mut ack, 0, b"a");
    let n = sys::append(&mut ack, n, fence.get(..FENCE_MAX).unwrap_or(fence));
    (ack, n.wrapping_add(1))
}

/// The quiesce a fiber sends: 'q', the round in decimal and a NUL, with
/// the byte count.
pub fn quiesce_message(round: c_uint) -> ([u8; 16], usize) {
    let mut q = [0u8; 16];
    let n = sys::append(&mut q, 0, b"q");
    let n = sys::append_decimal(&mut q, n, round);
    (q, n.wrapping_add(1))
}

/// The claim a sandbox sends on the pool socket: 't', the token and its
/// NUL, with the byte count.
pub fn claim_message(token: &[u8]) -> ([u8; GVISOR_TOKEN_MAX + 2], usize) {
    let mut claim = [0u8; GVISOR_TOKEN_MAX + 2];
    let token = token.get(..sys::nul_at(token)).unwrap_or(&[]);
    let n = sys::append(&mut claim, 0, b"t");
    let n = sys::append(
        &mut claim,
        n,
        token.get(..GVISOR_TOKEN_MAX).unwrap_or(token),
    );
    (claim, n.wrapping_add(1))
}

/// The bytes of a NUL-ended string in buf, the NUL not included.
fn c_str(buf: &[u8]) -> &[u8] {
    buf.get(..sys::nul_at(buf)).unwrap_or(&[])
}

/// One message off fd into buf, with recvmsg's flags and the first
/// descriptor passed along, -1 for none. channel_recv in child.rs.
fn recv(fd: c_int, flags: c_int, buf: &mut [u8]) -> Result<(usize, c_int), Errno> {
    let mut got = -1;
    // SAFETY: buf has buf.len() writable bytes.
    let r = unsafe { channel_recv(fd, flags, buf.as_mut_ptr().cast(), buf.len(), &mut got) };
    match usize::try_from(r) {
        Ok(n) => Ok((n, got)),
        Err(_) => Err(Errno::last()),
    }
}

/// close(2), whose answer nobody here looks at, as in C.
fn close(fd: c_int) {
    // SAFETY: an integer argument alone.
    unsafe { libc::close(fd) };
}

/// send(2) of buf with MSG_NOSIGNAL, so a peer gone is EPIPE and not a
/// signal. True when all of it went.
fn send_all(fd: c_int, buf: &[u8]) -> bool {
    // SAFETY: send reads buf.len() bytes of buf, which is live.
    let w = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
    usize::try_from(w) == Ok(buf.len())
}

impl Fiber<'_> {
    /// take_round notes a park message: 'p' names the round to answer,
    /// and 'c' ends the round it names. True when the message, the n
    /// bytes in msg, was one of those.
    fn take_round(&mut self, n: usize) -> bool {
        let msg = self.msg.get(..n).unwrap_or(&[]);
        take_round(msg, &mut self.st.park_round, &mut self.st.park_over)
    }

    /// Whether the message in msg is a park round's 'p'.
    fn is_park(&self) -> bool {
        self.msg.first() == Some(&b'p')
    }

    /// take_record takes the n bytes in msg as a resume's record, into
    /// polled. Ok(true) when it is one the fiber has not served yet,
    /// Ok(false) for a replay of a generation already served, EPROTO for
    /// anything else. The message's copy is wiped once copied, so the
    /// one copy of a seed is in polled, zeroed with it.
    pub fn take_record(&mut self, n: usize) -> Result<bool, Errno> {
        if self.msg.first() != Some(&b'i') {
            return Err(Errno(libc::EPROTO));
        }
        let n = n.min(RECORD_MAX);
        if let (Some(dst), Some(src)) = (self.polled.buf.get_mut(..n), self.msg.get(..n)) {
            dst.copy_from_slice(src);
        }
        wipe(self.msg.get_mut(..n).unwrap_or(&mut []));
        if parse_store(self.polled, n).is_err() {
            return Err(Errno(libc::EPROTO));
        }
        Ok(self.polled.inc.generation > self.st.served_generation)
    }

    /// channel_wait blocks until the channel has a message, then takes
    /// it into msg without blocking. A signal ends the wait with EINTR,
    /// so a handler of the template's (a park's SIGUSR1) is seen by its
    /// loop.
    fn channel_wait(&mut self) -> Result<(usize, c_int), Errno> {
        loop {
            let mut p = libc::pollfd {
                fd: self.st.channel_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: p is live for the call, and one entry long.
            if unsafe { libc::poll(&raw mut p, 1, -1) } < 0 {
                return Err(Errno::last());
            }
            match recv(self.st.channel_fd, libc::MSG_DONTWAIT, self.msg) {
                Err(Errno(libc::EAGAIN)) => continue,
                r => return r,
            }
        }
    }

    /// send_quiesce says 'q' with the round the fiber answers.
    fn send_quiesce(&self) -> Result<(), Errno> {
        let (q, n) = quiesce_message(self.st.park_round);
        if send_all(self.st.channel_fd, q.get(..n).unwrap_or(&[])) {
            Ok(())
        } else {
            Err(Errno::last())
        }
    }

    /// fz_fiber_ready. A born fiber reports ready on its pipe, with its
    /// birth seed gone and stderr at /dev/null, so nothing leads outside
    /// the tree once checkpointable. A resumed fiber acks its record
    /// under the new fence, the ack fiberd waits for before it routes
    /// anything here. Anything else does nothing.
    pub fn ready(&mut self) {
        if self.st.ready_fd >= 0 {
            // SAFETY: integer arguments alone. The answer is not looked
            // at, as in C.
            unsafe { libc::dup2(0, 2) };
            forget_seed(self.born);
            let rec = READY_BYTE;
            // SAFETY: write reads one byte of rec, which is live.
            unsafe { libc::write(self.st.ready_fd, (&raw const rec).cast(), 1) };
            close(self.st.ready_fd);
            self.st.ready_fd = -1;
            return;
        }
        if !self.st.ack_pending || self.st.channel_fd < 0 {
            return;
        }
        self.st.ack_pending = false;
        let (ack, n) = ack_message(fence_of(self.polled));
        send_all(self.st.channel_fd, ack.get(..n).unwrap_or(&[]));
        forget_seed(self.polled);
    }

    /// fz_accept. The next connection fiberd passes. A message without
    /// a descriptor carries nothing to serve. A park's round is noted
    /// for the quiesce to come, and ends this call as the park's signal
    /// would, with EINTR, since that signal may have landed already,
    /// before this wait began, and would then wake nothing.
    pub fn accept(&mut self) -> Result<c_int, Errno> {
        if self.st.channel_fd < 0 {
            return Err(Errno(libc::EBADF));
        }
        loop {
            let (n, fd) = self.channel_wait()?;
            if n == 0 {
                return Err(Errno(libc::ECONNRESET));
            }
            if fd >= 0 {
                return Ok(fd);
            }
            if self.take_round(n) && self.is_park() {
                return Err(Errno(libc::EINTR));
            }
        }
    }

    /// fz_quiesce. Takes whatever fiberd queued before its signal, the
    /// round and the carry-on of a round that already gave up on this
    /// fiber, then says 'q'. A descriptor is closed, and any other
    /// message is wiped, since it may be a record with a seed.
    pub fn quiesce(&mut self) -> Result<(), Errno> {
        if self.st.channel_fd < 0 {
            return Err(Errno(libc::EBADF));
        }
        loop {
            match recv(self.st.channel_fd, libc::MSG_DONTWAIT, self.msg) {
                Err(Errno(libc::EAGAIN)) => break,
                Err(e) => return Err(e),
                Ok((0, _)) => return Err(Errno(libc::ECONNRESET)),
                Ok((_, fd)) if fd >= 0 => close(fd),
                Ok((n, _)) => {
                    if !self.take_round(n) {
                        wipe(self.msg.get_mut(..n).unwrap_or(&mut []));
                    }
                }
            }
        }
        self.send_quiesce()
    }

    /// fz_incarnation_wait. Some with a resume's record, None when the
    /// park ended without one (serve on). Whatever a call does not hand
    /// over goes with the seed it may have left in polled (wait_none in
    /// C), and so does the seed the last call handed over.
    pub fn wait(&mut self) -> Result<Option<Incarnation>, Errno> {
        if self.st.channel_fd < 0 {
            return Err(Errno(libc::EBADF));
        }
        forget_seed(self.polled);
        let got = self.wait_for_record();
        if !matches!(got, Ok(Some(_))) {
            forget_seed(self.polled);
        }
        got
    }

    fn wait_for_record(&mut self) -> Result<Option<Incarnation>, Errno> {
        loop {
            // The round already gave up on this fiber: serve on.
            if self.st.park_over {
                self.st.park_over = false;
                return Ok(None);
            }
            let (n, fd) = self.channel_wait()?;
            if n == 0 {
                return Err(Errno(libc::ECONNRESET));
            }
            // A connection handed over meanwhile is nobody's to serve.
            if fd >= 0 {
                close(fd);
                continue;
            }
            // A new round while waiting (the fiber quiesced late, or on
            // a signal of its own) is answered afresh. A carry-on ends
            // the wait for the round it names, and a stale one is
            // dropped.
            if self.take_round(n) {
                if self.is_park() {
                    self.send_quiesce()?;
                }
                continue;
            }
            if !self.take_record(n)? {
                continue; // a replay
            }
            self.st.served_generation = self.polled.inc.generation;
            self.st.ack_pending = true;
            return Ok(Some(self.polled.inc));
        }
    }

    /// fz_seed_forget.
    pub fn seed_forget(&mut self) {
        forget_seed(self.born);
        forget_seed(self.polled);
    }

    /// fz_gvisor_identity. Waits for a token this process has not
    /// claimed with, claims its record with it on the pool socket, and
    /// keeps the connection for the ack. ENOENT when no fresh token
    /// shows within 3 s, ECONNRESET when the pool hangs up, EMSGSIZE for
    /// a record longer than the store, EPROTO for one that does not
    /// parse, or what the failing call left.
    pub fn gvisor_identity(&mut self, env: &mut [u8]) -> Result<Incarnation, Errno> {
        if self.st.gv_channel >= 0 {
            close(self.st.gv_channel);
            self.st.gv_channel = -1;
        }
        let mut token = [0u8; GVISOR_TOKEN_MAX + 1];
        let mut fresh = false;
        let mut i = 0;
        while i < TOKEN_TRIES && !fresh {
            fresh =
                read_spec_token(env, &mut token) && c_str(&token) != c_str(&self.st.gv_last_token);
            if !fresh {
                // SAFETY: an integer argument alone.
                unsafe { libc::usleep(TRY_EVERY_US) };
            }
            i = i.wrapping_add(1);
        }
        if !fresh {
            return Err(Errno(libc::ENOENT));
        }
        self.st.gv_last_token = token;
        // SAFETY: integer arguments alone.
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(Errno::last());
        }
        let mut a: libc::sockaddr_un = zeroed();
        a.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (d, s) in a.sun_path.iter_mut().zip(GVISOR_POOL_SOCKET) {
            *d = *s as c_char;
        }
        let mut rc = -1;
        let mut i = 0;
        while i < CONNECT_TRIES && rc < 0 {
            // SAFETY: a is a live sockaddr_un of the length given.
            rc = unsafe {
                libc::connect(
                    fd,
                    (&raw const a).cast(),
                    size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            };
            if rc < 0 && sys::errno() != libc::ECONNREFUSED && sys::errno() != libc::ENOENT {
                break;
            }
            if rc < 0 {
                // SAFETY: an integer argument alone.
                unsafe { libc::usleep(TRY_EVERY_US) };
            }
            i = i.wrapping_add(1);
        }
        if rc < 0 {
            let e = Errno::last();
            close(fd);
            return Err(e);
        }
        let (claim, cn) = claim_message(&token);
        let claim = claim.get(..cn).unwrap_or(&[]);
        // SAFETY: write reads claim.len() bytes of claim, which is live.
        let w = unsafe { libc::write(fd, claim.as_ptr().cast(), claim.len()) };
        if usize::try_from(w) != Ok(claim.len()) {
            let e = Errno::last();
            close(fd);
            return Err(e);
        }
        let mut iov = libc::iovec {
            iov_base: self.born.buf.as_mut_ptr().cast(),
            iov_len: RECORD_MAX,
        };
        let mut mh: libc::msghdr = zeroed();
        mh.msg_iov = &raw mut iov;
        mh.msg_iovlen = 1;
        let r = loop {
            // SAFETY: mh and iov are live for the call, and iov names
            // born's buf, RECORD_MAX bytes.
            let r = unsafe { libc::recvmsg(fd, &raw mut mh, 0) };
            if r < 0 && sys::errno() == libc::EINTR {
                continue;
            }
            break r;
        };
        let Ok(n) = usize::try_from(r) else {
            let e = Errno::last();
            close(fd);
            return Err(e);
        };
        if n == 0 || mh.msg_flags & libc::MSG_TRUNC != 0 {
            close(fd);
            return Err(Errno(if n == 0 {
                libc::ECONNRESET
            } else {
                libc::EMSGSIZE
            }));
        }
        if parse_store(self.born, n).is_err() {
            close(fd);
            return Err(Errno(libc::EPROTO));
        }
        self.st.served_generation = self.born.inc.generation;
        self.st.gv_channel = fd;
        Ok(self.born.inc)
    }

    /// fz_gvisor_ack. Says 'a' with the fence on the pool connection,
    /// closes it and forgets the seed, whether or not the write went.
    pub fn gvisor_ack(&mut self) -> Result<(), Errno> {
        if self.st.gv_channel < 0 {
            return Err(Errno(libc::EBADF));
        }
        let (ack, n) = ack_message(fence_of(self.born));
        let ack = ack.get(..n).unwrap_or(&[]);
        // SAFETY: write reads ack.len() bytes of ack, which is live.
        let w = unsafe { libc::write(self.st.gv_channel, ack.as_ptr().cast(), ack.len()) };
        let e = Errno::last();
        close(self.st.gv_channel);
        self.st.gv_channel = -1;
        forget_seed(self.born);
        if usize::try_from(w) != Ok(ack.len()) {
            return Err(e);
        }
        Ok(())
    }
}

/// spec_token copies FIBERD_TOKEN out of the spec environment into out,
/// read whole into env first (at most env.len() - 1 bytes, as the C
/// read it). False when the file or the token is not there. The search
/// is procfiles::spec_token.
fn read_spec_token(env: &mut [u8], out: &mut [u8]) -> bool {
    // SAFETY: a static NUL-ended path.
    let fd = unsafe { sys::open(GVISOR_SPEC_ENV.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    let cap = env.len().saturating_sub(1);
    let mut got = 0usize;
    while let Some(room) = env.get_mut(got..cap) {
        // SAFETY: read writes at most room.len() bytes of room, which is
        // live. An empty room reads 0 and ends the loop, as in C.
        let r = unsafe { libc::read(fd, room.as_mut_ptr().cast(), room.len()) };
        let Some(r) = usize::try_from(r).ok().filter(|&r| r > 0) else {
            break;
        };
        got = got.saturating_add(r);
    }
    close(fd);
    if got == 0 {
        return false;
    }
    spec_token(env.get_mut(..got).unwrap_or(&mut []), out)
}

/// errno once, at the boundary: the value, or -1 with errno set.
fn at_boundary(r: Result<c_int, Errno>) -> c_int {
    match r {
        Ok(v) => v,
        Err(Errno(e)) => {
            sys::set_errno(e);
            -1
        }
    }
}

/// fz_fiber_ready in libfiberzygote.h.
#[unsafe(no_mangle)]
pub extern "C" fn fz_fiber_ready() {
    // SAFETY: an entry, on the thread the header allows.
    unsafe { global() }.ready();
}

/// fz_accept in libfiberzygote.h: the descriptor, or -1 with errno.
#[unsafe(no_mangle)]
pub extern "C" fn fz_accept() -> c_int {
    // SAFETY: an entry, on the thread the header allows.
    at_boundary(unsafe { global() }.accept())
}

/// fz_quiesce in libfiberzygote.h: 0, or -1 with errno.
#[unsafe(no_mangle)]
pub extern "C" fn fz_quiesce() -> c_int {
    // SAFETY: an entry, on the thread the header allows.
    at_boundary(unsafe { global() }.quiesce().map(|()| 0))
}

/// fz_incarnation_wait in libfiberzygote.h: 1 with *inc filled, 0 to
/// serve on, or -1 with errno.
///
/// # Safety
/// inc is writable, or null, which the C would have crashed on and
/// which is then not written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_incarnation_wait(inc: *mut Incarnation) -> c_int {
    // SAFETY: an entry, on the thread the header allows.
    let got = unsafe { global() }.wait();
    at_boundary(got.map(|got| match got {
        Some(rec) => {
            // SAFETY: writable or null, by the contract above.
            if let Some(inc) = unsafe { inc.as_mut() } {
                *inc = rec;
            }
            1
        }
        None => 0,
    }))
}

/// fz_seed_forget in libfiberzygote.h.
#[unsafe(no_mangle)]
pub extern "C" fn fz_seed_forget() {
    // SAFETY: an entry, on the thread the header allows.
    unsafe { global() }.seed_forget();
}

/// fz_gvisor_identity in libfiberzygote.h: 0 with *id filled, or -1
/// with errno.
///
/// # Safety
/// id is writable, or null, which is then not written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fz_gvisor_identity(id: *mut Incarnation) -> c_int {
    // SAFETY: an entry, on the thread the header allows, and the spec
    // buffer is referenced here alone.
    let got = unsafe { global().gvisor_identity(&mut *SPEC_ENV.get()) };
    at_boundary(got.map(|rec| {
        // SAFETY: writable or null, by the contract above.
        if let Some(id) = unsafe { id.as_mut() } {
            *id = rec;
        }
        0
    }))
}

/// fz_gvisor_ack in libfiberzygote.h: 0, or -1 with errno.
#[unsafe(no_mangle)]
pub extern "C" fn fz_gvisor_ack() -> c_int {
    // SAFETY: an entry, on the thread the header allows.
    at_boundary(unsafe { global() }.gvisor_ack().map(|()| 0))
}

/// The C fuzz harnesses' view of the state (fuzz/fuzz_wait.c and
/// fuzz/fuzz_identity.c), in the fuzzshim archive alone, so a harness
/// sets up and checks what the C file's statics held.
#[cfg(feature = "fuzzshim")]
mod fuzz {
    use super::{BORN, POLLED, STATE, State};
    use crate::abi::RecordStore;

    /// The fiber's small state.
    #[unsafe(no_mangle)]
    pub extern "C" fn fz_rs_fuzz_state() -> *mut State {
        STATE.get()
    }

    /// The birth record's store.
    #[unsafe(no_mangle)]
    pub extern "C" fn fz_rs_fuzz_born() -> *mut RecordStore {
        BORN.get()
    }

    /// A resume's record's store.
    #[unsafe(no_mangle)]
    pub extern "C" fn fz_rs_fuzz_polled() -> *mut RecordStore {
        POLLED.get()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::type_complexity
    )]
    use super::*;

    /// An empty store, as the statics start.
    fn empty() -> Box<RecordStore> {
        // SAFETY: all zero bits are a RecordStore, as for BORN.
        Box::new(unsafe { core::mem::zeroed() })
    }

    const SEED_HEX: &[u8] = b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// A resume's record of generation g naming fence, as fiberd sends it.
    fn record(g: &str, fence: &str) -> Vec<u8> {
        record_with(g, fence, "/run/g/ep.sock", "-")
    }

    /// record with the endpoint and the payload's hex field given.
    fn record_with(g: &str, fence: &str, endpoint: &str, payload: &str) -> Vec<u8> {
        let mut r = vec![b'i'];
        let fields: [&[u8]; 11] = [
            g.as_bytes(),
            b"resume",
            fence.as_bytes(),
            endpoint.as_bytes(),
            payload.as_bytes(),
            b"-",
            b"-",
            b"-",
            b"-",
            b"-",
            SEED_HEX,
        ];
        for f in fields {
            r.extend_from_slice(f);
            r.push(0);
        }
        r
    }

    /// A message as the channel carries it: a tag, its text and a NUL.
    fn msg(tag: u8, text: &str) -> Vec<u8> {
        let mut m = vec![tag];
        m.extend_from_slice(text.as_bytes());
        m.push(0);
        m
    }

    /// What fiberd queues on the channel before the call.
    #[derive(Clone)]
    enum Q {
        /// A message with no descriptor.
        M(Vec<u8>),
        /// A message with a descriptor riding along.
        Fd(Vec<u8>),
        /// fiberd's end shut for writing, so the queue ends in EOF.
        Eof,
    }

    /// A fiber over a SOCK_SEQPACKET pair, with state of its own: the
    /// fiber's end is the channel, the peer is fiberd's.
    struct Rig {
        st: Box<State>,
        born: Box<RecordStore>,
        polled: Box<RecordStore>,
        msg: Box<[u8; RECORD_MAX]>,
        peer: c_int,
    }

    impl Rig {
        fn new() -> Rig {
            let mut sv = [-1; 2];
            // SAFETY: sv is live for the call.
            let rc = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    sv.as_mut_ptr(),
                )
            };
            assert_eq!(rc, 0, "socketpair");
            // Room for a whole RECORD_MAX message in flight.
            let sndbuf: c_int = 1 << 20;
            // SAFETY: sndbuf is live for the call and an int long.
            unsafe {
                libc::setsockopt(
                    sv[1],
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const sndbuf).cast(),
                    size_of::<c_int>() as libc::socklen_t,
                )
            };
            let mut st = Box::new(State::new());
            st.channel_fd = sv[0];
            Rig {
                st,
                born: empty(),
                polled: empty(),
                msg: Box::new([0; RECORD_MAX]),
                peer: sv[1],
            }
        }

        fn fiber(&mut self) -> Fiber<'_> {
            Fiber {
                st: &mut self.st,
                born: &mut self.born,
                polled: &mut self.polled,
                msg: &mut self.msg,
            }
        }

        /// Queues q on fiberd's end. Returns the descriptors sent, which
        /// the caller closes, so their copies in flight are the fiber's.
        fn queue(&self, q: &[Q]) -> Vec<c_int> {
            let mut sent = Vec::new();
            for m in q {
                match m {
                    Q::M(data) => send(self.peer, data, -1),
                    Q::Fd(data) => {
                        // SAFETY: a static NUL-ended path.
                        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
                        assert!(fd >= 0, "open /dev/null");
                        send(self.peer, data, fd);
                        sent.push(fd);
                    }
                    Q::Eof => {
                        // SAFETY: an integer argument alone.
                        unsafe { libc::shutdown(self.peer, libc::SHUT_WR) };
                    }
                }
            }
            sent
        }

        /// Every message the fiber sent fiberd, without waiting.
        fn answers(&self) -> Vec<Vec<u8>> {
            let mut got = Vec::new();
            loop {
                let mut buf = [0u8; 256];
                // SAFETY: buf is live for the call.
                let n = unsafe {
                    libc::recv(
                        self.peer,
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n <= 0 {
                    return got;
                }
                got.push(buf[..n as usize].to_vec());
            }
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            // SAFETY: the pair is the rig's own.
            unsafe {
                libc::close(self.st.channel_fd);
                libc::close(self.peer);
            }
        }
    }

    /// Sends data on sock as one message, with fd in SCM_RIGHTS unless
    /// it is -1.
    fn send(sock: c_int, data: &[u8], fd: c_int) {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut cbuf = [0u64; 4];
        let mut mh: libc::msghdr = zeroed();
        mh.msg_iov = &raw mut iov;
        mh.msg_iovlen = 1;
        if fd >= 0 {
            let bytes = size_of::<c_int>() as u32;
            mh.msg_control = cbuf.as_mut_ptr().cast();
            // SAFETY: CMSG_SPACE is arithmetic on its argument.
            mh.msg_controllen = unsafe { libc::CMSG_SPACE(bytes) } as usize;
            // SAFETY: mh describes cbuf, which has room for one descriptor.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&raw const mh);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(bytes) as usize;
                ptr::copy_nonoverlapping(
                    (&raw const fd).cast::<u8>(),
                    libc::CMSG_DATA(c),
                    bytes as usize,
                );
            }
        }
        // SAFETY: mh, iov and cbuf are live for the call.
        let r = unsafe { libc::sendmsg(sock, &raw const mh, libc::MSG_NOSIGNAL) };
        assert_eq!(r, data.len() as isize, "sendmsg");
    }

    fn close_all(fds: Vec<c_int>) {
        for fd in fds {
            // SAFETY: fd is the test's own.
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn messages_are_framed_as_in_c() {
        fn framed<const N: usize>((buf, n): ([u8; N], usize)) -> Vec<u8> {
            buf[..n].to_vec()
        }
        let cases: &[(&str, Vec<u8>, &[u8])] = &[
            ("an ack", framed(ack_message(b"g/2/5")), b"ag/2/5\0"),
            ("an ack of no fence", framed(ack_message(b"")), b"a\0"),
            ("a quiesce of round 0", framed(quiesce_message(0)), b"q0\0"),
            (
                "a quiesce of the largest round",
                framed(quiesce_message(u32::MAX)),
                b"q4294967295\0",
            ),
            (
                "a claim stops at the token's NUL",
                framed(claim_message(b"tok-1\0garbage")),
                b"ttok-1\0",
            ),
        ];
        for (name, got, want) in cases {
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn longest_fence_and_token_fit_their_messages() {
        let fence = [b'f'; FENCE_MAX - 1];
        let token = [b't'; GVISOR_TOKEN_MAX];
        let cases: &[(&str, &[u8], usize)] = &[
            (
                "the longest fence the parser keeps",
                &ack_message(&fence).0[..],
                FENCE_MAX + 1,
            ),
            (
                "the longest token spec_token keeps",
                &claim_message(&token).0[..],
                GVISOR_TOKEN_MAX + 2,
            ),
        ];
        for (name, buf, n) in cases {
            assert_eq!(buf[n - 1], 0, "{name}: NUL-ended");
            assert!(buf[1..n - 1].iter().all(|&b| b != 0), "{name}: whole");
        }
    }

    #[test]
    fn forget_seed_zeroes_both_copies() {
        let cases: &[(&str, Option<Vec<u8>>)] = &[
            ("a parsed record", Some(record("4", "g/1/1"))),
            ("an empty store", None),
        ];
        for (name, rec) in cases {
            let mut st = empty();
            if let Some(rec) = rec {
                st.buf[..rec.len()].copy_from_slice(rec);
                parse_store(&mut st, rec.len()).unwrap();
                assert_eq!(st.seed[1], 1, "{name}: the seed is there first");
            }
            forget_seed(&mut st);
            assert!(st.seed.iter().all(|&b| b == 0), "{name}: decoded seed");
            assert_eq!(st.inc.seed_len, 0, "{name}");
            if !st.seed_hex.is_null() {
                let off = st.seed_hex as usize - st.buf.as_ptr() as usize;
                assert!(st.buf[off..off + 64].iter().all(|&b| b == 0), "{name}: hex");
                assert_eq!(fence_of(&st), b"g/1/1", "{name}: the rest stays");
            }
        }
    }

    #[test]
    fn take_record_has_three_outcomes() {
        struct Case {
            name: &'static str,
            msg: Vec<u8>,
            served: c_uint,
            want: Result<bool, Errno>,
        }
        let cases = [
            Case {
                name: "a generation above the served one is fresh",
                msg: record("6", "g/2/6"),
                served: 5,
                want: Ok(true),
            },
            Case {
                name: "the served generation is a replay",
                msg: record("5", "g/2/5"),
                served: 5,
                want: Ok(false),
            },
            Case {
                name: "a generation below is a replay",
                msg: record("3", "g/2/3"),
                served: 5,
                want: Ok(false),
            },
            Case {
                name: "anything but a record is EPROTO",
                msg: msg(b'x', "6"),
                served: 5,
                want: Err(Errno(libc::EPROTO)),
            },
            Case {
                name: "a record that does not parse is EPROTO",
                msg: record("0", "g/2/0"),
                served: 0,
                want: Err(Errno(libc::EPROTO)),
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            rig.st.served_generation = tc.served;
            rig.msg[..tc.msg.len()].copy_from_slice(&tc.msg);
            let got = rig.fiber().take_record(tc.msg.len());
            assert_eq!(got, tc.want, "{}", tc.name);
            if tc.msg[0] == b'i' {
                // The message's copy is gone, the store's is the one.
                assert!(
                    rig.msg[..tc.msg.len()].iter().all(|&b| b == 0),
                    "{}: wiped",
                    tc.name
                );
                assert_eq!(
                    &rig.polled.buf[..tc.msg.len()],
                    &tc.msg[..],
                    "{}: copied",
                    tc.name
                );
            }
            if got.is_ok() {
                assert_eq!(rig.polled.inc.seed_len, 32, "{}", tc.name);
            }
            assert_eq!(
                rig.st.served_generation, tc.served,
                "{}: not moved here",
                tc.name
            );
        }
    }

    #[test]
    fn quiesce_drains_the_rounds_and_answers() {
        struct Case {
            name: &'static str,
            round: c_uint,
            queue: Vec<Q>,
            want: Result<(), Errno>,
            want_round: c_uint,
            want_over: bool,
            want_sent: Vec<Vec<u8>>,
        }
        let cases = [
            Case {
                name: "nothing queued answers the round already noted",
                round: 3,
                queue: vec![],
                want: Ok(()),
                want_round: 3,
                want_over: false,
                want_sent: vec![msg(b'q', "3")],
            },
            Case {
                name: "a round names what is answered",
                round: 0,
                queue: vec![Q::M(msg(b'p', "7"))],
                want: Ok(()),
                want_round: 7,
                want_over: false,
                want_sent: vec![msg(b'q', "7")],
            },
            Case {
                name: "its carry-on already there ends the round",
                round: 0,
                queue: vec![Q::M(msg(b'p', "7")), Q::M(msg(b'c', "7"))],
                want: Ok(()),
                want_round: 7,
                want_over: true,
                want_sent: vec![msg(b'q', "7")],
            },
            Case {
                name: "a stale carry-on is dropped",
                round: 0,
                queue: vec![
                    Q::M(msg(b'c', "6")),
                    Q::M(msg(b'p', "7")),
                    Q::M(msg(b'c', "5")),
                ],
                want: Ok(()),
                want_round: 7,
                want_over: false,
                want_sent: vec![msg(b'q', "7")],
            },
            Case {
                name: "a later round undoes an earlier carry-on",
                round: 0,
                queue: vec![
                    Q::M(msg(b'p', "7")),
                    Q::M(msg(b'c', "7")),
                    Q::M(msg(b'p', "8")),
                ],
                want: Ok(()),
                want_round: 8,
                want_over: false,
                want_sent: vec![msg(b'q', "8")],
            },
            Case {
                name: "a connection and a record are dropped",
                round: 0,
                queue: vec![
                    Q::Fd(msg(b'x', "")),
                    Q::M(record("9", "g/1/9")),
                    Q::M(msg(b'p', "2")),
                ],
                want: Ok(()),
                want_round: 2,
                want_over: false,
                want_sent: vec![msg(b'q', "2")],
            },
            Case {
                name: "fiberd gone is ECONNRESET, with no answer",
                round: 0,
                queue: vec![Q::M(msg(b'p', "4")), Q::Eof],
                want: Err(Errno(libc::ECONNRESET)),
                want_round: 4,
                want_over: false,
                want_sent: vec![],
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            rig.st.park_round = tc.round;
            let sent = rig.queue(&tc.queue);
            close_all(sent);
            let got = rig.fiber().quiesce();
            assert_eq!(got, tc.want, "{}", tc.name);
            assert_eq!(rig.st.park_round, tc.want_round, "{}: round", tc.name);
            assert_eq!(rig.st.park_over, tc.want_over, "{}: over", tc.name);
            assert_eq!(rig.answers(), tc.want_sent, "{}: sent", tc.name);
            // A record drained here leaves no copy of its seed behind.
            assert!(
                !rig.msg.windows(SEED_HEX.len()).any(|w| w == SEED_HEX),
                "{}: wiped",
                tc.name
            );
        }
    }

    #[test]
    fn accept_hands_over_a_connection_or_ends_on_a_round() {
        struct Case {
            name: &'static str,
            channel: bool,
            queue: Vec<Q>,
            want: Result<bool, Errno>, // Ok(true) is a descriptor
            want_round: c_uint,
            want_over: bool,
        }
        let cases = [
            Case {
                name: "a connection",
                channel: true,
                queue: vec![Q::Fd(msg(b'x', ""))],
                want: Ok(true),
                want_round: 0,
                want_over: false,
            },
            Case {
                name: "a park's round is EINTR, noted for the quiesce",
                channel: true,
                queue: vec![Q::M(msg(b'p', "7")), Q::Fd(msg(b'x', ""))],
                want: Err(Errno(libc::EINTR)),
                want_round: 7,
                want_over: false,
            },
            Case {
                name: "a carry-on is noted and the wait goes on",
                channel: true,
                queue: vec![Q::M(msg(b'c', "0")), Q::Fd(msg(b'x', ""))],
                want: Ok(true),
                want_round: 0,
                want_over: true,
            },
            Case {
                name: "a message with nothing to serve is skipped",
                channel: true,
                queue: vec![Q::M(record("2", "g/1/2")), Q::Fd(msg(b'x', ""))],
                want: Ok(true),
                want_round: 0,
                want_over: false,
            },
            Case {
                name: "fiberd gone is ECONNRESET",
                channel: true,
                queue: vec![Q::Eof],
                want: Err(Errno(libc::ECONNRESET)),
                want_round: 0,
                want_over: false,
            },
            Case {
                name: "no channel is EBADF",
                channel: false,
                queue: vec![],
                want: Err(Errno(libc::EBADF)),
                want_round: 0,
                want_over: false,
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            let sent = rig.queue(&tc.queue);
            close_all(sent);
            let fd = rig.st.channel_fd;
            if !tc.channel {
                rig.st.channel_fd = -1;
            }
            let got = rig.fiber().accept();
            rig.st.channel_fd = fd;
            assert_eq!(got.map(|fd| fd >= 0), tc.want, "{}", tc.name);
            if let Ok(fd) = got {
                close_all(vec![fd]);
            }
            assert_eq!(rig.st.park_round, tc.want_round, "{}: round", tc.name);
            assert_eq!(rig.st.park_over, tc.want_over, "{}: over", tc.name);
        }
    }

    #[test]
    fn wait_hands_over_a_fresh_record_alone() {
        struct Case {
            name: &'static str,
            served: c_uint,
            over: bool,
            queue: Vec<Q>,
            want: Result<Option<c_uint>, Errno>, // the generation handed over
            want_served: c_uint,
            want_sent: Vec<Vec<u8>>,
        }
        let cases = [
            Case {
                name: "a fresh record",
                served: 5,
                over: false,
                queue: vec![Q::M(record("6", "g/2/6"))],
                want: Ok(Some(6)),
                want_served: 6,
                want_sent: vec![],
            },
            Case {
                name: "a replay is skipped for the fresh one behind it",
                served: 5,
                over: false,
                queue: vec![
                    Q::M(record("5", "g/2/5")),
                    Q::M(record("3", "g/2/3")),
                    Q::M(record("7", "g/2/7")),
                ],
                want: Ok(Some(7)),
                want_served: 7,
                want_sent: vec![],
            },
            Case {
                name: "a replay and then fiberd gone hands nothing over",
                served: 5,
                over: false,
                queue: vec![Q::M(record("4", "g/2/4")), Q::Eof],
                want: Err(Errno(libc::ECONNRESET)),
                want_served: 5,
                want_sent: vec![],
            },
            Case {
                name: "the round already over serves on",
                served: 5,
                over: true,
                queue: vec![Q::M(record("6", "g/2/6"))],
                want: Ok(None),
                want_served: 5,
                want_sent: vec![],
            },
            Case {
                name: "a new round is answered, and its carry-on serves on",
                served: 5,
                over: false,
                queue: vec![Q::M(msg(b'p', "9")), Q::M(msg(b'c', "9"))],
                want: Ok(None),
                want_served: 5,
                want_sent: vec![msg(b'q', "9")],
            },
            Case {
                name: "a connection meanwhile is closed",
                served: 1,
                over: false,
                queue: vec![Q::Fd(msg(b'x', "")), Q::M(record("2", "g/1/2"))],
                want: Ok(Some(2)),
                want_served: 2,
                want_sent: vec![],
            },
            Case {
                name: "a refused record is EPROTO",
                served: 1,
                over: false,
                queue: vec![Q::M(msg(b'z', "2"))],
                want: Err(Errno(libc::EPROTO)),
                want_served: 1,
                want_sent: vec![],
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            rig.st.served_generation = tc.served;
            rig.st.park_over = tc.over;
            let sent = rig.queue(&tc.queue);
            close_all(sent);
            let got = rig.fiber().wait();
            assert_eq!(
                got.map(|r| r.map(|inc| inc.generation)),
                tc.want,
                "{}",
                tc.name
            );
            assert_eq!(
                rig.st.served_generation, tc.want_served,
                "{}: served",
                tc.name
            );
            assert_eq!(
                rig.st.ack_pending,
                matches!(tc.want, Ok(Some(_))),
                "{}: ack pending",
                tc.name
            );
            assert_eq!(rig.answers(), tc.want_sent, "{}: sent", tc.name);
            if let Ok(Some(inc)) = got {
                assert_eq!(inc.seed, rig.polled.seed.as_ptr(), "{}", tc.name);
                assert_eq!(inc.seed_len, 32, "{}", tc.name);
            } else {
                assert!(
                    rig.polled.seed.iter().all(|&b| b == 0),
                    "{}: no seed stays",
                    tc.name
                );
                assert_eq!(rig.polled.inc.seed_len, 0, "{}", tc.name);
            }
            assert!(
                !rig.st.park_over,
                "{}: a carry-on honoured is a round over",
                tc.name
            );
        }
    }

    #[test]
    fn ready_acks_a_resume_once() {
        let cases: &[(&str, bool, Vec<Vec<u8>>)] = &[
            (
                "after a resume, the ack names its fence",
                true,
                vec![msg(b'a', "g/3/4")],
            ),
            ("with nothing to ack, nothing is sent", false, vec![]),
        ];
        for (name, resumed, want) in cases {
            let mut rig = Rig::new();
            if *resumed {
                rig.queue(&[Q::M(record("4", "g/3/4"))]);
                assert!(matches!(rig.fiber().wait(), Ok(Some(_))), "{name}: wait");
            }
            rig.fiber().ready();
            rig.fiber().ready();
            assert_eq!(rig.answers(), *want, "{name}");
            assert!(!rig.st.ack_pending, "{name}");
            assert!(rig.polled.seed.iter().all(|&b| b == 0), "{name}: seed");
        }
    }

    #[test]
    fn gvisor_ack_says_the_fence_and_closes() {
        let cases: &[(&str, bool, Result<(), Errno>, Vec<Vec<u8>>)] = &[
            (
                "a claimed record is acked",
                true,
                Ok(()),
                vec![msg(b'a', "g/5/1")],
            ),
            (
                "no connection is EBADF",
                false,
                Err(Errno(libc::EBADF)),
                vec![],
            ),
        ];
        for (name, claimed, want, want_sent) in cases {
            let mut rig = Rig::new();
            let rec = record("1", "g/5/1");
            rig.born.buf[..rec.len()].copy_from_slice(&rec);
            parse_store(&mut rig.born, rec.len()).unwrap();
            // The fiber's channel end stands in for the pool connection,
            // which the ack closes, so the rig's drop closes a copy.
            if *claimed {
                // SAFETY: an integer argument alone.
                rig.st.gv_channel = unsafe { libc::dup(rig.st.channel_fd) };
            }
            assert_eq!(rig.fiber().gvisor_ack(), *want, "{name}");
            assert_eq!(rig.st.gv_channel, -1, "{name}: closed");
            assert_eq!(rig.answers(), *want_sent, "{name}");
            if *claimed {
                assert!(rig.born.seed.iter().all(|&b| b == 0), "{name}: seed");
            }
        }
    }

    #[test]
    fn a_refused_record_after_a_resume_stays_in_its_buffers() {
        // fz_incarnation_wait hands over a resume, the template waits
        // again, fiberd's next message is refused after it was copied
        // over the store's buffer, and then the template calls
        // fz_fiber_ready. The refused message is the worst one, RECORD_MAX
        // bytes with no NUL, so the old record's fence and seed pointers
        // name bytes that run to the end of buf. Main's C (HEAD before
        // stage 4) ran strlen there. Its ack memcpy overflowed the stack
        // (ASan: stack-buffer-overflow in fz_fiber_ready), and its
        // forget_seed zeroed the handed-over payload past buf.
        struct Case {
            name: &'static str,
            first: Vec<u8>,
            ready: bool,
            want_sent: Vec<Vec<u8>>,
            want_payload: &'static [u8],
        }
        let cut_fence = {
            let mut a = vec![b'a'];
            a.extend_from_slice(&[b'A'; FENCE_MAX]);
            a.push(0);
            a
        };
        let cases = [
            Case {
                // The seed's field sits 600 bytes past the fence, so the
                // refusal's wipe of it leaves more than FENCE_MAX bytes
                // with no NUL where the fence was.
                name: "the ack after a refusal is cut at FENCE_MAX",
                first: record_with("2", "g/1/2", &"e".repeat(600), "-"),
                ready: true,
                want_sent: vec![cut_fence],
                want_payload: &[],
            },
            Case {
                name: "the seed's wipe after a refusal stops at the end of buf",
                first: record_with("2", "g/1/2", "/run/g/ep.sock", "0102030405060708"),
                ready: false,
                want_sent: vec![],
                want_payload: &[1, 2, 3, 4, 5, 6, 7, 8],
            },
        ];
        for tc in cases {
            let mut rig = Rig::new();
            rig.queue(&[Q::M(tc.first.clone())]);
            let got = rig.fiber().wait();
            assert!(matches!(got, Ok(Some(_))), "{}: the resume", tc.name);
            let payload = rig.polled.payload;
            let mut bad = vec![b'A'; RECORD_MAX];
            bad[0] = b'i';
            rig.queue(&[Q::M(bad)]);
            assert_eq!(
                rig.fiber().wait().err(),
                Some(Errno(libc::EPROTO)),
                "{}: the refusal",
                tc.name
            );
            assert!(
                rig.st.ack_pending,
                "{}: the resume is still to ack",
                tc.name
            );
            if tc.ready {
                rig.fiber().ready();
            }
            let sent = rig.answers();
            assert_eq!(sent, tc.want_sent, "{}: sent", tc.name);
            for ack in &sent {
                assert_eq!(
                    ack.len(),
                    FENCE_MAX + 2,
                    "{}: the ack fits its buffer",
                    tc.name
                );
                assert_eq!(ack.last(), Some(&0), "{}: NUL-ended", tc.name);
            }
            // Nothing past buf was written: the payload handed over with
            // the resume is as it was.
            assert_eq!(rig.polled.payload, payload, "{}: past buf", tc.name);
            assert_eq!(
                &rig.polled.payload[..tc.want_payload.len()],
                tc.want_payload,
                "{}: payload",
                tc.name
            );
            // No seed is left, decoded or as hex.
            assert!(rig.polled.seed.iter().all(|&b| b == 0), "{}: seed", tc.name);
            assert_eq!(rig.polled.inc.seed_len, 0, "{}", tc.name);
            assert!(
                !rig.polled
                    .buf
                    .windows(SEED_HEX.len())
                    .any(|w| w == SEED_HEX),
                "{}: hex",
                tc.name
            );
        }
    }
}
