//! The zygote's serving loop (serve in core/src/zygote.rs) over the
//! bytes fiberd would send on the control socket. Every raw syscall,
//! mount, umount2 and mkdir fails with EPERM, so no fiber is born and
//! nothing is mounted, but CLONE and PREPARE still walk their parsing.
//! A thread drains the replies so a long input cannot wedge the zygote.
//!
//! The input is [flags][stream bytes]. Flag 1 sends the first line as
//! the REBIND message with the control socket riding along. Flag 2
//! sends two descriptors on the first message. Flag 4 sets an engine
//! endpoint. Flag 8 installs a control handler. Flag 16 fakes an own
//! mount namespace, so PREPARE mntns reaches the mount steps.
#![no_main]

#[path = "hooks.rs"]
mod hooks;
#[path = "sock.rs"]
mod sock;

use fiberzygote_core::abi::{Incarnation, MAX_LINE};
use fiberzygote_core::ctl::{fz_set_control, fz_set_engine, set_ctl_fd};
use fiberzygote_core::zygote::{State, Tables, Zygote, block_sigchld};
use libfuzzer_sys::fuzz_target;
use std::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use std::sync::Mutex;

fn refuse_syscall(_nr: c_long, _args: [c_long; 5]) -> c_long {
    // Not ENOSYS, or birth would fall back to a real clone.
    c_long::from(hooks::fail(libc::EPERM))
}

fn refuse_mount(
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: c_ulong,
    _: *const c_void,
) -> c_int {
    hooks::fail(libc::EPERM)
}

fn refuse_umount2(_: *const c_char, _: c_int) -> c_int {
    hooks::fail(libc::EPERM)
}

fn refuse_mkdir(_: *const c_char, _: libc::mode_t) -> c_int {
    hooks::fail(libc::EPERM)
}

unsafe extern "C" fn on_fiber(_: *const Incarnation) -> c_int {
    panic!("a fiber was born");
}

unsafe extern "C" fn on_control(line: *const c_char) {
    // SAFETY: the loop hands the handler a NUL-ended line.
    let n = unsafe { CStr::from_ptr(line) }.to_bytes().len();
    assert!(n < MAX_LINE, "a control line of {n} bytes");
}

/// The zygote's state, made once, as the statics are.
struct Zyg {
    st: Box<State>,
    t: Box<Tables>,
}

// SAFETY: the raw pointers in Tables (the fiber's environ) name Tables'
// own storage, and only the fuzzing thread ever reaches it, through the
// mutex.
unsafe impl Send for Zyg {}

static ZYGOTE: Mutex<Option<Zyg>> = Mutex::new(None);

/// Starts every input afresh, as a new zygote would. The SIGCHLD
/// descriptor stays, since serve opens it once per process.
fn reset(z: &mut Zyg) {
    *z.st = State {
        sigchld_fd: z.st.sigchld_fd,
        ..State::new()
    };
    z.t.hide_covered.fill(0);
    z.t.own_ns_why[0] = 0;
    z.t.rundir_parent[0] = 0;
    z.t.rundir_own[0] = 0;
    set_ctl_fd(-1);
    // SAFETY: null names no engine.
    unsafe { fz_set_engine(std::ptr::null()) };
    fz_set_control(None);
}

/// Sets or clears FIBERD_CTL_REBIND. Only this thread reads the
/// environment while it changes.
fn set_rebind(on: bool) {
    // SAFETY: by the comment above.
    unsafe {
        if on {
            std::env::set_var("FIBERD_CTL_REBIND", "1");
        } else {
            std::env::remove_var("FIBERD_CTL_REBIND");
        }
    }
}

fn drain(fd: c_int) {
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is live for the call.
        let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if r < 0 && sock::errno() == libc::EINTR {
            continue;
        }
        if r <= 0 {
            return;
        }
    }
}

fuzz_target!(
    init: {
        hooks::install(hooks::Shim {
            syscall: Some(refuse_syscall),
            mount: Some(refuse_mount),
            umount2: Some(refuse_umount2),
            mkdir: Some(refuse_mkdir),
            open: None,
        });
        // With this set serve would write a sysctl and drop a capability.
        // SAFETY: no other thread reads the environment yet.
        unsafe { std::env::remove_var("FIBERD_USERNS_NESTED") };
        // serve refuses to run without it, as fz_init leaves it. Before
        // the drain threads, which inherit it.
        block_sigchld();
        // SAFETY: all zero bits are a Tables, as the static's bss.
        let t = unsafe { Box::<Tables>::new_zeroed().assume_init() };
        *ZYGOTE.lock().unwrap() = Some(Zyg { st: Box::new(State::new()), t });
    },
    |data: &[u8]| {
        let Some((&flags, mut data)) = data.split_first() else {
            return;
        };
        let mut guard = ZYGOTE.lock().unwrap();
        let z = guard.as_mut().expect("the zygote made at init");
        reset(z);
        if flags & 4 != 0 {
            // SAFETY: a static NUL-ended endpoint.
            unsafe { fz_set_engine(c"/run/fiberd/engine.sock".as_ptr()) };
        }
        if flags & 8 != 0 {
            fz_set_control(Some(on_control));
        }
        if flags & 16 != 0 {
            z.st.have_own_ns = true;
        }

        let s = sock::pair(libc::SOCK_STREAM);
        let mut ctl_fd = s[0];
        if flags & 1 != 0 {
            // The first line is the REBIND message. The control socket
            // rides on it, and the target lets go of its own copy.
            set_rebind(true);
            let boot = sock::pair(libc::SOCK_STREAM);
            let first = data.iter().position(|&b| b == b'\n').map_or(data.len(), |nl| nl + 1);
            if first > 0 {
                sock::send_fds(boot[1], &data[..first], &[s[0]]);
            }
            sock::close(boot[1]);
            sock::close(s[0]);
            ctl_fd = boot[0];
            data = &data[first..];
        } else {
            set_rebind(false);
        }
        if !data.is_empty() {
            sock::send_scratch_fds(s[1], data, if flags & 2 != 0 { 2 } else { 0 });
        }
        // SAFETY: an integer call on our own socket.
        assert_eq!(unsafe { libc::shutdown(s[1], libc::SHUT_WR) }, 0);
        let peer = s[1];
        let t = std::thread::spawn(move || drain(peer));

        let mut zygote = Zygote {
            st: &mut z.st,
            t: &mut z.t,
        };
        let got = zygote.serve(ctl_fd, Some(on_fiber));
        if let Ok(v) = got {
            assert_eq!(v, 0, "serve gave {v}");
        }
        // Nothing was ever born.
        assert_eq!(z.st.npending, 0, "a child pending");
        assert_eq!(z.st.nkids, 0, "a fiber remembered");

        sock::close(ctl_fd);
        t.join().unwrap();
        sock::close(s[1]);
    }
);
