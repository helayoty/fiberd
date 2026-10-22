/* refzygote: the reference workload for fiberd's process runtime and the
 * conformance suite's template.
 *
 * Init, paid once in the zygote, allocates --heap-mb, touches every page
 * and burns some CPU to stand in for a JIT or graph build. Every fiber
 * is a copy-on-write fork of that.
 *
 * Each fiber serves a line protocol on its unix-socket endpoint. The
 * probes exist so the runtime's tests can see what a fiber sees.
 *
 *   ping            -> pong
 *   dirty <bytes>   -> ok        (grows the working set, charged as W)
 *   incr            -> <n>       (per-fiber counter, survives a park)
 *   get             -> <n>
 *   random          -> <n>       (libc random(), reseeded in every
 *                                 incarnation, so no two copies agree)
 *   seed            -> <hex>     (the record's seed under "keep_seed",
 *                                 else "-")
 *   getrandom       -> <hex>     (8 bytes straight from getrandom(2))
 *   fence           -> <fence>   (the current one, renewed by a resume)
 *   getenv <NAME>   -> value or "-" (proves the scrub)
 *   session         -> the session the caller named, or "-"
 *   generation      -> the lineage count from the record
 *   kind            -> the current record's kind, "fork" or "resume"
 *   borrow <pid> <fd> -> "ok" or the errno's name (proves a fiber cannot
 *                      take another's channel as fiberd does)
 *   payload         -> the birth payload in hex (up to 127 bytes), or "-"
 *   status <Key>    -> that field of /proc/self/status, or "-"
 *   read <path>     -> the file's first line, or "-"
 *   wopen <path>    -> "ok" or the errno's name of open(O_WRONLY). Nothing
 *                      is ever written.
 *   stat <path>     -> "dir", "file", "sock", "other" or the errno's name
 *   remount <path>  -> "ok" when a read-write remount succeeds (undone at
 *                      once), else the errno's name
 *   rdonly <path>   -> "ro" or "rw" for the mount holding path
 *   probe <name>    -> "ok", the errno's name, or the signal that ended
 *                      it ("SIGSYS"), for one call the fiber filter
 *                      refuses or lets through (see probes[] below)
 *   reserve <bytes> -> the engine's reply to a slice under this fiber's
 *                      own fence ("ok", "err capacity", ...)
 *   devfree         -> the engine's reply to releasing that slice
 *   engine <line>   -> the engine's one-line reply to <line> sent as it
 *                      is, so a test can make a fiber name a sibling's
 *                      fence and see "err fence"
 *
 * A handoff fiber (its record carries an identity) serves the same
 * protocol inside TLS 1.3 on the connections fz_accept() hands it, and
 * fails the handshake for any client certificate but the one the
 * identity names. That needs -DFZ_TLS and OpenSSL 3. Without it a
 * handoff fiber refuses to start.
 *
 * The clone payload, if any, is JSON. "dirty_bytes" and "device_bytes"
 * grow the fiber right after ready, which is how conformance case C6
 * drives a fiber over its W budget. The other keys are test knobs, read
 * where they act (ready_delay_ms, keep_seed, ready_misuse,
 * exit_after_ready, park_ignore, reply_delay_ms, park_delay_ms,
 * ack_skip).
 *
 * A park follows libfiberzygote.h. A fiber whose wait fails ends with
 * 122, the code for a lost record on every path.
 *
 * --http serves HTTP/1.1 instead of the line protocol, over the same
 * state. GET /readyz -> "ok", GET / or /count -> the counter, POST / or
 * /incr -> the counter after one increment, GET /fence -> the fence,
 * POST /dirty?bytes=N -> "ok N".
 *
 * --device-mb N makes the zygote an engine with a simulated device of N
 * MiB, the GPU model in miniature. Fibers hold slices over FIBERD_ENGINE
 * ("reserve <bytes>", "devfree"), the engine reports them in DEVICE
 * lines and drops one on EVICT. The engine names each caller's fence
 * from its socket peer's cgroup leaf and refuses a line naming any
 * other fence with "err fence", so no fiber can charge or free a
 * sibling's slice.
 *
 * Build: (cd core && cargo build --release --locked)
 *        gcc -O2 -pthread -o refzygote refzygote.c core/target/release/libfiberzygote_core.a
 *        (add -DFZ_TLS ... -lssl -lcrypto to serve handoff grants)
 * Run:   fiberd starts it; by hand: refzygote --heap-mb 64 3<>/dev/null
 *
 * --gvisor runs the same workload as a gVisor sandbox's init. There is
 * no fork. Every fiber is a sandbox restored from the template's
 * checkpoint, learns its record through fz_gvisor_identity, serves under
 * /host and closes its endpoint on SIGUSR1 so it can be checkpointed.
 */
#define _GNU_SOURCE
#include "libfiberzygote.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/klog.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/netlink.h>

#ifdef FZ_TLS
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/time.h>
#endif

static char *heap;
static size_t heap_sz;

static void heavy_init(size_t mb) {
    heap_sz = mb << 20;
    heap = malloc(heap_sz);
    if (!heap) { perror("malloc"); exit(1); }
    for (size_t i = 0; i < heap_sz; i += 4096) heap[i] = (char)(i >> 12);
    volatile unsigned x = 1;
    for (long i = 0; i < 20L * 1000 * 1000; i++) x = x * 1664525u + 1013904223u;
    (void)x;
}

static int gvisor_mode;

/* The park's signal. SIGUSR1 stays blocked while a fiber runs and is
 * let through only inside wait_readable's ppoll, which every blocking
 * wait goes through. So it cannot land between a look at the flag and a
 * wait nothing else would end. No SA_RESTART, so ppoll returns EINTR. */
static volatile sig_atomic_t park_requested;
static sigset_t serve_mask; /* the fiber's mask with SIGUSR1 let through */
static void on_usr1(int s) { (void)s; park_requested = 1; }

/* park_arm installs the handler and blocks the signal, once per
 * process, before anything that could be parked runs. */
static void park_arm(void) {
    struct sigaction sa = { .sa_handler = on_usr1 };
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t blk;
    sigemptyset(&blk);
    sigaddset(&blk, SIGUSR1);
    sigprocmask(SIG_BLOCK, &blk, &serve_mask);
    sigdelset(&serve_mask, SIGUSR1);
    park_requested = 0;
}

/* park_pending sees the flag or the signal still waiting behind the
 * block. */
static int park_pending(void) {
    sigset_t s;
    return park_requested || (sigpending(&s) == 0 && sigismember(&s, SIGUSR1));
}

/* wait_readable waits for fd with the park's signal let through. 0 when
 * readable, -1 with EINTR when a park was asked for. */
static int wait_readable(int fd) {
    if (park_requested) { errno = EINTR; return -1; }
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return ppoll(&p, 1, NULL, &serve_mask) < 0 ? -1 : 0;
}

/* dirty grows the working set by bytes, charged as W. Under a fork each
 * touched heap page becomes a private copy. A restored sandbox already
 * owns its heap, so it maps new memory instead. */
static size_t dirty(size_t bytes) {
    if (gvisor_mode) {
        char *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { fprintf(stderr, "refzygote: grow %zu: %s\n", bytes, strerror(errno)); return 0; }
        for (size_t i = 0; i < bytes; i += 4096) p[i] = 1;
        return bytes; /* kept on purpose */
    }
    if (bytes > heap_sz) bytes = heap_sz;
    /* A long request looks at the park flag. Under memory pressure each
     * page is a throttled fault, and the park's signal comes exactly then.
     * What was done is answered. */
    size_t i;
    for (i = 0; i < bytes && !park_pending(); i += 4096) heap[i] ^= 1;
    return i < bytes ? i : bytes;
}

/* Minimal extraction of "<key>": <n> from the JSON payload. */
static unsigned long long payload_num(const unsigned char *p, size_t n, const char *key) {
    if (!p || n == 0) return 0;
    char buf[4097];
    size_t m = n < sizeof buf - 1 ? n : sizeof buf - 1;
    memcpy(buf, p, m); buf[m] = 0;
    const char *k = strstr(buf, key);
    if (!k) return 0;
    k = strchr(k, ':');
    if (!k) return 0;
    return strtoull(k + 1, NULL, 10);
}

/* ---- the simulated device engine (zygote side) --------------------- */

static int listen_endpoint(const char *ep); /* below, with the fiber's serving code */

static pthread_mutex_t dev_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long dev_cap, dev_used;
static struct { char fence[128]; unsigned long long bytes; } dev_slices[4096];
static int ndev;
static char engine_path[256];
static int engine_fd = -1; /* bound in engine_start, served by engine_thread */

/* dev_set replaces a fiber's slice (0 drops it) and reports both the
 * slice and the whole device to fiberd. Called with dev_mu held. */
static const char *dev_set(const char *fence, unsigned long long bytes) {
    int i;
    for (i = 0; i < ndev && strcmp(dev_slices[i].fence, fence) != 0; i++) {}
    unsigned long long had = i < ndev ? dev_slices[i].bytes : 0;
    if (dev_used - had + bytes > dev_cap) return "err capacity";
    if (bytes == 0) {
        if (i < ndev) dev_slices[i] = dev_slices[--ndev];
    } else {
        if (i == ndev) {
            if (ndev >= (int)(sizeof dev_slices / sizeof dev_slices[0])) return "err too many slices";
            snprintf(dev_slices[ndev].fence, sizeof dev_slices[ndev].fence, "%s", fence);
            ndev++;
        }
        dev_slices[i].bytes = bytes;
    }
    dev_used = dev_used - had + bytes;
    /* A fence is at most 127 characters, so both lines fit. */
    char line[FZ_REPORT_MAX];
    snprintf(line, sizeof line, "DEVICE %s %llu 0", fence, bytes);
    fz_report_line(line);
    snprintf(line, sizeof line, "DEVICE - %llu %llu", dev_used, dev_cap);
    fz_report_line(line);
    return "ok";
}

static void on_control(const char *line) {
    if (strncmp(line, "EVICT ", 6) == 0) {
        pthread_mutex_lock(&dev_mu);
        dev_set(line + 6, 0);
        pthread_mutex_unlock(&dev_mu);
    }
}

/* ---- who is asking: the caller's fence from its cgroup -------------
 *
 * The engine never trusts the fence a line carries. It names the
 * caller's fence itself from the socket peer's cgroup. fiberd puts
 * every fiber in <grant_dir>/f-<epoch>-<seq> (leafName in
 * pkg/runtime/host) and the zygote in <grant_dir>/zygote, so a peer in
 * a leaf of our own grant's directory is a fiber of this grant and the
 * leaf's name is its fence. A line naming any other fence gets
 * "err fence". This check is the engine's, template code, and needs no
 * library call.
 *
 * The parse is split from the system calls so it can be unit tested
 * (sdk/c/template/test/engine_test.c) and fuzzed. Every parse takes n
 * bytes that may hold NULs and never reads past n. */

static char grant_dir[256]; /* the grant's cgroup directory, parent of the zygote's */

/* cgroup_unified finds the cgroup v2 line of a /proc/<pid>/cgroup file,
 * "0::<path>", and gives its path without the newline. Exactly one such
 * line, newline-terminated. The lines of a hybrid v1 hierarchy
 * ("1:name=systemd:/...") may come before or after it and are skipped.
 * A NUL anywhere refuses the file, since the kernel writes none. 0, or
 * -1 for no such line, two of them, or an unterminated line. */
static int cgroup_unified(const char *buf, size_t n, const char **path, size_t *len) {
    if (n && memchr(buf, 0, n)) return -1;
    int found = 0;
    size_t i = 0;
    while (i < n) {
        const char *nl = memchr(buf + i, '\n', n - i);
        if (!nl) return -1;
        size_t ln = (size_t)(nl - (buf + i));
        if (ln >= 3 && memcmp(buf + i, "0::", 3) == 0) {
            if (found) return -1;
            found = 1;
            *path = buf + i + 3;
            *len = ln - 3;
        }
        i += ln + 1;
    }
    return found ? 0 : -1;
}

/* dec_u64 parses s[0..n) as a decimal u64: digits only, no sign, no
 * leading zero, no overflow. "0" is refused with the leading zeros,
 * since fiberd mints epochs and sequence numbers from 1. */
static int dec_u64(const char *s, size_t n, unsigned long long *v) {
    if (n == 0 || n > 20 || s[0] == '0') return -1;
    unsigned long long x = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        unsigned d = (unsigned)(s[i] - '0');
        if (x > (ULLONG_MAX - d) / 10) return -1;
        x = x * 10 + d;
    }
    *v = x;
    return 0;
}

/* leaf_name parses "f-<epoch>-<seq>", the name fiberd gives a fiber's
 * cgroup, with nothing before or after. */
static int leaf_name(const char *s, size_t n, unsigned long long *epoch, unsigned long long *seq) {
    if (n < 2 || s[0] != 'f' || s[1] != '-') return -1;
    s += 2; n -= 2;
    const char *dash = memchr(s, '-', n);
    if (!dash) return -1;
    size_t el = (size_t)(dash - s);
    if (dec_u64(s, el, epoch) < 0) return -1;
    return dec_u64(dash + 1, n - el - 1, seq);
}

/* grant_dir_of reads the engine's own /proc/self/cgroup into dir. The
 * zygote runs in <grant_dir>/zygote, so the grant's directory is the
 * parent of the unified path. A path whose parent is empty or "/" or
 * whose last component is empty is refused, since no grant lives there.
 * 0, or -1. */
static int grant_dir_of(const char *buf, size_t n, char *dir, size_t dn) {
    const char *p; size_t len;
    if (cgroup_unified(buf, n, &p, &len) < 0) return -1;
    if (len == 0 || p[0] != '/') return -1;
    const char *end = p + len;
    while (end > p && end[-1] != '/') end--;
    /* end sits just past the last '/'. */
    if (end == p + len) return -1;        /* no last component */
    size_t parent = (size_t)(end - p) - 1;
    if (parent == 0) return -1;           /* the parent is "/" */
    if (parent >= dn) return -1;
    memcpy(dir, p, parent);
    dir[parent] = 0;
    return 0;
}

/* leaf_fence turns a peer's /proc/<pid>/cgroup into the peer's fence.
 * The peer must sit in <grant_dir>/f-<epoch>-<seq>: one component under
 * the grant's directory, matched whole (so "/r/g1" never matches
 * "/r/g10/f-1-1"), with nothing after the sequence number, not
 * " (deleted)" and not a sub-cgroup. The fence is <grant>/<epoch>/<seq>
 * with grant the last component of grant_dir, which is how core.Fence
 * prints and so the fiber id fiberd uses in EVICT and DEVICE lines. 0,
 * or -1, also when the fence does not fit fn. */
static int leaf_fence(const char *buf, size_t n, const char *gdir, char *fence, size_t fn) {
    if (fn) fence[0] = 0;
    const char *p; size_t len;
    if (cgroup_unified(buf, n, &p, &len) < 0) return -1;
    size_t gl = strlen(gdir);
    if (gl == 0 || len < gl + 2 || memcmp(p, gdir, gl) != 0 || p[gl] != '/') return -1;
    const char *leaf = p + gl + 1;
    size_t ll = len - gl - 1;
    if (memchr(leaf, '/', ll)) return -1;
    unsigned long long epoch, seq;
    if (leaf_name(leaf, ll, &epoch, &seq) < 0) return -1;
    const char *g = strrchr(gdir, '/');
    g = g ? g + 1 : gdir;
    if (!*g) return -1;
    int m = snprintf(fence, fn, "%s/%llu/%llu", g, epoch, seq);
    if (m < 0 || (size_t)m >= fn) { if (fn) fence[0] = 0; return -1; }
    return 0;
}

/* read_small reads path whole into buf and returns its length, or -1
 * when it cannot be read or does not fit. A file that fills buf is
 * refused too, since its end was never seen. */
static ssize_t read_small(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    for (;;) {
        if (got == n) { close(fd); return -1; }
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    return (ssize_t)got;
}

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

/* peer_fence names the fence of the fiber on conn from that fiber's
 * cgroup. The pid comes from SO_PEERCRED and is pinned by a pidfd from
 * SO_PEERPIDFD (Linux 6.5), so a pid reused after the peer's exit
 * cannot pass. A kernel without it gets pidfd_open(pid), which is
 * narrower, since the pid may already be another process's by the time
 * it is opened. Without that too the pid alone has to do. A peer not
 * visible in our pid namespace shows as pid 0 and is refused. After the
 * read the pidfd is polled: POLLIN means the peer has exited, so the
 * file may have been another process's, and the peer is refused. The
 * poll needs no kill permission, unlike pidfd_send_signal. 0, or -1. */
static int peer_fence(int conn, char *fence, size_t fn) {
    if (fn) fence[0] = 0;
    struct ucred cr; socklen_t cl = sizeof cr;
    if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0 || cr.pid <= 0) return -1;
    int pidfd = -1; socklen_t pl = sizeof pidfd;
    if (getsockopt(conn, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pl) < 0) pidfd = (int)syscall(SYS_pidfd_open, cr.pid, 0);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cgroup", (int)cr.pid);
    char buf[4096];
    ssize_t n = read_small(path, buf, sizeof buf);
    int rc = n < 0 ? -1 : leaf_fence(buf, (size_t)n, grant_dir, fence, fn);
    if (pidfd >= 0) {
        struct pollfd pf = { .fd = pidfd, .events = POLLIN };
        if (poll(&pf, 1, 0) != 0) rc = -1;
        close(pidfd);
    }
    if (rc < 0 && fn) fence[0] = 0;
    return rc;
}

/* One request per connection, "reserve <fence> <bytes>", "release
 * <fence>" or "stat", and a one-line reply. The peer check runs first
 * for every line, and reserve and release must name the peer's own
 * fence. Anything else about the fence is "err fence". */
static void *engine_thread(void *arg) {
    (void)arg;
    int s = engine_fd;
    /* fiberd learns of the device once the channel is up. */
    for (;;) {
        char first[FZ_REPORT_MAX];
        snprintf(first, sizeof first, "DEVICE - %llu %llu", dev_used, dev_cap);
        if (fz_report_line(first) == 0) break;
        usleep(5000);
    }
    for (;;) {
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR) continue; break; }
        char line[256]; ssize_t n = read(c, line, sizeof line - 1);
        if (n <= 0) { close(c); continue; }
        line[n] = 0; line[strcspn(line, "\r\n")] = 0;
        char out[128]; char fence[128]; char peer[128]; unsigned long long bytes;
        int known = peer_fence(c, peer, sizeof peer) == 0;
        pthread_mutex_lock(&dev_mu);
        if (!known) snprintf(out, sizeof out, "err fence\n");
        else if (sscanf(line, "reserve %127s %llu", fence, &bytes) == 2) snprintf(out, sizeof out, "%s\n", strcmp(fence, peer) == 0 ? dev_set(fence, bytes) : "err fence");
        else if (sscanf(line, "release %127s", fence) == 1) snprintf(out, sizeof out, "%s\n", strcmp(fence, peer) == 0 ? dev_set(fence, 0) : "err fence");
        else if (strcmp(line, "stat") == 0) snprintf(out, sizeof out, "%llu %llu\n", dev_used, dev_cap);
        else snprintf(out, sizeof out, "err unknown\n");
        pthread_mutex_unlock(&dev_mu);
        (void)!write(c, out, strlen(out));
        close(c);
    }
    return NULL;
}

static void engine_start(size_t mb) {
    dev_cap = (unsigned long long)mb << 20;
    char cwd[192];
    if (!getcwd(cwd, sizeof cwd)) { perror("refzygote: getcwd"); exit(2); }
    snprintf(engine_path, sizeof engine_path, "%s/engine.sock", cwd);
    /* The grant's cgroup directory, read once. fiberd starts the zygote
     * in <grant_dir>/zygote (proc through a cgroup fd, runc through
     * cgroupsPath with no cgroup namespace, so both see the same paths).
     * Outside fiberd there is no grant, as in zygotectl's build and
     * smoke runs, where the zygote sits in whatever cgroup the shell
     * has. The engine then starts with no grant directory and refuses
     * every caller, since no fiber is ever forked there. */
    char cg[4096];
    ssize_t n = read_small("/proc/self/cgroup", cg, sizeof cg);
    if (n < 0 || grant_dir_of(cg, (size_t)n, grant_dir, sizeof grant_dir) < 0) {
        grant_dir[0] = 0;
        fprintf(stderr, "refzygote: engine: no grant cgroup above our own in /proc/self/cgroup, every device request will be refused\n");
    }
    /* Bound before fz_serve remounts the run directory. A bind racing
     * that remount lands where no fiber can reach it. */
    engine_fd = listen_endpoint(engine_path);
    if (engine_fd < 0) { fprintf(stderr, "refzygote: engine listen %s: %s\n", engine_path, strerror(errno)); exit(2); }
    fz_set_engine(engine_path);
    fz_set_control(on_control);
    pthread_t t;
    if (pthread_create(&t, NULL, engine_thread, NULL) != 0) { perror("refzygote: engine thread"); exit(2); }
    pthread_detach(t);
}

/* ---- the fiber's side of the device ----------------------------------- */

static const fz_incarnation_t *cur_fiber; /* this fiber's birth record, for session and payload */
/* The record's seed in hex, kept only under "keep_seed" for the tests,
 * since the library zeroes its copy at ready. */
static char kept_seed[2 * 32 + 1];
/* What this process serves as, from the birth record and then each
 * resume's. Copied, since a resume's record lives only until the next
 * wait. */
static char cur_fence[128];
static char cur_endpoint[1024];
static char cur_kind[16];
static unsigned cur_generation;

/* The fence the engine should file the slice under. */
static const char *current_fence(void) { return cur_fence[0] ? cur_fence : "?"; }

/* engine_send sends one line to the engine on a fresh connection and
 * returns the engine's one-line reply, in reply, or an "err ..." of its
 * own when the engine cannot be reached. */
static const char *engine_send(const char *req, char *reply, size_t n) {
    const char *eng = getenv("FIBERD_ENGINE");
    if (!eng) return "err no engine";
    if (strncmp(eng, "unix://", 7) == 0) eng += 7;
    char buf[256];
    int m = snprintf(buf, sizeof buf, "%s\n", req);
    if (m < 0 || (size_t)m >= sizeof buf) return "err line too long";
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return "err socket";
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", eng);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return "err engine unreachable"; }
    (void)!write(s, buf, (size_t)m);
    ssize_t r = read(s, reply, n - 1);
    close(s);
    if (r <= 0) return "err no reply";
    reply[r] = 0; reply[strcspn(reply, "\r\n")] = 0;
    return reply;
}

/* device_reserve asks the engine for a slice (0 releases it) under this
 * fiber's own fence and returns the engine's reply. */
static const char *device_reserve(unsigned long long bytes, char *reply, size_t n) {
    const char *fence = current_fence();
    char req[256];
    if (bytes) snprintf(req, sizeof req, "reserve %s %llu", fence, bytes);
    else snprintf(req, sizeof req, "release %s", fence);
    return engine_send(req, reply, n);
}

/* first_line writes path's first line (or "-") and a newline to out. */
static void first_line(const char *path, char *out, size_t n) {
    char buf[200] = "-";
    FILE *f = fopen(path, "r");
    if (f) {
        if (!fgets(buf, sizeof buf, f)) snprintf(buf, sizeof buf, "-");
        fclose(f);
    }
    buf[strcspn(buf, "\r\n")] = 0;
    snprintf(out, n, "%s\n", buf);
}

/* errname writes an errno's name (the ones the probes below tell apart)
 * or "errno N", and a newline. */
static void errname(int e, char *out, size_t n) {
    switch (e) {
    case EROFS: snprintf(out, n, "EROFS\n"); break;
    case EACCES: snprintf(out, n, "EACCES\n"); break;
    case EPERM: snprintf(out, n, "EPERM\n"); break;
    case ENOENT: snprintf(out, n, "ENOENT\n"); break;
    case ENOSPC: snprintf(out, n, "ENOSPC\n"); break;
    case ECONNREFUSED: snprintf(out, n, "ECONNREFUSED\n"); break;
    case ENETUNREACH: snprintf(out, n, "ENETUNREACH\n"); break;
    case EHOSTUNREACH: snprintf(out, n, "EHOSTUNREACH\n"); break;
    case ETIMEDOUT: snprintf(out, n, "ETIMEDOUT\n"); break;
    case EINVAL: snprintf(out, n, "EINVAL\n"); break;
    case ESRCH: snprintf(out, n, "ESRCH\n"); break;
    case EBADF: snprintf(out, n, "EBADF\n"); break;
    case EFAULT: snprintf(out, n, "EFAULT\n"); break;
    case ENOSYS: snprintf(out, n, "ENOSYS\n"); break;
    case EAFNOSUPPORT: snprintf(out, n, "EAFNOSUPPORT\n"); break;
    case EPROTONOSUPPORT: snprintf(out, n, "EPROTONOSUPPORT\n"); break;
    default: snprintf(out, n, "errno %d\n", e); break;
    }
}

/* wopen_errno writes "ok" when open(path, O_WRONLY) succeeds, else the
 * errno's name. It never writes a byte, so it is safe to point at a
 * sysctl or a cgroup control. */
static void wopen_errno(const char *path, char *out, size_t n) {
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (fd >= 0) { close(fd); snprintf(out, n, "ok\n"); return; }
    errname(errno, out, n);
}

/* connect_errno writes "ok" when a TCP connect to "a.b.c.d:port"
 * succeeds within two seconds, else the errno's name. It shows whether a
 * host listener is reachable from the fiber's network namespace. */
static void connect_errno(const char *addr, char *out, size_t n) {
    char host[64]; unsigned port;
    if (sscanf(addr, "%63[^:]:%u", host, &port) != 2) { errname(EINVAL, out, n); return; }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { errname(EINVAL, out, n); return; }
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0) { errname(errno, out, n); return; }
    int rc = connect(s, (struct sockaddr *)&sa, sizeof sa);
    if (rc < 0 && errno == EINPROGRESS) {
        struct pollfd p = { .fd = s, .events = POLLOUT };
        if (poll(&p, 1, 2000) <= 0) { close(s); errname(ETIMEDOUT, out, n); return; }
        int err = 0; socklen_t el = sizeof err;
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el);
        rc = err ? -1 : 0;
        errno = err;
    }
    int saved = errno;
    close(s);
    if (rc == 0) snprintf(out, n, "ok\n"); else errname(saved, out, n);
}

/* unshare_errno tries unshare(CLONE_NEWUSER) in a child, so this
 * fiber's own namespaces stay as they are. */
static void unshare_errno(char *out, size_t n) {
    pid_t pid = fork();
    if (pid < 0) { errname(errno, out, n); return; }
    if (pid == 0) _exit(unshare(CLONE_NEWUSER) == 0 ? 0 : (errno & 0xff));
    int st = 0;
    if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st)) { errname(EIO, out, n); return; }
    if (WEXITSTATUS(st) == 0) snprintf(out, n, "ok\n"); else errname(WEXITSTATUS(st), out, n);
}

/* getrandom_fork draws once, forks, and writes what this process and the
 * child then each draw, "<parent> <child>". A restored copy whose
 * getrandom state page lost its wipe on fork answers the same twice. */
static void getrandom_fork(char *out, size_t n) {
    unsigned char p[8], c[8];
    int fds[2];
    if (getrandom(p, sizeof p, 0) != (ssize_t)sizeof p || pipe(fds) < 0) { errname(errno, out, n); return; }
    pid_t pid = fork();
    if (pid < 0) { errname(errno, out, n); close(fds[0]); close(fds[1]); return; }
    if (pid == 0) _exit(getrandom(c, sizeof c, 0) == (ssize_t)sizeof c && write(fds[1], c, sizeof c) == (ssize_t)sizeof c ? 0 : 1);
    close(fds[1]);
    ssize_t got = read(fds[0], c, sizeof c);
    close(fds[0]);
    int st = 0;
    if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0 || got != (ssize_t)sizeof c) { errname(EIO, out, n); return; }
    if (getrandom(p, sizeof p, 0) != (ssize_t)sizeof p) { errname(errno, out, n); return; }
    snprintf(out, n, "%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x\n",
             p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
}

/* mount_errno tries a fresh fstype mount on a scratch directory under
 * /tmp, undone at once, for a filesystem a fiber must not mount. */
static void mount_errno(const char *fstype, char *out, size_t n) {
    char dir[] = "/tmp/.probe-XXXXXX";
    if (!mkdtemp(dir)) { errname(errno, out, n); return; }
    int rc = mount(fstype, dir, fstype, 0, NULL);
    int saved = errno;
    if (rc == 0) umount2(dir, MNT_DETACH);
    rmdir(dir);
    if (rc == 0) snprintf(out, n, "ok\n"); else errname(saved, out, n);
}

/* remount_errno tries a read-write bind remount of path. One that
 * succeeds is put back read-only at once. */
static void remount_errno(const char *path, char *out, size_t n) {
    if (mount(NULL, path, NULL, MS_REMOUNT | MS_BIND, NULL) == 0) {
        mount(NULL, path, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL);
        snprintf(out, n, "ok\n");
        return;
    }
    errname(errno, out, n);
}

/* rdonly_errno writes "ro" or "rw" for the mount holding path. */
static void rdonly_errno(const char *path, char *out, size_t n) {
    struct statvfs sv;
    if (statvfs(path, &sv) < 0) { errname(errno, out, n); return; }
    snprintf(out, n, "%s\n", (sv.f_flag & ST_RDONLY) ? "ro" : "rw");
}

/* mkdir_errno tries mkdir(path) and removes what it made. */
static void mkdir_errno(const char *path, char *out, size_t n) {
    if (mkdir(path, 0755) == 0) { rmdir(path); snprintf(out, n, "ok\n"); return; }
    errname(errno, out, n);
}

/* stat_kind writes stat(path)'s file type, or the errno's name. */
static void stat_kind(const char *path, char *out, size_t n) {
    struct stat st;
    if (stat(path, &st) == 0) {
        const char *kind = S_ISDIR(st.st_mode) ? "dir" : S_ISREG(st.st_mode) ? "file" : S_ISSOCK(st.st_mode) ? "sock" : "other";
        snprintf(out, n, "%s\n", kind);
        return;
    }
    switch (errno) {
    case ENOENT: snprintf(out, n, "ENOENT\n"); break;
    case EACCES: snprintf(out, n, "EACCES\n"); break;
    default: snprintf(out, n, "errno %d\n", errno); break;
    }
}

/* status_field writes the value of key in /proc/self/status (or "-"). */
static void status_field(const char *key, char *out, size_t n) {
    snprintf(out, n, "-\n");
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    size_t kl = strlen(key);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, kl) != 0 || line[kl] != ':') continue;
        const char *v = line + kl + 1;
        while (*v == ' ' || *v == '\t') v++;
        snprintf(out, n, "%s", v);
        break;
    }
    fclose(f);
}

/* ---- one client connection, plaintext or TLS ------------------------- */

typedef struct {
    int fd;
#ifdef FZ_TLS
    SSL *ssl;
#endif
    char buf[512];
    size_t off, have;
} conn_t;

static ssize_t conn_read(conn_t *c, void *p, size_t n) {
#ifdef FZ_TLS
    if (c->ssl) {
        if (SSL_pending(c->ssl) <= 0 && wait_readable(c->fd) < 0) return -1;
        int r = SSL_read(c->ssl, p, n > 65536 ? 65536 : (int)n);
        return r > 0 ? r : 0;
    }
#endif
    if (wait_readable(c->fd) < 0) return -1;
    return read(c->fd, p, n);
}

static int conn_write(conn_t *c, const void *p, size_t n) {
#ifdef FZ_TLS
    if (c->ssl) return n == 0 || SSL_write(c->ssl, p, (int)n) > 0 ? 0 : -1;
#endif
    return write(c->fd, p, n) == (ssize_t)n ? 0 : -1;
}

/* conn_line reads one line without its newline and returns 0 at end of
 * stream. A line longer than n is cut to n-1 bytes. */
static int conn_line(conn_t *c, char *line, size_t n) {
    size_t m = 0;
    for (;;) {
        if (c->off == c->have) {
            ssize_t r = conn_read(c, c->buf, sizeof c->buf);
            if (r <= 0) { line[m] = 0; return m > 0; }
            c->off = 0; c->have = (size_t)r;
        }
        char ch = c->buf[c->off++];
        if (ch == '\n') break;
        if (m < n - 1) line[m++] = ch;
    }
    line[m] = 0;
    return 1;
}

static void conn_close(conn_t *c) {
#ifdef FZ_TLS
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
#endif
    close(c->fd);
}

#ifdef FZ_TLS
/* The handoff fiber's TLS server, loaded after the fork from the record,
 * so the key is never in the zygote's memory or in a file. */
static SSL_CTX *tls_ctx;
static const char *tls_caller;

/* tls_is_caller reports whether x is the grant's caller (RFC 8705
 * x5t#S256, the base64url SHA-256 of its DER). */
static int tls_is_caller(X509 *x) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdn = 0;
    if (X509_digest(x, EVP_sha256(), md, &mdn) != 1) return 0;
    char b64[4 * ((EVP_MAX_MD_SIZE + 2) / 3) + 1];
    int n = EVP_EncodeBlock((unsigned char *)b64, md, (int)mdn);
    while (n > 0 && b64[n - 1] == '=') n--;
    b64[n] = 0;
    for (int i = 0; i < n; i++) { if (b64[i] == '+') b64[i] = '-'; else if (b64[i] == '/') b64[i] = '_'; }
    return strcmp(b64, tls_caller) == 0;
}

/* The fiber has no CA store, so the pin is the trust. The callback
 * checks the leaf against it inside the handshake, so any other client
 * gets an alert before it is served. A chain above the leaf is ignored. */
static int tls_verify_leaf(int ok, X509_STORE_CTX *x) {
    (void)ok;
    if (X509_STORE_CTX_get_error_depth(x) != 0) return 1;
    X509 *leaf = X509_STORE_CTX_get0_cert(x);
    if (leaf && tls_is_caller(leaf)) return 1;
    X509_STORE_CTX_set_error(x, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

/* pem_cert and pem_key parse one PEM block from memory. */
static X509 *pem_cert(const char *pem) {
    BIO *b = BIO_new_mem_buf(pem, -1);
    if (!b) return NULL;
    X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    BIO_free(b);
    return x;
}

static EVP_PKEY *pem_key(const char *pem) {
    BIO *b = BIO_new_mem_buf(pem, -1);
    if (!b) return NULL;
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    return k;
}

static const char *tls_load(const fz_identity_t *id) {
    if (!id) return "no handoff identity";
    if (!id->caller[0]) return "identity names no caller";
    tls_caller = id->caller;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return "SSL_CTX_new failed";
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_leaf);
    /* No resumption, so every connection presents the caller's certificate. */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(ctx, 0);
    X509 *cert = pem_cert(id->cert_pem);
    EVP_PKEY *key = pem_key(id->key_pem);
    int ok = cert && key &&
             SSL_CTX_use_certificate(ctx, cert) == 1 &&
             SSL_CTX_use_PrivateKey(ctx, key) == 1 &&
             SSL_CTX_check_private_key(ctx) == 1;
    if (cert) X509_free(cert);
    if (key) EVP_PKEY_free(key);
    if (!ok) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return "cannot load the grant's certificate and key";
    }
    tls_ctx = ctx;
    return NULL;
}

/* tls_caller_ok looks again, after the handshake, at the certificate
 * tls_verify_leaf pinned. */
static int tls_caller_ok(SSL *s) {
    X509 *peer = SSL_get1_peer_certificate(s);
    if (!peer) return 0;
    int ok = tls_is_caller(peer);
    X509_free(peer);
    return ok;
}

/* tls_reseed mixes kernel entropy, and the host's seed if any, into
 * both OpenSSL DRBGs. Copies share DRBG state, and a CRIU resume keeps
 * the pid, so OpenSSL's own fork check never notices a copy. */
static int tls_reseed(const unsigned char *host, size_t hn) {
    unsigned char seed[64];
    if (hn > 32) hn = 32;
    if (getrandom(seed, 32, 0) != 32) return -1;
    if (hn) memcpy(seed + 32, host, hn);
    EVP_RAND_CTX *drbg[2] = { RAND_get0_public(NULL), RAND_get0_private(NULL) };
    for (int i = 0; i < 2; i++)
        if (!drbg[i] || EVP_RAND_reseed(drbg[i], 0, NULL, 0, seed, 32 + hn) != 1) return -1;
    return 0;
}

/* tls_start reseeds, runs the handshake and checks the caller. A caller
 * that stalls the handshake is dropped after 5 s. */
static int tls_start(conn_t *c) {
    if (tls_reseed(NULL, 0) < 0) return -1;
    struct timeval tv = { .tv_sec = 5 }, none = { 0 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    SSL *s = SSL_new(tls_ctx);
    if (!s) return -1;
    if (SSL_set_fd(s, c->fd) != 1 || SSL_accept(s) != 1 || !tls_caller_ok(s)) { SSL_free(s); return -1; }
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none);
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &none, sizeof none);
    c->ssl = s;
    return 0;
}
#endif

/* reseed_rngs_from reseeds every generator this template owns from the
 * kernel mixed with the host's seed. It runs once per incarnation, at
 * the fork, after a gVisor restore and after a resume. Both libc
 * generators are seeded, since rand() keeps its own state on some libcs.
 * OpenSSL's DRBGs exist only in a handoff fiber, and tls_start reseeds
 * them per handshake too. */
static void reseed_rngs_from(const unsigned char *host, size_t hn) {
    unsigned seed[2] = { 0, 0 };
    if (getrandom(seed, sizeof seed, 0) == (ssize_t)sizeof seed) {
        for (size_t i = 0; i < hn; i++) seed[i % 2] = seed[i % 2] * 31u + host[i];
        srandom(seed[0]); srand(seed[1]);
    }
#ifdef FZ_TLS
    if (tls_ctx) (void)tls_reseed(host, hn);
#else
    (void)host; (void)hn;
#endif
}

/* set_incarnation records what this process serves as, and keeps the
 * seed under "keep_seed". */
static void set_incarnation(const fz_incarnation_t *inc) {
    snprintf(cur_fence, sizeof cur_fence, "%s", inc->fence);
    snprintf(cur_endpoint, sizeof cur_endpoint, "%s", inc->endpoint);
    snprintf(cur_kind, sizeof cur_kind, "%s", inc->kind);
    cur_generation = inc->generation;
    if (cur_fiber && payload_num(cur_fiber->payload, cur_fiber->payload_len, "\"keep_seed\"") && inc->seed_len == 32)
        for (size_t i = 0; i < inc->seed_len; i++) snprintf(kept_seed + 2 * i, 3, "%02x", inc->seed[i]);
}

/* borrow_errno tries pidfd_open plus pidfd_getfd of fd in pid, to show
 * whether a fiber can reach another's channel the way fiberd does.
 * SYS_pidfd_open is defined with the engine's peer check above. */
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
static void borrow_errno(const char *arg, char *out, size_t n) {
    int pid, fd;
    if (sscanf(arg, "%d %d", &pid, &fd) != 2) { errname(EINVAL, out, n); return; }
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0) { errname(errno, out, n); return; }
    int got = (int)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
    int e = errno;
    close(pidfd);
    if (got < 0) { errname(e, out, n); return; }
    close(got);
    snprintf(out, n, "ok\n");
}

/* The probes behind "probe <name>". Each makes one call the fiber filter
 * refuses, or an allowed neighbour of one, and returns 0 or -1 with
 * errno. The arguments are harmless when the call goes through, and
 * each runs in a child, so nothing it changes reaches the fiber. */
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_memfd_secret
#define SYS_memfd_secret 447
#endif
#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif
/* The quota-escape routes the fiber filter refuses. The ioctl command
 * numbers are the asm-generic _IOW encodings, the same on x86_64 and
 * aarch64. file_setattr is FS_IOC_FSSETXATTR's syscall twin. */
#ifndef FS_IOC_FSSETXATTR
#define FS_IOC_FSSETXATTR 0x401c5820
#endif
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS 0x40086602
#endif
#ifndef SYS_file_setattr
#define SYS_file_setattr 469
#endif

static int probe_sock(int family, int type, int proto) {
    int s = socket(family, type | SOCK_CLOEXEC, proto);
    if (s < 0) return -1;
    close(s);
    return 0;
}

/* A raw clone with flags, as the filter sees one. Its child ends at once. */
static int clone_with(unsigned long flags) {
    long pid = syscall(SYS_clone, flags | SIGCHLD, 0, 0, 0, 0);
    if (pid == 0) _exit(0);
    if (pid < 0) return -1;
    waitpid((pid_t)pid, NULL, 0);
    return 0;
}

static int p_unshare_user(void) { return unshare(CLONE_NEWUSER); }
static int p_unshare_net(void) { return unshare(CLONE_NEWNET); }
static int p_unshare_fs(void) { return unshare(CLONE_FS); }
static int p_clone_newuser(void) { return clone_with(CLONE_NEWUSER); }
static int p_clone3(void) { return (int)syscall(SYS_clone3, NULL, 0); }
static int p_setns(void) { return setns(-1, 0); }
static int p_af_alg(void) { return probe_sock(AF_ALG, SOCK_SEQPACKET, 0); }
static int p_af_packet(void) { return probe_sock(AF_PACKET, SOCK_RAW, 0); }
static int p_af_vsock(void) { return probe_sock(AF_VSOCK, SOCK_STREAM, 0); }
static int p_af_unix(void) { return probe_sock(AF_UNIX, SOCK_STREAM, 0); }
static int p_af_inet(void) { return probe_sock(AF_INET, SOCK_STREAM, 0); }
static int p_af_inet6(void) { return probe_sock(AF_INET6, SOCK_STREAM, 0); }
static int p_nl_route(void) { return probe_sock(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); }
static int p_nl_generic(void) { return probe_sock(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC); }
static int p_nl_sock_diag(void) { return probe_sock(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG); }
static int p_nl_audit(void) { return probe_sock(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT); }
static int p_per_query(void) { return personality(0xffffffff) == -1 ? -1 : 0; }
static int p_per_uname26(void) { return personality(PER_LINUX | UNAME26) == -1 ? -1 : 0; }
static int p_io_uring(void) { return (int)syscall(SYS_io_uring_setup, 1, NULL); }
static int p_userfaultfd(void) { return (int)syscall(SYS_userfaultfd, O_CLOEXEC) < 0 ? -1 : 0; }
static int p_bpf(void) { return (int)syscall(SYS_bpf, 5 /* BPF_PROG_LOAD */, NULL, 0); }
static int p_perf(void) { return (int)syscall(SYS_perf_event_open, NULL, 0, -1, -1, 0); }
static int p_keyctl(void) { return (int)syscall(SYS_keyctl, 0 /* GET_KEYRING_ID */, -3 /* session */, 0) < 0 ? -1 : 0; }
static int p_memfd_secret(void) { return (int)syscall(SYS_memfd_secret, 0) < 0 ? -1 : 0; }
static int p_ptrace(void) { return (int)ptrace(PTRACE_TRACEME, 0, NULL, NULL); }
static int p_vm_readv(void) {
    char a = 1, b = 0;
    struct iovec l = { &b, 1 }, r = { &a, 1 };
    return process_vm_readv(getpid(), &l, 1, &r, 1, 0) < 0 ? -1 : 0;
}
static int p_kcmp(void) { return (int)syscall(SYS_kcmp, getpid(), getpid(), 1 /* KCMP_VM */, 0, 0) < 0 ? -1 : 0; }
static int p_pidfd_getfd(void) {
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0) return -1;
    return (int)syscall(SYS_pidfd_getfd, pidfd, 0, 0) < 0 ? -1 : 0;
}
static int p_syslog(void) { return klogctl(10 /* SIZE_BUFFER */, NULL, 0) < 0 ? -1 : 0; }
/* The hostname it already has, so a call that goes through changes nothing. */
static int p_sethostname(void) {
    char h[65] = {0};
    if (gethostname(h, sizeof h - 1) < 0) return -1;
    return sethostname(h, strlen(h));
}
/* A temporary file under /tmp an ioctl probe can target. The filter
 * refuses the command before the kernel reads the descriptor, so the
 * file's own filesystem does not matter. */
static int ioctl_on_tmp(unsigned long cmd, void *arg) {
    char path[] = "/tmp/.ftq-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    int rc = ioctl(fd, cmd, arg);
    int e = errno;
    close(fd);
    unlink(path);
    errno = e;
    return rc;
}
/* Change a file's project id, the proc fiber's route out of its disk
 * quota. */
static int p_fssetxattr(void) {
    unsigned char fsx[28] = {0}; /* struct fsxattr */
    return ioctl_on_tmp(FS_IOC_FSSETXATTR, fsx);
}
/* Clear the inode flags, which would drop FS_PROJINHERIT_FL. */
static int p_setflags(void) {
    long flags = 0;
    return ioctl_on_tmp(FS_IOC_SETFLAGS, &flags);
}
/* The syscall twin of FS_IOC_FSSETXATTR, added in Linux 6.13. */
static int p_file_setattr(void) {
    return (int)syscall(SYS_file_setattr, 0, (void *)0, 0, 0, 0);
}
static void *probe_idle(void *a) { return a; }
static int p_thread(void) {
    pthread_t t;
    int e = pthread_create(&t, NULL, probe_idle, NULL);
    if (e) { errno = e; return -1; }
    return pthread_join(t, NULL);
}
/* A fresh tmpfs on a scratch directory, undone at once. */
static int p_mount(void) {
    char dir[] = "/tmp/.probe-XXXXXX";
    if (!mkdtemp(dir)) return -1;
    int rc = mount("tmpfs", dir, "tmpfs", 0, NULL);
    int e = errno;
    if (rc == 0) umount2(dir, MNT_DETACH);
    rmdir(dir);
    errno = e;
    return rc;
}
/* A missing new root, so a pivot_root that passes the capability check
 * answers ENOENT and moves nothing. */
static int p_pivot_root(void) { return (int)syscall(SYS_pivot_root, "/.probe-none", "/.probe-none"); }
static int p_chroot(void) { return chroot("/"); }
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
/* Take the workspace off /workspace. The kernel lets a runc fiber do it,
 * since it holds CAP_SYS_ADMIN over its own mount namespace, so EPERM is
 * the filter's. Where /workspace is no mount the kernel would say
 * EINVAL. A pass costs the fiber its workspace, which the test reports. */
static int p_umount_workspace(void) { return umount2("/workspace", MNT_DETACH); }
/* Move the workspace onto a scratch directory under /tmp, which the
 * kernel would allow for the same reason. A move that goes through is
 * put back. */
static int p_move_mount_workspace(void) {
    char dir[] = "/tmp/.probe-XXXXXX";
    if (!mkdtemp(dir)) return -1;
    int rc = (int)syscall(SYS_move_mount, AT_FDCWD, "/workspace", AT_FDCWD, dir, 0);
    int e = errno;
    if (rc == 0) syscall(SYS_move_mount, AT_FDCWD, dir, AT_FDCWD, "/workspace", 0);
    rmdir(dir);
    errno = e;
    return rc;
}
/* getpid through the x32 table, which a fiber has no use for. */
static int p_x32(void) {
#if defined(__x86_64__)
    return (int)syscall(0x40000000 | SYS_getpid) < 0 ? -1 : 0;
#else
    errno = ENOSYS;
    return -1;
#endif
}

static const struct { const char *name; int (*fn)(void); } probes[] = {
    { "unshare-user", p_unshare_user }, { "unshare-net", p_unshare_net }, { "unshare-fs", p_unshare_fs },
    { "clone-newuser", p_clone_newuser }, { "clone3", p_clone3 }, { "setns", p_setns },
    { "af-alg", p_af_alg }, { "af-packet", p_af_packet }, { "af-vsock", p_af_vsock },
    { "af-unix", p_af_unix }, { "af-inet", p_af_inet }, { "af-inet6", p_af_inet6 },
    { "netlink-route", p_nl_route }, { "netlink-generic", p_nl_generic },
    { "netlink-sock-diag", p_nl_sock_diag }, { "netlink-audit", p_nl_audit },
    { "personality-query", p_per_query }, { "personality-uname26", p_per_uname26 },
    { "io-uring", p_io_uring }, { "userfaultfd", p_userfaultfd }, { "bpf", p_bpf }, { "perf", p_perf },
    { "keyctl", p_keyctl }, { "memfd-secret", p_memfd_secret },
    { "ptrace", p_ptrace }, { "process-vm-readv", p_vm_readv }, { "kcmp", p_kcmp }, { "pidfd-getfd", p_pidfd_getfd },
    { "syslog", p_syslog }, { "sethostname", p_sethostname },
    { "thread", p_thread }, { "x32", p_x32 },
    { "mount", p_mount }, { "pivot-root", p_pivot_root }, { "chroot", p_chroot },
    { "umount-workspace", p_umount_workspace }, { "move-mount-workspace", p_move_mount_workspace },
    { "fssetxattr", p_fssetxattr }, { "setflags", p_setflags }, { "file-setattr", p_file_setattr },
};

/* probe runs the named probe in a child and writes its answer. */
static void probe(const char *name, char *out, size_t n) {
    int (*fn)(void) = NULL;
    for (size_t i = 0; i < sizeof probes / sizeof probes[0]; i++)
        if (strcmp(name, probes[i].name) == 0) fn = probes[i].fn;
    if (!fn) { snprintf(out, n, "err unknown probe\n"); return; }
    pid_t pid = fork();
    if (pid < 0) { errname(errno, out, n); return; }
    if (pid == 0) _exit(fn() == 0 ? 0 : (errno & 0xff));
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) { errname(errno, out, n); return; }
    if (WIFSIGNALED(st)) {
        if (WTERMSIG(st) == SIGSYS) snprintf(out, n, "SIGSYS\n");
        else snprintf(out, n, "signal %d\n", WTERMSIG(st));
        return;
    }
    if (WEXITSTATUS(st) == 0) snprintf(out, n, "ok\n"); else errname(WEXITSTATUS(st), out, n);
}

static unsigned long long reply_delay;

/* ---- the workspace, for the file-transfer tests ----------------------- */

/* write_line writes text and a newline to path, made or truncated. */
static void write_line(const char *args, char *out, size_t n) {
    char path[256];
    const char *sp = strchr(args, ' ');
    if (!sp || (size_t)(sp - args) >= sizeof path) { snprintf(out, n, "err want <path> <text>\n"); return; }
    memcpy(path, args, (size_t)(sp - args)); path[sp - args] = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) { errname(errno, out, n); return; }
    size_t len = strlen(sp + 1);
    int ok = write(fd, sp + 1, len) == (ssize_t)len && write(fd, "\n", 1) == 1;
    int saved = errno;
    close(fd);
    if (ok) snprintf(out, n, "ok\n"); else errname(saved, out, n);
}

/* held_fd is a file the fiber keeps open across a park, so a resume
 * must find it where the dump saw it. */
static int held_fd = -1;

static void hold_open(const char *path, char *out, size_t n) {
    if (held_fd >= 0) close(held_fd);
    held_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (held_fd < 0) errname(errno, out, n); else snprintf(out, n, "ok\n");
}

/* held_write appends text and a newline at the held file's offset. */
static void held_write(const char *text, char *out, size_t n) {
    if (held_fd < 0) { snprintf(out, n, "err nothing held\n"); return; }
    size_t len = strlen(text);
    if (write(held_fd, text, len) != (ssize_t)len || write(held_fd, "\n", 1) != 1) errname(errno, out, n);
    else snprintf(out, n, "ok\n");
}

/* held_read writes the held file's first line from its start. */
static void held_read(char *out, size_t n) {
    if (held_fd < 0) { snprintf(out, n, "err nothing held\n"); return; }
    char buf[200];
    ssize_t got = pread(held_fd, buf, sizeof buf - 1, 0);
    if (got < 0) { errname(errno, out, n); return; }
    buf[got] = 0;
    buf[strcspn(buf, "\n")] = 0;
    snprintf(out, n, "%s\n", got == 0 ? "-" : buf);
}

/* scribble appends one numbered line after another to a file from a
 * thread of its own, so a park races a write in flight. scribbled is
 * how many lines went in, which the file must hold exactly after a
 * resume: a capture that ran with the fiber running would hold more. */
static pthread_t scribbler;
static int scribbling;
static volatile unsigned long scribbled;
static int scribble_fd = -1;

static void *scribble_thread(void *arg) {
    (void)arg;
    while (__atomic_load_n(&scribbling, __ATOMIC_ACQUIRE)) {
        char line[32];
        int len = snprintf(line, sizeof line, "%lu\n", scribbled + 1);
        if (write(scribble_fd, line, (size_t)len) != len) break;
        scribbled++;
        usleep(200);
    }
    return NULL;
}

static void scribble(const char *path, char *out, size_t n) {
    if (strcmp(path, "stop") == 0) {
        if (!scribbling) { snprintf(out, n, "ok %lu\n", scribbled); return; }
        __atomic_store_n(&scribbling, 0, __ATOMIC_RELEASE);
        pthread_join(scribbler, NULL);
        close(scribble_fd);
        scribble_fd = -1;
        snprintf(out, n, "ok %lu\n", scribbled);
        return;
    }
    if (scribbling) { snprintf(out, n, "err already scribbling\n"); return; }
    scribble_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (scribble_fd < 0) { errname(errno, out, n); return; }
    scribbled = 0;
    __atomic_store_n(&scribbling, 1, __ATOMIC_RELEASE);
    if (pthread_create(&scribbler, NULL, scribble_thread, NULL) != 0) {
        scribbling = 0;
        close(scribble_fd);
        scribble_fd = -1;
        errname(errno, out, n);
        return;
    }
    snprintf(out, n, "ok\n");
}

/* second_arg splits "<first> <rest>" into first, of size n, and returns
 * rest, or NULL when there is no space or first does not fit. */
static const char *second_arg(const char *args, char *first, size_t n) {
    const char *sp = strchr(args, ' ');
    if (!sp || (size_t)(sp - args) >= n) return NULL;
    memcpy(first, args, (size_t)(sp - args)); first[sp - args] = 0;
    return sp + 1;
}

/* rename_path and symlink_path let a fiber swap the workspace mount
 * point of its grant's root filesystem for a link, as a sibling may. */
static void rename_path(const char *args, char *out, size_t n) {
    char from[256];
    const char *to = second_arg(args, from, sizeof from);
    if (!to) { snprintf(out, n, "err want <from> <to>\n"); return; }
    if (rename(from, to) == 0) snprintf(out, n, "ok\n"); else errname(errno, out, n);
}

static void symlink_path(const char *args, char *out, size_t n) {
    char target[256];
    const char *at = second_arg(args, target, sizeof target);
    if (!at) { snprintf(out, n, "err want <target> <link>\n"); return; }
    if (symlink(target, at) == 0) snprintf(out, n, "ok\n"); else errname(errno, out, n);
}

static int serve_client(conn_t *c, const char *fence, unsigned long *counter) {
    char line[256];
    while (conn_line(c, line, sizeof line)) {
        line[strcspn(line, "\r")] = 0;
        char out[256];
        if (strcmp(line, "ping") == 0) snprintf(out, sizeof out, "pong\n");
        else if (strncmp(line, "dirty ", 6) == 0) { size_t n = dirty((size_t)strtoull(line + 6, NULL, 10)); snprintf(out, sizeof out, "ok %zu\n", n); }
        else if (strcmp(line, "incr") == 0) snprintf(out, sizeof out, "%lu\n", ++*counter);
        else if (strcmp(line, "get") == 0) snprintf(out, sizeof out, "%lu\n", *counter);
        else if (strcmp(line, "fence") == 0) snprintf(out, sizeof out, "%s\n", cur_fence[0] ? cur_fence : fence);
        else if (strcmp(line, "pid") == 0) snprintf(out, sizeof out, "%d\n", (int)getpid());
        else if (strcmp(line, "random") == 0) snprintf(out, sizeof out, "%ld\n", random());
        else if (strcmp(line, "seed") == 0) snprintf(out, sizeof out, "%s\n", kept_seed[0] ? kept_seed : "-");
        else if (strcmp(line, "getrandom") == 0) {
            unsigned char b[8];
            if (getrandom(b, sizeof b, 0) != (ssize_t)sizeof b) errname(errno, out, sizeof out);
            else snprintf(out, sizeof out, "%02x%02x%02x%02x%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        }
        else if (strcmp(line, "getrandom fork") == 0) getrandom_fork(out, sizeof out);
        else if (strcmp(line, "rss") == 0) {
            /* resident bytes as this process's kernel sees them */
            long size = 0, pages = 0; FILE *sm = fopen("/proc/self/statm", "r");
            if (sm) { if (fscanf(sm, "%ld %ld", &size, &pages) != 2) pages = 0; fclose(sm); }
            snprintf(out, sizeof out, "%ld\n", pages * 4096L);
        }
        else if (strncmp(line, "getenv ", 7) == 0) { const char *v = getenv(line + 7); snprintf(out, sizeof out, "%s\n", v ? v : "-"); }
        else if (strcmp(line, "session") == 0) snprintf(out, sizeof out, "%s\n", cur_fiber && cur_fiber->session[0] ? cur_fiber->session : "-");
        else if (strcmp(line, "generation") == 0) snprintf(out, sizeof out, "%u\n", cur_generation);
        else if (strcmp(line, "kind") == 0) snprintf(out, sizeof out, "%s\n", cur_kind[0] ? cur_kind : "-");
        else if (strncmp(line, "borrow ", 7) == 0) borrow_errno(line + 7, out, sizeof out);
        else if (strcmp(line, "payload") == 0) {
            size_t n = cur_fiber ? cur_fiber->payload_len : 0;
            if (n == 0 || 2 * n + 2 > sizeof out) snprintf(out, sizeof out, "-\n");
            else { for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", cur_fiber->payload[i]); memcpy(out + 2 * n, "\n", 2); }
        }
        else if (strncmp(line, "status ", 7) == 0) status_field(line + 7, out, sizeof out);
        else if (strncmp(line, "read ", 5) == 0) first_line(line + 5, out, sizeof out);
        else if (strncmp(line, "write ", 6) == 0) write_line(line + 6, out, sizeof out);
        else if (strncmp(line, "hold ", 5) == 0) hold_open(line + 5, out, sizeof out);
        else if (strncmp(line, "held write ", 11) == 0) held_write(line + 11, out, sizeof out);
        else if (strcmp(line, "held read") == 0) held_read(out, sizeof out);
        else if (strncmp(line, "scribble ", 9) == 0) scribble(line + 9, out, sizeof out);
        else if (strcmp(line, "scribbled") == 0) snprintf(out, sizeof out, "%lu\n", scribbled);
        else if (strncmp(line, "rename ", 7) == 0) rename_path(line + 7, out, sizeof out);
        else if (strncmp(line, "symlink ", 8) == 0) symlink_path(line + 8, out, sizeof out);
        else if (strncmp(line, "wopen ", 6) == 0) wopen_errno(line + 6, out, sizeof out);
        else if (strncmp(line, "stat ", 5) == 0) stat_kind(line + 5, out, sizeof out);
        else if (strncmp(line, "connect ", 8) == 0) connect_errno(line + 8, out, sizeof out);
        else if (strcmp(line, "unshare user") == 0) unshare_errno(out, sizeof out);
        else if (strncmp(line, "mount ", 6) == 0) mount_errno(line + 6, out, sizeof out);
        else if (strncmp(line, "mkdir ", 6) == 0) mkdir_errno(line + 6, out, sizeof out);
        else if (strncmp(line, "remount ", 8) == 0) remount_errno(line + 8, out, sizeof out);
        else if (strncmp(line, "rdonly ", 7) == 0) rdonly_errno(line + 7, out, sizeof out);
        else if (strncmp(line, "probe ", 6) == 0) probe(line + 6, out, sizeof out);
        else if (strncmp(line, "reserve ", 8) == 0) { char rp[128]; snprintf(out, sizeof out, "%s\n", device_reserve(strtoull(line + 8, NULL, 10), rp, sizeof rp)); }
        else if (strcmp(line, "devfree") == 0) { char rp[128]; snprintf(out, sizeof out, "%s\n", device_reserve(0, rp, sizeof rp)); }
        else if (strncmp(line, "engine ", 7) == 0) { char rp[128]; snprintf(out, sizeof out, "%s\n", engine_send(line + 7, rp, sizeof rp)); }
        else snprintf(out, sizeof out, "err unknown command\n");
        if (conn_write(c, out, strlen(out)) < 0) break;
        /* "reply_delay_ms": a pause between the reply and the next read,
         * where a park's signal may land, for the runtime's tests. */
        if (reply_delay) usleep((useconds_t)(reply_delay * 1000));
    }
    return 0;
}

/* One HTTP/1.1 request per connection (Connection: close), routed onto
 * the same state the line protocol serves. */
static int http_mode;

static void http_reply(conn_t *c, int status, const char *reason, const char *body) {
    char head[256];
    int n = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                     status, reason, strlen(body));
    if (conn_write(c, head, (size_t)n) < 0) return;
    (void)conn_write(c, body, strlen(body));
}

static int serve_http(conn_t *c, const char *fence, unsigned long *counter) {
    char req[4096]; size_t n = 0;
    /* Read the head (up to the blank line); the body, if any, is ignored. */
    while (n < sizeof req - 1) {
        ssize_t r = conn_read(c, req + n, sizeof req - 1 - n);
        if (r <= 0) break;
        n += (size_t)r; req[n] = 0;
        if (strstr(req, "\r\n\r\n") || strstr(req, "\n\n")) break;
    }
    if (n == 0) return -1;
    req[n] = 0;
    char method[8], target[512];
    if (sscanf(req, "%7s %511s", method, target) != 2) { http_reply(c, 400, "Bad Request", "bad request\n"); return 0; }
    char *q = strchr(target, '?');
    const char *query = "";
    if (q) { *q = 0; query = q + 1; }
    char body[256];
    if (strcmp(target, "/readyz") == 0) { http_reply(c, 200, "OK", "ok\n"); return 0; }
    if (strcmp(method, "GET") == 0 && (strcmp(target, "/") == 0 || strcmp(target, "/count") == 0)) {
        snprintf(body, sizeof body, "%lu\n", *counter); http_reply(c, 200, "OK", body); return 0;
    }
    if (strcmp(method, "POST") == 0 && (strcmp(target, "/") == 0 || strcmp(target, "/incr") == 0)) {
        snprintf(body, sizeof body, "%lu\n", ++*counter); http_reply(c, 200, "OK", body); return 0;
    }
    if (strcmp(target, "/fence") == 0) { snprintf(body, sizeof body, "%s\n", cur_fence[0] ? cur_fence : fence); http_reply(c, 200, "OK", body); return 0; }
    if (strcmp(method, "POST") == 0 && strcmp(target, "/dirty") == 0) {
        const char *b = strstr(query, "bytes=");
        size_t got = dirty(b ? (size_t)strtoull(b + 6, NULL, 10) : 0);
        snprintf(body, sizeof body, "ok %zu\n", got); http_reply(c, 200, "OK", body); return 0;
    }
    http_reply(c, 404, "Not Found", "not found\n");
    return 0;
}

/* Listen on a unix socket path or "tcp://host:port". A TCP listener
 * binds the wildcard of the host's family, so it is reachable however
 * the home is addressed. Returns the listening fd, or -1. */
static int listen_endpoint(const char *ep) {
    if (strncmp(ep, "tcp://", 6) == 0) {
        const char *hp = ep + 6;
        const char *colon = strrchr(hp, ':');
        if (!colon) { errno = EINVAL; return -1; }
        int port = atoi(colon + 1);
        int v6 = hp[0] == '[';
        int s = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) return -1;
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        int rc;
        if (v6) {
            struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port), .sin6_addr = in6addr_any };
            rc = bind(s, (struct sockaddr *)&a6, sizeof a6);
        } else {
            struct sockaddr_in a4 = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(INADDR_ANY) };
            rc = bind(s, (struct sockaddr *)&a4, sizeof a4);
        }
        if (rc < 0 || listen(s, 16) < 0) { int e = errno; close(s); errno = e; return -1; }
        return s;
    }
    if (strncmp(ep, "unix://", 7) == 0) ep += 7;
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(ep) >= sizeof a.sun_path) { close(s); errno = ENAMETOOLONG; return -1; }
    strcpy(a.sun_path, ep);
    unlink(ep);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 16) < 0) { int e = errno; close(s); errno = e; return -1; }
    return s;
}

/* park answers a park's SIGUSR1 in a forked fiber, with nothing being
 * served. After a resume it reseeds and listens on the record's
 * endpoint, after a failed park on the one it had. ack_skip is the test
 * knob that never acks. Returns -1 when the fiber must end with 122. */
static int park(int handoff, int ack_skip, int *listener) {
    *listener = -1;
    if (fz_quiesce() < 0) return -1;
    fz_incarnation_t inc;
    int rc;
    while ((rc = fz_incarnation_wait(&inc)) < 0 && errno == EINTR) {}
    if (rc < 0) return -1;
    if (rc > 0) {
        set_incarnation(&inc);
        reseed_rngs_from(inc.seed, inc.seed_len);
    }
    if (!handoff && (*listener = listen_endpoint(cur_endpoint)) < 0) return -1;
    if (ack_skip) fz_seed_forget();
    else fz_fiber_ready();
    return 0;
}

static int on_fiber(const fz_incarnation_t *f) {
    cur_fiber = f;
    set_incarnation(f);
    park_arm();
    int park_ignore = payload_num(f->payload, f->payload_len, "\"park_ignore\"") != 0;
    unsigned long long park_delay = payload_num(f->payload, f->payload_len, "\"park_delay_ms\"");
    reply_delay = payload_num(f->payload, f->payload_len, "\"reply_delay_ms\"");
    int ack_skip = payload_num(f->payload, f->payload_len, "\"ack_skip\"") != 0;
    /* This fiber's random() would otherwise replay the zygote's
     * sequence, the same in every sibling. The library leaves reseeding
     * to the template (see fz_on_fiber), and hands it the host's seed. */
    reseed_rngs_from(f->seed, f->seed_len);
    int handoff = f->identity != NULL;
    if (handoff) {
#ifdef FZ_TLS
        const char *why = tls_load(f->identity);
#else
        const char *why = "built without TLS (-DFZ_TLS)";
#endif
        if (why) {
            fprintf(stderr, "refzygote %s: handoff: %s\n", f->fence, why);
            return 6;
        }
    }
    int s = handoff ? -1 : listen_endpoint(f->endpoint);
    if (!handoff && s < 0) {
        fprintf(stderr, "refzygote %s: listen %s: %s\n", f->fence, f->endpoint, strerror(errno));
        return 4;
    }
    /* "ready_delay_ms" lets tests make a fiber miss its deadline. */
    unsigned long long delay = payload_num(f->payload, f->payload_len, "\"ready_delay_ms\"");
    if (delay) usleep((useconds_t)(delay * 1000));
    /* "ready_misuse" misuses fd 3 as a buggy workload would, so tests see
     * the zygote refuse the fiber and serve on. 1 writes a stray byte, 2
     * closes it, 3 tries fz_report_line, which must fail in a fiber. */
    switch (payload_num(f->payload, f->payload_len, "\"ready_misuse\"")) {
    case 1: (void)!write(3, "x", 1); break;
    case 2: close(3); break;
    case 3: {
        char line[FZ_REPORT_MAX];
        snprintf(line, sizeof line, "DEVICE %s 1 0", f->fence);
        if (fz_report_line(line) == 0) return 7;
        break;
    }
    default: break;
    }
    fz_fiber_ready();
    /* "exit_after_ready" is a fiber that ran and ended at once. */
    if (payload_num(f->payload, f->payload_len, "\"exit_after_ready\"")) return 0;

    /* Birth payload: grow the working set as instructed. Over the grant's
     * w_budget this is where the kernel kills us. */
    size_t db = (size_t)payload_num(f->payload, f->payload_len, "\"dirty_bytes\"");
    if (db) dirty(db);
    /* And its device slice, which the engine reports and the home holds
     * against the grant's device budget. */
    unsigned long long dev = payload_num(f->payload, f->payload_len, "\"device_bytes\"");
    if (dev) { char rp[128]; device_reserve(dev, rp, sizeof rp); }

    unsigned long counter = 0;
    for (;;) {
        if (park_requested && park_ignore) park_requested = 0; /* test knob: fiberd must fail the park */
        if (park_requested) {
            /* The listener closes too, so a new connection is refused
             * rather than left in a queue the dump would find. */
            park_requested = 0;
            /* "park_delay_ms" is a request that takes this long to end,
             * for a fiber that answers after fiberd's deadline. */
            if (park_delay) usleep((useconds_t)(park_delay * 1000));
            if (!handoff) {
                close(s);
                if (strncmp(cur_endpoint, "tcp://", 6) != 0) unlink(cur_endpoint);
            }
            if (park(handoff, ack_skip, &s) < 0) return 122;
            continue;
        }
        /* The wait lets the signal through, so one that lands here is
         * seen at the top of the loop and never behind a blocking accept. */
        if (wait_readable(handoff ? FZ_CHANNEL_FD : s) < 0) { if (errno == EINTR) continue; return 5; }
        int fd = handoff ? fz_accept() : accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) { if (errno == EINTR) continue; return 5; }
        conn_t c = { .fd = fd };
#ifdef FZ_TLS
        if (handoff && tls_start(&c) < 0) { close(fd); continue; }
#endif
        if (http_mode) serve_http(&c, f->fence, &counter);
        else serve_client(&c, f->fence, &counter);
        conn_close(&c);
    }
}

/* ---- gVisor mode ------------------------------------------------------ */

/* Blocks until the next checkpoint of this sandbox completes. Returns 1
 * in a sandbox restored from that image, 0 in the original (or on a
 * failed checkpoint). Each wait needs a fresh open. */
static int wait_checkpoint(void) {
    int fd = open("/proc/gvisor/checkpoint", O_RDONLY);
    if (fd < 0) { perror("refzygote: /proc/gvisor/checkpoint"); exit(6); }
    char buf[32]; ssize_t n;
    while ((n = read(fd, buf, sizeof buf - 1)) < 0 && errno == EINTR) {}
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    return strncmp(buf, "restore", 7) == 0;
}

/* Serve one incarnation on ep until SIGUSR1. It returns with the
 * endpoint closed and unlinked, which the host waits for before
 * checkpointing. */
static int gvisor_serve_once(const char *fence, const char *ep, const unsigned char *payload, size_t plen, unsigned long *counter) {
    /* Readiness here is the endpoint accepting connections, so the delay
     * a test asks for comes before the bind. */
    unsigned long long delay = payload_num(payload, plen, "\"ready_delay_ms\"");
    if (delay) usleep((useconds_t)(delay * 1000));
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 2;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(ep) >= sizeof a.sun_path) return 3;
    strcpy(a.sun_path, ep);
    unlink(ep);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 16) < 0) {
        fprintf(stderr, "refzygote %s: bind %s: %s\n", fence, ep, strerror(errno));
        return 4;
    }
    /* Bound, so fiberd may connect. */
    (void)fz_gvisor_ack();
    size_t db = (size_t)payload_num(payload, plen, "\"dirty_bytes\"");
    if (db) dirty(db);
    while (!park_requested) {
        if (wait_readable(s) < 0) continue;
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;
        conn_t cc = { .fd = c };
        if (http_mode) serve_http(&cc, fence, counter);
        else serve_client(&cc, fence, counter);
        conn_close(&cc);
    }
    close(s);
    unlink(ep);
    park_requested = 0;
    return 0;
}

static int gvisor_main(void) {
    park_arm();
    /* Init is done. The backend checkpoints from outside while this
     * process blocks in wait_checkpoint(), gVisor's documented sync point,
     * where every restored sandbox resumes. Nothing else tells an original
     * from a copy, since a copy even sees the filesystem as it was. */
    int m = open("/host/warm.ready", O_CREAT | O_WRONLY, 0644);
    if (m < 0) { perror("refzygote: /host/warm.ready"); return 6; }
    close(m);
    fprintf(stderr, "refzygote: warm, waiting for the template checkpoint\n");
    static unsigned long counter;
    for (;;) {
        if (!wait_checkpoint()) {
            /* The original goes on in place, with nothing to serve. */
            fprintf(stderr, "refzygote: checkpointed, resumed in place\n");
            continue;
        }
        /* A restored sandbox. Its identity comes on fiberd's channel,
         * where a pooled one waits. Every copy holds the same RNG state,
         * so reseed before anything draws. */
        fz_incarnation_t id;
        if (fz_gvisor_identity(&id) < 0) {
            fprintf(stderr, "refzygote: restored without an identity: %s\n", strerror(errno));
            return 122;
        }
        reseed_rngs_from(id.seed, id.seed_len);
        /* The record the fiber-side commands read, as on_fiber's is under a fork. */
        cur_fiber = &id;
        set_incarnation(&id);
        fprintf(stderr, "refzygote: incarnation %s serving on %s\n", id.fence, id.endpoint);
        int rc = gvisor_serve_once(id.fence, id.endpoint, id.payload, id.payload_len, &counter);
        cur_fiber = NULL;
        if (rc) return rc;
    }
}

int main(int argc, char **argv) {
    int gvisor = 0;
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "--gvisor") == 0) gvisor = 1;
    gvisor_mode = gvisor;
    if (!gvisor) fz_init(argc, argv); /* gVisor: no fork, no CoW delta, so no need to pin the layout */
    size_t heap_mb = 64, device_mb = 0;
    const char *logpath = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--heap-mb") == 0 && i + 1 < argc) heap_mb = (size_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--device-mb") == 0 && i + 1 < argc) device_mb = (size_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) logpath = argv[++i];
        else if (strcmp(argv[i], "--gvisor") == 0) {}
        else if (strcmp(argv[i], "--http") == 0) http_mode = 1;
        else { fprintf(stderr, "usage: %s [--heap-mb N] [--device-mb N] [--log PATH] [--gvisor] [--http]\n", argv[0]); return 2; }
    }
    if (logpath) {
        /* Reopen stdio from inside. A container's init inherits
         * descriptors opened outside its mount namespace, which criu
         * cannot map when it checkpoints the zygote. */
        int lf = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        int nf = open("/dev/null", O_RDONLY);
        if (lf < 0 || nf < 0) { perror("refzygote: --log"); return 2; }
        dup2(nf, 0); dup2(lf, 1); dup2(lf, 2);
        close(lf); close(nf);
    }
    heavy_init(heap_mb);
    if (gvisor) return gvisor_main();
#ifdef FZ_TLS
    /* Library setup is paid once here and shared by every fiber. */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
    if (device_mb) engine_start(device_mb); /* the engine thread reports once fz_serve is up */
    /* The control channel is fd 3, where fiberd puts it. */
    int rc = fz_serve(3, on_fiber);
    if (rc < 0) { perror("refzygote: fz_serve"); return 1; }
    return 0;
}
