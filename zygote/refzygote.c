/* refzygote: the reference workload for fiberd's process runtime and the
 * conformance suite's template.
 *
 * Init (paid once, in the zygote): allocate --heap-mb and touch every page,
 * then burn some CPU to stand in for a JIT or graph build. Every fiber is a
 * copy-on-write fork of that.
 *
 * Each fiber serves a line protocol on its unix-socket endpoint:
 *
 *   ping            -> pong
 *   dirty <bytes>   -> ok        (grows the working set by that much: CoW
 *                                 faults on the inherited heap after a fork,
 *                                 new allocations in a restored sandbox;
 *                                 either way charged to the fiber as W)
 *   incr            -> <n>       (per-fiber counter; state that must survive
 *                                 a park/resume, see phase 6)
 *   get             -> <n>
 *   random          -> <n>       (libc random(), reseeded in every new
 *                                 incarnation: at the fork, after a
 *                                 restore, and when the fence changes
 *                                 under a resumed fiber, so no two
 *                                 copies draw the same sequence)
 *   getrandom       -> <hex>     (8 bytes straight from getrandom(2):
 *                                 shows whether the kernel's entropy is
 *                                 fresh in a copy, with no template
 *                                 state in between)
 *   fence           -> <fence>   (the current one: after a resume the agent
 *                                 publishes the new fence beside a unix
 *                                 endpoint, and that file wins over the
 *                                 birth fence in memory)
 *   getenv <NAME>   -> value or "-" (proves the scrub: only FIBERD_* exist)
 *   status <Key>    -> that field of /proc/self/status, or "-"
 *                      (CapEff and NoNewPrivs prove the privilege drop)
 *   read <path>     -> the file's first line, or "-" when it cannot be
 *                      read (proves what the mount namespace hides)
 *   wopen <path>    -> "ok" when open(path, O_WRONLY) succeeds, else the
 *                      errno's name (EROFS, EACCES, EPERM, ENOENT, or
 *                      "errno <n>"). Nothing is ever written.
 *                      (proves which host controls are read-only)
 *   stat <path>     -> what stat(path) finds, "dir", "file", "sock" or
 *                      "other", else the errno's name (ENOENT, EACCES,
 *                      or "errno <n>"). Nothing is opened or changed.
 *                      (proves what the mount namespace shows of other
 *                      grants' directories)
 *   remount <path>  -> "ok" when a read-write remount of the mount at
 *                      path succeeds (undone at once), else the errno's
 *                      name (proves whether a fiber may lift a read-only
 *                      bind it was given)
 *
 * A handoff fiber (FIBERD_HANDOFF_FD set) serves the same protocol inside
 * TLS 1.3 on the connections the agent passes it through fz_accept(),
 * instead of a listener of its own. It serves the grant's identity
 * (fz_handoff_identity(), sent down the channel at birth, never a file)
 * and accepts only the client certificate whose x5t#S256 that identity
 * names. That needs a build with -DFZ_TLS and OpenSSL 3. Without it a
 * handoff fiber refuses to start.
 *
 * The clone payload, if any, is JSON with an optional "dirty_bytes": the
 * fiber dirties that much right after reporting ready, which is how
 * conformance case C6 drives a fiber over its W budget; and an optional
 * "device_bytes", reserved from the engine the same way. Two keys are
 * for the runtime's own tests. "ready_delay_ms" delays the ready report,
 * for a fiber that misses its deadline. "ready_misuse" makes a fiber
 * misuse the readiness pipe at fd 3 the way a buggy workload would. 1
 * writes a stray byte on it before reporting, 2 closes it and never
 * reports, and 3 calls fz_report, which must fail in a fiber. The zygote
 * must refuse such a fiber and go on serving.
 *
 * --http makes every fiber serve HTTP/1.1 on its endpoint instead of the
 * line protocol, for consumers that route web traffic to fibers (an
 * ingress proxy in front of the endpoint): GET /readyz -> "ok", GET / or
 * GET /count -> the counter, POST / or POST /incr -> the counter after
 * one increment, GET /fence -> the fence, POST /dirty?bytes=N -> "ok N".
 * The same counter, the same fence, the same working set: only the
 * framing differs.
 *
 * --device-mb N makes the zygote an engine with a simulated device of N
 * MiB: the GPU model in miniature. The zygote owns the device; fibers are
 * its clients over the unix socket named by FIBERD_ENGINE, holding slices
 * ("reserve <bytes>" on the fiber sets its slice; "devfree" drops it).
 * The engine reports every slice to the agent (DEVICE lines) and drops a
 * slice on EVICT, which is what a park does before the CPU checkpoint; a
 * resumed fiber renegotiates by reserving again. A real CUDA engine is a
 * drop-in that speaks the same lines.
 *
 * Build: gcc -O2 -pthread -o refzygote refzygote.c libfiberzygote.c
 *        (add -DFZ_TLS ... -lssl -lcrypto to serve handoff grants)
 * Run:   fiberd starts it; by hand: refzygote --heap-mb 64 3<>/dev/null
 *
 * --gvisor runs the same workload as the init process of a gVisor sandbox
 * (fiberd's gvisor backend). There is no fork: after init the process
 * triggers its own checkpoint through /proc/gvisor/checkpoint; every fiber
 * is a sandbox restored from that image, which learns its fence, endpoint
 * and payload from the restore-time environment (/proc/gvisor/spec_environ),
 * serves on /host (the grant's run directory, bind-mounted), closes its
 * endpoint on SIGUSR1 so the sandbox can be checkpointed, and re-binds
 * under the next fence when restored again. --http applies there too.
 */
#define _GNU_SOURCE
#include "libfiberzygote.h"

#include <errno.h>
#include <fcntl.h>
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
#include <sys/un.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>

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

/* Grow the fiber's working set by bytes. Under a fork this writes to the
 * inherited heap: every page touched becomes a private copy, charged to
 * the fiber's cgroup as W. In a restored sandbox there is no shared page
 * to break, the whole heap is already the fiber's own, so growing W means
 * allocating new memory; the kept allocations add up the same way. */
static size_t dirty(size_t bytes) {
    if (gvisor_mode) {
        char *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { fprintf(stderr, "refzygote: grow %zu: %s\n", bytes, strerror(errno)); return 0; }
        for (size_t i = 0; i < bytes; i += 4096) p[i] = 1;
        return bytes; /* kept on purpose */
    }
    if (bytes > heap_sz) bytes = heap_sz;
    for (size_t i = 0; i < bytes; i += 4096) heap[i] ^= 1;
    return bytes;
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

/* dev_set replaces a fiber's slice (0 drops it) and reports both the
 * slice and the whole device to the agent. Called with dev_mu held. */
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
    fz_report("DEVICE %s %llu 0", fence, bytes);
    fz_report("DEVICE - %llu %llu", dev_used, dev_cap);
    return "ok";
}

static void on_control(const char *line) {
    if (strncmp(line, "EVICT ", 6) == 0) {
        pthread_mutex_lock(&dev_mu);
        dev_set(line + 6, 0);
        pthread_mutex_unlock(&dev_mu);
    }
}

/* One request per connection: "reserve <fence> <bytes>", "release <fence>"
 * or "stat"; the reply is one line. */
static void *engine_thread(void *arg) {
    (void)arg;
    int s = listen_endpoint(engine_path);
    if (s < 0) { fprintf(stderr, "refzygote: engine listen %s: %s\n", engine_path, strerror(errno)); return NULL; }
    /* The agent learns of the device once the channel is up. */
    while (fz_report("DEVICE - %llu %llu", dev_used, dev_cap) < 0) usleep(5000);
    for (;;) {
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR) continue; break; }
        char line[256]; ssize_t n = read(c, line, sizeof line - 1);
        if (n <= 0) { close(c); continue; }
        line[n] = 0; line[strcspn(line, "\r\n")] = 0;
        char out[128]; char fence[128]; unsigned long long bytes;
        pthread_mutex_lock(&dev_mu);
        if (sscanf(line, "reserve %127s %llu", fence, &bytes) == 2) snprintf(out, sizeof out, "%s\n", dev_set(fence, bytes));
        else if (sscanf(line, "release %127s", fence) == 1) snprintf(out, sizeof out, "%s\n", dev_set(fence, 0));
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
    fz_set_engine(engine_path);
    fz_set_control(on_control);
    pthread_t t;
    if (pthread_create(&t, NULL, engine_thread, NULL) != 0) { perror("refzygote: engine thread"); exit(2); }
    pthread_detach(t);
}

/* ---- the fiber's side of the device ----------------------------------- */

static const char *cur_endpoint; /* this fiber's endpoint, for the fence file */
static const char *cur_fence;

/* The fence this incarnation lives under: the one the agent published
 * beside the unix endpoint after a resume (the fence in memory is the
 * birth fence, stale then), else fallback, the fence in memory. A fiber
 * behind the agent's tcp relay serves a unix socket too and reads the
 * file beside it. A gVisor incarnation has no fence file: its fence
 * comes from the restore-time spec and is current already. */
static const char *live_fence(char *buf, size_t n, const char *fallback) {
    const char *ep = cur_endpoint ? cur_endpoint : "";
    if (strncmp(ep, "unix://", 7) == 0) ep += 7;
    if (ep[0] == '/') {
        char path[300]; snprintf(path, sizeof path, "%s.fence", ep);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(buf, (int)n, f)) { buf[strcspn(buf, "\r\n")] = 0; fclose(f); if (buf[0]) return buf; }
            fclose(f);
        }
    }
    return fallback ? fallback : "?";
}

/* The fence the engine should file the slice under. */
static const char *current_fence(char *buf, size_t n) { return live_fence(buf, n, cur_fence); }

/* device_reserve asks the engine for a slice of bytes (0 releases it) and
 * returns the engine's reply line. */
static const char *device_reserve(unsigned long long bytes, char *reply, size_t n) {
    const char *eng = getenv("FIBERD_ENGINE");
    if (!eng) return "err no engine";
    if (strncmp(eng, "unix://", 7) == 0) eng += 7;
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return "err socket";
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", eng);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return "err engine unreachable"; }
    char fb[128]; const char *fence = current_fence(fb, sizeof fb);
    char req[256];
    int m = bytes ? snprintf(req, sizeof req, "reserve %s %llu\n", fence, bytes) : snprintf(req, sizeof req, "release %s\n", fence);
    (void)!write(s, req, (size_t)m);
    ssize_t r = read(s, reply, n - 1);
    close(s);
    if (r <= 0) return "err no reply";
    reply[r] = 0; reply[strcspn(reply, "\r\n")] = 0;
    return reply;
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
    default: snprintf(out, n, "errno %d\n", e); break;
    }
}

/* wopen_errno writes "ok" when open(path, O_WRONLY) succeeds (the
 * descriptor is closed at once), else the errno's name. It never writes
 * a byte, so it is safe to point at a sysctl or a cgroup control. The
 * open alone tells whether the mount is read-only. */
static void wopen_errno(const char *path, char *out, size_t n) {
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (fd >= 0) { close(fd); snprintf(out, n, "ok\n"); return; }
    errname(errno, out, n);
}

/* connect_errno writes "ok" when a TCP connect to "a.b.c.d:port"
 * succeeds within two seconds (the socket is closed at once), else the
 * errno's name. It is the one way a fiber can show whether a host
 * listener is reachable from its network namespace. */
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

/* unshare_errno writes what unshare(CLONE_NEWUSER) answers in a child
 * process, so this fiber's own namespaces stay as they are. */
static void unshare_errno(char *out, size_t n) {
    pid_t pid = fork();
    if (pid < 0) { errname(errno, out, n); return; }
    if (pid == 0) _exit(unshare(CLONE_NEWUSER) == 0 ? 0 : (errno & 0xff));
    int st = 0;
    if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st)) { errname(EIO, out, n); return; }
    if (WEXITSTATUS(st) == 0) snprintf(out, n, "ok\n"); else errname(WEXITSTATUS(st), out, n);
}

/* mount_errno writes what mounting a fresh instance of fstype at a
 * scratch directory under /tmp answers. A mount that succeeds is undone
 * at once. The probe for a filesystem a fiber must not be able to mount. */
static void mount_errno(const char *fstype, char *out, size_t n) {
    char dir[] = "/tmp/.probe-XXXXXX";
    if (!mkdtemp(dir)) { errname(errno, out, n); return; }
    int rc = mount(fstype, dir, fstype, 0, NULL);
    int saved = errno;
    if (rc == 0) umount2(dir, MNT_DETACH);
    rmdir(dir);
    if (rc == 0) snprintf(out, n, "ok\n"); else errname(saved, out, n);
}

/* remount_errno writes what a read-write bind remount of the mount at
 * path answers. One that succeeds is put back read-only at once. */
static void remount_errno(const char *path, char *out, size_t n) {
    if (mount(NULL, path, NULL, MS_REMOUNT | MS_BIND, NULL) == 0) {
        mount(NULL, path, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL);
        snprintf(out, n, "ok\n");
        return;
    }
    errname(errno, out, n);
}

/* mkdir_errno writes what mkdir(path) answers, removing a directory it
 * managed to make. */
static void mkdir_errno(const char *path, char *out, size_t n) {
    if (mkdir(path, 0755) == 0) { rmdir(path); snprintf(out, n, "ok\n"); return; }
    errname(errno, out, n);
}

/* stat_kind writes what stat(path) finds, by file type, or the errno's
 * name when it fails. It opens nothing and changes nothing. */
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
        int r = SSL_read(c->ssl, p, n > 65536 ? 65536 : (int)n);
        return r > 0 ? r : 0;
    }
#endif
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
/* The handoff fiber's TLS server, loaded after the fork from the identity
 * the agent sent down the fiber's channel, so the key never sits in the
 * zygote's memory or in a file another grant's fibers could read. */
static SSL_CTX *tls_ctx;
static const char *tls_caller;

/* The caller's certificate is self-signed. What makes it trusted is the
 * pin checked after the handshake, so chain verification accepts it. */
static int tls_any_chain(int ok, X509_STORE_CTX *x) { (void)ok; (void)x; return 1; }

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

static const char *tls_load(void) {
    const fz_identity_t *id = fz_handoff_identity();
    if (!id) return "no handoff identity";
    if (!id->caller[0]) return "identity names no caller";
    tls_caller = id->caller;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return "SSL_CTX_new failed";
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_any_chain);
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

/* tls_caller_ok reports whether the peer's certificate is the grant's
 * caller (RFC 8705 x5t#S256, the base64url SHA-256 of its DER). */
static int tls_caller_ok(SSL *s) {
    X509 *peer = SSL_get1_peer_certificate(s);
    if (!peer) return 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdn = 0;
    int ok = X509_digest(peer, EVP_sha256(), md, &mdn) == 1;
    X509_free(peer);
    if (!ok) return 0;
    char b64[4 * ((EVP_MAX_MD_SIZE + 2) / 3) + 1];
    int n = EVP_EncodeBlock((unsigned char *)b64, md, (int)mdn);
    while (n > 0 && b64[n - 1] == '=') n--;
    b64[n] = 0;
    for (int i = 0; i < n; i++) { if (b64[i] == '+') b64[i] = '-'; else if (b64[i] == '/') b64[i] = '_'; }
    return strcmp(b64, tls_caller) == 0;
}

/* tls_reseed mixes fresh kernel entropy into both of OpenSSL's DRBGs.
 * Forked fibers and fibers restored from one checkpoint start with the
 * same DRBG state, and a CRIU resume keeps the pid, so OpenSSL's own
 * fork check never notices a copy. */
static int tls_reseed(void) {
    unsigned char seed[32];
    if (getrandom(seed, sizeof seed, 0) != (ssize_t)sizeof seed) return -1;
    EVP_RAND_CTX *drbg[2] = { RAND_get0_public(NULL), RAND_get0_private(NULL) };
    for (int i = 0; i < 2; i++)
        if (!drbg[i] || EVP_RAND_reseed(drbg[i], 0, NULL, 0, seed, sizeof seed) != 1) return -1;
    return 0;
}

/* tls_start runs the handshake on c and checks the caller, after a
 * reseed of its own (see tls_reseed). A caller that stalls the handshake
 * is dropped after 5 s. */
static int tls_start(conn_t *c) {
    if (tls_reseed() < 0) return -1;
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

/* reseed_rngs gives every generator this template owns a fresh seed from
 * the kernel. It runs once per incarnation: in the child at the fork,
 * after a restore returns (gVisor), and when a resumed fiber sees a new
 * fence (CRIU keeps the pid and the parked RNG state, so nothing else
 * marks the copy). Both libc generators are seeded, since rand() keeps
 * its own state on some libcs. OpenSSL's DRBGs are reseeded once they
 * exist, which is in a handoff fiber; tls_start does it again per
 * handshake. */
static void reseed_rngs(void) {
    unsigned seed[2] = { 0, 0 };
    if (getrandom(seed, sizeof seed, 0) == (ssize_t)sizeof seed) { srandom(seed[0]); srand(seed[1]); }
#ifdef FZ_TLS
    if (tls_ctx) (void)tls_reseed();
#endif
}

/* The fence this process last served under. A resumed fiber finds a new
 * one in the file beside its endpoint (live_fence) and reseeds before it
 * serves the connection it just accepted. */
static char seen_fence[128];

static void reseed_if_new_fence(const char *fallback) {
    char fb[128];
    const char *now = live_fence(fb, sizeof fb, fallback);
    if (strcmp(now, seen_fence) == 0) return;
    snprintf(seen_fence, sizeof seen_fence, "%s", now);
    reseed_rngs();
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
        else if (strcmp(line, "fence") == 0) { char fb[128]; snprintf(out, sizeof out, "%s\n", live_fence(fb, sizeof fb, fence)); }
        else if (strcmp(line, "pid") == 0) snprintf(out, sizeof out, "%d\n", (int)getpid());
        else if (strcmp(line, "random") == 0) snprintf(out, sizeof out, "%ld\n", random());
        else if (strcmp(line, "getrandom") == 0) {
            unsigned char b[8];
            if (getrandom(b, sizeof b, 0) != (ssize_t)sizeof b) errname(errno, out, sizeof out);
            else snprintf(out, sizeof out, "%02x%02x%02x%02x%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        }
        else if (strcmp(line, "rss") == 0) {
            /* resident bytes as this process's kernel sees them */
            long size = 0, pages = 0; FILE *sm = fopen("/proc/self/statm", "r");
            if (sm) { if (fscanf(sm, "%ld %ld", &size, &pages) != 2) pages = 0; fclose(sm); }
            snprintf(out, sizeof out, "%ld\n", pages * 4096L);
        }
        else if (strncmp(line, "getenv ", 7) == 0) { const char *v = getenv(line + 7); snprintf(out, sizeof out, "%s\n", v ? v : "-"); }
        else if (strncmp(line, "status ", 7) == 0) status_field(line + 7, out, sizeof out);
        else if (strncmp(line, "read ", 5) == 0) first_line(line + 5, out, sizeof out);
        else if (strncmp(line, "wopen ", 6) == 0) wopen_errno(line + 6, out, sizeof out);
        else if (strncmp(line, "stat ", 5) == 0) stat_kind(line + 5, out, sizeof out);
        else if (strncmp(line, "connect ", 8) == 0) connect_errno(line + 8, out, sizeof out);
        else if (strcmp(line, "unshare user") == 0) unshare_errno(out, sizeof out);
        else if (strncmp(line, "mount ", 6) == 0) mount_errno(line + 6, out, sizeof out);
        else if (strncmp(line, "mkdir ", 6) == 0) mkdir_errno(line + 6, out, sizeof out);
        else if (strncmp(line, "remount ", 8) == 0) remount_errno(line + 8, out, sizeof out);
        else if (strncmp(line, "reserve ", 8) == 0) { char rp[128]; snprintf(out, sizeof out, "%s\n", device_reserve(strtoull(line + 8, NULL, 10), rp, sizeof rp)); }
        else if (strcmp(line, "devfree") == 0) { char rp[128]; snprintf(out, sizeof out, "%s\n", device_reserve(0, rp, sizeof rp)); }
        else snprintf(out, sizeof out, "err unknown command\n");
        if (conn_write(c, out, strlen(out)) < 0) break;
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
    char body[128];
    if (strcmp(target, "/readyz") == 0) { http_reply(c, 200, "OK", "ok\n"); return 0; }
    if (strcmp(method, "GET") == 0 && (strcmp(target, "/") == 0 || strcmp(target, "/count") == 0)) {
        snprintf(body, sizeof body, "%lu\n", *counter); http_reply(c, 200, "OK", body); return 0;
    }
    if (strcmp(method, "POST") == 0 && (strcmp(target, "/") == 0 || strcmp(target, "/incr") == 0)) {
        snprintf(body, sizeof body, "%lu\n", ++*counter); http_reply(c, 200, "OK", body); return 0;
    }
    if (strcmp(target, "/fence") == 0) { char fb[128]; snprintf(body, sizeof body, "%s\n", live_fence(fb, sizeof fb, fence)); http_reply(c, 200, "OK", body); return 0; }
    if (strcmp(method, "POST") == 0 && strcmp(target, "/dirty") == 0) {
        const char *b = strstr(query, "bytes=");
        size_t got = dirty(b ? (size_t)strtoull(b + 6, NULL, 10) : 0);
        snprintf(body, sizeof body, "ok %zu\n", got); http_reply(c, 200, "OK", body); return 0;
    }
    http_reply(c, 404, "Not Found", "not found\n");
    return 0;
}

/* Listen on an endpoint as fiberd spells it: a unix socket path, or
 * "tcp://host:port" (the host is the address fiberd advertises; the
 * listener binds the wildcard of that address family so it is reachable
 * however the home is addressed). Returns the listening fd, or -1. */
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

static int on_fiber(const fz_fiber_t *f) {
    cur_endpoint = f->endpoint;
    cur_fence = f->fence;
    /* This fiber's random() would otherwise replay the zygote's
     * sequence, the same in every sibling. The library leaves reseeding
     * to the template (see fz_on_fiber). */
    snprintf(seen_fence, sizeof seen_fence, "%s", f->fence);
    reseed_rngs();
    int handoff = getenv("FIBERD_HANDOFF_FD") != NULL;
    if (handoff) {
#ifdef FZ_TLS
        const char *why = tls_load();
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
    /* "ready_misuse" is a buggy workload's treatment of fd 3, for tests
     * that the zygote refuses the fiber and keeps serving. */
    switch (payload_num(f->payload, f->payload_len, "\"ready_misuse\"")) {
    case 1: (void)!write(3, "x", 1); break;
    case 2: close(3); break;
    case 3: if (fz_report("DEVICE %s 1 0", f->fence) == 0) return 7; break;
    default: break;
    }
    fz_fiber_ready();

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
        int fd = handoff ? fz_accept() : accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) { if (errno == EINTR) continue; return 5; }
        /* A resume lands here, mid-accept, with the parked RNG state. A
         * fiber serving a unix socket sees the new fence beside it and
         * reseeds before this first connection is served. A tcp or
         * handoff fiber has no file to watch, so only its per-handshake
         * TLS reseed covers it. */
        reseed_if_new_fence(f->fence);
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

static volatile sig_atomic_t park_requested;
static void on_usr1(int s) { (void)s; park_requested = 1; }

/* One value from /proc/gvisor/spec_environ (KEY=VALUE entries separated by
 * NUL or newline: the environment of the spec the sandbox was last created
 * or restored with). */
static char *spec_env(const char *name) {
    static char buf[65536];
    int fd = open("/proc/gvisor/spec_environ", O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t n = 0, r;
    while ((r = read(fd, buf + n, sizeof buf - 1 - n)) > 0) n += r;
    close(fd);
    if (n <= 0) return NULL;
    buf[n] = 0;
    for (ssize_t i = 0; i < n; i++) if (buf[i] == '\n') buf[i] = 0;
    size_t kl = strlen(name);
    for (char *p = buf; p < buf + n; p += strlen(p) + 1)
        if (strncmp(p, name, kl) == 0 && p[kl] == '=') return strdup(p + kl + 1);
    return NULL;
}

/* Blocks until the next checkpoint of this sandbox completes. Returns 1
 * when this process is running in a sandbox restored from that image,
 * 0 when it is the original resumed in place (or the checkpoint failed).
 * Opening registers interest in the next checkpoint; the read answers
 * "resume", "restore" or "error" and the file must be reopened to wait
 * again. */
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

static size_t unhex(const char *h, unsigned char *out, size_t max) {
    size_t n = 0;
    for (; h[0] && h[1] && n < max; h += 2) {
        unsigned v; if (sscanf(h, "%2x", &v) != 1) break;
        out[n++] = (unsigned char)v;
    }
    return n;
}

/* Serve one incarnation on ep until SIGUSR1; returns with the endpoint
 * closed and unlinked (the host waits for that before checkpointing). */
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
    size_t db = (size_t)payload_num(payload, plen, "\"dirty_bytes\"");
    if (db) dirty(db);
    while (!park_requested) {
        struct pollfd p = { .fd = s, .events = POLLIN };
        int r = poll(&p, 1, 100);
        if (r <= 0) continue;
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
    struct sigaction sa = { .sa_handler = on_usr1 }; /* no SA_RESTART: blocking calls return EINTR */
    sigaction(SIGUSR1, &sa, NULL);
    /* Init is done: tell the backend, which takes the template checkpoint
     * from outside (runsc checkpoint --leave-running) while this process
     * is blocked in wait_checkpoint(). That blocking read is gVisor's
     * documented sync point: it is where every sandbox restored from the
     * image resumes, and it returns once the restore is complete and the
     * new spec's environment is in place. Nothing else tells an original
     * and a restored copy apart: a restored sandbox even sees the
     * filesystem as it was at checkpoint time. */
    int m = open("/host/warm.ready", O_CREAT | O_WRONLY, 0644);
    if (m < 0) { perror("refzygote: /host/warm.ready"); return 6; }
    close(m);
    fprintf(stderr, "refzygote: warm, waiting for the template checkpoint\n");
    static unsigned long counter;
    char last[256] = "none";
    for (;;) {
        if (!wait_checkpoint()) {
            /* "resume": the original (or a fiber parked with sync) goes
             * on in place. Nothing to serve; the host ends it or, for
             * the template, it just keeps standing by. */
            fprintf(stderr, "refzygote: checkpointed, resumed in place\n");
            continue;
        }
        /* "restore": running in a freshly restored sandbox under the new
         * spec. Every sandbox restored from one image holds the same RNG
         * state, so reseed before anything draws from it. Its environment
         * names the fence; give it a moment in case it is still being
         * installed. */
        reseed_rngs();
        char *fence = NULL, *ep = NULL, *ph = NULL;
        for (int i = 0; i < 3000; i++) {
            free(fence); free(ep); free(ph);
            fence = spec_env("FIBERD_FENCE"); ep = spec_env("FIBERD_ENDPOINT"); ph = spec_env("FIBERD_PAYLOAD");
            if (fence && ep && strcmp(fence, "none") != 0 && strcmp(fence, last) != 0) break;
            usleep(1000);
        }
        if (!fence || !ep || strcmp(fence, "none") == 0) {
            fprintf(stderr, "refzygote: restored without a fence in the spec environment; standing by\n");
        } else {
            fprintf(stderr, "refzygote: incarnation %s serving on %s\n", fence, ep);
            unsigned char payload[4096]; size_t plen = 0;
            if (ph && strcmp(ph, "-") != 0) plen = unhex(ph, payload, sizeof payload);
            snprintf(last, sizeof last, "%s", fence);
            int rc = gvisor_serve_once(fence, ep, payload, plen, &counter);
            if (rc) return rc;
        }
        free(fence); free(ep); free(ph);
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
        /* Reopen stdio from inside: a zygote that is a container's init
         * inherits descriptors opened outside its mount namespace, which
         * criu cannot map when it checkpoints the zygote's pages. */
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
