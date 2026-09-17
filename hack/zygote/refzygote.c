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
 *   fence           -> <fence>
 *   getenv <NAME>   -> value or "-" (proves the scrub: only FIBERD_* exist)
 *   quit            -> closes the connection
 *
 * The clone payload, if any, is JSON with an optional "dirty_bytes": the
 * fiber dirties that much right after reporting ready, which is how
 * conformance case C6 drives a fiber over its W budget.
 *
 * Build: gcc -O2 -o refzygote refzygote.c libfiberzygote.c
 * Run:   fiberd starts it; by hand: refzygote --heap-mb 64 3<>/dev/null
 *
 * --gvisor runs the same workload as the init process of a gVisor sandbox
 * (fiberd's gvisor backend). There is no fork: after init the process
 * triggers its own checkpoint through /proc/gvisor/checkpoint; every fiber
 * is a sandbox restored from that image, which learns its fence, endpoint
 * and payload from the restore-time environment (/proc/gvisor/spec_environ),
 * serves on /host (the grant's run directory, bind-mounted), closes its
 * endpoint on SIGUSR1 so the sandbox can be checkpointed, and re-binds
 * under the next fence when restored again.
 */
#define _GNU_SOURCE
#include "libfiberzygote.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

static int serve_client(int c, const char *fence, unsigned long *counter) {
    FILE *in = fdopen(dup(c), "r");
    if (!in) return -1;
    char line[256];
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\r\n")] = 0;
        char out[256];
        if (strcmp(line, "ping") == 0) snprintf(out, sizeof out, "pong\n");
        else if (strncmp(line, "dirty ", 6) == 0) { size_t n = dirty((size_t)strtoull(line + 6, NULL, 10)); snprintf(out, sizeof out, "ok %zu\n", n); }
        else if (strcmp(line, "incr") == 0) snprintf(out, sizeof out, "%lu\n", ++*counter);
        else if (strcmp(line, "get") == 0) snprintf(out, sizeof out, "%lu\n", *counter);
        else if (strcmp(line, "fence") == 0) snprintf(out, sizeof out, "%s\n", fence);
        else if (strcmp(line, "pid") == 0) snprintf(out, sizeof out, "%d\n", (int)getpid());
        else if (strcmp(line, "rss") == 0) {
            /* resident bytes as this process's kernel sees them */
            long size = 0, pages = 0; FILE *sm = fopen("/proc/self/statm", "r");
            if (sm) { if (fscanf(sm, "%ld %ld", &size, &pages) != 2) pages = 0; fclose(sm); }
            snprintf(out, sizeof out, "%ld\n", pages * 4096L);
        }
        else if (strncmp(line, "getenv ", 7) == 0) { const char *v = getenv(line + 7); snprintf(out, sizeof out, "%s\n", v ? v : "-"); }
        else if (strcmp(line, "quit") == 0) break;
        else snprintf(out, sizeof out, "err unknown command\n");
        if (write(c, out, strlen(out)) < 0) break;
    }
    fclose(in);
    return 0;
}

static int on_fiber(const fz_fiber_t *f) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 2;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(f->endpoint) >= sizeof a.sun_path) return 3;
    strcpy(a.sun_path, f->endpoint);
    unlink(f->endpoint);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 16) < 0) {
        fprintf(stderr, "refzygote %s: bind %s: %s\n", f->fence, f->endpoint, strerror(errno));
        return 4;
    }
    /* "ready_delay_ms" lets tests make a fiber miss its deadline. */
    unsigned long long delay = payload_num(f->payload, f->payload_len, "\"ready_delay_ms\"");
    if (delay) usleep((useconds_t)(delay * 1000));
    fz_fiber_ready();

    /* Birth payload: grow the working set as instructed. Over the grant's
     * w_budget this is where the kernel kills us. */
    size_t db = (size_t)payload_num(f->payload, f->payload_len, "\"dirty_bytes\"");
    if (db) dirty(db);

    unsigned long counter = 0;
    for (;;) {
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR) continue; return 5; }
        serve_client(c, f->fence, &counter);
        close(c);
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
        serve_client(c, fence, counter);
        close(c);
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
         * spec. Its environment names the fence; give it a moment in
         * case it is still being installed. */
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
    size_t heap_mb = 64;
    int ctl_fd = 3;
    const char *logpath = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--heap-mb") == 0 && i + 1 < argc) heap_mb = (size_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--ctl-fd") == 0 && i + 1 < argc) ctl_fd = atoi(argv[++i]);
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) logpath = argv[++i];
        else if (strcmp(argv[i], "--gvisor") == 0) {}
        else { fprintf(stderr, "usage: %s [--heap-mb N] [--ctl-fd N] [--log PATH] [--gvisor]\n", argv[0]); return 2; }
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
    int rc = fz_serve(ctl_fd, on_fiber);
    if (rc < 0) { perror("refzygote: fz_serve"); return 1; }
    return 0;
}
