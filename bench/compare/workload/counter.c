/* counter: the one workload every system in the comparison runs
 * (docs/design/compare.md). It allocates and touches --heap-mb,
 * then serves a per-instance counter. One handler, three entry modes.
 *
 *   --plain                 a plain process: listen on 0.0.0.0:--port
 *                           (Pods, agent-sandbox, the Firecracker guest).
 *                           --ifup eth0=172.16.0.2/30 configures an
 *                           interface first, for a guest where counter is
 *                           init and nothing else exists.
 *   (default)               a fiberd zygote: fz_init first, warm once,
 *                           fz_serve on fd 3, and each fiber serves the
 *                           endpoint it is given (proc, runc).
 *   --gvisor                the init of a gVisor sandbox: warm, then the
 *                           self-checkpoint loop refzygote uses, serving
 *                           the endpoint named by the restore-time
 *                           environment until SIGUSR1 (fiberd gVisor).
 *
 * The framing is HTTP/1.1 by default. GET /readyz answers ok, POST /incr
 * the counter after one increment, GET /count the counter. --framing
 * line serves the reference workload's line protocol instead ("incr",
 * "get", "ping"), which is what the Hyperlight helper speaks, so proc can
 * be measured under both framings in one run.
 *
 * Build (Linux): gcc <ZYGOTE_CFLAGS> -o counter counter.c ../../../zygote/libfiberzygote.c
 * The Firecracker guest and the gVisor rootfs take -static-pie.
 */
#define _GNU_SOURCE
#include "../../../zygote/libfiberzygote.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int line_framing;
static int gvisor_mode;

/* Every copy of the warm process starts with its RNG state: a forked
 * fiber and every sandbox restored from the self-checkpoint alike. Each
 * new incarnation reseeds libc before it serves, as refzygote does. */
static void reseed_rngs(void) {
    unsigned seed[2] = { 0, 0 };
    if (getrandom(seed, sizeof seed, 0) == (ssize_t)sizeof seed) { srandom(seed[0]); srand(seed[1]); }
}

/* The expensive init, paid once: a heap touched page by page and some
 * CPU, standing in for a JIT or a graph build. */
static void heavy_init(size_t mb) {
    size_t n = mb << 20;
    char *heap = malloc(n);
    if (!heap) { perror("counter: malloc"); exit(1); }
    for (size_t i = 0; i < n; i += 4096) heap[i] = (char)(i >> 12);
    volatile unsigned x = 1;
    for (long i = 0; i < 20L * 1000 * 1000; i++) x = x * 1664525u + 1013904223u;
    (void)x;
}

/* ---- the handler ------------------------------------------------------ */

static void reply(int fd, int status, const char *body) {
    char out[256];
    int n = line_framing
        ? snprintf(out, sizeof out, "%s\n", body)
        : snprintf(out, sizeof out, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s\n",
                   status, status == 200 ? "OK" : "Not Found", strlen(body) + 1, body);
    (void)!write(fd, out, (size_t)n);
}

/* One request per connection in HTTP, many lines per connection in the
 * line framing. The counter is the instance's state. */
static void serve_conn(int fd, unsigned long *counter) {
    char buf[2048], num[32];
    if (line_framing) {
        FILE *in = fdopen(dup(fd), "r");
        if (!in) return;
        while (fgets(buf, sizeof buf, in)) {
            buf[strcspn(buf, "\r\n")] = 0;
            if (strcmp(buf, "incr") == 0) { snprintf(num, sizeof num, "%lu", ++*counter); reply(fd, 200, num); }
            else if (strcmp(buf, "get") == 0) { snprintf(num, sizeof num, "%lu", *counter); reply(fd, 200, num); }
            else if (strcmp(buf, "ping") == 0) reply(fd, 200, "pong");
            else if (strcmp(buf, "quit") == 0) break;
            else reply(fd, 200, "err unknown command");
        }
        fclose(in);
        return;
    }
    size_t n = 0;
    while (n < sizeof buf - 1) {
        ssize_t r = read(fd, buf + n, sizeof buf - 1 - n);
        if (r <= 0) break;
        n += (size_t)r; buf[n] = 0;
        if (strstr(buf, "\r\n\r\n") || strstr(buf, "\n\n")) break;
    }
    if (n == 0) return;
    char method[8], target[256];
    if (sscanf(buf, "%7s %255s", method, target) != 2) { reply(fd, 400, "bad request"); return; }
    if (strcmp(target, "/readyz") == 0) reply(fd, 200, "ok");
    else if (strcmp(method, "POST") == 0 && strcmp(target, "/incr") == 0) { snprintf(num, sizeof num, "%lu", ++*counter); reply(fd, 200, num); }
    else if (strcmp(method, "GET") == 0 && strcmp(target, "/count") == 0) { snprintf(num, sizeof num, "%lu", *counter); reply(fd, 200, num); }
    else reply(fd, 404, "not found");
}

/* Listen on an endpoint as fiberd spells it: a unix socket path, or
 * tcp://host:port (bound on the wildcard of the family, as refzygote
 * does). Returns the listening fd or -1. */
static int listen_endpoint(const char *ep) {
    if (strncmp(ep, "tcp://", 6) == 0) {
        const char *colon = strrchr(ep + 6, ':');
        if (!colon) { errno = EINVAL; return -1; }
        int port = atoi(colon + 1), v6 = ep[6] == '[';
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
        if (rc < 0 || listen(s, 64) < 0) { int e = errno; close(s); errno = e; return -1; }
        return s;
    }
    if (strncmp(ep, "unix://", 7) == 0) ep += 7;
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(ep) >= sizeof a.sun_path) { close(s); errno = ENAMETOOLONG; return -1; }
    strcpy(a.sun_path, ep);
    unlink(ep);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 64) < 0) { int e = errno; close(s); errno = e; return -1; }
    return s;
}

static volatile sig_atomic_t stop_requested;
static void on_usr1(int s) { (void)s; stop_requested = 1; }

/* Accept and serve until stop_requested (gVisor) or forever. */
static void serve_loop(int s, unsigned long *counter) {
    while (!stop_requested) {
        struct pollfd p = { .fd = s, .events = POLLIN };
        if (poll(&p, 1, 100) <= 0) continue;
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;
        serve_conn(c, counter);
        close(c);
    }
    stop_requested = 0;
}

/* ---- --plain: a process, possibly init -------------------------------- */

/* ifup configures "name=a.b.c.d/prefix" and brings it up, with ioctls,
 * so a guest needs no iproute2. */
static int ifup(const char *spec) {
    char name[IFNAMSIZ], addr[32]; int prefix;
    if (sscanf(spec, "%15[^=]=%31[^/]/%d", name, addr, &prefix) != 3) { errno = EINVAL; return -1; }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq r; memset(&r, 0, sizeof r);
    snprintf(r.ifr_name, IFNAMSIZ, "%s", name);
    struct sockaddr_in *sin = (struct sockaddr_in *)&r.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1 || ioctl(s, SIOCSIFADDR, &r) < 0) { close(s); return -1; }
    sin->sin_addr.s_addr = htonl(prefix == 0 ? 0 : ~0u << (32 - prefix));
    if (ioctl(s, SIOCSIFNETMASK, &r) < 0) { close(s); return -1; }
    if (ioctl(s, SIOCGIFFLAGS, &r) < 0) { close(s); return -1; }
    r.ifr_flags |= IFF_UP | IFF_RUNNING;
    int rc = ioctl(s, SIOCSIFFLAGS, &r);
    close(s);
    return rc;
}

static int plain_main(int port) {
    char ep[32];
    snprintf(ep, sizeof ep, "tcp://0.0.0.0:%d", port);
    int s = listen_endpoint(ep);
    if (s < 0) { perror("counter: listen"); return 4; }
    unsigned long counter = 0;
    serve_loop(s, &counter);
    return 0;
}

/* ---- zygote mode -------------------------------------------------------- */

static int on_fiber(const fz_fiber_t *f) {
    reseed_rngs();
    int s = listen_endpoint(f->endpoint);
    if (s < 0) { fprintf(stderr, "counter %s: listen %s: %s\n", f->fence, f->endpoint, strerror(errno)); return 4; }
    fz_fiber_ready();
    unsigned long counter = 0;
    serve_loop(s, &counter);
    return 0;
}

/* ---- gVisor mode, as refzygote does it ---------------------------------- */

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

/* Blocks until the next checkpoint of this sandbox completes. 1 when
 * running in a sandbox restored from it, 0 when resumed in place. */
static int wait_checkpoint(void) {
    int fd = open("/proc/gvisor/checkpoint", O_RDONLY);
    if (fd < 0) { perror("counter: /proc/gvisor/checkpoint"); exit(6); }
    char buf[32]; ssize_t n;
    while ((n = read(fd, buf, sizeof buf - 1)) < 0 && errno == EINTR) {}
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    return strncmp(buf, "restore", 7) == 0;
}

static int gvisor_main(void) {
    struct sigaction sa = { .sa_handler = on_usr1 };
    sigaction(SIGUSR1, &sa, NULL);
    int m = open("/host/warm.ready", O_CREAT | O_WRONLY, 0644);
    if (m < 0) { perror("counter: /host/warm.ready"); return 6; }
    close(m);
    unsigned long counter = 0;
    char last[256] = "none";
    for (;;) {
        if (!wait_checkpoint()) continue;
        reseed_rngs(); /* a sandbox restored from the image, see refzygote */
        char *fence = NULL, *ep = NULL;
        for (int i = 0; i < 3000; i++) {
            free(fence); free(ep);
            fence = spec_env("FIBERD_FENCE"); ep = spec_env("FIBERD_ENDPOINT");
            if (fence && ep && strcmp(fence, "none") != 0 && strcmp(fence, last) != 0) break;
            usleep(1000);
        }
        if (fence && ep && strcmp(fence, "none") != 0) {
            snprintf(last, sizeof last, "%s", fence);
            int s = listen_endpoint(ep);
            if (s < 0) { fprintf(stderr, "counter %s: bind %s: %s\n", fence, ep, strerror(errno)); return 4; }
            serve_loop(s, &counter);
            close(s);
            unlink(ep);
        }
        free(fence); free(ep);
    }
}

int main(int argc, char **argv) {
    int plain = 0, port = 8080;
    size_t heap_mb = 32;
    const char *up = NULL;
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "--gvisor") == 0) gvisor_mode = 1;
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "--plain") == 0) plain = 1;
    if (!plain && !gvisor_mode) fz_init(argc, argv); /* the zygote contract: first thing in main */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--heap-mb") == 0 && i + 1 < argc) heap_mb = (size_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ifup") == 0 && i + 1 < argc) up = argv[++i];
        else if (strcmp(argv[i], "--framing") == 0 && i + 1 < argc) line_framing = strcmp(argv[++i], "line") == 0;
        else if (strcmp(argv[i], "--plain") == 0 || strcmp(argv[i], "--gvisor") == 0) {}
        else { fprintf(stderr, "usage: %s [--heap-mb N] [--framing http|line] [--plain [--port N] [--ifup IF=IP/PREFIX]] [--gvisor]\n", argv[0]); return 2; }
    }
    if (up && ifup(up) < 0) { perror("counter: ifup"); return 3; }
    heavy_init(heap_mb);
    if (plain) return plain_main(port);
    if (gvisor_mode) return gvisor_main();
    int rc = fz_serve(3, on_fiber);
    if (rc < 0) { perror("counter: fz_serve"); return 1; }
    return 0;
}
