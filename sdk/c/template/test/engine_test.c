/* engine_test pins which address a fiber's tcp endpoint binds
 * (listen_endpoint), on the loopback. It needs no cgroup and no fiber.
 * It reaches refzygote.c's statics the way the fuzz harness does, by
 * including the file.
 *
 * Build and run: make zygote-c-test. Prints "ok", or one
 * "--- FAIL: <name>: ..." line per failed case and exits 1. */
#define main refzygote_main
#include "../refzygote.c"
#undef main
#include <stdarg.h>

static int failed;

__attribute__((format(printf, 2, 3)))
static void fail(const char *name, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "--- FAIL: %s: ", name);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    failed = 1;
}

/* A tcp endpoint to the address its listener binds. fiberd advertises
 * and relays on the endpoint's host, so the fiber binds that host and
 * no wildcard. Port 0 lets the kernel pick one. */
static const struct {
    const char *name;
    const char *ep;
    int family;       /* 0 when the listen fails with EINVAL */
    const char *addr; /* the bound address, when family is set */
} listen_cases[] = {
    { "ipv4 loopback", "tcp://127.0.0.1:0", AF_INET, "127.0.0.1" },
    { "ipv6 loopback", "tcp://[::1]:0", AF_INET6, "::1" },
    { "a hostname, which fiberd never writes", "tcp://localhost:0", 0, NULL },
    { "an ipv4 literal in brackets", "tcp://[127.0.0.1]:0", 0, NULL },
    { "an ipv6 literal without brackets", "tcp://::1:0", 0, NULL },
    { "an empty host", "tcp://:0", 0, NULL },
    { "empty brackets", "tcp://[]:0", 0, NULL },
    { "an unclosed bracket", "tcp://[::1:0", 0, NULL },
    { "no port", "tcp://127.0.0.1", 0, NULL },
    { "a host longer than any literal", "tcp://[1111:2222:3333:4444:5555:6666:7777:8888:9999:aaaa]:0", 0, NULL },
};

/* Whether this host can bind ::1, which a container without IPv6 cannot. */
static int ipv6_loopback(void) {
    int s = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
    struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_addr = in6addr_loopback };
    int ok = bind(s, (struct sockaddr *)&a, sizeof a) == 0;
    close(s);
    return ok;
}

int main(void) {
    for (size_t i = 0; i < sizeof listen_cases / sizeof listen_cases[0]; i++) {
        const char *name = listen_cases[i].name, *ep = listen_cases[i].ep;
        if (listen_cases[i].family == AF_INET6 && !ipv6_loopback()) { fprintf(stderr, "--- SKIP: %s: no IPv6 loopback here\n", name); continue; }
        errno = 0;
        int s = listen_endpoint(ep);
        if (!listen_cases[i].family) {
            if (s >= 0) { close(s); fail(name, "listened on %s, want EINVAL", ep); }
            else if (errno != EINVAL) fail(name, "errno = %s, want EINVAL", strerror(errno));
            continue;
        }
        if (s < 0) { fail(name, "listen %s: %s", ep, strerror(errno)); continue; }
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        char got[INET6_ADDRSTRLEN] = "";
        if (getsockname(s, (struct sockaddr *)&ss, &sl) < 0) fail(name, "getsockname: %s", strerror(errno));
        else if (ss.ss_family != listen_cases[i].family) fail(name, "family = %d, want %d", ss.ss_family, listen_cases[i].family);
        else {
            const void *a = ss.ss_family == AF_INET6 ? (const void *)&((struct sockaddr_in6 *)&ss)->sin6_addr : (const void *)&((struct sockaddr_in *)&ss)->sin_addr;
            inet_ntop(ss.ss_family, a, got, sizeof got);
            if (strcmp(got, listen_cases[i].addr) != 0) fail(name, "bound %s, want %s", got, listen_cases[i].addr);
        }
        close(s);
    }
    if (failed) return 1;
    puts("ok");
    return 0;
}
