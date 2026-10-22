/* engine_test pins the engine's fence parse in refzygote.c: how a
 * /proc/<pid>/cgroup file becomes a peer's fence (leaf_fence) and how
 * the engine's own file becomes the grant's cgroup directory
 * (grant_dir_of). Both are pure, so this runs anywhere, with no cgroup
 * and no fiber. It also pins which address a fiber's tcp endpoint
 * binds (listen_endpoint), on the loopback. It reaches refzygote.c's
 * statics the way the fuzz harness does, by including the file.
 *
 * Build and run: make zygote-c-test. Prints "ok", or one
 * "--- FAIL: <name>: ..." line per failed case and exits 1. */
#define main refzygote_main
#include "../refzygote.c"
#undef main
#include <stdarg.h>

/* S(x) is a literal with its length, so a case may hold a NUL. */
#define S(x) x, sizeof(x) - 1

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

/* A peer's file against a grant directory. */
static const struct {
    const char *name;
    const char *in; size_t n;
    const char *grant;
    size_t fn;     /* the fence buffer offered, 0 for the full one */
    int want;      /* the rc */
    const char *fence; /* when want is 0 */
} leaf_cases[] = {
    { "a fiber's leaf", S("0::/r/g1/f-1-1\n"), "/r/g1", 0, 0, "g1/1/1" },
    { "a resumed fiber's leaf, a higher seq", S("0::/r/g1/f-1-7\n"), "/r/g1", 0, 0, "g1/1/7" },
    { "a later epoch", S("0::/r/g1/f-42-3\n"), "/r/g1", 0, 0, "g1/42/3" },
    { "a hybrid v1 file, the 0:: line last", S("12:memory:/r/g1/f-1-1\n1:name=systemd:/x\n0::/r/g1/f-2-3\n"), "/r/g1", 0, 0, "g1/2/3" },
    { "a hybrid v1 file, the 0:: line first", S("0::/r/g1/f-2-3\n1:name=systemd:/x\n"), "/r/g1", 0, 0, "g1/2/3" },
    { "a deeper grant directory", S("0::/sys/fs/cgroup/fiberd/d4/f-1-2\n"), "/sys/fs/cgroup/fiberd/d4", 0, 0, "d4/1/2" },
    { "u64 max is accepted", S("0::/r/g1/f-18446744073709551615-18446744073709551615\n"), "/r/g1", 0, 0, "g1/18446744073709551615/18446744073709551615" },
    { "the zygote's leaf", S("0::/r/g1/zygote\n"), "/r/g1", 0, -1, NULL },
    { "a pooled leaf, not f-", S("0::/r/g1/p-1-1\n"), "/r/g1", 0, -1, NULL },
    { "a probe leaf", S("0::/r/g1/probe\n"), "/r/g1", 0, -1, NULL },
    { "the grant directory itself", S("0::/r/g1\n"), "/r/g1", 0, -1, NULL },
    { "another grant's leaf", S("0::/r/g2/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { "a prefix grant, /r/g1 against /r/g10", S("0::/r/g10/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { "a prefix grant the other way, /r/g10 against /r/g1", S("0::/r/g1/f-1-1\n"), "/r/g10", 0, -1, NULL },
    { "junk after seq", S("0::/r/g1/f-1-1x\n"), "/r/g1", 0, -1, NULL },
    { "a space after seq", S("0::/r/g1/f-1-1 \n"), "/r/g1", 0, -1, NULL },
    { "a (deleted) suffix", S("0::/r/g1/f-1-1 (deleted)\n"), "/r/g1", 0, -1, NULL },
    { "a sub-cgroup under the leaf", S("0::/r/g1/f-1-1/sub\n"), "/r/g1", 0, -1, NULL },
    { "a trailing slash", S("0::/r/g1/f-1-1/\n"), "/r/g1", 0, -1, NULL },
    { "a leading zero in epoch", S("0::/r/g1/f-01-1\n"), "/r/g1", 0, -1, NULL },
    { "a leading zero in seq", S("0::/r/g1/f-1-01\n"), "/r/g1", 0, -1, NULL },
    { "a zero epoch", S("0::/r/g1/f-0-1\n"), "/r/g1", 0, -1, NULL },
    { "a zero seq", S("0::/r/g1/f-1-0\n"), "/r/g1", 0, -1, NULL },
    { "an empty epoch", S("0::/r/g1/f--1\n"), "/r/g1", 0, -1, NULL },
    { "an empty seq", S("0::/r/g1/f-1-\n"), "/r/g1", 0, -1, NULL },
    { "no seq at all", S("0::/r/g1/f-1\n"), "/r/g1", 0, -1, NULL },
    { "a plus sign", S("0::/r/g1/f-+1-1\n"), "/r/g1", 0, -1, NULL },
    { "a minus sign", S("0::/r/g1/f-1--1\n"), "/r/g1", 0, -1, NULL },
    { "a hex digit", S("0::/r/g1/f-1a-1\n"), "/r/g1", 0, -1, NULL },
    { "u64 max + 1", S("0::/r/g1/f-18446744073709551616-1\n"), "/r/g1", 0, -1, NULL },
    { "21 digits", S("0::/r/g1/f-100000000000000000000-1\n"), "/r/g1", 0, -1, NULL },
    { "no 0:: line, a pure v1 file", S("12:memory:/r/g1/f-1-1\n1:name=systemd:/x\n"), "/r/g1", 0, -1, NULL },
    { "two 0:: lines", S("0::/r/g1/f-1-1\n0::/r/g1/f-1-2\n"), "/r/g1", 0, -1, NULL },
    { "an unterminated last line", S("0::/r/g1/f-1-1"), "/r/g1", 0, -1, NULL },
    { "an unterminated v1 line after it", S("0::/r/g1/f-1-1\n1:name=systemd:/x"), "/r/g1", 0, -1, NULL },
    { "a carriage return", S("0::/r/g1/f-1-1\r\n"), "/r/g1", 0, -1, NULL },
    { "an embedded NUL in the path", S("0::/r/g1/f-1-1\0\n"), "/r/g1", 0, -1, NULL },
    { "an embedded NUL in a v1 line", S("1:x:/a\0\n0::/r/g1/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { "a NUL where the newline should be", S("0::/r/g1/f-1-1\0"), "/r/g1", 0, -1, NULL },
    { ".. through another grant", S("0::/r/g2/../g1/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { ".. under the grant", S("0::/r/g1/../g1/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { ".. as the leaf", S("0::/r/g1/..\n"), "/r/g1", 0, -1, NULL },
    { "// before the leaf", S("0::/r/g1//f-1-1\n"), "/r/g1", 0, -1, NULL },
    { "// inside the grant directory", S("0:://r/g1/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { "a relative path", S("0::r/g1/f-1-1\n"), "/r/g1", 0, -1, NULL },
    { "an empty path", S("0::\n"), "/r/g1", 0, -1, NULL },
    { "an empty file", S(""), "/r/g1", 0, -1, NULL },
    { "an empty grant directory", S("0::/f-1-1\n"), "", 0, -1, NULL },
    { "a grant directory of /", S("0:://f-1-1\n"), "/", 0, -1, NULL },
    { "the fence buffer one short", S("0::/r/g1/f-1-1\n"), "/r/g1", 6, -1, NULL },
    { "the fence buffer exactly fits", S("0::/r/g1/f-1-1\n"), "/r/g1", 7, 0, "g1/1/1" },
};

/* The engine's own file to its grant directory. */
static const struct {
    const char *name;
    const char *in; size_t n;
    size_t dn;     /* the dir buffer offered, 0 for the full one */
    int want;
    const char *dir; /* when want is 0 */
} dir_cases[] = {
    { "the zygote under a grant", S("0::/r/g1/zygote\n"), 0, 0, "/r/g1" },
    { "a deeper root", S("0::/sys/fs/cgroup/fiberd/d4/zygote\n"), 0, 0, "/sys/fs/cgroup/fiberd/d4" },
    { "a hybrid v1 file", S("1:name=systemd:/x\n0::/r/g1/zygote\n"), 0, 0, "/r/g1" },
    { "runc's cgroupsPath", S("0::/fiberd/g1/zygote\n"), 0, 0, "/fiberd/g1" },
    { "a root-level zygote, parent /", S("0::/zygote\n"), 0, -1, NULL },
    { "the root itself", S("0::/\n"), 0, -1, NULL },
    { "a trailing slash, no last component", S("0::/r/g1/zygote/\n"), 0, -1, NULL },
    { "an empty path", S("0::\n"), 0, -1, NULL },
    { "a relative path", S("0::zygote\n"), 0, -1, NULL },
    { "no 0:: line", S("1:name=systemd:/r/g1/zygote\n"), 0, -1, NULL },
    { "two 0:: lines", S("0::/r/g1/zygote\n0::/r/g2/zygote\n"), 0, -1, NULL },
    { "an unterminated line", S("0::/r/g1/zygote"), 0, -1, NULL },
    { "an embedded NUL", S("0::/r/g1\0/zygote\n"), 0, -1, NULL },
    { "the dir buffer one short", S("0::/r/g1/zygote\n"), 5, -1, NULL },
    { "the dir buffer exactly fits", S("0::/r/g1/zygote\n"), 6, 0, "/r/g1" },
};

/* The two together: the zygote's file names the grant directory, and a
 * peer's file against it names the fence. */
static const struct {
    const char *name;
    const char *zygote; size_t zn;
    const char *peer; size_t pn;
    int want;
    const char *fence;
} pair_cases[] = {
    { "a fiber of the engine's grant", S("0::/r/g1/zygote\n"), S("0::/r/g1/f-1-1\n"), 0, "g1/1/1" },
    { "a fiber of another grant", S("0::/r/g1/zygote\n"), S("0::/r/g2/f-1-1\n"), -1, NULL },
    { "the zygote itself", S("0::/r/g1/zygote\n"), S("0::/r/g1/zygote\n"), -1, NULL },
};

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
    for (size_t i = 0; i < sizeof leaf_cases / sizeof leaf_cases[0]; i++) {
        const char *name = leaf_cases[i].name;
        char fence[128];
        memset(fence, 'x', sizeof fence);
        size_t fn = leaf_cases[i].fn ? leaf_cases[i].fn : sizeof fence;
        int rc = leaf_fence(leaf_cases[i].in, leaf_cases[i].n, leaf_cases[i].grant, fence, fn);
        if (rc != leaf_cases[i].want) { fail(name, "rc = %d, want %d", rc, leaf_cases[i].want); continue; }
        if (rc == 0 && strcmp(fence, leaf_cases[i].fence) != 0) fail(name, "fence = %s, want %s", fence, leaf_cases[i].fence);
        if (rc != 0 && fence[0] != 0) fail(name, "fence not cleared on refusal");
    }
    for (size_t i = 0; i < sizeof dir_cases / sizeof dir_cases[0]; i++) {
        const char *name = dir_cases[i].name;
        char dir[256];
        memset(dir, 'x', sizeof dir);
        size_t dn = dir_cases[i].dn ? dir_cases[i].dn : sizeof dir;
        int rc = grant_dir_of(dir_cases[i].in, dir_cases[i].n, dir, dn);
        if (rc != dir_cases[i].want) { fail(name, "rc = %d, want %d", rc, dir_cases[i].want); continue; }
        if (rc == 0 && strcmp(dir, dir_cases[i].dir) != 0) fail(name, "dir = %s, want %s", dir, dir_cases[i].dir);
    }
    for (size_t i = 0; i < sizeof pair_cases / sizeof pair_cases[0]; i++) {
        const char *name = pair_cases[i].name;
        char dir[256], fence[128];
        if (grant_dir_of(pair_cases[i].zygote, pair_cases[i].zn, dir, sizeof dir) != 0) { fail(name, "the zygote's file was refused"); continue; }
        int rc = leaf_fence(pair_cases[i].peer, pair_cases[i].pn, dir, fence, sizeof fence);
        if (rc != pair_cases[i].want) { fail(name, "rc = %d, want %d", rc, pair_cases[i].want); continue; }
        if (rc == 0 && strcmp(fence, pair_cases[i].fence) != 0) fail(name, "fence = %s, want %s", fence, pair_cases[i].fence);
    }
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
