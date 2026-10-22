/* fuzz_refzygote runs the reference workload's own parsers. conn_line on
 * a fiber's endpoint, serve_http over one request, payload_num over the
 * clone payload, the EVICT control line, and the engine's fence parse
 * over a /proc/<pid>/cgroup file (grant_dir_of for its own, leaf_fence
 * for a peer's). The command dispatch of serve_client is left out, since
 * its commands open, connect and mount wherever a line says. The heap is
 * never set up, so a dirty request touches nothing.
 *
 * The input is [mode][selector][bytes], mode 0 to 4 by the first byte
 * modulo 5. */
#include "common.h"
#define main refzygote_main
#include "../refzygote.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    unsigned mode = data[0] % 5, sel = data[1];
    data += 2; size -= 2;
    switch (mode) {
    case 0: { /* conn_line over a stream of lines, into buffers of each size */
        static const size_t sizes[] = { 2, 8, 64, 256 };
        size_t n = sizes[sel % 4];
        conn_t c;
        memset(&c, 0, sizeof c);
        c.fd = memfd_of(data, size);
        char line[256];
        while (conn_line(&c, line, n))
            if (strlen(line) >= n) abort();
        close(c.fd);
        break;
    }
    case 1: { /* one HTTP request, the reply going to a peer nobody reads */
        int s[2];
        stream_pair(SOCK_STREAM, s);
        if (size) send_fds(s[1], data, size, NULL, 0);
        if (shutdown(s[1], SHUT_WR) < 0) abort();
        conn_t c;
        memset(&c, 0, sizeof c);
        c.fd = s[0];
        unsigned long counter = sel;
        int rc = serve_http(&c, "grant/1/1", &counter);
        if (rc != 0 && rc != -1) abort();
        close(s[0]);
        close(s[1]);
        break;
    }
    case 2: { /* the numbers refzygote reads out of the payload */
        static const char *const keys[] = { "\"ready_delay_ms\"", "\"ready_misuse\"", "\"dirty_bytes\"", "\"device_bytes\"" };
        payload_num(data, size, keys[sel % 4]);
        break;
    }
    case 3: { /* a control line from fiberd: EVICT <fence> or anything else */
        char *line = malloc(size + 1);
        if (!line) abort();
        memcpy(line, data, size);
        line[size] = 0;
        dev_cap = 1 << 20;
        on_control(line);
        free(line);
        ndev = 0;
        dev_used = 0;
        break;
    }
    default: { /* a /proc/<pid>/cgroup file, as the engine's own and as a peer's */
        static const char *const grants[] = { "/r/g1", "/sys/fs/cgroup/fiberd/d4", "/", "" };
        static const size_t sizes[] = { 1, 8, 24, 128 };
        const char *grant = grants[sel % 4];
        size_t fn = sizes[(sel / 4) % 4];
        char dir[256], fence[128];
        memset(dir, 'x', sizeof dir);
        memset(fence, 'x', sizeof fence);
        if (grant_dir_of((const char *)data, size, dir, sizeof dir) == 0 && strnlen(dir, sizeof dir) == sizeof dir) abort();
        int rc = leaf_fence((const char *)data, size, grant, fence, fn);
        /* A fence is NUL-ended within what was offered and starts with
         * the grant's last component. Nothing of a refusal survives. */
        const char *g = strrchr(grant, '/');
        g = g ? g + 1 : grant;
        if (rc == 0 && strnlen(fence, fn) == fn) abort();
        if (rc == 0 && (*g == 0 || strncmp(fence, g, strlen(g)) != 0 || fence[strlen(g)] != '/')) abort();
        if (rc != 0 && fence[0] != 0) abort();
        break;
    }
    }
    return 0;
}
