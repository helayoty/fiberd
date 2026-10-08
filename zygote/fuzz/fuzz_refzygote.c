/* fuzz_refzygote runs the reference workload's own parsers. conn_line on
 * a fiber's endpoint, serve_http over one request, payload_num over the
 * clone payload, unhex, and the EVICT control line. The command dispatch
 * of serve_client is left out, since its commands open, connect and
 * mount wherever a line says. The heap is never set up, so a dirty
 * request touches nothing.
 *
 * The input is [mode][selector][bytes]. */
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
    case 3: { /* hex payload, as the gvisor spec carries it */
        char *hex = malloc(size + 1);
        if (!hex) abort();
        memcpy(hex, data, size);
        hex[size] = 0;
        unsigned char out[64];
        if (unhex(hex, out, sizeof out) > sizeof out) abort();
        free(hex);
        break;
    }
    default: { /* a control line from the agent: EVICT <fence> or anything else */
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
    }
    return 0;
}
