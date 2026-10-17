/* fuzz_identity delivers one message on a fiber's channel, as fiberd
 * queues the incarnation record before the CLONE, and lets the child's
 * record read take it apart ('i' then eleven NUL-ended fields), with
 * descriptors it must not keep.
 *
 * The input is [descriptor count][message bytes]. An empty message is a
 * closed channel instead. */
#include "common.h"
#include "../libfiberzygote.c"

/* read_incarnation is the child's, in core/src/child.rs, and private
 * there, since only scrub_and_run calls it. This is the same three
 * steps over the two entries it is made of, fz_rs_channel_recv and
 * fz_rs_parse_incarnation, into the birth record's store, the core's
 * (core/src/fiber.rs), which the fuzzshim archive hands out. */
static int read_incarnation(int fd, struct record_store *born, const char **why) {
    int passed;
    ssize_t r = fz_rs_channel_recv(fd, 0, born->buf, sizeof born->buf, &passed);
    if (passed >= 0) close(passed);
    if (r < 0 && errno == EPROTO) { *why = "record too long"; return -1; }
    if (r < 0) { *why = "recvmsg on the channel failed"; return -1; }
    if (r == 0) { *why = "channel closed before the record arrived"; return -1; }
    return fz_rs_parse_incarnation(born, (size_t)r, why);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    size_t nfds = data[0] % 4;
    data++; size--;

    int s[2];
    stream_pair(SOCK_SEQPACKET, s);
    if (size) send_scratch_fds(s[1], data, size, nfds);
    close(s[1]);

    struct record_store *born = fz_rs_fuzz_born();
    memset(&born->inc, 0, sizeof born->inc);
    memset(&born->identity, 0, sizeof born->identity);
    born->seed_hex = NULL;
    const char *why = NULL;
    int rc = read_incarnation(s[0], born, &why);
    if (rc == 0) {
        /* Eleven fields, each non-empty and NUL-ended, back to back
         * after the 'i', and together they are the whole message. The
         * fence, kind, endpoint and identity point into the record, the
         * payload, session and seed into their own buffers. */
        const char *gen = born->buf + 1;
        char want[16];
        snprintf(want, sizeof want, "%u", born->inc.generation);
        if (born->inc.generation == 0 || strcmp(gen, want) != 0) abort();
        if (born->inc.kind != gen + strlen(gen) + 1 || !*born->inc.kind) abort();
        if (born->inc.fence != born->inc.kind + strlen(born->inc.kind) + 1) abort();
        if (born->inc.endpoint != born->inc.fence + strlen(born->inc.fence) + 1) abort();
        if (!*born->inc.fence || strlen(born->inc.fence) >= FENCE_MAX || !*born->inc.endpoint) abort();
        if (born->inc.payload != born->payload || born->inc.payload_len > sizeof born->payload) abort();
        if (born->inc.session != born->session || strlen(born->inc.session) >= sizeof born->session) abort();
        if (born->inc.seed != born->seed || born->inc.seed_len != SEED_LEN) abort();
        if (!born->seed_hex || born->seed_hex < born->buf || born->seed_hex >= born->buf + size || strlen(born->seed_hex) != 2 * SEED_LEN) abort();
        if (born->seed_hex + strlen(born->seed_hex) + 1 != born->buf + size) abort();
        if (born->inc.identity) {
            const fz_identity_t *id = born->inc.identity;
            if (id != &born->identity || !*id->key_pem || !*id->cert_pem || !*id->caller || !*id->caller_pem) abort();
            if (id->cert_pem != id->key_pem + strlen(id->key_pem) + 1) abort();
            if (id->caller != id->cert_pem + strlen(id->cert_pem) + 1) abort();
            if (id->caller_pem != id->caller + strlen(id->caller) + 1) abort();
            if (strcmp(id->key_pem, "-") == 0) abort();
        }
        /* The seed is zeroed when the fiber is ready, and by
         * fz_seed_forget, which zeroes it the same way. */
        fz_seed_forget();
        for (size_t i = 0; i < SEED_LEN; i++) if (born->seed[i]) abort();
        for (size_t i = 0; i < 2 * SEED_LEN; i++) if (born->seed_hex[i]) abort();
        if (born->inc.seed_len != 0) abort();
    } else if (!why) {
        abort();
    }
    close(s[0]);
    return 0;
}
