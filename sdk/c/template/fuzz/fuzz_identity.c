/* fuzz_identity delivers one message on a fiber's channel, as fiberd
 * queues the incarnation record before the CLONE, and lets
 * read_incarnation take it apart ('i' then eleven NUL-ended fields),
 * with descriptors it must not keep.
 *
 * The input is [descriptor count][message bytes]. An empty message is a
 * closed channel instead. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    size_t nfds = data[0] % 4;
    data++; size--;

    int s[2];
    stream_pair(SOCK_SEQPACKET, s);
    if (size) send_scratch_fds(s[1], data, size, nfds);
    close(s[1]);

    memset(&incarnation, 0, sizeof incarnation);
    memset(&rec_identity, 0, sizeof rec_identity);
    rec_seed_hex = NULL;
    const char *why = NULL;
    int rc = read_incarnation(s[0], &why);
    if (rc == 0) {
        /* Eleven fields, each non-empty and NUL-ended, back to back
         * after the 'i', and together they are the whole message. The
         * fence, kind, endpoint and identity point into the record, the
         * payload, session and seed into their own buffers. */
        const char *gen = record_buf + 1;
        char want[16];
        snprintf(want, sizeof want, "%u", incarnation.generation);
        if (incarnation.generation == 0 || strcmp(gen, want) != 0) abort();
        if (incarnation.kind != gen + strlen(gen) + 1 || !*incarnation.kind) abort();
        if (incarnation.fence != incarnation.kind + strlen(incarnation.kind) + 1) abort();
        if (incarnation.endpoint != incarnation.fence + strlen(incarnation.fence) + 1) abort();
        if (!*incarnation.fence || strlen(incarnation.fence) >= FENCE_MAX || !*incarnation.endpoint) abort();
        if (incarnation.payload != rec_payload || incarnation.payload_len > sizeof rec_payload) abort();
        if (incarnation.session != rec_session || strlen(incarnation.session) >= sizeof rec_session) abort();
        if (incarnation.seed != rec_seed || incarnation.seed_len != SEED_LEN) abort();
        if (!rec_seed_hex || rec_seed_hex < record_buf || rec_seed_hex >= record_buf + size || strlen(rec_seed_hex) != 2 * SEED_LEN) abort();
        if (rec_seed_hex + strlen(rec_seed_hex) + 1 != record_buf + size) abort();
        if (incarnation.identity) {
            const fz_identity_t *id = incarnation.identity;
            if (id != &rec_identity || !*id->key_pem || !*id->cert_pem || !*id->caller || !*id->caller_pem) abort();
            if (id->cert_pem != id->key_pem + strlen(id->key_pem) + 1) abort();
            if (id->caller != id->cert_pem + strlen(id->cert_pem) + 1) abort();
            if (id->caller_pem != id->caller + strlen(id->caller) + 1) abort();
            if (strcmp(id->key_pem, "-") == 0) abort();
        }
        /* The seed is zeroed when the fiber is ready. */
        forget_seed();
        for (size_t i = 0; i < SEED_LEN; i++) if (rec_seed[i]) abort();
        if (rec_seed_hex[0] || incarnation.seed_len != 0) abort();
    } else if (!why) {
        abort();
    }
    close(s[0]);
    return 0;
}
