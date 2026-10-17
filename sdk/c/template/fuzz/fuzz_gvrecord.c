/* fuzz_gvrecord feeds the record parser one record, held in a buffer of
 * exactly its size so a read past the end crashes. That is the parser a
 * gVisor sandbox runs on what the pool socket hands it, and the one a
 * forked fiber runs on its channel's first message. Every caller of it
 * is in the Rust core, so this drives its entry, fz_rs_parse_incarnation
 * (core/src/record.rs), the one they share. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > RECORD_MAX) return 0;
    /* The store is sized to the record, so a read past its end crashes. */
    struct record_store *st = malloc(sizeof *st);
    if (!st) abort();
    memset(st, 0, sizeof *st);
    char *rec = malloc(size);
    if (!rec) abort();
    memcpy(rec, data, size);
    memcpy(st->buf, data, size);
    const char *why = NULL;
    int rc = fz_rs_parse_incarnation(st, size, &why);
    const fz_incarnation_t incarnation = st->inc;
    /* Offsets into st->buf, as offsets into the exact-size copy. */
#define IN_REC(ptr) ((ptr) >= st->buf && (ptr) < st->buf + size)
    if (rc == 0) {
        /* The generation is the decimal in the first field, 1 or more. */
        if (incarnation.generation == 0) abort();
        char gen[16];
        snprintf(gen, sizeof gen, "%u", incarnation.generation);
        if (strcmp(gen, rec + 1) != 0) abort();
        /* kind, fence and endpoint are fields of the record, non-empty, and the fence fits. */
        if (!IN_REC(incarnation.kind) || !*incarnation.kind) abort();
        if (!IN_REC(incarnation.fence) || !*incarnation.fence || strlen(incarnation.fence) >= FENCE_MAX) abort();
        if (!IN_REC(incarnation.endpoint) || !*incarnation.endpoint) abort();
        /* The seed is exactly 32 decoded bytes, from a hex field of 64 in the record. */
        if (incarnation.seed != st->seed || incarnation.seed_len != SEED_LEN) abort();
        if (!IN_REC(st->seed_hex) || strlen(st->seed_hex) != 2 * SEED_LEN) abort();
        /* The payload stays within its buffer. */
        if (incarnation.payload != st->payload || incarnation.payload_len > sizeof st->payload) abort();
        /* The session is a NUL-ended copy that fits an environment value. */
        if (incarnation.session != st->session || strlen(incarnation.session) >= sizeof st->session) abort();
        /* The identity is all four fields or none, each in the record. */
        if (incarnation.identity) {
            const char *f[4] = { incarnation.identity->key_pem, incarnation.identity->cert_pem, incarnation.identity->caller, incarnation.identity->caller_pem };
            for (int i = 0; i < 4; i++) if (!IN_REC(f[i]) || !*f[i] || strcmp(f[i], "-") == 0) abort();
        }
        if (rec[0] != 'i' || rec[size - 1] != 0) abort();
    } else {
        if (rc != -1 || !why) abort();
        if (incarnation.fence || incarnation.seed || incarnation.payload || incarnation.kind || incarnation.endpoint || incarnation.session || incarnation.identity) abort();
    }
    free(rec);
    free(st);
    return 0;
}
