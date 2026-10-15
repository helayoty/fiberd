/* fuzz_gvrecord feeds parse_incarnation one record, held in a buffer of
 * exactly its size so a read past the end crashes. That is the parser a
 * gVisor sandbox runs on what the pool socket hands it, and the one a
 * forked fiber runs on its channel's first message. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > RECORD_MAX) return 0;
    char *rec = malloc(size);
    if (!rec) abort();
    memcpy(rec, data, size);

    memset(&incarnation, 0, sizeof incarnation);
    memset(&rec_identity, 0, sizeof rec_identity);
    memset(rec_session, 0, sizeof rec_session);
    rec_seed_hex = NULL;
    const char *why = NULL;
    int rc = parse_incarnation(rec, size, &why);
    if (rc == 0) {
        /* The generation is the decimal in the first field, 1 or more. */
        if (incarnation.generation == 0) abort();
        char gen[16];
        snprintf(gen, sizeof gen, "%u", incarnation.generation);
        if (strcmp(gen, rec + 1) != 0) abort();
        /* kind, fence and endpoint are fields of the record, non-empty, and the fence fits. */
        if (incarnation.kind < rec || incarnation.kind >= rec + size || !*incarnation.kind) abort();
        if (incarnation.fence < rec || incarnation.fence >= rec + size || !*incarnation.fence || strlen(incarnation.fence) >= FENCE_MAX) abort();
        if (incarnation.endpoint < rec || incarnation.endpoint >= rec + size || !*incarnation.endpoint) abort();
        /* The seed is exactly 32 decoded bytes, from a hex field of 64 in the record. */
        if (incarnation.seed != rec_seed || incarnation.seed_len != SEED_LEN) abort();
        if (rec_seed_hex < rec || rec_seed_hex >= rec + size || strlen(rec_seed_hex) != 2 * SEED_LEN) abort();
        /* The payload stays within its buffer. */
        if (incarnation.payload != rec_payload || incarnation.payload_len > sizeof rec_payload) abort();
        /* The session is a NUL-ended copy that fits an environment value. */
        if (incarnation.session != rec_session || strlen(incarnation.session) >= sizeof rec_session) abort();
        /* The identity is all four fields or none, each in the record. */
        if (incarnation.identity) {
            const char *f[4] = { incarnation.identity->key_pem, incarnation.identity->cert_pem, incarnation.identity->caller, incarnation.identity->caller_pem };
            for (int i = 0; i < 4; i++) if (f[i] < rec || f[i] >= rec + size || !*f[i] || strcmp(f[i], "-") == 0) abort();
        }
        if (rec[0] != 'i' || rec[size - 1] != 0) abort();
    } else {
        if (rc != -1 || !why) abort();
        if (incarnation.fence || incarnation.seed || incarnation.payload || incarnation.kind || incarnation.endpoint || incarnation.session || incarnation.identity) abort();
    }
    free(rec);
    return 0;
}
