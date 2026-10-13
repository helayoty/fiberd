/* fuzz_gvrecord feeds gv_parse_identity one identity record, held in a
 * buffer of exactly its size so a read past the end crashes. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > GVISOR_RECORD_MAX) return 0;
    char *rec = malloc(size);
    if (!rec) abort();
    memcpy(rec, data, size);

    fz_gvisor_identity_t id;
    memset(&id, 0, sizeof id);
    memset(gv_fence, 0, sizeof gv_fence);
    gv_seed_hex = NULL;
    errno = 0;
    int rc = gv_parse_identity(rec, size, &id);
    if (rc == 0) {
        /* The fence is a copy, non-empty and shorter than FENCE_MAX. */
        if (id.fence != gv_fence || !*id.fence || strlen(id.fence) >= FENCE_MAX) abort();
        /* The seed is exactly 32 decoded bytes, from a hex field in the record. */
        if (id.seed != gv_seed || id.seed_len != GVISOR_SEED) abort();
        if (gv_seed_hex < rec || gv_seed_hex >= rec + size || strlen(gv_seed_hex) < 2 * GVISOR_SEED) abort();
        /* The payload stays within its buffer. */
        if (id.payload != gv_payload || id.payload_len > sizeof gv_payload) abort();
        /* kind and endpoint are fields of the record, and the endpoint is non-empty. */
        if (id.kind < rec || id.kind >= rec + size || id.endpoint < rec || id.endpoint >= rec + size) abort();
        if (!*id.endpoint) abort();
        if (rec[0] != 'i' || rec[size - 1] != 0) abort();
    } else {
        if (rc != -1 || errno != EPROTO) abort();
        if (id.fence || id.seed || id.payload || id.kind || id.endpoint) abort();
    }
    free(rec);
    return 0;
}
