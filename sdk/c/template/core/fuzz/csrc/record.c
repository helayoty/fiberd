/* The C record parser as main (4afa97c) had it, frozen here as the
 * oracle the record_diff fuzz target compares the Rust parser with on
 * every input. The parser functions, the store and the constants are
 * copied unchanged from sdk/c/template/libfiberzygote.c at that commit
 * (lines 270-285, 1062-1091 and 1106-1179), only the entries at the end
 * are new. The header is the live one, byte-identical to main's. Nothing
 * here is linked into the library. */
#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "../../../libfiberzygote.h"

#define FENCE_MAX 128
#define ENV_VALUE_MAX 1024

/* An incarnation record, as fiberd's first message on the channel
 * delivers it, as a gVisor sandbox reads it off the pool socket and as
 * a resume sends it again, 'i' then eleven NUL-ended fields (see
 * libfiberzygote.h). It lives in the fiber's memory (the child's copy
 * of these pages), never the zygote's. The bound leaves room for a
 * payload and a caller certificate of any key size, and only the pages
 * a record touches are ever copied. The decoded payload, session and
 * seed live beside it, and the seed is zeroed once used. The birth
 * record stays in born for the fiber's life, since a handoff fiber's
 * TLS library points into it. A record that arrives later, a resume's,
 * lands in polled. */
#define RECORD_MAX 65536
#define RECORD_FIELDS 11
#define SEED_LEN 32
struct record_store {
    /* The small fields come first, so a short record and what is parsed
     * out of it share one page of a fresh fiber's memory. */
    char session[ENV_VALUE_MAX];
    unsigned char seed[SEED_LEN];
    char *seed_hex; /* the seed's field in buf, zeroed with seed */
    fz_identity_t identity;
    fz_incarnation_t inc;
    char buf[RECORD_MAX];
    unsigned char payload[RECORD_MAX / 2];
};

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) {
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (unsigned char)(hi << 4 | lo);
    }
    return n;
}

/* parse_generation reads a generation as the record carries it: decimal
 * digits only, 1 or more, within unsigned. 0 when it is not one. */
static unsigned parse_generation(const char *s) {
    if (!*s || *s == '0') return 0; /* no zero, no leading zero */
    unsigned long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        unsigned d = (unsigned)(*s - '0');
        if (v > (UINT_MAX - d) / 10) return 0;
        v = v * 10 + d;
    }
    return (unsigned)v;
}

/* parse_incarnation takes the record in st->buf, n bytes, apart into
 * the store and fills st->inc from it. Returns 0, or -1 with a reason,
 * and st->inc is then untouched. It allocates nothing and takes no
 * lock, since the fork path runs it before on_fiber (see
 * scrub_and_run). */
static int parse_incarnation(struct record_store *st, size_t n, const char **why) {
    const char *fields[RECORD_FIELDS];
    char *rec = st->buf;
    char *p = rec + 1, *end = rec + n;
    if (n < 2 || rec[0] != 'i' || end[-1] != 0) { *why = "not an incarnation record"; return -1; }
    for (int i = 0; i < RECORD_FIELDS; i++) {
        if (p >= end) { *why = "record has too few fields"; return -1; }
        if (!*p) { *why = "record has an empty field"; return -1; }
        fields[i] = p;
        p += strlen(p) + 1;
    }
    if (p != end) { *why = "record has too many fields"; return -1; }
    unsigned generation = parse_generation(fields[0]);
    if (!generation) { *why = "record names no generation"; return -1; }
    if (strlen(fields[2]) >= FENCE_MAX) { *why = "record fence too long"; return -1; }
    if (strlen(fields[3]) >= ENV_VALUE_MAX) { *why = "record endpoint too long"; return -1; }
    /* The session is bounded and NUL-free as on the CLONE line, since it
     * becomes an environment value. */
    size_t slen = 0;
    if (strcmp(fields[5], "-") != 0) {
        if (strlen(fields[5]) / 2 >= sizeof st->session) { *why = "record session too long"; return -1; }
        slen = unhex(fields[5], (unsigned char *)st->session, sizeof st->session - 1);
        if (memchr(st->session, 0, slen)) { *why = "record session holds a NUL"; return -1; }
    }
    /* A handoff identity is all four fields or none. */
    int set = 0;
    for (int i = 6; i < 10; i++) if (strcmp(fields[i], "-") != 0) set++;
    if (set != 0 && set != 4) { *why = "record identity is incomplete"; return -1; }
    if (strlen(fields[10]) != 2 * SEED_LEN || unhex(fields[10], st->seed, sizeof st->seed) != SEED_LEN) {
        memset(st->seed, 0, sizeof st->seed);
        *why = "record seed is not 32 bytes";
        return -1;
    }
    size_t plen = 0;
    if (strcmp(fields[4], "-") != 0) plen = unhex(fields[4], st->payload, sizeof st->payload);
    st->session[slen] = 0;
    st->seed_hex = (char *)fields[10];
    if (set) {
        st->identity.key_pem = fields[6];
        st->identity.cert_pem = fields[7];
        st->identity.caller = fields[8];
        st->identity.caller_pem = fields[9];
    }
    st->inc.fence = fields[2];
    st->inc.endpoint = fields[3];
    st->inc.payload = st->payload;
    st->inc.payload_len = plen;
    st->inc.session = st->session;
    st->inc.generation = generation;
    st->inc.kind = fields[1];
    st->inc.seed = st->seed;
    st->inc.seed_len = SEED_LEN;
    st->inc.identity = set ? &st->identity : NULL;
    return 0;
}

int fz_c_parse_incarnation(struct record_store *st, size_t n, const char **why) { return parse_incarnation(st, n, why); }
unsigned fz_c_parse_generation(const char *s) { return parse_generation(s); }
size_t fz_c_unhex(const char *s, unsigned char *out, size_t cap) { return unhex(s, out, cap); }
