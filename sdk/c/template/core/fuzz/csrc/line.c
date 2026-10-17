/* The C line parsers as main (4afa97c) had them, frozen here as the
 * oracle the line_diff fuzz target compares the Rust parsers with on
 * every input. The parsing is copied from sdk/c/template/libfiberzygote.c
 * at that commit, verbatim where it could be. The I/O is cut away. A
 * file is read from a byte buffer, a line comes in as a C string, and
 * what the C code would send, keep or mount is handed back instead. The
 * c_line_* entries are new. Nothing here is linked into the library.
 *
 * The line_diff input format. The first byte picks the parser, that
 * byte modulo C_LINE_PARSERS (7). The rest is that parser's input.
 *
 *   0  CLONE line      c_line_clone
 *   1  RUNDIR line     c_line_rundir
 *   2  any line        c_line_setup_kind and c_line_rebind
 *   3  park message    c_line_round, and c_line_take_round from
 *                      park_round 1 and park_over 0
 *   4  mountinfo       c_line_mountinfo. The second byte is the chunk
 *                      byte (c_line_chunk). Its low 7 bits size the
 *                      reads, and with its high bit set the remount
 *                      callback refuses every mount point. The file is
 *                      the bytes after it.
 *   5  uid_map         c_line_uid_map
 *   6  spec env        c_line_spec_token, into GVISOR_TOKEN_MAX + 1
 *
 * A line parser (0, 1, 2) gets the rest cut as recv_line would hand it
 * over, by c_line_cut. That is the bytes before the first newline or
 * NUL, at most MAX_LINE - 1 of them. A file parser (4, 5, 6) and the
 * park message (3) get the bytes as they are, cut only where the C code
 * reads no further. An input of the selector alone is an empty input.
 *
 * The parsers check no prefix, as in the C file, where read_setup chose
 * the parser by its prefix first (parser 2 has that choice). What has
 * not moved to Rust is not here. keep_path stays in C until stage 3,
 * and fz_serve's dispatch until stage 5. */
#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* At main's values. */
#define MAX_LINE 65536
#define FENCE_MAX 128
#define RUNDIR_MAX 4096
#define ENV_VALUE_MAX 1024
#define RECORD_MAX 65536
#define GVISOR_TOKEN_MAX 64

#define C_LINE_PARSERS 7

/* ---- shared, from main 270-285 and 1108-1119 ---- */

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

/* ---- the CLONE line, from handle_clone at main 1617-1678 ---- */

struct confine {
    int pidns, mntns, nocaps;
};

/* The session named on the CLONE line, decoded, for the fiber's record. */
static char session_buf[ENV_VALUE_MAX];

/* A field of the line as an offset into it and a length, off -1 for a
 * field the line does not have. */
struct c_field {
    ptrdiff_t off;
    size_t len;
};

/* What handle_clone made of a line, up to and including the session's
 * NUL check. */
enum {
    C_CLONE_OK,           /* went on to the state checks and the clone */
    C_CLONE_MALFORMED,    /* "ERROR %.*s malformed CLONE", fence or "?" */
    C_CLONE_FENCE_LONG,   /* "ERROR %.*s fence too long (at most 127 characters)" */
    C_CLONE_SESSION_LONG, /* "ERROR %s session too long (at most 1023 bytes)" */
    C_CLONE_SESSION_NUL,  /* "ERROR %s session holds a NUL byte" */
};

struct c_clone {
    int reason;      /* one of C_CLONE_* */
    int pidns, mntns, nocaps;
    int deadline_ms; /* atoi with the default 50, set once the fence fits, else 0 */
    struct c_field fence, endpoint, deadline, payload, session_hex;
    size_t slen;     /* the decoded session's bytes in session, the NUL check's view */
    unsigned char session[ENV_VALUE_MAX];
};

static struct c_field field_of(const char *line, const char *tok) {
    struct c_field f = { -1, 0 };
    if (tok) { f.off = tok - line; f.len = strlen(tok); }
    return f;
}

/* handle_clone's parsing, the sendf calls turned into reasons. Between
 * the fence check and the deadline, main checks state (mntns refusals,
 * the channel), and after the session it checks the pending table and
 * the endpoint's length. Those stay with the caller. */
static void parse_clone(char *line, struct c_clone *out) {
    char *const start = line;
    /* CLONE <fence> <endpoint> <deadline_ms> <hexpayload|-> <hexsession|-> [opt,opt...] */
    char *save = NULL;
    strtok_r(line, " ", &save);
    const char *fence = strtok_r(NULL, " ", &save);
    const char *endpoint = strtok_r(NULL, " ", &save);
    const char *dl = strtok_r(NULL, " ", &save);
    const char *hex = strtok_r(NULL, " ", &save);
    const char *shex = strtok_r(NULL, " ", &save);
    char *opts = strtok_r(NULL, " ", &save);
    struct confine cf = {0};
    char *osave = NULL;
    for (char *o = opts ? strtok_r(opts, ",", &osave) : NULL; o; o = strtok_r(NULL, ",", &osave)) {
        if (strcmp(o, "pidns") == 0) cf.pidns = 1;
        else if (strcmp(o, "mntns") == 0) cf.mntns = 1;
        else if (strcmp(o, "nocaps") == 0) cf.nocaps = 1;
    }
    out->pidns = cf.pidns;
    out->mntns = cf.mntns;
    out->nocaps = cf.nocaps;
    out->fence = field_of(start, fence);
    out->endpoint = field_of(start, endpoint);
    out->deadline = field_of(start, dl);
    out->payload = field_of(start, hex);
    out->session_hex = field_of(start, shex);
    if (!fence || !endpoint || !dl || !hex || !shex) {
        out->reason = C_CLONE_MALFORMED;
        return;
    }
    if (strlen(fence) >= FENCE_MAX) {
        out->reason = C_CLONE_FENCE_LONG;
        return;
    }
    int deadline_ms = atoi(dl);
    if (deadline_ms <= 0) deadline_ms = 50;
    out->deadline_ms = deadline_ms;
    size_t slen = 0;
    if (strcmp(shex, "-") != 0) {
        if (strlen(shex) / 2 >= sizeof session_buf) {
            out->reason = C_CLONE_SESSION_LONG;
            return;
        }
        slen = unhex(shex, (unsigned char *)session_buf, sizeof session_buf - 1);
        out->slen = slen;
        memcpy(out->session, session_buf, slen);
        if (memchr(session_buf, 0, slen)) {
            out->reason = C_CLONE_SESSION_NUL;
            return;
        }
    }
    session_buf[slen] = 0;
    out->reason = C_CLONE_OK;
}

/* c_line_clone parses line, a CLONE line as a C string, which it cuts
 * up in place as strtok_r does. out is zeroed first, then filled. */
void c_line_clone(char *line, struct c_clone *out) {
    memset(out, 0, sizeof *out);
    parse_clone(line, out);
}

/* ---- the RUNDIR line, set_rundir at main 1750-1767 ---- */

static char rundir_parent[RUNDIR_MAX];
static char rundir_own[RUNDIR_MAX];

/* set_rundir takes "RUNDIR <parent> <own>" apart and keeps the two
 * paths for mount_ns. Both must be absolute and clean, and own must be
 * a direct child of parent (one name, not "." or ".."), since own is
 * made again inside the tmpfs that covers parent. A parent of "/" would
 * cover the root. Returns 0, or -1 with a reason. Runs in the zygote's
 * loop, where allocation would be fine, but the paths go to static
 * storage so the child reads them without any. */
static int set_rundir(char *line, const char **why) {
    char *save = NULL;
    strtok_r(line, " ", &save);
    const char *parent = strtok_r(NULL, " ", &save);
    const char *own = strtok_r(NULL, " ", &save);
    if (!parent || !own || strtok_r(NULL, " ", &save)) { *why = "want RUNDIR <parent> <own>"; return -1; }
    size_t pl = strlen(parent), ol = strlen(own);
    if (pl >= RUNDIR_MAX || ol >= RUNDIR_MAX) { *why = "path too long"; return -1; }
    if (parent[0] != '/' || own[0] != '/') { *why = "want absolute paths"; return -1; }
    if (pl == 1) { *why = "parent must not be /"; return -1; }
    if (parent[pl - 1] == '/' || own[ol - 1] == '/' || strstr(parent, "//") || strstr(own, "//")) { *why = "want clean paths"; return -1; }
    if (ol <= pl + 1 || strncmp(own, parent, pl) != 0 || own[pl] != '/') { *why = "own must be under parent"; return -1; }
    const char *name = own + pl + 1;
    if (strchr(name, '/') || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) { *why = "own must be a direct child of parent"; return -1; }
    memcpy(rundir_parent, parent, pl + 1);
    memcpy(rundir_own, own, ol + 1);
    return 0;
}

struct c_rundir {
    const char *why; /* NULL when kept, else the reason, a static string */
    char parent[RUNDIR_MAX];
    char own[RUNDIR_MAX];
};

/* c_line_rundir parses line, a RUNDIR line as a C string, cut up in
 * place. Returns 0 with both paths kept in out, or -1 with out->why set
 * and both paths empty. */
int c_line_rundir(char *line, struct c_rundir *out) {
    rundir_parent[0] = rundir_own[0] = 0;
    out->why = NULL;
    int rc = set_rundir(line, &out->why);
    memcpy(out->parent, rundir_parent, strlen(rundir_parent) + 1);
    memcpy(out->own, rundir_own, strlen(rundir_own) + 1);
    return rc;
}

/* ---- line classification, read_setup at main 1906-1934 and
 * rebind_ctl at 1865-1880 ---- */

enum {
    C_SETUP_PATH,          /* HIDE / or DROP /, to keep_path */
    C_SETUP_RUNDIR,        /* RUNDIR , to set_rundir */
    C_SETUP_PREPARE_MNTNS, /* PREPARE mntns, ends the setup */
    C_SETUP_PREPARE_NONE,  /* PREPARE none, ends the setup */
    C_SETUP_OTHER,         /* a protocol error before READY */
};

/* c_line_setup_kind says what read_setup does with line, a C string. */
int c_line_setup_kind(const char *line) {
    if (strncmp(line, "HIDE /", 6) == 0 || strncmp(line, "DROP /", 6) == 0) {
        return C_SETUP_PATH;
    } else if (strncmp(line, "RUNDIR ", 7) == 0) {
        return C_SETUP_RUNDIR;
    } else if (strcmp(line, "PREPARE mntns") == 0) {
        return C_SETUP_PREPARE_MNTNS;
    } else if (strcmp(line, "PREPARE none") == 0) {
        return C_SETUP_PREPARE_NONE;
    } else {
        return C_SETUP_OTHER;
    }
}

/* c_line_rebind is 1 when line, a C string, is the REBIND rebind_ctl
 * takes, else 0. */
int c_line_rebind(const char *line) {
    return strcmp(line, "REBIND") == 0;
}

/* ---- park rounds, record_round and take_round at main 1487-1500 ---- */

static char channel_msg[RECORD_MAX];
static unsigned park_round;
static int park_over;

/* record_round is the one decimal field of a 'p' or 'c' record in
 * channel_msg, n bytes, or 0 for none. */
static unsigned record_round(size_t n) {
    if (n < 3 || channel_msg[n - 1] != 0) return 0;
    return parse_generation(channel_msg + 1);
}

/* take_round notes a park message: 'p' names the round to answer, and
 * 'c' ends the round it names. 1 when the message was one of those. */
static int take_round(size_t n) {
    switch (channel_msg[0]) {
    case 'p': park_round = record_round(n); park_over = 0; return 1;
    case 'c': if (record_round(n) == park_round) park_over = 1; return 1;
    default: return 0;
    }
}

/* load_msg puts n bytes of msg in channel_msg, at most RECORD_MAX, as a
 * receive into it would. An empty message reads as kind 0. */
static size_t load_msg(const unsigned char *msg, size_t n) {
    if (n > RECORD_MAX) n = RECORD_MAX;
    /* Not a store before the memcpy, which gcc -O2 drops when n is 0. */
    if (n == 0) channel_msg[0] = 0;
    else memcpy(channel_msg, msg, n);
    return n;
}

/* c_line_round is record_round over msg, n bytes. */
unsigned c_line_round(const unsigned char *msg, size_t n) {
    return record_round(load_msg(msg, n));
}

/* c_line_take_round is take_round over msg, n bytes, from the state in
 * *round and *over, which it updates. Returns 1 for a 'p' or 'c'. */
int c_line_take_round(const unsigned char *msg, size_t n, unsigned *round, int *over) {
    n = load_msg(msg, n);
    park_round = *round;
    park_over = *over;
    int rc = take_round(n);
    *round = park_round;
    *over = park_over;
    return rc;
}

/* ---- mountinfo, unescape_mount at main 475-486 and lock_sys at
 * 583-631 ---- */

/* unescape_mount undoes mountinfo's octal escapes (\040 for a space) in
 * place. */
static void unescape_mount(char *s) {
    char *w = s;
    for (; *s; s++, w++) {
        if (s[0] == '\\' && s[1] >= '0' && s[1] <= '7' && s[2] >= '0' && s[2] <= '7' && s[3] >= '0' && s[3] <= '7') {
            *w = (char)((s[1] - '0') * 64 + (s[2] - '0') * 8 + (s[3] - '0'));
            s += 3;
        } else {
            *w = *s;
        }
    }
    *w = 0;
}

/* The file lock_sys reads, fed from a buffer at most chunk bytes a
 * read, and the remount it asks for, handed to the caller. */
static const unsigned char *feed;
static size_t feed_left, feed_chunk;
static int (*remount_fn)(void *ctx, const char *mp);
static void *remount_ctx;

static ssize_t feed_read(char *dst, size_t cap) {
    size_t k = feed_left < cap ? feed_left : cap;
    if (k > feed_chunk) k = feed_chunk;
    memcpy(dst, feed, k);
    feed += k;
    feed_left -= k;
    return (ssize_t)k;
}

static int ro_remount(const char *path) {
    return remount_fn(remount_ctx, path);
}

/* lock_sys with the read from feed_read, and without the open, the
 * close and the cover of /sys/firmware after the loop. */
static int lock_sys(void) {
    int rc = 0;
    char buf[8192];
    size_t have = 0;
    int skipping = 0; /* inside a line too long for buf */
    for (;;) {
        ssize_t n = feed_read(buf + have, sizeof buf - have);
        if (n == 0) break; /* EOF. mountinfo ends every line with '\n' */
        have += (size_t)n;
        size_t start = 0;
        char *nl;
        while ((nl = memchr(buf + start, '\n', have - start)) != NULL) {
            *nl = 0;
            if (skipping) {
                skipping = 0;
            } else {
                /* 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
                 * (0)(1)(2)  (3)   (4) is the mount point */
                char *save = NULL, *mp = NULL;
                int i = 0;
                for (char *tok = strtok_r(buf + start, " ", &save); tok; tok = strtok_r(NULL, " ", &save))
                    if (i++ == 4) { mp = tok; break; }
                if (mp) {
                    unescape_mount(mp);
                    if ((strcmp(mp, "/sys") == 0 || strncmp(mp, "/sys/", 5) == 0) && ro_remount(mp) < 0) rc = -1;
                }
            }
            start = (size_t)(nl - buf) + 1;
        }
        if (start == 0 && have == sizeof buf) {
            skipping = 1; /* no newline in a full buffer, so drop it and finish the line next read */
            have = 0;
        } else {
            memmove(buf, buf + start, have - start);
            have -= start;
        }
    }
    return rc;
}

/* c_line_chunk maps parser 4's chunk byte to the read size, 1 to 64
 * bytes for the low 7 bits below 64, else 128 to 8192 in steps of 128.
 * The high bit is the remount verdict and plays no part here. */
size_t c_line_chunk(unsigned char b) {
    unsigned c = b & 0x7f;
    return c < 64 ? c + 1 : (c - 63) * 128;
}

/* c_line_mountinfo runs lock_sys's loop over the n bytes of data as
 * /proc/self/mountinfo, read at most chunk bytes at a time (at least 1).
 * remount gets every mount point lock_sys would remount read-only, in
 * order, and answers as ro_remount would, 0 or -1. Returns lock_sys's
 * rc from the loop, 0 or -1. */
int c_line_mountinfo(const unsigned char *data, size_t n, size_t chunk,
                     int (*remount)(void *ctx, const char *mp), void *ctx) {
    feed = data;
    feed_left = n;
    feed_chunk = chunk ? chunk : 1;
    remount_fn = remount;
    remount_ctx = ctx;
    return lock_sys();
}

/* ---- uid_map, in_child_userns at main 1772-1784 ---- */

/* in_child_userns with the n bytes of data as /proc/self/uid_map, of
 * which the one read takes at most sizeof buf - 1. */
static int in_child_userns(const unsigned char *data, size_t len) {
    char buf[128];
    ssize_t n = (ssize_t)(len < sizeof buf - 1 ? len : sizeof buf - 1);
    memcpy(buf, data, (size_t)n);
    if (n <= 0) return 0;
    buf[n] = 0;
    unsigned long inside, outside, count;
    if (sscanf(buf, "%lu %lu %lu", &inside, &outside, &count) != 3) return 0;
    return !(inside == 0 && outside == 0 && count == 4294967295UL);
}

/* c_line_uid_map is 1 when data, n bytes of uid_map, names a user
 * namespace other than the initial one, else 0. */
int c_line_uid_map(const unsigned char *data, size_t n) {
    return in_child_userns(data, n);
}

/* ---- the spec environment, spec_token at main 2055-2071 ---- */

/* spec_token copies FIBERD_TOKEN out of the spec environment, KEY=VALUE
 * entries separated by NUL or newline. 0 when it is not there. Here the
 * file is data, n bytes, of which the reads take at most sizeof buf - 1. */
static int spec_token(const unsigned char *data, size_t size, char *out, size_t n) {
    static char buf[65536];
    ssize_t got = (ssize_t)(size < sizeof buf - 1 ? size : sizeof buf - 1);
    memcpy(buf, data, (size_t)got);
    if (got <= 0) return 0;
    buf[got] = 0;
    for (ssize_t i = 0; i < got; i++) if (buf[i] == '\n') buf[i] = 0;
    for (char *p = buf; p < buf + got; p += strlen(p) + 1) {
        if (strncmp(p, "FIBERD_TOKEN=", 13) != 0) continue;
        size_t len = strlen(p + 13);
        if (len == 0 || len >= n) return 0;
        memcpy(out, p + 13, len + 1);
        return 1;
    }
    return 0;
}

/* c_line_spec_token looks for FIBERD_TOKEN in data, n bytes of the spec
 * environment. Returns 1 with the token, NUL-ended, in out (cap bytes),
 * or 0 with out untouched. */
int c_line_spec_token(const unsigned char *data, size_t n, char *out, size_t cap) {
    return spec_token(data, n, out, cap);
}

/* ---- the input format ---- */

/* c_line_cut copies a line parser's input into out, cap bytes, as
 * recv_line hands a line over. That is the bytes before the first
 * newline or NUL, at most MAX_LINE - 1 and at most cap - 1 of them,
 * then a NUL. Returns the line's length. */
size_t c_line_cut(const unsigned char *data, size_t n, char *out, size_t cap) {
    size_t k = 0;
    if (cap == 0) return 0;
    while (k < n && k + 1 < cap && k + 1 < MAX_LINE && data[k] != '\n' && data[k] != 0) {
        out[k] = (char)data[k];
        k++;
    }
    out[k] = 0;
    return k;
}
