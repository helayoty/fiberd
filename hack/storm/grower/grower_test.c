/* grower_test pins storm-grower's pure parts: the command line, the
 * dirty command, each worker's descriptors and how a worker's dirtied
 * total grows. It needs no cgroup and forks nothing. It reaches
 * grower.c's statics the way sdk/c/template/test/engine_test.c does, by
 * including the file.
 *
 * Build and run: make storm-grower-test. Prints "ok", or one
 * "--- FAIL: <name>: ..." line per failed case and exits 1. */
#define main grower_main
#include "grower.c"
#undef main
#include <stdarg.h>

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

static const struct {
    const char *name;
    const char *args[6]; /* after argv[0], NULL-terminated */
    int want;
    size_t heap_mb;
    int forks;
} arg_cases[] = {
    { "the shared layout", { "--heap-mb", "64", "--forks", "8", NULL }, 0, 64, 8 },
    { "the separate layout", { "--heap-mb", "64", "--forks", "0", NULL }, 0, 64, 0 },
    { "either order", { "--forks", "8", "--heap-mb", "64", NULL }, 0, 64, 8 },
    { "the most forks", { "--heap-mb", "1", "--forks", "64", NULL }, 0, 1, 64 },
    { "one fork too many", { "--heap-mb", "1", "--forks", "65", NULL }, -1, 0, 0 },
    { "no heap", { "--forks", "8", NULL }, -1, 0, 0 },
    { "no forks", { "--heap-mb", "64", NULL }, -1, 0, 0 },
    { "a zero heap", { "--heap-mb", "0", "--forks", "8", NULL }, -1, 0, 0 },
    { "a heap past the cap", { "--heap-mb", "1048577", "--forks", "8", NULL }, -1, 0, 0 },
    { "a negative fork count", { "--heap-mb", "64", "--forks", "-1", NULL }, -1, 0, 0 },
    { "a value with junk", { "--heap-mb", "64x", "--forks", "8", NULL }, -1, 0, 0 },
    { "an empty value", { "--heap-mb", "", "--forks", "8", NULL }, -1, 0, 0 },
    { "a flag without a value", { "--heap-mb", "64", "--forks", NULL }, -1, 0, 0 },
    { "an unknown flag", { "--heap-mb", "64", "--forks", "8", "--plain", NULL }, -1, 0, 0 },
    { "a value past long", { "--heap-mb", "99999999999999999999", "--forks", "8", NULL }, -1, 0, 0 },
};

static const struct {
    const char *name;
    const char *line;
    int want;
    size_t bytes;
} dirty_cases[] = {
    { "zero", "dirty 0", 0, 0 },
    { "two MiB", "dirty 2097152", 0, 2097152 },
    { "a leading zero", "dirty 07", 0, 7 },
    { "size max", "dirty 18446744073709551615", 0, SIZE_MAX },
    { "size max + 1", "dirty 18446744073709551616", -1, 0 },
    { "21 digits", "dirty 100000000000000000000", -1, 0 },
    { "no number", "dirty ", -1, 0 },
    { "no space", "dirty", -1, 0 },
    { "two spaces", "dirty  1", -1, 0 },
    { "a minus sign", "dirty -1", -1, 0 },
    { "a plus sign", "dirty +1", -1, 0 },
    { "junk after the number", "dirty 12x", -1, 0 },
    { "a trailing space", "dirty 12 ", -1, 0 },
    { "a carriage return", "dirty 12\r", -1, 0 },
    { "another command", "ping", -1, 0 },
    { "a longer verb", "dirtyx 1", -1, 0 },
    { "upper case", "DIRTY 1", -1, 0 },
};

static const struct {
    const char *name;
    int i, in, out;
} fd_cases[] = {
    { "the first worker, and the separate layout's only one", 0, 3, 4 },
    { "the second worker", 1, 5, 6 },
    { "the eighth worker", 7, 17, 18 },
};

/* One step of a worker's growth, on a heap of 4 pages. */
struct step {
    size_t want;
    size_t total;   /* the answer */
    size_t mapped;  /* separate: page-rounded bytes mapped so far */
    int touched;    /* shared: heap pages written so far */
};

static const struct {
    const char *name;
    int shared;
    struct step steps[5];
    int n;
} grow_cases[] = {
    { "shared: page by page", 1,
      { { PAGE, PAGE, 0, 1 }, { 2 * PAGE, 2 * PAGE, 0, 2 } }, 2 },
    { "shared: a part page touches it, the rest of it later touches nothing", 1,
      { { 5000, 5000, 0, 2 }, { 2 * PAGE, 2 * PAGE, 0, 2 }, { 2 * PAGE + 1, 2 * PAGE + 1, 0, 3 } }, 3 },
    { "shared: never down", 1,
      { { 3 * PAGE, 3 * PAGE, 0, 3 }, { PAGE, 3 * PAGE, 0, 3 }, { 0, 3 * PAGE, 0, 3 } }, 3 },
    { "shared: capped at the heap", 1,
      { { 10 * PAGE, 4 * PAGE, 0, 4 }, { 11 * PAGE, 4 * PAGE, 0, 4 } }, 2 },
    { "shared: zero touches nothing", 1,
      { { 0, 0, 0, 0 } }, 1 },
    { "separate: new memory, page-rounded", 0,
      { { 5000, 5000, 2 * PAGE, 0 }, { 3 * PAGE, 3 * PAGE, 3 * PAGE, 0 } }, 2 },
    { "separate: not capped at the heap", 0,
      { { 6 * PAGE, 6 * PAGE, 6 * PAGE, 0 } }, 1 },
    { "separate: never down, and nothing mapped twice", 0,
      { { 2 * PAGE, 2 * PAGE, 2 * PAGE, 0 }, { PAGE, 2 * PAGE, 2 * PAGE, 0 }, { 2 * PAGE, 2 * PAGE, 2 * PAGE, 0 } }, 3 },
    { "separate: a part page past a mapped one maps nothing", 0,
      { { PAGE + 1, PAGE + 1, 2 * PAGE, 0 }, { 2 * PAGE, 2 * PAGE, 2 * PAGE, 0 } }, 2 },
    { "separate: a want whose rounding overflows is refused", 0,
      { { PAGE, PAGE, PAGE, 0 }, { SIZE_MAX, PAGE, PAGE, 0 } }, 2 },
};

/* touched counts heap pages whose first byte was flipped from zero. */
static int touched(const char *heap, size_t sz) {
    int n = 0;
    for (size_t i = 0; i < sz; i += PAGE) n += heap[i] != 0;
    return n;
}

int main(void) {
    for (size_t i = 0; i < sizeof arg_cases / sizeof arg_cases[0]; i++) {
        const char *name = arg_cases[i].name;
        char *argv[8] = { "storm-grower" };
        int argc = 1;
        for (int j = 0; arg_cases[i].args[j]; j++) argv[argc++] = (char *)arg_cases[i].args[j];
        size_t mb = 0;
        int k = -1;
        int rc = parse_args(argc, argv, &mb, &k);
        if (rc != arg_cases[i].want) { fail(name, "rc = %d, want %d", rc, arg_cases[i].want); continue; }
        if (rc == 0 && (mb != arg_cases[i].heap_mb || k != arg_cases[i].forks))
            fail(name, "heap %zu forks %d, want %zu and %d", mb, k, arg_cases[i].heap_mb, arg_cases[i].forks);
    }
    for (size_t i = 0; i < sizeof dirty_cases / sizeof dirty_cases[0]; i++) {
        const char *name = dirty_cases[i].name;
        size_t n = 12345;
        int rc = parse_dirty(dirty_cases[i].line, &n);
        if (rc != dirty_cases[i].want) { fail(name, "rc = %d, want %d", rc, dirty_cases[i].want); continue; }
        if (rc == 0 && n != dirty_cases[i].bytes) fail(name, "bytes = %zu, want %zu", n, dirty_cases[i].bytes);
    }
    for (size_t i = 0; i < sizeof fd_cases / sizeof fd_cases[0]; i++) {
        int in, out;
        worker_fds(fd_cases[i].i, &in, &out);
        if (in != fd_cases[i].in || out != fd_cases[i].out)
            fail(fd_cases[i].name, "fds %d and %d, want %d and %d", in, out, fd_cases[i].in, fd_cases[i].out);
    }
    for (size_t i = 0; i < sizeof grow_cases / sizeof grow_cases[0]; i++) {
        const char *name = grow_cases[i].name;
        struct grower g = { .shared = grow_cases[i].shared, .heap_sz = 4 * PAGE };
        g.heap = calloc(1, g.heap_sz);
        if (!g.heap) { fail(name, "calloc"); continue; }
        for (int s = 0; s < grow_cases[i].n; s++) {
            const struct step *st = &grow_cases[i].steps[s];
            size_t got = grow_to(&g, st->want);
            if (got != st->total) { fail(name, "step %d: total = %zu, want %zu", s, got, st->total); break; }
            if (g.mapped != st->mapped) { fail(name, "step %d: mapped = %zu, want %zu", s, g.mapped, st->mapped); break; }
            int t = touched(g.heap, g.heap_sz);
            if (t != st->touched) { fail(name, "step %d: heap pages touched = %d, want %d", s, t, st->touched); break; }
        }
        free(g.heap);
    }
    if (failed) return 1;
    puts("ok");
    return 0;
}
