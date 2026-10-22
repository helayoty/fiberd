/* storm-grower: the plain processes of the overcommit storm's baseline
 * (hack/storm -plain). They grow as the storm's fibers do, with no
 * fiberd and nothing to park, so the kernel's OOM killer is all that
 * acts.
 *
 *   storm-grower --heap-mb N --forks K
 *
 * K > 0 is the shared layout. The process touches an N MiB heap, then
 * forks K workers that share it copy-on-write, as fibers share their
 * zygote's heap. Worker i reads commands on fd 3+2i and answers on fd
 * 4+2i. The parent only waits for its workers.
 *
 * K = 0 is the separate layout. The process touches its own heap and is
 * its one worker, on fds 3 and 4.
 *
 * Go cannot fork without an exec, so the fork lives here, and storm
 * drives the workers over those pipes. Before it touches anything the
 * process waits for one line on stdin, so storm can first move it into
 * the baseline's cgroup.
 *
 * A worker says "ready" once it serves, then answers one command per
 * line. EOF on its command fd ends it.
 *
 *   dirty <bytes> -> ok <bytes>
 *
 * The worker's dirtied total reaches bytes, and the answer is the total.
 * A shared worker writes the first bytes of the heap, each page becoming
 * a private copy, capped at the heap as in refzygote. A separate worker
 * already owns its heap, so it maps and touches new memory instead, as
 * refzygote does in a restored sandbox. Either way each new byte is new
 * memory, which is the storm's growth.
 *
 * Build: make storm-grower (the Makefile's ZYGOTE_CFLAGS and
 * ZYGOTE_LDFLAGS). Test: make storm-grower-test. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096
#define MAX_FORKS 64
#define MAX_HEAP_MB (1 << 20)

struct grower {
    int shared;     /* forked from the parent that touched the heap */
    char *heap;
    size_t heap_sz;
    size_t done;    /* the dirtied total answered so far */
    size_t mapped;  /* separate only: page-rounded bytes mapped past the heap */
};

/* worker_fds names worker i's command and answer descriptors. */
static void worker_fds(int i, int *in, int *out) {
    *in = 3 + 2 * i;
    *out = 4 + 2 * i;
}

/* parse_args reads --heap-mb and --forks, both required. 0, or -1 for a
 * bad command line. */
static int parse_args(int argc, char **argv, size_t *heap_mb, int *forks) {
    long mb = -1, k = -1;
    for (int i = 1; i < argc; i++) {
        long *dst;
        if (strcmp(argv[i], "--heap-mb") == 0) dst = &mb;
        else if (strcmp(argv[i], "--forks") == 0) dst = &k;
        else return -1;
        if (i + 1 >= argc) return -1;
        char *end;
        errno = 0;
        long v = strtol(argv[++i], &end, 10);
        if (errno || end == argv[i] || *end || v < 0) return -1;
        *dst = v;
    }
    if (mb < 1 || mb > MAX_HEAP_MB || k < 0 || k > MAX_FORKS) return -1;
    *heap_mb = (size_t)mb;
    *forks = (int)k;
    return 0;
}

/* parse_dirty reads "dirty <bytes>", the line without its newline. Only
 * decimal digits after one space, and no overflow. */
static int parse_dirty(const char *line, size_t *bytes) {
    if (strncmp(line, "dirty ", 6) != 0) return -1;
    const char *p = line + 6;
    if (*p < '0' || *p > '9') return -1;
    size_t n = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        size_t d = (size_t)(*p - '0');
        if (n > (SIZE_MAX - d) / 10) return -1;
        n = n * 10 + d;
    }
    *bytes = n;
    return 0;
}

/* page_up rounds n up to a page. -1 when that overflows. */
static int page_up(size_t n, size_t *out) {
    if (n > SIZE_MAX - (PAGE - 1)) return -1;
    *out = (n + PAGE - 1) & ~(size_t)(PAGE - 1);
    return 0;
}

/* grow_to brings the worker's dirtied total to want and returns the
 * total, which never goes down. Only pages not touched before are
 * touched now. A mapping that fails leaves the total where it was. */
static size_t grow_to(struct grower *g, size_t want) {
    if (want <= g->done) return g->done;
    if (g->shared) {
        if (want > g->heap_sz) want = g->heap_sz;
        if (want <= g->done) return g->done;
        size_t from, to;
        if (page_up(g->done, &from) < 0 || page_up(want, &to) < 0) return g->done;
        for (size_t i = from; i < to && i < g->heap_sz; i += PAGE) g->heap[i] ^= 1;
        g->done = want;
        return g->done;
    }
    size_t to;
    if (page_up(want, &to) < 0) return g->done;
    if (to > g->mapped) {
        size_t n = to - g->mapped;
        char *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            fprintf(stderr, "storm-grower: grow %zu: %s\n", n, strerror(errno));
            return g->done;
        }
        for (size_t i = 0; i < n; i += PAGE) p[i] = 1;
        g->mapped = to; /* kept on purpose */
    }
    g->done = want;
    return g->done;
}

/* touch_heap allocates the heap and writes every page, the template's
 * init. */
static int touch_heap(struct grower *g, size_t mb) {
    g->heap_sz = mb << 20;
    g->heap = malloc(g->heap_sz);
    if (!g->heap) return -1;
    for (size_t i = 0; i < g->heap_sz; i += PAGE) g->heap[i] = (char)(i >> 12);
    return 0;
}

/* serve answers commands on in until EOF. */
static int serve(struct grower *g, int in, int out) {
    FILE *f = fdopen(in, "r");
    if (!f) return 1;
    if (dprintf(out, "ready\n") < 0) return 1;
    char line[64];
    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        if (len == 0 || line[len - 1] != '\n') {
            /* Too long for any command: drop the rest of it. */
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {}
            if (dprintf(out, "err line too long\n") < 0) return 1;
            continue;
        }
        line[len - 1] = 0;
        size_t want;
        int rc = parse_dirty(line, &want) == 0
            ? dprintf(out, "ok %zu\n", grow_to(g, want))
            : dprintf(out, "err unknown command\n");
        if (rc < 0) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    size_t heap_mb;
    int forks;
    if (parse_args(argc, argv, &heap_mb, &forks) < 0) {
        fprintf(stderr, "usage: %s --heap-mb N --forks K (0 <= K <= %d)\n", argv[0], MAX_FORKS);
        return 2;
    }
    /* storm places this process, then says go. */
    char go[8];
    if (read(0, go, sizeof go) <= 0) return 1;
    struct grower g = { .shared = forks > 0 };
    if (touch_heap(&g, heap_mb) < 0) { perror("storm-grower: malloc"); return 1; }
    if (forks == 0) return serve(&g, 3, 4);
    for (int i = 0; i < forks; i++) {
        pid_t pid = fork();
        if (pid < 0) { perror("storm-grower: fork"); continue; }
        if (pid == 0) {
            /* A worker keeps only its own pipes, so its answer pipe ends
             * when it does. */
            int in, out;
            worker_fds(i, &in, &out);
            for (int j = 0; j < forks; j++) {
                int a, b;
                worker_fds(j, &a, &b);
                if (j != i) { close(a); close(b); }
            }
            _exit(serve(&g, in, out));
        }
    }
    for (int j = 0; j < forks; j++) {
        int a, b;
        worker_fds(j, &a, &b);
        close(a);
        close(b);
    }
    while (wait(NULL) > 0 || errno == EINTR) {}
    return 0;
}
