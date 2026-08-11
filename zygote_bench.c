/* zygote_bench: measure the mechanism behind Clone().
 *
 * warm mode: init a heavy parent once (the zygote), then fork() N children.
 *            Each child dirties a small working set W and reports readiness.
 *            Latency = fork-to-ready per child. Memory = PSS across the family.
 * cold mode: fork+exec a fresh process N times; each pays full init.
 *
 * Build: gcc -O2 -o zb zygote_bench.c
 * Run:   ./zb warm 50 128 4   (50 clones, 128MB zygote heap, 4MB working set)
 *        ./zb cold 10 128
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* "Load the model": allocate heap_mb and touch every page, plus burn some
 * CPU to stand in for JIT/graph-build. This is the cost cold start pays
 * per instance and the zygote pays exactly once. */
static char *heavy_init(int heap_mb) {
    size_t sz = (size_t)heap_mb << 20;
    char *heap = malloc(sz);
    if (!heap) { perror("malloc"); exit(1); }
    for (size_t i = 0; i < sz; i += 4096) heap[i] = (char)(i >> 12);
    volatile unsigned x = 1;                 /* fake graph build */
    for (long i = 0; i < 60L * 1000 * 1000; i++) x = x * 1664525u + 1013904223u;
    (void)x;
    return heap;
}

static int cmp_d(const void *a, const void *b) {
    double d = *(const double *)a - *(const double *)b;
    return d < 0 ? -1 : d > 0 ? 1 : 0;
}

static void report(const char *label, double *lat, int n) {
    qsort(lat, n, sizeof(double), cmp_d);
    double sum = 0; for (int i = 0; i < n; i++) sum += lat[i];
    printf("%s  n=%d  p50=%.2fms  p90=%.2fms  p99=%.2fms  max=%.2fms  mean=%.2fms\n",
           label, n, lat[n/2], lat[(int)(n*0.90)], lat[(int)(n*0.99)],
           lat[n-1], sum/n);
}

static long pss_kb(pid_t pid) {
    char path[64], line[256]; long pss = -1;
    snprintf(path, sizeof path, "/proc/%d/smaps_rollup", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "Pss: %ld kB", &pss) == 1) break;
    fclose(f);
    return pss;
}

/* ---- warm: the zygote path ---- */
static int run_warm(int n, int heap_mb, int ws_mb) {
    double t0 = now_ms();
    char *heap = heavy_init(heap_mb);
    printf("zygote init: %.0fms (heap %dMB)  -- paid ONCE\n", now_ms() - t0, heap_mb);

    int (*pipes)[2] = calloc(n, sizeof(int[2]));
    pid_t *kids = calloc(n, sizeof(pid_t));
    double *start = calloc(n, sizeof(double));
    double *lat = calloc(n, sizeof(double));
    size_t ws = (size_t)ws_mb << 20;

    /* fork storm: launch all N without waiting (concurrent clones) */
    for (int i = 0; i < n; i++) {
        if (pipe(pipes[i])) { perror("pipe"); exit(1); }
        start[i] = now_ms();
        pid_t pid = fork();
        if (pid == 0) {                       /* --- child: a fiber --- */
            close(pipes[i][0]);
            for (size_t j = 0; j < ws && j < (size_t)heap_mb<<20; j += 4096)
                heap[j] ^= 1;                 /* dirty working set W (CoW faults) */
            char c = 'r';
            if (write(pipes[i][1], &c, 1) != 1) _exit(2); /* "serving" */
            pause();                          /* stay resident for PSS measure */
            _exit(0);
        }
        kids[i] = pid;
        close(pipes[i][1]);
    }
    for (int i = 0; i < n; i++) {             /* collect readiness */
        char c;
        if (read(pipes[i][0], &c, 1) != 1) { fprintf(stderr, "child %d failed\n", i); exit(1); }
        lat[i] = now_ms() - start[i];
        close(pipes[i][0]);
    }
    report("warm clone (fork from zygote)", lat, n);

    long parent = pss_kb(getpid()), total = parent > 0 ? parent : 0, ck;
    int counted = 0;
    for (int i = 0; i < n; i++)
        if ((ck = pss_kb(kids[i])) > 0) { total += ck; counted++; }
    if (parent > 0)
        printf("memory: zygote PSS=%ldMB, zygote+%d fibers total PSS=%ldMB "
               "(naive copies would be %ldMB) -> CoW sharing real\n",
               parent >> 10, counted, total >> 10,
               (long)(heap_mb) * (counted + 1));

    for (int i = 0; i < n; i++) kill(kids[i], SIGKILL);
    while (wait(NULL) > 0) {}
    return 0;
}

/* ---- cold: what every instance pays without a zygote ---- */
static int run_cold(int n, int heap_mb, const char *self) {
    double *lat = calloc(n, sizeof(double));
    for (int i = 0; i < n; i++) {
        int p[2]; if (pipe(p)) { perror("pipe"); exit(1); }
        char fdbuf[16], mbbuf[16];
        snprintf(fdbuf, sizeof fdbuf, "%d", p[1]);
        snprintf(mbbuf, sizeof mbbuf, "%d", heap_mb);
        double t0 = now_ms();
        pid_t pid = fork();
        if (pid == 0) {
            close(p[0]);
            execl(self, self, "initonly", mbbuf, fdbuf, (char *)NULL);
            _exit(3);
        }
        close(p[1]);
        char c;
        if (read(p[0], &c, 1) != 1) { fprintf(stderr, "cold child failed\n"); exit(1); }
        lat[i] = now_ms() - t0;
        close(p[0]);
        waitpid(pid, NULL, 0);
    }
    report("cold start (init per instance)", lat, n);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 4 && !strcmp(argv[1], "initonly")) {   /* cold-start child */
        int fd = atoi(argv[3]);
        heavy_init(atoi(argv[2]));
        char c = 'r';
        if (write(fd, &c, 1) != 1) return 2;
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "usage: %s warm N [heapMB] [wsMB] | %s cold N [heapMB]\n",
                argv[0], argv[0]);
        return 1;
    }
    int n = atoi(argv[2]);
    int heap = argc > 3 ? atoi(argv[3]) : 128;
    if (!strcmp(argv[1], "warm")) return run_warm(n, heap, argc > 4 ? atoi(argv[4]) : 4);
    if (!strcmp(argv[1], "cold")) return run_cold(n, heap, argv[0]);
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 1;
}
