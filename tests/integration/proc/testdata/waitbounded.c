/* waitbounded drives libfiberzygote's wait_bounded, the reaping step the
 * zygote's loop never blocks in, against a real child.
 *
 *   waitbounded alive    the child sleeps on, and the wait must give up
 *                        at its bound
 *   waitbounded killed   the child is killed first, and the wait must
 *                        reap it
 *
 * Prints "<alive|reaped|error> <milliseconds taken>". Built by the tests
 * in tests/integration/proc (see reap_linux_test.go) against the core
 * archive built with its testhooks feature, which exports the step as
 * fz_rs_wait_bounded (core/src/zygote.rs). */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

pid_t fz_rs_wait_bounded(pid_t pid, int *status, int ms);

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: waitbounded alive|killed\n");
        return 2;
    }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) { for (;;) pause(); }
    if (strcmp(argv[1], "killed") == 0) kill(pid, SIGKILL);
    long t0 = now_ms();
    int status = 0;
    pid_t w = fz_rs_wait_bounded(pid, &status, 100);
    long took = now_ms() - t0;
    printf("%s %ld\n", w == 0 ? "alive" : w == pid ? "reaped" : "error", took);
    if (w == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    return 0;
}
