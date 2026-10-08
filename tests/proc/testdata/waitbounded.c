/* waitbounded drives libfiberzygote's wait_bounded, the reaping step the
 * zygote's loop never blocks in, against a real child.
 *
 *   waitbounded alive    the child sleeps on, and the wait must give up
 *                        at its bound
 *   waitbounded killed   the child is killed first, and the wait must
 *                        reap it
 *
 * Prints "<alive|reaped|error> <milliseconds taken>". Built by the tests
 * in tests/proc (see reap_linux_test.go). The library is included as
 * source so a static function can be called. */
#include "../../../zygote/libfiberzygote.c"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: waitbounded alive|killed\n");
        return 2;
    }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) { for (;;) pause(); }
    if (strcmp(argv[1], "killed") == 0) kill(pid, SIGKILL);
    struct timespec t0 = now_ts();
    int status = 0;
    pid_t w = wait_bounded(pid, &status, 100);
    long took = -ms_until(t0);
    printf("%s %ld\n", w == 0 ? "alive" : w == pid ? "reaped" : "error", took);
    if (w == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    return 0;
}
