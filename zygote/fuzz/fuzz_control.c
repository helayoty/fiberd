/* fuzz_control drives fz_serve with the bytes an agent would send on the
 * control socket, with descriptors riding along and the REBIND handshake
 * first when asked. No fiber is born. The clone3 syscall is shimmed to
 * fail, so handle_clone parses the line and builds the child's
 * environment, then answers ERROR. Nothing is mounted either. mount,
 * umount2 and mkdir are shimmed to fail, so PREPARE mntns walks
 * prepare_ns over the paths the input named and refuses. A thread
 * drains the replies so a long input cannot wedge the zygote on a full
 * socket.
 *
 * The input is [flags][stream bytes]. Flag 1 sends the first line on a
 * bootstrap socket as the REBIND message, with the control socket riding
 * along. Flag 2 sends two descriptors on the first message. Flag 4 sets
 * an engine endpoint. Flag 8 installs a control handler. Flag 16 has the
 * zygote believe fz_init took it a mount namespace of its own, so
 * PREPARE mntns reaches the mount steps (and their shims) rather than
 * refusing at once. */
#include "common.h"
#include <pthread.h>
#include <sys/stat.h>
long fz_fuzz_syscall(long nr, ...);
int fz_fuzz_mount(const char *src, const char *target, const char *type, unsigned long flags, const void *opts);
int fz_fuzz_umount2(const char *target, int flags);
int fz_fuzz_mkdir(const char *path, mode_t mode);
#define syscall fz_fuzz_syscall
#define mount fz_fuzz_mount
#define umount2 fz_fuzz_umount2
#define mkdir fz_fuzz_mkdir
#include "../libfiberzygote.c"
#undef syscall
#undef mount
#undef umount2
#undef mkdir

long fz_fuzz_syscall(long nr, ...) {
    (void)nr;
    errno = EPERM; /* not ENOSYS, or birth would fall back to a real clone */
    return -1;
}

int fz_fuzz_mount(const char *src, const char *target, const char *type, unsigned long flags, const void *opts) {
    (void)src; (void)target; (void)type; (void)flags; (void)opts;
    errno = EPERM;
    return -1;
}

int fz_fuzz_umount2(const char *target, int flags) {
    (void)target; (void)flags;
    errno = EPERM;
    return -1;
}

int fz_fuzz_mkdir(const char *path, mode_t mode) {
    (void)path; (void)mode;
    errno = EPERM;
    return -1;
}

static int on_fiber(const fz_fiber_t *f) {
    (void)f;
    abort(); /* never born */
}

static void on_control(const char *line) {
    if (strlen(line) >= MAX_LINE) abort();
}

static void *drain(void *arg) {
    int fd = *(int *)arg;
    char buf[4096];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return NULL;
    }
}

/* The zygote keeps what HIDE, DROP and RUNDIR said for the children it
 * will fork. Each input starts from a fresh zygote. */
static void reset_zygote(void) {
    for (int i = 0; i < nhide; i++) free(hide_paths[i]);
    for (int i = 0; i < ndrop; i++) free(drop_paths[i]);
    nhide = ndrop = 0;
    memset(hide_covered, 0, sizeof hide_covered);
    paths_refused = NULL;
    have_own_ns = ns_prepared = 0;
    own_ns_why[0] = 0;
    rundir_parent[0] = rundir_own[0] = 0;
    nkids = npending = ndoomed = 0;
    g_ctl_fd = -1;
    engine_endpoint[0] = 0;
    control_handler = NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    /* With this set fz_serve would write a sysctl and drop a capability. */
    unsetenv("FIBERD_USERNS_NESTED");
    /* fz_serve refuses to run without it, as fz_init leaves it. Before
     * the drain threads, which inherit it. */
    block_sigchld();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    unsigned flags = data[0];
    data++; size--;
    reset_zygote();
    if (flags & 4) fz_set_engine("/run/fiberd/engine.sock");
    if (flags & 8) fz_set_control(on_control);
    if (flags & 16) have_own_ns = 1;

    int s[2];
    stream_pair(SOCK_STREAM, s);
    int ctl_fd = s[0];
    if (flags & 1) {
        /* The first line is the REBIND message. The control socket rides
         * on it, and the harness lets go of its own copy. */
        setenv("FIBERD_CTL_REBIND", "1", 1);
        int boot[2];
        stream_pair(SOCK_STREAM, boot);
        const uint8_t *nl = memchr(data, '\n', size);
        size_t first = nl ? (size_t)(nl - data) + 1 : size;
        if (first) send_fds(boot[1], data, first, &s[0], 1);
        close(boot[1]);
        close(s[0]);
        ctl_fd = boot[0];
        data += first; size -= first;
    } else {
        unsetenv("FIBERD_CTL_REBIND");
    }
    if (size) send_scratch_fds(s[1], data, size, flags & 2 ? 2 : 0);
    if (shutdown(s[1], SHUT_WR) < 0) abort();
    pthread_t t;
    if (pthread_create(&t, NULL, drain, &s[1]) != 0) abort();

    int rc = fz_serve(ctl_fd, on_fiber);
    if (rc != 0 && rc != -1) abort();
    if (npending != 0 || nkids != 0) abort(); /* nothing was ever born */

    close(ctl_fd);
    pthread_join(t, NULL);
    close(s[1]);
    return 0;
}
