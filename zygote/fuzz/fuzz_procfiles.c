/* fuzz_procfiles serves the fuzz input as a file under /proc and runs the
 * parser that reads it, lock_sys over /proc/self/mountinfo or
 * in_child_userns over /proc/self/uid_map. open is shimmed to hand out a
 * memfd, and mount is shimmed to record what was asked and answer as
 * told, so nothing is mounted.
 *
 * The input is [mode and mount verdict][file bytes]. */
#include "common.h"
int fz_fuzz_open(const char *path, int flags, ...);
int fz_fuzz_mount(const char *src, const char *target, const char *type, unsigned long flags, const void *opts);
#define open fz_fuzz_open
#define mount fz_fuzz_mount
#include "../libfiberzygote.c"
#undef open
#undef mount

static const char *proc_path; /* the one path the parser may open */
static int proc_fd = -1;      /* what it gets, once */
static int mount_refused;     /* what the mount shim answers */
static int mounts;

int fz_fuzz_open(const char *path, int flags, ...) {
    if (proc_fd >= 0 && proc_path && strcmp(path, proc_path) == 0 && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = proc_fd;
        proc_fd = -1;
        return fd;
    }
    abort(); /* nothing else may be opened from here */
}

int fz_fuzz_mount(const char *src, const char *target, const char *type, unsigned long flags, const void *opts) {
    (void)src; (void)type; (void)flags; (void)opts;
    mounts++;
    /* lock_sys remounts under /sys and nowhere else. */
    if (strcmp(target, "/sys") != 0 && strncmp(target, "/sys/", 5) != 0) abort();
    if (mount_refused) { errno = EPERM; return -1; }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    unsigned mode = data[0] & 1;
    mount_refused = (data[0] >> 1) & 1;
    data++; size--;
    mounts = 0;
    proc_fd = memfd_of(data, size);
    if (mode == 0) {
        proc_path = "/proc/self/mountinfo";
        int rc = lock_sys();
        /* Only the mounts under /sys are touched, so with one in the
         * table the result follows the mount verdict alone, and with none
         * nothing can fail. The file's contents cannot fail it. */
        if (mounts == 0 && rc != 0) abort();
        if (mounts > 0 && (rc == 0) != (mount_refused == 0)) abort();
    } else {
        proc_path = "/proc/self/uid_map";
        int rc = in_child_userns();
        if (rc != 0 && rc != 1) abort();
        if (mounts != 0) abort();
    }
    if (proc_fd >= 0) abort(); /* the parser must have opened its file */
    return 0;
}
