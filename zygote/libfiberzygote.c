/* See libfiberzygote.h. Linux only: clone3, close_range, getrandom. */
#define _GNU_SOURCE
#include "libfiberzygote.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <endian.h>
#include <stddef.h>

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#define MAX_LINE 65536
#define MAX_KIDS 4096
#define MAX_PENDING 1024
#define MAX_PATHS 16

extern char **environ;

static int ready_fd = -1;

/* paths_refused says why a HIDE, DROP or RUNDIR line was refused, or is
 * NULL. A mntns fiber would then run with less hidden than the agent
 * asked for, so every later mntns CLONE is refused instead. */
static const char *paths_refused;

/* What a mntns fiber must not see (HIDE, covered) or keep (DROP,
 * unmounted), as the agent sent them. */
static char *hide_paths[MAX_PATHS];
static int nhide;
static char *drop_paths[MAX_PATHS];
static int ndrop;

/* The agent's run directory and this grant's directory in it (RUNDIR),
 * in static storage the child reads without allocating. Empty until the
 * agent sends them. */
#define RUNDIR_MAX 4096
static char rundir_parent[RUNDIR_MAX];
static char rundir_own[RUNDIR_MAX];

/* The control channel, once fz_serve has it, for lines sent from other
 * threads (fz_report); one mutex keeps lines whole. */
static int g_ctl_fd = -1;
static pthread_mutex_t g_ctl_mu = PTHREAD_MUTEX_INITIALIZER;
static char engine_endpoint[256];
static fz_on_control control_handler;

/* Fibers that reported ready: pid -> fence, for EXITED lines. */
static struct {
    pid_t pid;
    char fence[128];
} kids[MAX_KIDS];
static int nkids;

/* Children forked but not yet ready. The main loop polls every ready
 * pipe at once, so a storm of CLONEs is forked back to back and each is
 * acknowledged the moment its own child reports, never behind the
 * others. */
static struct {
    pid_t pid;
    int ready_fd;
    char fence[128];
    struct timespec deadline;
} pending[MAX_PENDING];
static int npending;

static struct timespec now_ts(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
}

static long ms_until(struct timespec t) {
    struct timespec n = now_ts();
    return (t.tv_sec - n.tv_sec) * 1000 + (t.tv_nsec - n.tv_nsec) / 1000000;
}

/* ---- small I/O helpers ---- */

static int write_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, buf, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        buf += w; n -= (size_t)w;
    }
    return 0;
}

static int sendf(int fd, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int sendf(int fd, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    buf[n++] = '\n';
    pthread_mutex_lock(&g_ctl_mu);
    int rc = write_all(fd, buf, (size_t)n);
    pthread_mutex_unlock(&g_ctl_mu);
    return rc;
}

void fz_set_engine(const char *endpoint) {
    snprintf(engine_endpoint, sizeof engine_endpoint, "%s", endpoint ? endpoint : "");
}

void fz_set_control(fz_on_control handler) { control_handler = handler; }

int fz_report(const char *fmt, ...) {
    if (g_ctl_fd < 0) return -1;
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    buf[n++] = '\n';
    pthread_mutex_lock(&g_ctl_mu);
    int rc = write_all(g_ctl_fd, buf, (size_t)n);
    pthread_mutex_unlock(&g_ctl_mu);
    return rc;
}

/* Read one line; descriptors riding along via SCM_RIGHTS land in fds_out
 * in order (unused slots -1, extras closed). Returns line length, 0 on
 * EOF, -1 on error. A partial line at EOF is returned NUL-terminated.
 *
 * The line is read in two steps rather than a byte at a time: a peek
 * (MSG_PEEK, no control buffer, so nothing is installed) shows where the
 * newline is, then exactly that much is read with the control buffer.
 * The descriptors stay attached to the right line because an AF_UNIX
 * stream read, peeking or not, never crosses from one message's data into
 * another's when their SCM_RIGHTS differ: a read that returns descriptors
 * returns only bytes they were sent with, and the agent sends them on the
 * CLONE line alone. A read may still stop short of the newline (a long
 * line split into several buffers), so the loop goes on from there. */
#define MAX_PASSED 2
static ssize_t recv_line(int fd, char *buf, size_t cap, int fds_out[MAX_PASSED]) {
    size_t len = 0;
    int nfds = 0;
    for (int i = 0; i < MAX_PASSED; i++) fds_out[i] = -1;
    while (len + 1 < cap) {
        struct iovec iov = { .iov_base = buf + len, .iov_len = cap - 1 - len };
        struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
        ssize_t r = recvmsg(fd, &mh, MSG_PEEK);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { buf[len] = 0; return len ? (ssize_t)len : 0; }
        char *nl = memchr(buf + len, '\n', (size_t)r);
        size_t want = nl ? (size_t)(nl - (buf + len)) + 1 : (size_t)r;
        char cbuf[CMSG_SPACE(4 * sizeof(int))];
        iov.iov_len = want;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof cbuf;
        r = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { buf[len] = 0; return len ? (ssize_t)len : 0; }
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
            size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < n; i++) {
                int got;
                memcpy(&got, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
                if (nfds < MAX_PASSED) fds_out[nfds++] = got;
                else close(got);
            }
        }
        len += (size_t)r;
        if (buf[len - 1] == '\n') { buf[len - 1] = 0; return (ssize_t)len; }
    }
    errno = EMSGSIZE;
    return -1;
}

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

/* ---- child bookkeeping ---- */

static void remember(pid_t pid, const char *fence) {
    if (nkids >= MAX_KIDS) return;
    kids[nkids].pid = pid;
    snprintf(kids[nkids].fence, sizeof kids[nkids].fence, "%s", fence);
    nkids++;
}

static void forget(pid_t pid) {
    for (int i = 0; i < nkids; i++)
        if (kids[i].pid == pid) { kids[i] = kids[--nkids]; return; }
}

static void drop_pending(int i) {
    close(pending[i].ready_fd);
    pending[i] = pending[--npending];
}

static int pending_index(pid_t pid) {
    for (int i = 0; i < npending; i++)
        if (pending[i].pid == pid) return i;
    return -1;
}

static void send_died(int ctl_fd, const char *fence, int status) {
    if (WIFSIGNALED(status))
        sendf(ctl_fd, "ERROR %s died before ready: signal:%d", fence, WTERMSIG(status));
    else
        sendf(ctl_fd, "ERROR %s died before ready: exit:%d", fence, WEXITSTATUS(status));
}

static void reap(int ctl_fd) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        int i = pending_index(pid);
        if (i >= 0) { /* died before it ever reported ready */
            send_died(ctl_fd, pending[i].fence, status);
            drop_pending(i);
            continue;
        }
        forget(pid);
        if (WIFSIGNALED(status))
            sendf(ctl_fd, "EXITED %d signal:%d", (int)pid, WTERMSIG(status));
        else
            sendf(ctl_fd, "EXITED %d exit:%d", (int)pid, WEXITSTATUS(status));
    }
}

/* ---- birth ---- */

/* birth forks the fiber straight into its leaf cgroup. With pidns the
 * child is the init of its own pid namespace (pid 1 inside), so a
 * checkpoint of it restores anywhere without colliding with a live pid.
 * With mntns it gets a mount namespace of its own. Both need
 * CAP_SYS_ADMIN, and a namespace the kernel refuses fails the birth: no
 * fiber runs without one it was asked to have.
 *
 * A kernel without clone3, or without CLONE_INTO_CGROUP (before 5.7),
 * gets the legacy clone with the same namespace flags. The child then
 * moves itself into its leaf before it touches memory, so the window is
 * its first instructions only. A child that cannot reach its leaf ends
 * there with exit 125: it must not run charged to the zygote's cgroup.
 * Both calls are the raw syscall, so the child runs on a copy of this
 * stack with no atfork handlers, under the rule above scrub_and_run. */
static pid_t birth(int cgroup_fd, unsigned long long want) {
    struct clone_args args;
    memset(&args, 0, sizeof args);
    args.exit_signal = SIGCHLD;
    args.flags = want;
    if (cgroup_fd >= 0) {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = (unsigned long long)cgroup_fd;
    }
    long pid = syscall(SYS_clone3, &args, sizeof args);
    if (pid >= 0) return (pid_t)pid;
    if (errno != ENOSYS && errno != EINVAL && errno != E2BIG) return -1;
    /* flags, then a zero stack (the child's is this one, copied) and
     * zero tids and tls, in whichever order the architecture takes them. */
    pid = syscall(SYS_clone, (unsigned long)(want | SIGCHLD), 0UL, 0UL, 0UL, 0UL);
    if (pid == 0 && cgroup_fd >= 0) {
        int procs = openat(cgroup_fd, "cgroup.procs", O_WRONLY | O_CLOEXEC);
        if (procs < 0) _exit(125);
        /* "0" is the writer itself, whatever its pid namespace. */
        if (write(procs, "0", 1) < 0) _exit(125);
        close(procs);
    }
    return (pid_t)pid;
}

/* Exit codes of a child that could not be confined. New codes go at the
 * end: the agent's tests name the existing ones. */
enum { EX_MNT_PRIVATE = 110, EX_MNT_PROC, EX_MNT_DROP, EX_MNT_HIDE, EX_CAPS, EX_MNT_RO, EX_MNT_RUNDIR, EX_USERNS };

/* ro_remount makes the mount at path read-only in this namespace alone.
 * MS_REMOUNT|MS_BIND changes the per-mount flags, not the superblock, so
 * the agent and the host keep writing through their own mounts of the
 * same filesystem; the flags are set outright, so nosuid, nodev and
 * noexec are restated. It needs no bind first: any mount point will do. */
static int ro_remount(const char *path) {
    return mount(NULL, path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
}

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

/* lock_controls takes away the fiber's write access to the kernel's
 * knobs. The fiber is euid 0 in the initial user namespace with every
 * capability dropped, and sysctl and kernfs (cgroup, sysfs) check the
 * owner write bit for euid 0 and ask for no capability: without this,
 * /proc/sys/kernel/core_pattern and modprobe are host root, and
 * /sys/fs/cgroup lifts the fiber's own and other grants' limits. A
 * read-only mount is what stands in the way, since the check happens in
 * the fiber's mount namespace.
 *
 *   - /proc/sys is a directory of the proc mount, not a mount of its
 *     own, so it is bound onto itself to have a mount to make read-only.
 *     A first MS_BIND ignores MS_RDONLY; only the remount applies it.
 *     Called after the fresh /proc, it covers the /proc the fiber sees.
 *   - All of /sys, every mount under it included, is made read-only in
 *     place: sysfs has knobs of its own writable by euid 0 (/sys/kernel,
 *     /sys/module/<m>/parameters), and the cgroup mount is under it.
 *     Changing the flags of the existing mounts rather than stacking a
 *     bind on each keeps the tree CRIU dumps the same shape (no mount is
 *     overmounted, nothing new to match on restore); CRIU restores the
 *     flags with the mounts, so a resumed fiber is as closed as a born
 *     one. The fiber loses nothing it may use: a process without
 *     capabilities has no business writing under /sys, and reading
 *     (cpu topology, cgroup limits) still works. Where /sys has no
 *     mounts (a rootfs without sysfs) there is nothing to do.
 *
 * This runs in the child right after clone3, while the zygote's other
 * threads (an engine) may hold malloc's lock: nothing here allocates.
 * mountinfo is read with the raw syscalls into a stack buffer and the
 * lines are split by hand; a line split across two reads is carried
 * over, and one longer than the buffer is skipped to its newline rather
 * than misread as several (no mount under /sys has a name that long).
 *
 * Every mount is tried whatever happened to the ones before it, so one
 * refusal leaves as little writable as possible. Returns 0, or -1 when
 * any step failed. */
static int lock_controls(void) {
    int rc = 0;
    if (mount("/proc/sys", "/proc/sys", NULL, MS_BIND, NULL) < 0 || ro_remount("/proc/sys") < 0) rc = -1;
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[8192];
    size_t have = 0;
    int skipping = 0; /* inside a line too long for buf */
    for (;;) {
        ssize_t n = read(fd, buf + have, sizeof buf - have);
        if (n < 0) { if (errno == EINTR) continue; rc = -1; break; }
        if (n == 0) break; /* EOF; mountinfo ends every line with '\n' */
        have += (size_t)n;
        size_t start = 0;
        char *nl;
        while ((nl = memchr(buf + start, '\n', have - start)) != NULL) {
            *nl = 0;
            if (skipping) {
                skipping = 0;
            } else {
                /* 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
                 * (0)(1)(2)  (3)   (4): the mount point */
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
            skipping = 1; /* no newline in a full buffer: drop it, finish the line next read */
            have = 0;
        } else {
            memmove(buf, buf + start, have - start);
            have -= start;
        }
    }
    int e = errno;
    close(fd);
    errno = e;
    return rc;
}

/* fd_path writes "/proc/self/fd/<fd>" to buf (at least 32 bytes), by
 * hand: no stdio in the child (see the rule at scrub_and_run). */
static void fd_path(char *buf, int fd) {
    static const char pfx[] = "/proc/self/fd/";
    char d[16];
    size_t n = sizeof d;
    unsigned v = (unsigned)fd;
    do { d[--n] = (char)('0' + v % 10); v /= 10; } while (v);
    memcpy(buf, pfx, sizeof pfx - 1);
    memcpy(buf + sizeof pfx - 1, d + n, sizeof d - n);
    buf[sizeof pfx - 1 + sizeof d - n] = 0;
}

/* narrow_rundir leaves the fiber one directory of the agent's run
 * directory: its own grant's. Every grant's directory (endpoint sockets,
 * fence files, the zygote's log) sits under one parent, and a fiber is
 * euid 0, so without this a fiber of one grant could unlink or rebind
 * another grant's sockets. The parent is covered with an empty read-only
 * tmpfs, in this namespace alone, and the grant's own directory is bound
 * back at its place from a descriptor opened before the cover, so what
 * the fiber creates there (its endpoint) lands in the agent's real
 * directory and what the agent writes there (a fence file) is seen.
 * The cwd is moved onto the bind so the checkpoint names it through the
 * mount that will exist on restore. CRIU dumps the tmpfs with its one
 * empty directory and the bind as an external mount the agent names on
 * restore, so a resumed fiber is bound to the resuming grant's
 * directory. Nothing here allocates. Returns 0, or -1, and the child
 * then ends. */
static int narrow_rundir(void) {
    int fd = open(rundir_own, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    if (mount("tmpfs", rundir_parent, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64k,mode=0755") < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    char src[32];
    fd_path(src, fd);
    int rc = 0;
    if (mkdir(rundir_own, 0755) < 0 ||
        mount(src, rundir_own, NULL, MS_BIND, NULL) < 0 ||
        mount(NULL, rundir_parent, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64k") < 0 ||
        chdir(rundir_own) < 0)
        rc = -1;
    close(fd);
    return rc;
}

/* The steps of mount_ns that can fail, for its result and for the child's
 * exit code. */
enum { F_PRIVATE = 1, F_PROC = 2, F_RO = 4, F_DROP = 8, F_HIDE = 16, F_RUNDIR = 32 };

/* mount_ns makes the child's mount namespace its own: nothing propagates
 * back to the agent, /proc shows only its pid namespace, the kernel's
 * controls under /proc/sys and /sys are read-only, the DROP paths are
 * gone, the run directory shows this grant's directory alone and the
 * HIDE directories are empty. Returns the F_ bits of the steps that
 * failed, 0 when all went through, and the child ends on any of them.
 * When private propagation is refused nothing is mounted or unmounted
 * at all, since every change would propagate back into the agent's
 * namespace (covering the agent's own paths, unmounting its restore
 * root).
 *
 * The order matters: DROP before RUNDIR, so the restore root is gone
 * before anything is mounted under it; RUNDIR before HIDE, so a HIDE
 * path under another grant's directory is already gone (skipped) and
 * one under the fiber's own is covered on the bind.
 *
 * A HIDE path that does not exist is skipped; one that is not a
 * directory fails (a file cannot be covered without CRIU binding the
 * original back on restore). */
static int mount_ns(int own_pidns) {
    int failed = 0;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) return F_PRIVATE;
    if (own_pidns && mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) failed |= F_PROC;
    if (lock_controls() < 0) failed |= F_RO;
    for (int i = 0; i < ndrop; i++)
        if (umount2(drop_paths[i], MNT_DETACH) < 0 && errno != EINVAL && errno != ENOENT) failed |= F_DROP;
    if (rundir_parent[0] && narrow_rundir() < 0) failed |= F_RUNDIR;
    for (int i = 0; i < nhide; i++) {
        struct stat st;
        if (stat(hide_paths[i], &st) < 0) {
            if (errno != ENOENT) failed |= F_HIDE;
            continue;
        }
        if (!S_ISDIR(st.st_mode) ||
            mount("tmpfs", hide_paths[i], "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k,mode=0555") < 0)
            failed |= F_HIDE;
    }
    return failed;
}

/* mount_exit is the child's exit code for the first of mount_ns's failed
 * steps, in the order mount_ns takes them. */
static int mount_exit(int failed) {
    if (failed & F_PRIVATE) return EX_MNT_PRIVATE;
    if (failed & F_PROC) return EX_MNT_PROC;
    if (failed & F_RO) return EX_MNT_RO;
    if (failed & F_DROP) return EX_MNT_DROP;
    if (failed & F_RUNDIR) return EX_MNT_RUNDIR;
    return EX_MNT_HIDE;
}

/* drop_caps leaves the child with no capability it can use or regain:
 * no_new_privs (exec never raises permitted above the empty set it
 * has), no ambient set, empty effective, permitted and inheritable sets,
 * and an empty bounding set where the caller holds CAP_SETPCAP (a
 * container's default set often lacks it; no_new_privs already covers
 * what the bounding set would). Returns 0, or -1 if no_new_privs or the
 * empty sets were refused. */
static int drop_caps(void) {
    int rc = 0;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) rc = -1;
    for (int c = 0; prctl(PR_CAPBSET_READ, c, 0, 0, 0) >= 0; c++)
        (void)prctl(PR_CAPBSET_DROP, c, 0, 0, 0);
#ifdef PR_CAP_AMBIENT
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 && errno != EINVAL) rc = -1;
#endif
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct d[_LINUX_CAPABILITY_U32S_3];
    memset(d, 0, sizeof d);
    if (syscall(SYS_capset, &h, d) < 0) rc = -1;
    return rc;
}

struct confine {
    int pidns, mntns, nocaps;
};

/* deny_nested_userns is set when the agent asked for nested user
 * namespaces to be denied (FIBERD_USERNS_NESTED=deny). The zygote's own
 * namespace has its limit set to 0 (cap_nested_userns), and every fiber
 * gets the filter below as well, since a checkpoint restores a fiber
 * into a new user namespace with the default limit and criu carries
 * seccomp filters across. */
static int deny_nested_userns;

#if defined(__x86_64__)
#define FZ_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define FZ_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define FZ_ARG_LO(i) (offsetof(struct seccomp_data, args) + 8 * (i))
#else
#define FZ_ARG_LO(i) (offsetof(struct seccomp_data, args) + 8 * (i) + 4)
#endif
/* On x86_64 a number with this bit set selects the x32 table under the
 * same AUDIT_ARCH_X86_64, where unshare and friends have other numbers
 * than the ones matched below. The kernel's own name is
 * __X32_SYSCALL_BIT. */
#define FZ_X32_SYSCALL_BIT 0x40000000

/* userns_filter refuses the system calls that make or join a user
 * namespace: unshare and clone with CLONE_NEWUSER, setns onto a user
 * namespace (or onto whatever the descriptor is), and clone3, whose
 * flags sit in a struct seccomp cannot read. clone3 answers ENOSYS, as
 * a kernel without it would, so libc falls back to clone. On x86_64 an
 * x32 number kills the process, as libseccomp and Docker do, so the
 * matches below cannot be sidestepped through the other table.
 * Everything else passes. Installing needs CAP_SYS_ADMIN in the
 * caller's user namespace or no_new_privs. Allocation-free, for
 * scrub_and_run. */
static int userns_filter(void) {
#ifndef FZ_AUDIT_ARCH
    errno = ENOSYS;
    return -1;
#else
    static struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FZ_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        /* nr >= X32_SYSCALL_BIT: an x32 call, not one of ours */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, FZ_X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        /* unshare(flags) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, FZ_ARG_LO(0)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* clone(flags, ...) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, FZ_ARG_LO(0)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* clone3(struct clone_args *) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        /* setns(fd, nstype) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setns, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, FZ_ARG_LO(1)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = sizeof f / sizeof f[0], .filter = f };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
#endif
}

/* FZ_HANDOFF_FD in a handoff fiber, -1 otherwise. */
static int handoff_fd = -1;

/* The grant's identity, as the agent's first message on the channel
 * delivers it: 'k' then three NUL-ended fields. It lives in the fiber's
 * memory (this is the child's copy of the page), never the zygote's. */
#define IDENTITY_MAX 8192
static char identity_buf[IDENTITY_MAX];
static fz_identity_t identity;
static int have_identity;

/* read_identity takes the identity message off the channel. The agent
 * queues it before the CLONE, so it is there to read. Returns 0, or -1
 * with a reason for the zygote's log. */
static int read_identity(int fd, const char **why) {
    char cbuf[CMSG_SPACE(4 * sizeof(int))];
    struct iovec iov = { .iov_base = identity_buf, .iov_len = sizeof identity_buf };
    struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    ssize_t r;
    do r = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC); while (r < 0 && errno == EINTR);
    /* Anything passed with it is not ours to keep. */
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
        size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < n; i++) { int got; memcpy(&got, CMSG_DATA(c) + i * sizeof(int), sizeof(int)); close(got); }
    }
    if (r < 0) { *why = "recvmsg on the channel failed"; return -1; }
    if (r == 0) { *why = "channel closed before the identity arrived"; return -1; }
    if (mh.msg_flags & MSG_TRUNC) { *why = "identity message too long"; return -1; }
    if (r < 2 || identity_buf[0] != 'k' || identity_buf[r - 1] != 0) { *why = "first message is not the identity"; return -1; }
    const char *fields[3];
    char *p = identity_buf + 1, *end = identity_buf + r;
    for (int i = 0; i < 3; i++) {
        if (p >= end || !*p) { *why = "identity message has an empty field"; return -1; }
        fields[i] = p;
        p += strlen(p) + 1;
    }
    if (p != end) { *why = "identity message has too many fields"; return -1; }
    identity.key_pem = fields[0];
    identity.cert_pem = fields[1];
    identity.caller = fields[2];
    have_identity = 1;
    return 0;
}

const fz_identity_t *fz_handoff_identity(void) {
    return have_identity ? &identity : NULL;
}

/* The fiber's environment, built by the parent before the clone (see
 * handle_clone) and assigned whole in the child. */
#define ENV_VALUE_MAX 1024
static char env_fence[sizeof "FIBERD_FENCE=" + 128];
static char env_endpoint[sizeof "FIBERD_ENDPOINT=" + ENV_VALUE_MAX];
static char env_engine[sizeof "FIBERD_ENGINE=" + sizeof engine_endpoint];
static char env_handoff[sizeof "FIBERD_HANDOFF_FD=" + 16];
static char *fiber_environ[5];

/* child_say writes a startup failure to stderr, still the zygote's log
 * here, with write(2) alone: see the rule above scrub_and_run. */
static void child_say(const char *fence, const char *what, const char *why) {
    const char *parts[] = { "libfiberzygote ", fence, ": ", what, ": ", why, "\n" };
    for (size_t i = 0; i < sizeof parts / sizeof parts[0]; i++)
        (void)!write(2, parts[i], strlen(parts[i]));
}

/* scrub_and_run is the child between clone3 and the application.
 *
 * THE RULE FOR THIS PATH: nothing here may allocate, free, or use stdio
 * before on_fiber runs. clone3 copies one thread of the zygote; the
 * others (an engine) may hold malloc's lock or a stream's lock at that
 * instant, and the copy of such a lock is held forever. Everything the
 * fiber needs built (its environment, its identity buffers) is built by
 * the parent before the clone or read into static storage with raw
 * syscalls; errors are written with write(2) (child_say). */
static void scrub_and_run(int ready_w, int handoff, const char *fence, const char *endpoint,
                          const unsigned char *payload, size_t payload_len,
                          struct confine cf, fz_on_fiber on_fiber) {
    /* The control channel is the zygote's, not this child's: fz_report
     * from a fiber must fail, not write into whatever lands at fd 3 (the
     * readiness pipe, below). The mutex copied from the zygote may be
     * held by a thread that does not exist here; it starts over. */
    g_ctl_fd = -1;
    control_handler = NULL;
    static const pthread_mutex_t fresh = PTHREAD_MUTEX_INITIALIZER;
    memcpy(&g_ctl_mu, &fresh, sizeof g_ctl_mu);

    /* Descriptors: the readiness pipe parked at fd 3 (overwriting the
     * inherited control descriptor), a handoff fiber's channel to the
     * agent at FZ_HANDOFF_FD, everything above closed, and the standard
     * three pointed at /dev/null (stderr once ready). Nothing else a
     * ready fiber holds leads outside its own tree; the handoff channel
     * is the one socket CRIU is told is external. */
    if (handoff >= 0 && (handoff = fcntl(handoff, F_DUPFD, FZ_HANDOFF_FD + 1)) < 0) _exit(120);
    if (dup2(ready_w, 3) < 0) _exit(120);
    int first_closed = 4;
    if (handoff >= 0) {
        if (dup2(handoff, FZ_HANDOFF_FD) < 0) _exit(120);
        handoff_fd = FZ_HANDOFF_FD;
        first_closed = FZ_HANDOFF_FD + 1;
        /* The grant's identity is the channel's first message, read
         * here into this child's memory so no application code runs
         * without it and no checkpoint is taken before it is consumed. */
        const char *why = NULL;
        if (read_identity(handoff_fd, &why) < 0) {
            child_say(fence, "handoff identity", why);
            _exit(121);
        }
    }
    /* The raw syscall: glibc has a wrapper since 2.34, musl has none. */
    if (syscall(SYS_close_range, first_closed, ~0U, 0) < 0) {
        for (int fd = first_closed; fd < 65536; fd++) close(fd);
    }
    ready_fd = 3;
    /* stderr stays the zygote's log until fz_fiber_ready, so a fiber that
     * fails to start can say why; no fiber is checkpointed before then. */
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null >= 0) {
        dup2(null, 0); dup2(null, 1);
        if (null > 3) close(null);
    }

    /* Environment: nothing inherited but the identity assigned now. The
     * parent built fiber_environ for this clone; the handoff entry is
     * there only for a handoff fiber. The grant's TLS identity is in
     * memory (fz_handoff_identity), not in any file it could name. */
    environ = fiber_environ;

    /* Session, signals, entropy. No PR_SET_PDEATHSIG: a resumed fiber has
     * a different parent, and the runtime kills leaves through the cgroup
     * when the zygote or the agent goes away. */
    setsid();
    signal(SIGCHLD, SIG_DFL);
    sigset_t none; sigemptyset(&none); sigprocmask(SIG_SETMASK, &none, NULL);
    unsigned seed = 0;
    if (getrandom(&seed, sizeof seed, 0) == (ssize_t)sizeof seed) srandom(seed);

    /* Mounts first: they need the capabilities dropped right after. A
     * fiber that cannot be confined as the agent asked does not run: the
     * child ends, its exit code naming the step that failed. */
    if (cf.mntns) {
        int failed = mount_ns(cf.pidns);
        if (failed) _exit(mount_exit(failed));
    }
    /* Before the capabilities go, since installing may need
     * CAP_SYS_ADMIN. */
    if (deny_nested_userns && userns_filter() < 0) {
        child_say(fence, "deny nested user namespaces", strerror(errno));
        _exit(EX_USERNS);
    }
    if (cf.nocaps && drop_caps() < 0) _exit(EX_CAPS);

    fz_fiber_t f = { .fence = fence, .endpoint = endpoint,
                     .payload = payload, .payload_len = payload_len };
    _exit(on_fiber(&f) & 0xff);
}

void fz_init(int argc, char **argv) {
    (void)argc;
    int p = personality(0xffffffff);
    if (p == -1 || (p & ADDR_NO_RANDOMIZE)) return;
    if (personality((unsigned long)(p | ADDR_NO_RANDOMIZE)) == -1) return;
    /* Re-exec so the new personality applies to every mapping. Loops are
     * impossible: the second incarnation sees the flag and returns. */
    execv("/proc/self/exe", argv);
    /* If exec fails we carry on randomised; deltas will be larger. */
}

/* The ready record is the one byte 'r'. The zygote takes anything else
 * on the pipe as a fiber that misused it. */
#define READY_BYTE 'r'

void fz_fiber_ready(void) {
    if (ready_fd < 0) return;
    dup2(0, 2); /* /dev/null: nothing outside the tree once checkpointable */
    const char rec = READY_BYTE;
    (void)!write(ready_fd, &rec, 1);
    close(ready_fd);
    ready_fd = -1;
}

int fz_accept(void) {
    if (handoff_fd < 0) { errno = EBADF; return -1; }
    for (;;) {
        char b;
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = cbuf, .msg_controllen = sizeof cbuf };
        ssize_t r = recvmsg(handoff_fd, &mh, MSG_CMSG_CLOEXEC);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) { errno = ECONNRESET; return -1; }
        int fd = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && fd < 0)
                memcpy(&fd, CMSG_DATA(c), sizeof(int));
        if (fd >= 0) return fd;
        /* A message without a descriptor (or one truncated away) carries
         * nothing to serve; wait for the next. The identity message
         * never lands here: scrub_and_run read it before on_fiber ran. */
    }
}

/* A pending child's pipe became readable (or closed): ready, or gone, or
 * misused. Only the ready record (see fz_fiber_ready) makes a fiber; on
 * EOF or anything else the child, if still alive, is killed and the
 * CLONE answered with an ERROR. Nothing here waits on a live child: a
 * fiber that closed or scribbled on the pipe and kept running would
 * otherwise hold the zygote, and every other grant's clone behind it. */
static void settle_pending(int ctl_fd, int i) {
    unsigned char rec[2];
    ssize_t n;
    do n = read(pending[i].ready_fd, rec, sizeof rec); while (n < 0 && errno == EINTR);
    if (n == 1 && rec[0] == READY_BYTE) {
        remember(pending[i].pid, pending[i].fence);
        sendf(ctl_fd, "CLONED %s %d", pending[i].fence, (int)pending[i].pid);
        drop_pending(i);
        return;
    }
    int status = 0;
    pid_t w = waitpid(pending[i].pid, &status, WNOHANG);
    /* A child that exited closed the pipe before it can be reaped: its
     * mount namespace (the covers, the run directory bind) is torn down
     * in between, and that takes a moment. On EOF, give it that moment
     * before taking it for a live child that closed the pipe. Bounded,
     * so a fiber that did close it and runs on costs the zygote 200ms,
     * not a wait. */
    for (int tries = 0; n == 0 && w == 0 && tries < 200; tries++) {
        struct timespec ms = { 0, 1000000 };
        nanosleep(&ms, NULL);
        w = waitpid(pending[i].pid, &status, WNOHANG);
    }
    if (w == 0) {
        /* Alive: it closed the pipe or wrote something else on it. */
        kill(pending[i].pid, SIGKILL);
        while (waitpid(pending[i].pid, &status, 0) < 0 && errno == EINTR) {}
        if (n > 0)
            sendf(ctl_fd, "ERROR %s wrote 0x%02x on the readiness pipe instead of reporting ready (fd 3 is not the fiber's to use); killed",
                  pending[i].fence, rec[0]);
        else
            sendf(ctl_fd, "ERROR %s closed the readiness pipe without reporting ready; killed", pending[i].fence);
    } else if (w == pending[i].pid) {
        /* Gone before reporting (or right after misreporting). */
        send_died(ctl_fd, pending[i].fence, status);
    } else {
        sendf(ctl_fd, "ERROR %s closed the readiness pipe without reporting ready", pending[i].fence);
    }
    drop_pending(i);
}

/* Kill and report every pending child past its deadline. */
static void expire_pending(int ctl_fd) {
    for (int i = 0; i < npending;) {
        if (ms_until(pending[i].deadline) > 0) { i++; continue; }
        kill(pending[i].pid, SIGKILL);
        int status;
        waitpid(pending[i].pid, &status, 0);
        sendf(ctl_fd, "ERROR %s deadline exceeded before ready", pending[i].fence);
        drop_pending(i);
    }
}

static int handle_clone(int ctl_fd, char *line, const int passed[MAX_PASSED], fz_on_fiber on_fiber) {
    /* CLONE <fence> <endpoint> <deadline_ms> <hexpayload|-> [opt,opt...] */
    char *save = NULL;
    strtok_r(line, " ", &save);
    const char *fence = strtok_r(NULL, " ", &save);
    const char *endpoint = strtok_r(NULL, " ", &save);
    const char *dl = strtok_r(NULL, " ", &save);
    const char *hex = strtok_r(NULL, " ", &save);
    char *opts = strtok_r(NULL, " ", &save);
    struct confine cf = {0};
    int want_handoff = 0;
    char *osave = NULL;
    for (char *o = opts ? strtok_r(opts, ",", &osave) : NULL; o; o = strtok_r(NULL, ",", &osave)) {
        if (strcmp(o, "pidns") == 0) cf.pidns = 1;
        else if (strcmp(o, "mntns") == 0) cf.mntns = 1;
        else if (strcmp(o, "nocaps") == 0) cf.nocaps = 1;
        else if (strcmp(o, "handoff") == 0) want_handoff = 1;
    }
    if (!fence || !endpoint || !dl) {
        sendf(ctl_fd, "ERROR %s malformed CLONE", fence ? fence : "?");
        return 0;
    }
    if (cf.mntns && paths_refused) {
        sendf(ctl_fd, "ERROR %s refused: the mount namespace cannot hide what the agent asked (%s)", fence, paths_refused);
        return 0;
    }
    /* With handoff the channel is the last descriptor passed, after the
     * cgroup's when there is one. */
    int cgroup_fd = passed[0], handoff = -1;
    if (want_handoff) {
        if (passed[1] >= 0) handoff = passed[1];
        else { handoff = passed[0]; cgroup_fd = -1; }
        if (handoff < 0) {
            sendf(ctl_fd, "ERROR %s handoff without a channel", fence);
            return 0;
        }
    }
    int deadline_ms = atoi(dl);
    if (deadline_ms <= 0) deadline_ms = 50;
    static unsigned char payload[MAX_LINE / 2];
    size_t plen = (hex && strcmp(hex, "-") != 0) ? unhex(hex, payload, sizeof payload) : 0;

    if (npending >= MAX_PENDING) {
        sendf(ctl_fd, "ERROR %s too many clones in flight", fence);
        return 0;
    }
    /* The fiber's environment, built here where allocation is fine (the
     * child only points environ at it). Static storage is reused per
     * clone: the child's copy-on-write pages keep this clone's values. */
    if (snprintf(env_fence, sizeof env_fence, "FIBERD_FENCE=%s", fence) >= (int)sizeof env_fence ||
        snprintf(env_endpoint, sizeof env_endpoint, "FIBERD_ENDPOINT=%s", endpoint) >= (int)sizeof env_endpoint) {
        sendf(ctl_fd, "ERROR %s fence or endpoint too long", fence);
        return 0;
    }
    int ne = 0;
    fiber_environ[ne++] = env_fence;
    fiber_environ[ne++] = env_endpoint;
    if (engine_endpoint[0]) {
        snprintf(env_engine, sizeof env_engine, "FIBERD_ENGINE=%s", engine_endpoint);
        fiber_environ[ne++] = env_engine;
    }
    if (handoff >= 0) {
        snprintf(env_handoff, sizeof env_handoff, "FIBERD_HANDOFF_FD=%d", FZ_HANDOFF_FD);
        fiber_environ[ne++] = env_handoff;
    }
    fiber_environ[ne] = NULL;
    int rp[2];
    if (pipe2(rp, O_CLOEXEC) < 0) { sendf(ctl_fd, "ERROR %s pipe: %s", fence, strerror(errno)); return 0; }

    unsigned long long want = (cf.pidns ? CLONE_NEWPID : 0) | (cf.mntns ? CLONE_NEWNS : 0);
    pid_t pid = birth(cgroup_fd, want);
    if (pid < 0) {
        sendf(ctl_fd, "ERROR %s clone: %s", fence, strerror(errno));
        close(rp[0]); close(rp[1]);
        return 0;
    }
    if (pid == 0) {
        close(rp[0]);
        scrub_and_run(rp[1], handoff, fence, endpoint, payload, plen, cf, on_fiber);
        _exit(127); /* not reached */
    }
    close(rp[1]);
    /* Do not wait here: park the child and return to the loop, so the
     * next CLONE in a storm is forked right away. */
    pending[npending].pid = pid;
    pending[npending].ready_fd = rp[0];
    snprintf(pending[npending].fence, sizeof pending[npending].fence, "%s", fence);
    pending[npending].deadline = now_ts();
    pending[npending].deadline.tv_sec += deadline_ms / 1000;
    pending[npending].deadline.tv_nsec += (long)(deadline_ms % 1000) * 1000000L;
    if (pending[npending].deadline.tv_nsec >= 1000000000L) {
        pending[npending].deadline.tv_sec++;
        pending[npending].deadline.tv_nsec -= 1000000000L;
    }
    npending++;
    return 0;
}

/* set_rundir takes "RUNDIR <parent> <own>" apart and keeps the two
 * paths for mount_ns. Both must be absolute and clean, and own must be
 * a direct child of parent (one name, not "." or ".."), since own is
 * made again inside the tmpfs that covers parent; a parent of "/" would
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

/* in_child_userns reports whether this process runs in a user namespace
 * other than the initial one, read from its uid_map. The initial
 * namespace maps everything to itself in one line. */
static int in_child_userns(void) {
    char buf[128];
    int fd = open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    unsigned long inside, outside, count;
    if (sscanf(buf, "%lu %lu %lu", &inside, &outside, &count) != 3) return 0;
    return !(inside == 0 && outside == 0 && count == 4294967295UL);
}

static int write_str(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(val)) { errno = n < 0 ? saved : EIO; return -1; }
    return 0;
}

/* cap_nested_userns sets user.max_user_namespaces to 0 in this process's
 * own user namespace, so no fiber forked from here can make a user
 * namespace and be capable again, then drops CAP_SYS_RESOURCE, which the
 * write needs and which would let a fiber raise the limit back. The
 * sysctl is per user namespace. It is refused in the initial one, where
 * the write would reach the host, and it is reached through a fresh proc
 * mount when /proc/sys is read-only here (a container's default). The
 * mount is this mount namespace's and is undone before anything else
 * sees it. Returns 0, or -1 with errno and a line on stderr. */
static int cap_nested_userns(void) {
    if (!in_child_userns()) {
        fprintf(stderr, "libfiberzygote: FIBERD_USERNS_NESTED is set outside a user namespace; refusing to touch the host's limit\n");
        errno = EPERM;
        return -1;
    }
    const char *knob = "sys/user/max_user_namespaces";
    char direct[128];
    snprintf(direct, sizeof direct, "/proc/%s", knob);
    int rc = write_str(direct, "0");
    if (rc < 0 && (errno == EROFS || errno == EACCES)) {
        char dir[] = "/tmp/.fz-proc-XXXXXX";
        if (!mkdtemp(dir)) { fprintf(stderr, "libfiberzygote: scratch for a proc mount: %s\n", strerror(errno)); return -1; }
        if (mount("proc", dir, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
            fprintf(stderr, "libfiberzygote: mount proc at %s: %s\n", dir, strerror(errno));
            rmdir(dir);
            return -1;
        }
        char path[192];
        snprintf(path, sizeof path, "%s/%s", dir, knob);
        rc = write_str(path, "0");
        int saved = errno;
        umount2(dir, MNT_DETACH);
        rmdir(dir);
        errno = saved;
    }
    if (rc < 0) {
        fprintf(stderr, "libfiberzygote: user.max_user_namespaces=0: %s\n", strerror(errno));
        return -1;
    }
    /* Read back through the regular /proc, which may be read-only but
     * is readable, so a write that landed elsewhere is caught. */
    char got[32] = "";
    int fd = open(direct, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { ssize_t n = read(fd, got, sizeof got - 1); if (n > 0) got[n] = 0; close(fd); }
    if (strtoul(got, NULL, 10) != 0 || got[0] == 0) {
        fprintf(stderr, "libfiberzygote: user.max_user_namespaces reads %s after the write\n", got[0] ? got : "nothing");
        errno = EIO;
        return -1;
    }
    if (prctl(PR_CAPBSET_DROP, CAP_SYS_RESOURCE, 0, 0, 0) < 0) {
        fprintf(stderr, "libfiberzygote: drop CAP_SYS_RESOURCE from the bounding set: %s\n", strerror(errno));
        return -1;
    }
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct d[_LINUX_CAPABILITY_U32S_3];
    if (syscall(SYS_capget, &h, d) < 0) return -1;
    d[CAP_TO_INDEX(CAP_SYS_RESOURCE)].effective &= ~CAP_TO_MASK(CAP_SYS_RESOURCE);
    d[CAP_TO_INDEX(CAP_SYS_RESOURCE)].permitted &= ~CAP_TO_MASK(CAP_SYS_RESOURCE);
    d[CAP_TO_INDEX(CAP_SYS_RESOURCE)].inheritable &= ~CAP_TO_MASK(CAP_SYS_RESOURCE);
    if (syscall(SYS_capset, &h, d) < 0) {
        fprintf(stderr, "libfiberzygote: drop CAP_SYS_RESOURCE: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* rebind_ctl takes the control socket the agent sends as a REBIND
 * message on the bootstrap one and puts it at ctl_fd in its place. The
 * agent makes that socket in this zygote's network namespace, where a
 * checkpoint of the zygote finds it. */
static int rebind_ctl(int ctl_fd) {
    static char line[64];
    int passed[MAX_PASSED];
    ssize_t n = recv_line(ctl_fd, line, sizeof line, passed);
    if (n <= 0 || strcmp(line, "REBIND") != 0 || passed[0] < 0) {
        for (int i = 0; i < MAX_PASSED; i++) if (passed[i] >= 0) close(passed[i]);
        fprintf(stderr, "libfiberzygote: expected REBIND with a socket, got %s\n", n > 0 ? line : "end of stream");
        errno = EPROTO;
        return -1;
    }
    if (dup2(passed[0], ctl_fd) < 0) return -1;
    for (int i = 0; i < MAX_PASSED; i++) if (passed[i] >= 0) close(passed[i]);
    return 0;
}

int fz_serve(int ctl_fd, fz_on_fiber on_fiber) {
    signal(SIGPIPE, SIG_IGN);
    /* Both before READY, so a zygote that cannot deny nested user
     * namespaces or take its channel never serves and the agent sees the
     * warm fail. */
    if (getenv("FIBERD_CTL_REBIND") && rebind_ctl(ctl_fd) < 0) return -1;
    const char *nested = getenv("FIBERD_USERNS_NESTED");
    if (nested && strcmp(nested, "deny") == 0) {
        if (cap_nested_userns() < 0) return -1;
        deny_nested_userns = 1;
    }
    if (sendf(ctl_fd, "READY") < 0) return -1;
    g_ctl_fd = ctl_fd; /* from here on other threads may fz_report */
    static char line[MAX_LINE];
    static struct pollfd fds[1 + MAX_PENDING];
    for (;;) {
        /* Poll the control socket and every pending readiness pipe, no
         * longer than the nearest deadline (or 100ms to reap). */
        fds[0].fd = ctl_fd; fds[0].events = POLLIN;
        int timeout = 100;
        for (int i = 0; i < npending; i++) {
            fds[1 + i].fd = pending[i].ready_fd;
            fds[1 + i].events = POLLIN;
            long left = ms_until(pending[i].deadline);
            if (left < 0) left = 0;
            if (left < timeout) timeout = (int)left;
        }
        int r = poll(fds, (nfds_t)(1 + npending), timeout);
        if (r < 0 && errno != EINTR) return -1;
        /* Settle children whose pipes spoke, walking backwards because
         * settling removes entries by swapping in the last one. */
        for (int i = npending - 1; i >= 0; i--)
            if (fds[1 + i].revents & (POLLIN | POLLHUP | POLLERR))
                settle_pending(ctl_fd, i);
        expire_pending(ctl_fd);
        reap(ctl_fd);
        if (!(fds[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        int passed[MAX_PASSED];
        ssize_t n = recv_line(ctl_fd, line, sizeof line, passed);
        if (n <= 0) {
            if (n == 0) { /* agent gone: take the family with us */
                for (int i = 0; i < nkids; i++) kill(kids[i].pid, SIGKILL);
                for (int i = 0; i < npending; i++) kill(pending[i].pid, SIGKILL);
                return 0;
            }
            return -1;
        }
        if (strncmp(line, "CLONE ", 6) == 0) {
            handle_clone(ctl_fd, line, passed, on_fiber);
        } else if (strcmp(line, "PING") == 0) {
            sendf(ctl_fd, "PONG");
        } else if (strncmp(line, "HIDE /", 6) == 0 || strncmp(line, "DROP /", 6) == 0) {
            int hide = line[0] == 'H';
            char **paths = hide ? hide_paths : drop_paths;
            int *n = hide ? &nhide : &ndrop;
            char *p = *n < MAX_PATHS ? strdup(line + 5) : NULL;
            if (p) {
                paths[(*n)++] = p;
            } else {
                paths_refused = hide ? "HIDE: too many paths" : "DROP: too many paths";
                sendf(ctl_fd, "ERROR ? %s refused", paths_refused);
            }
        } else if (strncmp(line, "RUNDIR ", 7) == 0) {
            const char *why = NULL;
            if (set_rundir(line, &why) < 0) {
                paths_refused = "RUNDIR refused";
                sendf(ctl_fd, "ERROR ? RUNDIR refused: %s", why);
            }
        } else if (control_handler) {
            control_handler(line);
        } else {
            sendf(ctl_fd, "ERROR ? unknown message");
        }
        for (int i = 0; i < MAX_PASSED; i++)
            if (passed[i] >= 0) close(passed[i]);
    }
}
