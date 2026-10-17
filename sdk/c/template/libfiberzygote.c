/* See libfiberzygote.h. Linux only, for clone3 and close_range. */
#define _GNU_SOURCE
#include "libfiberzygote.h"

/* This file implements ABI version 9, so a header of another version refuses to build it. */
#if FZ_ABI_VERSION != 9
#error "libfiberzygote.c implements FZ_ABI_VERSION 9"
#endif

#include <dirent.h>
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
#include <sys/signalfd.h>
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
#include <limits.h>
#include <stddef.h>

#define MAX_LINE 65536
#define MAX_KIDS 4096
#define MAX_PENDING 1024
#define MAX_PATHS 16

/* A fence is at most FENCE_MAX - 1 characters, so the records below hold
 * it whole and every CLONED, ERROR and EXITED line names exactly the
 * fence fiberd sent. A longer one is refused, never cut. */
#define FENCE_MAX 128

/* The ready record is the one byte 'r', which fz_fiber_ready writes
 * (READY_BYTE in core/src/fiber.rs). The zygote takes anything else on
 * the pipe as a fiber that misused it. */
#define READY_BYTE 'r'

/* A control line is at most SEND_MAX - 1 characters. The longest is the
 * ERROR naming a HIDE path that could not be covered (prepare_reason),
 * which must reach fiberd whole rather than be dropped. */
#define RUNDIR_MAX 4096
#define SEND_MAX (RUNDIR_MAX + 512)

extern char **environ;

/* SIGCHLD, blocked since fz_init, read here in the poll set. A child's
 * exit wakes the loop, so its EXITED line goes out at once and not at
 * the next timeout. Opened once per process. The child closes it and
 * unblocks the signal (see scrub_and_run). */
static int sigchld_fd = -1;

static void block_sigchld(void) {
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &chld, NULL);
}

/* Why a HIDE, DROP, RUNDIR or PREPARE line was refused, or NULL. A mntns
 * fiber would run with less hidden than fiberd asked for. Set before
 * READY, it is sent as the ERROR the zygote ends on instead of READY,
 * and fiberd fails the warm. Set after READY (a setup line that came
 * late), every later mntns CLONE is refused with it instead. */
static const char *paths_refused;

/* The zygote's own mount namespace. fz_init takes it (own_mountns) when
 * FIBERD_OWN_MNTNS is set, before any thread exists, and fz_serve fills
 * it at PREPARE mntns (prepare_ns), before READY. A mntns fiber's
 * namespace is then a copy with the grant-wide work already done, and
 * its birth adds only what is its own (mount_ns in core/src/mounts.rs).
 * A fiberd whose
 * fibers get no mount namespace (runc, an artifact build) leaves the
 * variable unset, and the zygote stays in the namespace it was started
 * in, as before. */
static int have_own_ns;     /* own_mountns went through */
static char own_ns_why[160]; /* why it did not, for prepare_ns to refuse with */
static int ns_prepared;     /* prepare_ns went through, so mntns fibers may be born */

/* What a mntns fiber must not see (HIDE, covered) or keep (DROP,
 * unmounted), as fiberd sent them. hide_covered says which HIDE paths
 * prepare_ns found and covered. One missing then is looked for again at
 * each birth (see mount_ns in core/src/mounts.rs), so a directory
 * fiberd makes after READY is hidden as it was before the zygote had a
 * namespace of its own.
 *
 * Each path is kept whole in fixed storage the size of a line, since a
 * line is at most MAX_LINE - 1 characters and the path is the line less
 * its prefix. A smaller table would cut a long path, and stat would then
 * answer for another name than the one fiberd sent. The pages never
 * written cost nothing, in memory or in a checkpoint. The size is
 * KEEP_MAX in core/src/abi.rs too. */
#define KEEP_MAX MAX_LINE
static char hide_paths[MAX_PATHS][KEEP_MAX];
static int nhide;
static unsigned char hide_covered[MAX_PATHS];
static char drop_paths[MAX_PATHS][KEEP_MAX];
static int ndrop;
_Static_assert(KEEP_MAX == 65536, "KEEP_MAX is 65536 in core/src/abi.rs");
_Static_assert(PATH_MAX <= KEEP_MAX, "a realpath result fits a kept path");

/* fiberd's run directory and this grant's directory in it (RUNDIR),
 * in static storage the child reads without allocating. Empty until the
 * fiberd sends them. */
static char rundir_parent[RUNDIR_MAX];
static char rundir_own[RUNDIR_MAX];

/* The control channel, once fz_serve has it, for lines other threads
 * send with fz_report. One mutex keeps lines whole. */
static int g_ctl_fd = -1;
static pthread_mutex_t g_ctl_mu = PTHREAD_MUTEX_INITIALIZER;
static char engine_endpoint[256];
static fz_on_control control_handler;

/* Fibers that reported ready, pid to fence, for EXITED lines. */
static struct {
    pid_t pid;
    char fence[FENCE_MAX];
} kids[MAX_KIDS];
static int nkids;

/* Children forked but not yet ready. The loop polls every ready pipe at
 * once, so a storm is forked back to back and each CLONE is acknowledged
 * the moment its own child reports, never behind the others. */
static struct {
    pid_t pid;
    int ready_fd;
    char fence[FENCE_MAX];
    struct timespec deadline;
} pending[MAX_PENDING];
static int npending;

/* Children killed before ready that the kernel had not let go of within
 * the bounded wait (see doom). Their CLONE is already answered, so when
 * they are finally reaped nothing is said about them. */
static pid_t doomed[MAX_PENDING];
static int ndoomed;

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
    char buf[SEND_MAX];
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

/* Read one line. Descriptors riding along in SCM_RIGHTS land in fds_out
 * in order, unused slots -1 and extras closed. Returns the line length,
 * 0 on EOF, -1 on error. A partial line at EOF is returned NUL-terminated.
 *
 * The line is read in two steps rather than a byte at a time. A peek
 * with no control buffer, so nothing is installed, shows where the
 * newline is. Then exactly that much is read with the control buffer.
 * The descriptors stay attached to the right line because an AF_UNIX
 * stream read, peeking or not, never crosses from one message's data
 * into another's when their SCM_RIGHTS differ, and fiberd sends
 * descriptors on the CLONE line alone. A read may still stop short of
 * the newline when a long line arrives in several buffers, so the loop
 * goes on from there. */
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

/* The record parser lives in the Rust core (core/src/record.rs). Every
 * caller is in the core now (the child's path and the fiber-side API).
 * The entry is declared here for the fuzz harnesses, which include this
 * file and parse with it. */
struct record_store;
int fz_rs_parse_incarnation(struct record_store *st, size_t n, const char **why);

/* The line parsers live in the Rust core too (core/src/line.rs and
 * core/src/procfiles.rs), behind these entries. Each takes a line or a
 * file's bytes apart as the C did, cutting a line up in place as
 * strtok_r did, so the fields stay C strings here. The replies, the
 * mounts and every error line are chosen here from what they return. */

/* What fz_rs_parse_clone made of a CLONE line (core/src/abi.rs). */
struct fz_rs_clone {
    const char *fence;    /* NUL-ended in the line, or NULL when it has none */
    const char *endpoint; /* NUL-ended in the line, or NULL when it has none */
    size_t endpoint_len;
    int deadline_ms;      /* with the default of 50, once the fence fits */
    int pidns, mntns, nocaps;
    size_t session_len;   /* decoded into the session buffer, NUL-ended */
};
_Static_assert(sizeof(struct fz_rs_clone) == 48, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, fence) == 0, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, endpoint) == 8, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, endpoint_len) == 16, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, deadline_ms) == 24, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, pidns) == 28, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, mntns) == 32, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, nocaps) == 36, "fz_rs_clone layout");
_Static_assert(offsetof(struct fz_rs_clone, session_len) == 40, "fz_rs_clone layout");
/* Why fz_rs_parse_clone refused the line, or 0 when the checks on the
 * zygote's own state are next (CloneRefusal in core/src/line.rs). */
enum { FZ_RS_CLONE_OK = 0, FZ_RS_CLONE_MALFORMED = 1, FZ_RS_CLONE_FENCE_LONG = 2, FZ_RS_CLONE_SESSION_LONG = 3, FZ_RS_CLONE_SESSION_NUL = 4 };
int fz_rs_parse_clone(char *line, char *session, size_t cap, struct fz_rs_clone *out);
/* The Rust writes RUNDIR_MAX bytes at most into each path (RUNDIR_MAX in
 * core/src/abi.rs), so the two buffers must be that size. */
_Static_assert(sizeof rundir_parent == 4096 && sizeof rundir_own == 4096, "rundir buffers match RUNDIR_MAX in core/src/abi.rs");
int fz_rs_set_rundir(char *line, char *parent, char *own, const char **why);
/* What read_setup does with a line (Setup in core/src/line.rs). */
enum { FZ_RS_SETUP_HIDE = 0, FZ_RS_SETUP_DROP = 1, FZ_RS_SETUP_RUNDIR = 2, FZ_RS_SETUP_PREPARE_MNTNS = 3, FZ_RS_SETUP_PREPARE_NONE = 4, FZ_RS_SETUP_OTHER = 5 };
int fz_rs_setup_kind(const char *line);
int fz_rs_is_rebind(const char *line);
char *fz_rs_mountinfo_sys_mount(char *buf, size_t have, size_t *start, int *skipping);
size_t fz_rs_mountinfo_carry(char *buf, size_t cap, size_t have, size_t start, int *skipping);
int fz_rs_in_child_userns(const char *uid_map);

/* The child's path lives in the Rust core (core/src/child.rs and
 * core/src/mounts.rs): the clone3 birth with its legacy fallback,
 * scrub_and_run from the clone to on_fiber, the mount steps, the seccomp
 * filter against nested user namespaces and the capability drop. No
 * system call of the child's is made here any more. The zygote-side
 * callers that stay (lock_sys, prepare_ns) reach the shared steps
 * through these entries. fz_rs_channel_recv is declared for the fuzz
 * harnesses, since its callers are all in the core now. */
pid_t fz_rs_birth(int cgroup_fd, unsigned long long want);
int fz_rs_ro_remount(const char *path);
int fz_rs_cover_empty(const char *path);
int fz_rs_narrow_rundir(const char *parent, const char *own);
int fz_rs_cover_hide(const char *path, const char *self_exe);
int fz_rs_drop_paths_now(const char (*paths)[KEEP_MAX], int n);
ssize_t fz_rs_channel_recv(int fd, int flags, char *buf, size_t cap, int *fd_out);

/* What the child's path needs from the zygote (Child in core/src/abi.rs),
 * built by handle_clone before the clone. The zygote's statics the child
 * resets stay here until stage 5, and scrub_and_run resets them with
 * plain stores before the one call into the core. The fiber's state (the
 * channel, the park round, the readiness pipe, the served generation and
 * the record stores) is the core's (core/src/fiber.rs), which resets it
 * and reads the birth record into it itself. */
struct fz_rs_child {
    int ready_r, ready_w, channel, sigchld_fd;
    int pidns, mntns, nocaps, deny_nested_userns;
    int nhide, ndrop;
    const char *fence;
    fz_on_fiber on_fiber;
    const char *self_exe;
    const char (*hide)[KEEP_MAX];
    const unsigned char *hide_covered;
    const char (*drop)[KEEP_MAX];
};
_Static_assert(sizeof(struct fz_rs_child) == 88, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, ready_r) == 0, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, ready_w) == 4, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, channel) == 8, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, sigchld_fd) == 12, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, pidns) == 16, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, mntns) == 20, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, nocaps) == 24, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, deny_nested_userns) == 28, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, nhide) == 32, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, ndrop) == 36, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, fence) == 40, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, on_fiber) == 48, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, self_exe) == 56, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, hide) == 64, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, hide_covered) == 72, "fz_rs_child layout");
_Static_assert(offsetof(struct fz_rs_child, drop) == 80, "fz_rs_child layout");
_Static_assert(FZ_CHANNEL_FD == 4 && FZ_CHANNEL_PEER_FD == 5, "the channel descriptors are 4 and 5 in core/src/abi.rs");
_Noreturn void fz_rs_scrub_and_run(const struct fz_rs_child *c);

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

/* Exit codes of a child that could not be confined or set up. New codes
 * go at the end, because fiberd's tests name the existing ones. 116
 * (the run directory) is retired and not reused. The zygote narrows the
 * run directory once, at PREPARE, and refuses every mntns CLONE when it
 * cannot, so no child ends over it. */
enum {
    EX_MNT_PRIVATE = 110, EX_MNT_PROC, EX_MNT_DROP, EX_MNT_HIDE, EX_CAPS, EX_MNT_RO, EX_USERNS = 117,
    EX_FDS = 120, EX_IDENTITY = 121, EX_CGROUP = 125
};
/* The child ends with these codes from the Rust core (core/src/child.rs),
 * which pins the same numbers. exit_why below reads them for fiberd. */
_Static_assert(EX_MNT_PRIVATE == 110 && EX_MNT_PROC == 111 && EX_MNT_DROP == 112 && EX_MNT_HIDE == 113 &&
               EX_CAPS == 114 && EX_MNT_RO == 115 && EX_USERNS == 117 && EX_FDS == 120 && EX_IDENTITY == 121 &&
               EX_CGROUP == 125, "the exit codes match core/src/child.rs");

/* exit_why says what a code above stands for, or NULL for any other
 * code (the template's own). */
static const char *exit_why(int code) {
    switch (code) {
    case EX_MNT_PRIVATE: return "could not make its mount namespace private";
    case EX_MNT_PROC: return "could not mount its own /proc";
    case EX_MNT_DROP: return "could not unmount a DROP path";
    case EX_MNT_HIDE: return "could not cover a HIDE path that appeared after READY";
    case EX_CAPS: return "could not drop its capabilities";
    case EX_MNT_RO: return "could not make the host controls under /proc read-only";
    case EX_USERNS: return "could not install the user namespace filter";
    case EX_FDS: return "could not set up its descriptors";
    case EX_IDENTITY: return "did not get its incarnation record";
    case EX_CGROUP: return "could not join its cgroup leaf";
    default: return NULL;
    }
}

static void send_died(int ctl_fd, const char *fence, int status) {
    if (WIFSIGNALED(status)) {
        sendf(ctl_fd, "ERROR %s died before ready: signal:%d", fence, WTERMSIG(status));
        return;
    }
    int code = WEXITSTATUS(status);
    const char *why = exit_why(code);
    if (why)
        sendf(ctl_fd, "ERROR %s died before ready: exit:%d (%s)", fence, code, why);
    else
        sendf(ctl_fd, "ERROR %s died before ready: exit:%d", fence, code);
}

/* wait_bounded reaps pid if it ends within ms milliseconds, polling with
 * WNOHANG. The zygote never blocks in waitpid. A child the kernel holds
 * after SIGKILL (a mount namespace being torn down, a stuck filesystem)
 * would hold the loop, and every grant's clones behind it. Returns what
 * waitpid returns, 0 while the child is still there at the end. */
static pid_t wait_bounded(pid_t pid, int *status, int ms) {
    for (;;) {
        pid_t w;
        do w = waitpid(pid, status, WNOHANG); while (w < 0 && errno == EINTR);
        if (w != 0 || ms-- <= 0) return w;
        struct timespec one_ms = { 0, 1000000 };
        nanosleep(&one_ms, NULL);
    }
}

/* doom kills a pending child and reaps it if the kernel lets go of it in
 * time. One it does not is left to reap() with its CLONE answered. */
static void doom(pid_t pid) {
    kill(pid, SIGKILL);
    int status;
    if (wait_bounded(pid, &status, 500) == 0 && ndoomed < MAX_PENDING) doomed[ndoomed++] = pid;
}

static int forget_doomed(pid_t pid) {
    for (int i = 0; i < ndoomed; i++)
        if (doomed[i] == pid) { doomed[i] = doomed[--ndoomed]; return 1; }
    return 0;
}

/* reported_ready says whether a pending child's pipe holds its ready
 * record, without waiting on it. A child that reported and ended while
 * the loop sat in a bounded wait on another child (settle_pending, doom)
 * is reaped before its pipe is ever polled. It was a fiber that ran and
 * exited, not a birth that failed, and its CLONE is answered so. */
static int reported_ready(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN)) return 0;
    unsigned char rec[2];
    ssize_t n;
    do n = read(fd, rec, sizeof rec); while (n < 0 && errno == EINTR);
    return n == 1 && rec[0] == READY_BYTE;
}

static void reap(int ctl_fd) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (forget_doomed(pid)) continue;
        int i = pending_index(pid);
        if (i >= 0 && !reported_ready(pending[i].ready_fd)) { /* died before it ever reported ready */
            send_died(ctl_fd, pending[i].fence, status);
            drop_pending(i);
            continue;
        }
        if (i >= 0) { /* ready, then gone, both inside one bounded wait */
            sendf(ctl_fd, "CLONED %s %d", pending[i].fence, (int)pid);
            drop_pending(i);
        }
        forget(pid);
        if (WIFSIGNALED(status))
            sendf(ctl_fd, "EXITED %d signal:%d", (int)pid, WTERMSIG(status));
        else
            sendf(ctl_fd, "EXITED %d exit:%d", (int)pid, WEXITSTATUS(status));
    }
}

/* ---- birth ---- */

/* birth forks the fiber straight into its leaf cgroup, with the
 * namespaces in want, or takes the legacy clone where clone3 is missing
 * and has the child join its leaf itself. Returns the pid, 0 in the
 * child, or -1 with errno. The body is core/src/child.rs, under the
 * rule above scrub_and_run. */
static pid_t birth(int cgroup_fd, unsigned long long want) {
    return fz_rs_birth(cgroup_fd, want);
}

/* ro_remount makes the mount at path read-only in this namespace alone,
 * for lock_sys. The body is core/src/mounts.rs. */
static int ro_remount(const char *path) {
    return fz_rs_ro_remount(path);
}

/* unescape_mount, which undid mountinfo's octal escapes (\040 for a
 * space) in place, is in the Rust core now (procfiles::unescape_mount),
 * called from the line loop lock_sys drives below. */

/* lock_sys takes away the fiber's write access to the kernel's knobs
 * under /sys. The fiber is euid 0 in the initial user namespace with
 * every capability dropped, and kernfs (cgroup, sysfs) checks the owner
 * write bit for euid 0 and asks for no capability. Without this
 * /sys/fs/cgroup lifts the fiber's own and other grants' limits. A
 * read-only mount stands in the way, since the check happens in the
 * fiber's mount namespace. (The same for /proc/sys and the rest of the
 * fiber's fresh /proc is per fiber, lock_procsys and lock_proc in
 * core/src/mounts.rs.)
 *
 * All of /sys, every mount under it included, is made read-only in
 * place. sysfs has knobs of its own writable by euid 0 (/sys/kernel,
 * /sys/module/<m>/parameters), and the cgroup mount is under it.
 * Changing the flags of the existing mounts, rather than stacking a
 * bind on each, keeps the tree CRIU dumps the same shape, and CRIU
 * restores the flags with the mounts, so a resumed fiber is as closed
 * as a born one. Reading under /sys still works. Where /sys has no
 * mounts there is nothing to do. This is done once, in the zygote's own
 * namespace (from prepare_ns), and every fiber's copy carries the
 * flags. A mount the host adds under /sys after that never reaches the
 * zygote's namespace, which is private, so no fiber sees it at all.
 * /sys/firmware is covered with an empty tmpfs besides.
 *
 * lock_sys reads mountinfo with raw syscalls into a stack buffer and
 * splits it by hand, allocating nothing. The rule above scrub_and_run
 * no longer binds it, since it runs in the zygote, and the code is kept
 * as it was. A line split across two reads is carried over. One longer
 * than the buffer is skipped to its newline rather than misread as
 * several, and no mount under /sys has a name that long.
 *
 * Every mount is tried whatever happened to the ones before it, so one
 * refusal leaves as little writable as possible. Returns 0, or -1 when
 * any step failed. */

/* cover_empty mounts an empty read-only tmpfs over the directory at
 * path. Returns 0, -1 with errno, or 0 having done nothing when there is
 * no such path. The body is core/src/mounts.rs. */
static int cover_empty(const char *path) {
    return fz_rs_cover_empty(path);
}

static int lock_sys(void) {
    int rc = 0;
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[8192];
    size_t have = 0;
    int skipping = 0; /* inside a line too long for buf */
    for (;;) {
        ssize_t n = read(fd, buf + have, sizeof buf - have);
        if (n < 0) { if (errno == EINTR) continue; rc = -1; break; }
        if (n == 0) break; /* EOF. mountinfo ends every line with '\n' */
        have += (size_t)n;
        /* The Rust core walks the complete lines, hands over each mount
         * point under /sys (the fifth field, unescaped in place) and then
         * carries the partial line to the front, or drops a full buffer
         * with no newline and skips to the end of that line. */
        size_t start = 0;
        for (const char *mp; (mp = fz_rs_mountinfo_sys_mount(buf, have, &start, &skipping)) != NULL;)
            if (ro_remount(mp) < 0) rc = -1;
        have = fz_rs_mountinfo_carry(buf, sizeof buf, have, start, &skipping);
    }
    int e = errno;
    close(fd);
    errno = e;
    /* /sys/firmware (DMI tables, EFI variables, ACPI tables) is readable
     * by euid 0 and says what the node is. Covered once, here, as runc
     * and Docker mask it. */
    if (cover_empty("/sys/firmware") < 0) rc = -1;
    return rc;
}

/* narrow_rundir leaves the zygote, and so every fiber, one directory of
 * fiberd's run directory, its own grant's (RUNDIR). Runs once, from
 * prepare_ns. Returns 0, or -1, and every mntns CLONE is then refused.
 * The body is core/src/mounts.rs. */
static int narrow_rundir(void) {
    return fz_rs_narrow_rundir(rundir_parent, rundir_own);
}

/* The steps of prepare_ns and mount_ns that can fail, for their results,
 * the reason every mntns CLONE is refused and the child's exit code. */
enum { F_PRIVATE = 1, F_PROC = 2, F_RO = 4, F_DROP = 8, F_HIDE = 16, F_RUNDIR = 32 };

/* The zygote's own executable as /proc/self/exe names it, read once at
 * PREPARE (prepare_ns). Empty when it could not be read. A HIDE path
 * that holds it is covered with the executable bound back at its place
 * (cover_hide), since fiberd runs a registry template from its
 * template cache and hides the cache. */
static char self_exe[RUNDIR_MAX];

/* cover_hide covers HIDE path i with an empty read-only tmpfs, with the
 * zygote's executable bound back inside when the path holds it. Returns
 * 1 when it did, 0 when the path does not exist (nothing to hide yet)
 * and -1 when it exists and could not be covered, with errno set. The
 * body is core/src/mounts.rs, where mount_ns calls it per fiber. */
static int cover_hide(int i) {
    return fz_rs_cover_hide(hide_paths[i], self_exe);
}

/* drop_paths_now unmounts every DROP path from the calling namespace.
 * Returns 0, or -1 when one that is mounted would not go. The body is
 * core/src/mounts.rs, where mount_ns calls it per fiber. */
static int drop_paths_now(void) {
    return fz_rs_drop_paths_now(drop_paths, ndrop);
}

/* prepare_why is the reason the zygote refuses to serve after the first
 * of prepare_ns's failed steps, in the order prepare_ns takes them. A
 * HIDE failure names the path and the error, since the cause is in the
 * fiberd's environment (a capability it lacks, a mount it cannot make)
 * and fiberd's log is where it is read. */
static char prepare_reason[RUNDIR_MAX + 96];
static const char *prepare_why(int failed, int hide_i, int hide_errno) {
    if (failed & F_RO) return "the zygote could not make /sys read-only in its namespace";
    if (failed & F_DROP) return "the zygote could not unmount a DROP path";
    if (failed & F_RUNDIR) return "the zygote could not narrow the run directory";
    snprintf(prepare_reason, sizeof prepare_reason, "the zygote could not cover a HIDE path (%s: %s)",
             hide_i >= 0 ? hide_paths[hide_i] : "?", strerror(hide_errno));
    return prepare_reason;
}

/* prepare_ns fills the zygote's own mount namespace with what every
 * mntns fiber must see, once, at PREPARE mntns and before READY. Every
 * mount under /sys is made read-only, the DROP paths are unmounted, the
 * run directory shows this grant's directory alone and the HIDE
 * directories are empty, but for the zygote's own executable when one
 * of them holds it. A fiber's namespace is a copy of this one, so
 * its birth pays for its own /proc and nothing grant-wide. The zygote
 * itself sees other grants' directories and the hidden paths no more
 * than its fibers do.
 *
 * The order matters. DROP comes before RUNDIR, so the restore root is
 * gone before anything is mounted under it. RUNDIR comes before HIDE,
 * so a HIDE path under another grant's directory is already gone and
 * skipped, and one under this grant's own is covered on the bind.
 *
 * Fails closed. Any step refused, or no namespace of the zygote's own
 * to work in (fz_init skipped, a thread before it, unshare refused),
 * sets paths_refused, and fz_serve answers fiberd with an ERROR
 * naming it instead of READY, since every fiber of a plain proc grant
 * asks for a mount namespace and fiberd fails the warm. A line
 * refused earlier keeps its reason and nothing is mounted. Returns 0,
 * or -1 with paths_refused set. */
static int prepare_ns(void) {
    if (paths_refused) return -1;
    if (!have_own_ns) {
        paths_refused = own_ns_why[0] ? own_ns_why : "fz_init did not run, so the zygote has no mount namespace of its own";
        return -1;
    }
    int failed = 0, hide_i = -1, hide_errno = 0;
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof self_exe - 1);
    self_exe[n > 0 ? n : 0] = 0;
    if (lock_sys() < 0) failed |= F_RO;
    if (drop_paths_now() < 0) failed |= F_DROP;
    if (rundir_parent[0] && narrow_rundir() < 0) failed |= F_RUNDIR;
    /* fiberd names a HIDE path as it was configured and the kernel
     * names the executable resolved (/proc/self/exe). With a symlink in
     * the path, under (core/src/mounts.rs) would miss, the cover would land on the real
     * directory with the executable not bound back, and no park of the
     * grant could name it. Each path is resolved here, into a buffer of
     * the PATH_MAX bytes realpath promises, and kept in its slot. One
     * that does not exist yet keeps its name. */
    for (int i = 0; i < nhide; i++) {
        char real[PATH_MAX];
        if (realpath(hide_paths[i], real)) memcpy(hide_paths[i], real, strlen(real) + 1);
    }
    for (int i = 0; i < nhide; i++) {
        int c = cover_hide(i);
        if (c < 0 && hide_i < 0) {
            hide_i = i;
            hide_errno = errno;
        }
        if (c < 0) failed |= F_HIDE;
        hide_covered[i] = c > 0;
    }
    if (failed) {
        paths_refused = prepare_why(failed, hide_i, hide_errno);
        return -1;
    }
    ns_prepared = 1;
    return 0;
}

/* thread_count is the number of threads of this process, from
 * /proc/self/task, or -1 when it cannot be read. */
static int thread_count(void) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    for (struct dirent *e; (e = readdir(d)) != NULL;)
        if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* own_mountns moves the zygote into a mount namespace of its own and
 * makes every mount in it private, so nothing the host mounts later
 * reaches it and nothing mounted in it reaches the host. prepare_ns
 * fills it, and every mntns fiber's namespace is a copy of it. fiberd
 * asks for it with FIBERD_OWN_MNTNS in the environment, as it asks for
 * the other work done before READY (FIBERD_CTL_REBIND,
 * FIBERD_USERNS_NESTED), because fz_init runs before fiberd's first
 * line can be read and a zygote whose fibers share its namespace has no
 * use for one.
 *
 * It must run before any thread exists, from fz_init. unshare moves the
 * calling thread alone when the fs_struct is shared, so with a thread
 * already made the serving thread would be in one namespace and the
 * others in the host's, and CRIU refuses to checkpoint a tree whose
 * threads differ in namespace. A template with a thread before fz_init
 * is refused here, and the reason ends the zygote at PREPARE instead of
 * READY (fail closed, see prepare_ns). So does a kernel or a capability
 * set that refuses the namespace. No fiber runs less confined than the
 * fiberd asked. */
static void own_mountns(void) {
    if (!getenv("FIBERD_OWN_MNTNS")) {
        snprintf(own_ns_why, sizeof own_ns_why, "FIBERD_OWN_MNTNS was not set, so the zygote took no mount namespace of its own");
        return;
    }
    int threads = thread_count();
    if (threads != 1) {
        snprintf(own_ns_why, sizeof own_ns_why, "%s, so the zygote took no mount namespace of its own",
                 threads < 0 ? "the zygote cannot count its threads (/proc/self/task)" : "a thread existed before fz_init");
        return;
    }
    /* The raw syscall, like the rest of the file, so the fuzz harnesses
     * that shim syscall() keep it from running there. */
    if (syscall(SYS_unshare, CLONE_NEWNS) < 0) {
        snprintf(own_ns_why, sizeof own_ns_why, "the zygote could not take a mount namespace of its own: unshare: errno %d", errno);
        return;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        snprintf(own_ns_why, sizeof own_ns_why, "the zygote could not make its mount namespace private: errno %d", errno);
        return;
    }
    have_own_ns = 1;
}

/* The nocaps option. The child drops every capability it can use or
 * regain (drop_caps in core/src/child.rs). */
struct confine {
    int pidns, mntns, nocaps;
};

/* Set when fiberd asked for nested user namespaces to be denied
 * (FIBERD_USERNS_NESTED=deny). The zygote's own namespace has its limit
 * set to 0 (cap_nested_userns), and every fiber gets a seccomp filter as
 * well (userns_filter in core/src/child.rs), because a checkpoint
 * restores a fiber into a new user namespace with the default limit,
 * and criu carries seccomp filters across. */
static int deny_nested_userns;

/* A session, an endpoint and a fence as the fiber's environment carries
 * them are at most ENV_VALUE_MAX - 1 characters. */
#define ENV_VALUE_MAX 1024

/* An incarnation record and what is parsed out of it, 'i' then eleven
 * NUL-ended fields (see libfiberzygote.h). The fiber's two stores, the
 * birth record's and a resume's, are the Rust core's (core/src/fiber.rs),
 * in its bss as they were here. The layout stays here, pinned to the
 * core's (core/src/abi.rs) with the same numbers, for the fuzz harnesses
 * that include this file and look into the stores. */
#define RECORD_MAX 65536
#define SEED_LEN 32
struct record_store {
    char session[ENV_VALUE_MAX];
    unsigned char seed[SEED_LEN];
    char *seed_hex; /* the seed's field in buf, zeroed with seed */
    fz_identity_t identity;
    fz_incarnation_t inc;
    char buf[RECORD_MAX];
    unsigned char payload[RECORD_MAX / 2];
};
/* The Rust core mirrors these layouts (core/src/abi.rs) with the same
 * numbers, so a field moved on either side fails to compile. */
_Static_assert(sizeof(fz_identity_t) == 32, "fz_identity_t layout");
_Static_assert(offsetof(fz_identity_t, key_pem) == 0, "fz_identity_t layout");
_Static_assert(offsetof(fz_identity_t, cert_pem) == 8, "fz_identity_t layout");
_Static_assert(offsetof(fz_identity_t, caller) == 16, "fz_identity_t layout");
_Static_assert(offsetof(fz_identity_t, caller_pem) == 24, "fz_identity_t layout");
_Static_assert(sizeof(fz_incarnation_t) == 80, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, fence) == 0, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, endpoint) == 8, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, payload) == 16, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, payload_len) == 24, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, session) == 32, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, generation) == 40, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, kind) == 48, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, seed) == 56, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, seed_len) == 64, "fz_incarnation_t layout");
_Static_assert(offsetof(fz_incarnation_t, identity) == 72, "fz_incarnation_t layout");
_Static_assert(sizeof(struct record_store) == 99480, "record_store layout");
_Static_assert(offsetof(struct record_store, session) == 0, "record_store layout");
_Static_assert(offsetof(struct record_store, seed) == 1024, "record_store layout");
_Static_assert(offsetof(struct record_store, seed_hex) == 1056, "record_store layout");
_Static_assert(offsetof(struct record_store, identity) == 1064, "record_store layout");
_Static_assert(offsetof(struct record_store, inc) == 1096, "record_store layout");
_Static_assert(offsetof(struct record_store, buf) == 1176, "record_store layout");
_Static_assert(offsetof(struct record_store, payload) == 66712, "record_store layout");

/* The fiber's environment, built by the parent before the clone (see
 * handle_clone) and assigned whole in the child. */
static char env_fence[sizeof "FIBERD_FENCE=" + FENCE_MAX];
static char env_endpoint[sizeof "FIBERD_ENDPOINT=" + ENV_VALUE_MAX];
static char env_engine[sizeof "FIBERD_ENGINE=" + sizeof engine_endpoint];
static char env_channel[sizeof "FIBERD_CHANNEL_FD=" + 16];
static char env_session[sizeof "FIBERD_SESSION=" + ENV_VALUE_MAX];
static char *fiber_environ[6];
/* The session named on the CLONE line, decoded, for the fiber's record. */
static char session_buf[ENV_VALUE_MAX];

/* scrub_and_run is the child between the clone and the application.
 *
 * THE RULE FOR THIS PATH. Nothing here may allocate, free, use stdio or
 * take a lock before on_fiber runs, on either birth path. The clone
 * copies one thread of the zygote. The others (an engine) may hold
 * malloc's lock, a stream's lock, the locale's or libc's random state
 * lock at that instant, and the copy of such a lock is held forever.
 * glibc's fork() reinitialises those for its child and the raw clone
 * does not, which is also why nothing here relies on what fork() would
 * have reset (the thread descriptor's cached tid, the robust list).
 * Only system calls and pure string functions are used. Everything the
 * fiber needs built (its environment, its record) is built by the
 * parent before the clone or read into static storage with raw
 * syscalls, and errors are written with write(2).
 *
 * The path itself is core/src/child.rs, under the same rule. What is
 * left here is plain stores to this file's statics, which stay here
 * until stage 5, and the one call. Nothing reads these statics before
 * on_fiber, so their order against the child's system calls does not
 * matter, and no system call is made here. */
static void scrub_and_run(const struct fz_rs_child *c) {
    /* The control channel is the zygote's, not this child's. fz_report
     * from a fiber must fail, not write into whatever lands at fd 3 (the
     * readiness pipe). The mutex copied from the zygote may be held by a
     * thread that does not exist here, so it starts over. */
    g_ctl_fd = -1;
    control_handler = NULL;
    static const pthread_mutex_t fresh = PTHREAD_MUTEX_INITIALIZER;
    memcpy(&g_ctl_mu, &fresh, sizeof g_ctl_mu);
    /* The core closes the zygote's SIGCHLD descriptor (c->sigchld_fd),
     * parks the readiness pipe at fd 3 and the channel at FZ_CHANNEL_FD,
     * and resets the fiber's state (core/src/fiber.rs) to name them. */
    sigchld_fd = -1;
    /* Environment. Nothing is inherited but the identity assigned now.
     * The parent built fiber_environ for this clone. The grant's TLS
     * identity is in memory (the record), not in any file it could
     * name. */
    environ = fiber_environ;
    fz_rs_scrub_and_run(c);
}

void fz_init(int argc, char **argv) {
    (void)argc;
    /* Before any thread exists, so every thread inherits it. A thread
     * with SIGCHLD unblocked would take a child's exit with the default
     * action, and the loop's descriptor (fz_serve) would never see it.
     * The mask survives the re-exec below. */
    block_sigchld();
    int p = personality(0xffffffff);
    if (p == -1 || (p & ADDR_NO_RANDOMIZE)) { own_mountns(); return; }
    if (personality((unsigned long)(p | ADDR_NO_RANDOMIZE)) == -1) { own_mountns(); return; }
    /* Re-exec so the new personality applies to every mapping. Loops are
     * impossible, because the second incarnation sees the flag and returns.
     * The mount namespace is taken by the incarnation that goes on, so
     * it is taken once. */
    execv("/proc/self/exe", argv);
    /* If exec fails we carry on randomised, and deltas will be larger. */
    own_mountns();
}

/* The fiber-side API (fz_fiber_ready, fz_accept, fz_quiesce,
 * fz_incarnation_wait, fz_seed_forget) and the gVisor side
 * (fz_gvisor_identity, fz_gvisor_ack) are the Rust core's
 * (core/src/fiber.rs), exported from there with the header's
 * signatures, with the state only they and the child's path touch. */

/* A pending child's pipe became readable or closed. Only the ready
 * record (see fz_fiber_ready) makes a fiber. On EOF or anything else
 * the child, if still alive, is killed and the CLONE answered with an
 * ERROR. Nothing here waits on a live child. A fiber that closed or
 * scribbled on the pipe and kept running would otherwise hold the
 * zygote, and every other grant's clone behind it. */
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
    /* A child that exited closed the pipe before it can be reaped, since
     * its mount namespace (the covers, the run directory bind) is torn
     * down in between, and that takes a moment. On EOF, give it that
     * moment before taking it for a live child that closed the pipe. The
     * wait is bounded, so a fiber that did close it and runs on costs
     * the zygote 200ms, not a hang. */
    if (n == 0 && w == 0) w = wait_bounded(pending[i].pid, &status, 200);
    if (w == 0) {
        /* Alive. It closed the pipe or wrote something else on it. */
        doom(pending[i].pid);
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
        doom(pending[i].pid);
        sendf(ctl_fd, "ERROR %s deadline exceeded before ready", pending[i].fence);
        drop_pending(i);
    }
}

static int handle_clone(int ctl_fd, char *line, const int passed[MAX_PASSED], fz_on_fiber on_fiber) {
    /* CLONE <fence> <endpoint> <deadline_ms> <hexpayload|-> <hexsession|-> [opt,opt...]
     * The Rust core takes the line apart (line::parse_clone), cutting it
     * up in place, and decodes the session into session_buf. Each ERROR
     * is sent from here, at the place its check always had among the
     * checks on the zygote's own state. */
    struct fz_rs_clone cl;
    int refused = fz_rs_parse_clone(line, session_buf, sizeof session_buf, &cl);
    const char *fence = cl.fence, *endpoint = cl.endpoint;
    struct confine cf = { .pidns = cl.pidns, .mntns = cl.mntns, .nocaps = cl.nocaps };
    /* Until the fence is known to fit, it goes on the line cut to what
     * the records hold, so the line is sent rather than dropped. */
    if (refused == FZ_RS_CLONE_MALFORMED) {
        sendf(ctl_fd, "ERROR %.*s malformed CLONE", FENCE_MAX - 1, fence ? fence : "?");
        return 0;
    }
    if (refused == FZ_RS_CLONE_FENCE_LONG) {
        sendf(ctl_fd, "ERROR %.*s fence too long (at most %d characters)", FENCE_MAX - 1, fence, FENCE_MAX - 1);
        return 0;
    }
    if (cf.mntns && paths_refused) {
        sendf(ctl_fd, "ERROR %s refused: the mount namespace cannot hide what fiberd asked (%s)", fence, paths_refused);
        return 0;
    }
    if (cf.mntns && !ns_prepared) {
        sendf(ctl_fd, "ERROR %s refused: no mount namespace was prepared before READY (fiberd sent PREPARE none)", fence);
        return 0;
    }
    /* The channel is the last descriptor passed, after the cgroup's when
     * there is one. */
    int cgroup_fd = passed[0], channel = passed[1];
    if (channel < 0) { channel = passed[0]; cgroup_fd = -1; }
    if (channel < 0) {
        sendf(ctl_fd, "ERROR %s CLONE without a channel", fence);
        return 0;
    }
    int deadline_ms = cl.deadline_ms;
    /* The payload reaches the fiber on its record. The line's copy is
     * not decoded here. The session is a C string for the fiber's
     * environment, so a NUL inside it, or more than fits, is refused
     * rather than cut. */
    if (refused == FZ_RS_CLONE_SESSION_LONG) {
        sendf(ctl_fd, "ERROR %s session too long (at most %d bytes)", fence, ENV_VALUE_MAX - 1);
        return 0;
    }
    if (refused == FZ_RS_CLONE_SESSION_NUL) {
        sendf(ctl_fd, "ERROR %s session holds a NUL byte", fence);
        return 0;
    }
    size_t slen = cl.session_len;

    if (npending >= MAX_PENDING) {
        sendf(ctl_fd, "ERROR %s too many clones in flight", fence);
        return 0;
    }
    /* The fiber's environment, built here where allocation is fine. The
     * child only points environ at it. Static storage is reused per
     * clone, and the child's copy-on-write pages keep this clone's
     * values. */
    snprintf(env_fence, sizeof env_fence, "FIBERD_FENCE=%s", fence);
    /* At most ENV_VALUE_MAX - 1 characters, as the fence is at most
     * FENCE_MAX - 1 (see libfiberzygote.h). Checked on the length itself,
     * since env_endpoint has room for the name as well. */
    if (cl.endpoint_len >= ENV_VALUE_MAX) {
        sendf(ctl_fd, "ERROR %s endpoint too long (at most %d characters)", fence, ENV_VALUE_MAX - 1);
        return 0;
    }
    snprintf(env_endpoint, sizeof env_endpoint, "FIBERD_ENDPOINT=%s", endpoint);
    int ne = 0;
    fiber_environ[ne++] = env_fence;
    fiber_environ[ne++] = env_endpoint;
    if (engine_endpoint[0]) {
        snprintf(env_engine, sizeof env_engine, "FIBERD_ENGINE=%s", engine_endpoint);
        fiber_environ[ne++] = env_engine;
    }
    snprintf(env_channel, sizeof env_channel, "FIBERD_CHANNEL_FD=%d", FZ_CHANNEL_FD);
    fiber_environ[ne++] = env_channel;
    if (slen) {
        snprintf(env_session, sizeof env_session, "FIBERD_SESSION=%s", session_buf);
        fiber_environ[ne++] = env_session;
    }
    fiber_environ[ne] = NULL;
    int rp[2];
    if (pipe2(rp, O_CLOEXEC) < 0) { sendf(ctl_fd, "ERROR %s pipe: %s", fence, strerror(errno)); return 0; }

    /* What the child's path needs, built before the clone so the child
     * does nothing but its plain stores and the one call. */
    struct fz_rs_child child = {
        .ready_r = rp[0], .ready_w = rp[1], .channel = channel, .sigchld_fd = sigchld_fd,
        .pidns = cf.pidns, .mntns = cf.mntns, .nocaps = cf.nocaps, .deny_nested_userns = deny_nested_userns,
        .nhide = nhide, .ndrop = ndrop,
        .fence = fence, .on_fiber = on_fiber,
        .self_exe = self_exe, .hide = hide_paths, .hide_covered = hide_covered, .drop = drop_paths,
    };
    unsigned long long want = (cf.pidns ? CLONE_NEWPID : 0) | (cf.mntns ? CLONE_NEWNS : 0);
    pid_t pid = birth(cgroup_fd, want);
    if (pid < 0) {
        sendf(ctl_fd, "ERROR %s clone: %s", fence, strerror(errno));
        close(rp[0]); close(rp[1]);
        return 0;
    }
    if (pid == 0) {
        scrub_and_run(&child);
        _exit(127); /* not reached */
    }
    close(rp[1]);
    /* Do not wait here. Park the child and return to the loop, so the
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
 * made again inside the tmpfs that covers parent. A parent of "/" would
 * cover the root. Returns 0, or -1 with a reason. Runs in the zygote's
 * loop, where allocation would be fine, but the paths go to static
 * storage so the child reads them without any. The parsing is in the
 * Rust core (line::parse_rundir). */
static int set_rundir(char *line, const char **why) { return fz_rs_set_rundir(line, rundir_parent, rundir_own, why); }

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
    return fz_rs_in_child_userns(buf);
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
 * the write would reach the host. When /proc/sys is read-only here (a
 * container's default) the knob is reached through a fresh proc mount,
 * which belongs to this mount namespace and is undone before anything
 * else sees it. Returns 0, or -1 with errno and a line on stderr. */
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

/* rebind_ctl takes the control socket fiberd sends as a REBIND
 * message on the bootstrap one and puts it at ctl_fd in its place. The
 * fiberd makes that socket in this zygote's network namespace, where a
 * checkpoint of the zygote finds it. */
static int rebind_ctl(int ctl_fd) {
    static char line[64];
    int passed[MAX_PASSED];
    ssize_t n = recv_line(ctl_fd, line, sizeof line, passed);
    if (n <= 0 || !fz_rs_is_rebind(line) || passed[0] < 0) {
        for (int i = 0; i < MAX_PASSED; i++) if (passed[i] >= 0) close(passed[i]);
        fprintf(stderr, "libfiberzygote: expected REBIND with a socket, got %s\n", n > 0 ? line : "end of stream");
        errno = EPROTO;
        return -1;
    }
    if (dup2(passed[0], ctl_fd) < 0) return -1;
    for (int i = 0; i < MAX_PASSED; i++) if (passed[i] >= 0) close(passed[i]);
    return 0;
}

/* keep_path keeps a HIDE or DROP line's path for prepare_ns and
 * mount_ns, or refuses it when the zygote holds no more. */
static void keep_path(const char *line) {
    int hide = line[0] == 'H';
    char (*paths)[KEEP_MAX] = hide ? hide_paths : drop_paths;
    int *count = hide ? &nhide : &ndrop;
    if (*count < MAX_PATHS) {
        /* The line is at most MAX_LINE - 1 characters (recv_line), so
         * the path after its prefix always fits its KEEP_MAX slot. */
        const char *p = line + 5;
        memcpy(paths[(*count)++], p, strlen(p) + 1);
        return;
    }
    paths_refused = hide ? "HIDE: too many paths" : "DROP: too many paths";
    fprintf(stderr, "libfiberzygote: %s refused\n", paths_refused);
}

/* read_setup takes fiberd's setup lines before READY. HIDE, DROP and
 * RUNDIR name what every mntns fiber's namespace must have, and
 * PREPARE ends them. PREPARE mntns has the zygote prepare its own
 * namespace with them (prepare_ns), and PREPARE none says no fiber will
 * ask for a mount namespace, so nothing is mounted and a mntns CLONE is
 * refused later. A refused line leaves its reason in paths_refused and
 * READY still goes out, so fiberd sees the warm succeed and every
 * mntns CLONE refused with that reason (fail closed). Any other line
 * here is a protocol error, and the zygote does not serve. Returns 1 to
 * serve, 0 when fiberd closed the channel first, -1 on an error with
 * errno set and a line on stderr. */
static int read_setup(int ctl_fd) {
    static char line[MAX_LINE];
    int passed[MAX_PASSED];
    for (;;) {
        ssize_t n = recv_line(ctl_fd, line, sizeof line, passed);
        for (int i = 0; i < MAX_PASSED; i++)
            if (passed[i] >= 0) close(passed[i]);
        if (n < 0) return -1;
        if (n == 0) return 0;
        switch (fz_rs_setup_kind(line)) {
        case FZ_RS_SETUP_HIDE:
        case FZ_RS_SETUP_DROP:
            keep_path(line);
            break;
        case FZ_RS_SETUP_RUNDIR: {
            const char *why = NULL;
            if (set_rundir(line, &why) < 0) {
                paths_refused = "RUNDIR refused";
                fprintf(stderr, "libfiberzygote: RUNDIR refused: %s\n", why);
            }
            break;
        }
        case FZ_RS_SETUP_PREPARE_MNTNS:
            if (prepare_ns() < 0) fprintf(stderr, "libfiberzygote: PREPARE refused: %s\n", paths_refused);
            return 1;
        case FZ_RS_SETUP_PREPARE_NONE:
            return 1;
        default:
            fprintf(stderr, "libfiberzygote: expected HIDE, DROP, RUNDIR or PREPARE before READY, got %.60s\n", line);
            errno = EPROTO;
            return -1;
        }
    }
}

int fz_serve(int ctl_fd, fz_on_fiber on_fiber) {
    signal(SIGPIPE, SIG_IGN);
    /* All before READY, so a zygote that skipped fz_init, cannot deny
     * nested user namespaces or cannot take its channel never serves and
     * fiberd sees the warm fail. SIGCHLD unblocked here means it may
     * be unblocked in a thread fz_init would have covered, and a fiber's
     * exit would then reach the loop a timeout late. */
    sigset_t have;
    if (pthread_sigmask(SIG_BLOCK, NULL, &have) != 0 || !sigismember(&have, SIGCHLD)) {
        fprintf(stderr, "libfiberzygote: SIGCHLD is not blocked; call fz_init first thing in main\n");
        errno = EINVAL;
        return -1;
    }
    if (sigchld_fd < 0) {
        sigset_t chld;
        sigemptyset(&chld);
        sigaddset(&chld, SIGCHLD);
        sigchld_fd = signalfd(-1, &chld, SFD_NONBLOCK | SFD_CLOEXEC);
        if (sigchld_fd < 0) return -1;
    }
    if (getenv("FIBERD_CTL_REBIND") && rebind_ctl(ctl_fd) < 0) return -1;
    const char *nested = getenv("FIBERD_USERNS_NESTED");
    if (nested && strcmp(nested, "deny") == 0) {
        if (cap_nested_userns() < 0) return -1;
        deny_nested_userns = 1;
    }
    /* The setup lines and the namespace they describe come before READY,
     * so READY means every mntns fiber's namespace is ready to copy. A
     * zygote that could not build it says so instead of READY and ends.
     * Every fiber of a plain proc grant asks for a mount namespace, so
     * a zygote that would refuse them all is no warm template, and the
     * fiberd must fail the warm rather than report the grant ready. */
    int setup = read_setup(ctl_fd);
    if (setup <= 0) return setup;
    if (paths_refused) {
        sendf(ctl_fd, "ERROR ? %s", paths_refused);
        errno = ENOTRECOVERABLE;
        return -1;
    }
    if (sendf(ctl_fd, "READY") < 0) return -1;
    g_ctl_fd = ctl_fd; /* from here on other threads may fz_report */
    static char line[MAX_LINE];
    static struct pollfd fds[2 + MAX_PENDING];
    for (;;) {
        /* Poll the control socket, the SIGCHLD descriptor and every
         * pending readiness pipe, no longer than the nearest deadline.
         * The 100ms is a backstop. A SIGCHLD taken elsewhere (a thread
         * that unblocked it) then costs a wait, not a hang. */
        fds[0].fd = ctl_fd; fds[0].events = POLLIN;
        fds[1].fd = sigchld_fd; fds[1].events = POLLIN;
        int timeout = 100;
        for (int i = 0; i < npending; i++) {
            fds[2 + i].fd = pending[i].ready_fd;
            fds[2 + i].events = POLLIN;
            long left = ms_until(pending[i].deadline);
            if (left < 0) left = 0;
            if (left < timeout) timeout = (int)left;
        }
        int r = poll(fds, (nfds_t)(2 + npending), timeout);
        if (r < 0 && errno != EINTR) return -1;
        /* Drain the signal. Exits coalesce into one pending SIGCHLD, and
         * reap below takes every child that is gone. */
        if (fds[1].revents & POLLIN) {
            struct signalfd_siginfo si;
            while (read(sigchld_fd, &si, sizeof si) > 0) {}
        }
        /* Settle children whose pipes spoke, walking backwards because
         * settling removes entries by swapping in the last one. */
        for (int i = npending - 1; i >= 0; i--)
            if (fds[2 + i].revents & (POLLIN | POLLHUP | POLLERR))
                settle_pending(ctl_fd, i);
        expire_pending(ctl_fd);
        reap(ctl_fd);
        if (!(fds[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        int passed[MAX_PASSED];
        ssize_t n = recv_line(ctl_fd, line, sizeof line, passed);
        if (n <= 0) {
            if (n == 0) { /* fiberd gone: take the family with us */
                for (int i = 0; i < nkids; i++) kill(kids[i].pid, SIGKILL);
                for (int i = 0; i < npending; i++) kill(pending[i].pid, SIGKILL);
                return 0;
            }
            return -1;
        }
        if (strncmp(line, "CLONE ", 6) == 0) {
            handle_clone(ctl_fd, line, passed, on_fiber);
        } else if (strncmp(line, "HIDE ", 5) == 0 || strncmp(line, "DROP ", 5) == 0 ||
                   strncmp(line, "RUNDIR ", 7) == 0 || strncmp(line, "PREPARE ", 8) == 0) {
            /* The namespace was prepared before READY and takes no more.
             * A path asked for now would go unhidden, so every mntns
             * CLONE from here on is refused rather than born short. */
            if (!paths_refused) paths_refused = "a setup line (HIDE, DROP, RUNDIR or PREPARE) came after READY";
            sendf(ctl_fd, "ERROR ? %.*s after READY refused: the namespace was prepared before READY; every mntns CLONE is refused",
                  (int)strcspn(line, " "), line);
        } else if (control_handler) {
            control_handler(line);
        } else {
            sendf(ctl_fd, "ERROR ? unknown message");
        }
        for (int i = 0; i < MAX_PASSED; i++)
            if (passed[i] >= 0) close(passed[i]);
    }
}
