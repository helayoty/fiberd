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
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/sched.h>

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#define MAX_LINE 65536
#define MAX_KIDS 4096
#define MAX_PENDING 1024

static int ready_fd = -1;

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
    int pidns;
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

/* Read one line; if a descriptor rides along via SCM_RIGHTS, store it in
 * *fd_out (else -1). Returns line length, 0 on EOF, -1 on error. */
static ssize_t recv_line(int fd, char *buf, size_t cap, int *fd_out) {
    size_t len = 0;
    *fd_out = -1;
    while (len + 1 < cap) {
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = buf + len, .iov_len = 1 };
        struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = cbuf, .msg_controllen = sizeof cbuf };
        ssize_t r = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return len ? (ssize_t)len : 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && *fd_out < 0)
                memcpy(fd_out, CMSG_DATA(c), sizeof(int));
        if (buf[len] == '\n') { buf[len] = 0; return (ssize_t)len + 1; }
        len++;
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

/* birth forks the fiber. With pidns the child is the init of its own pid
 * namespace (pid 1 inside), so a checkpoint of it restores anywhere
 * without colliding with a live pid; *got_pidns reports whether that was
 * granted (it needs CAP_SYS_ADMIN). */
static pid_t birth(int cgroup_fd, int pidns, int *got_pidns) {
    struct clone_args args;
    memset(&args, 0, sizeof args);
    args.exit_signal = SIGCHLD;
    if (cgroup_fd >= 0) {
        args.flags = CLONE_INTO_CGROUP;
        args.cgroup = (unsigned long long)cgroup_fd;
    }
    *got_pidns = 0;
    if (pidns) {
        args.flags |= CLONE_NEWPID;
        long pid = syscall(SYS_clone3, &args, sizeof args);
        if (pid >= 0) { *got_pidns = 1; return (pid_t)pid; }
        if (errno != EPERM && errno != EINVAL && errno != ENOSYS) return -1;
        args.flags &= ~(unsigned long long)CLONE_NEWPID;
    }
    long pid = syscall(SYS_clone3, &args, sizeof args);
    if (pid >= 0) return (pid_t)pid;
    if (errno != ENOSYS && errno != EINVAL && errno != EPERM) return -1;
    /* Kernel without CLONE_INTO_CGROUP: fork, then move before touching
     * memory. The window is the child's first instructions only. */
    pid = fork();
    if (pid == 0 && cgroup_fd >= 0) {
        int procs = openat(cgroup_fd, "cgroup.procs", O_WRONLY | O_CLOEXEC);
        if (procs >= 0) {
            char b[32];
            int n = snprintf(b, sizeof b, "%d", (int)getpid());
            if (write(procs, b, (size_t)n) < 0) _exit(125);
            close(procs);
        }
    }
    return (pid_t)pid;
}

static void scrub_and_run(int ready_w, const char *fence, const char *endpoint,
                          const unsigned char *payload, size_t payload_len,
                          fz_on_fiber on_fiber) {
    /* Descriptors: the readiness pipe parked at fd 3 (overwriting the
     * inherited control descriptor), everything above closed, and the
     * standard three pointed at /dev/null. A fiber inherits nothing that
     * leads outside its own tree; that is also what lets CRIU checkpoint
     * it without --external tricks. */
    if (dup2(ready_w, 3) < 0) _exit(120);
    /* The raw syscall: glibc has a wrapper since 2.34, musl has none. */
    if (syscall(SYS_close_range, 4, ~0U, 0) < 0) {
        for (int fd = 4; fd < 65536; fd++) close(fd);
    }
    ready_fd = 3;
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null >= 0) {
        dup2(null, 0); dup2(null, 1); dup2(null, 2);
        if (null > 3) close(null);
    }

    /* Environment: nothing inherited but the identity assigned now. */
    clearenv();
    setenv("FIBERD_FENCE", fence, 1);
    setenv("FIBERD_ENDPOINT", endpoint, 1);
    if (engine_endpoint[0]) setenv("FIBERD_ENGINE", engine_endpoint, 1);

    /* Session, signals, entropy. No PR_SET_PDEATHSIG: a resumed fiber has
     * a different parent, and the runtime kills leaves through the cgroup
     * when the zygote or the agent goes away. */
    setsid();
    signal(SIGCHLD, SIG_DFL);
    sigset_t none; sigemptyset(&none); sigprocmask(SIG_SETMASK, &none, NULL);
    unsigned seed = 0;
    if (getrandom(&seed, sizeof seed, 0) == (ssize_t)sizeof seed) srandom(seed);

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

void fz_fiber_ready(void) {
    if (ready_fd < 0) return;
    char c = 'r';
    (void)!write(ready_fd, &c, 1);
    close(ready_fd);
    ready_fd = -1;
}

/* A pending child's pipe became readable (or closed): ready, or gone. */
static void settle_pending(int ctl_fd, int i) {
    char c;
    ssize_t n = read(pending[i].ready_fd, &c, 1);
    if (n == 1 && c == 'r') {
        remember(pending[i].pid, pending[i].fence);
        sendf(ctl_fd, "CLONED %s %d pidns=%d", pending[i].fence, (int)pending[i].pid, pending[i].pidns);
        drop_pending(i);
        return;
    }
    /* EOF without the byte: the child exited (or closed the pipe) before
     * reporting. Reap it here unless reap() already did. */
    int status = 0;
    if (waitpid(pending[i].pid, &status, 0) == pending[i].pid)
        send_died(ctl_fd, pending[i].fence, status);
    else
        sendf(ctl_fd, "ERROR %s closed readiness pipe without reporting", pending[i].fence);
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

static int handle_clone(int ctl_fd, char *line, int cgroup_fd, fz_on_fiber on_fiber) {
    /* CLONE <fence> <endpoint> <deadline_ms> <hexpayload|-> [pidns] */
    char *save = NULL;
    strtok_r(line, " ", &save);
    const char *fence = strtok_r(NULL, " ", &save);
    const char *endpoint = strtok_r(NULL, " ", &save);
    const char *dl = strtok_r(NULL, " ", &save);
    const char *hex = strtok_r(NULL, " ", &save);
    const char *opt = strtok_r(NULL, " ", &save);
    int want_pidns = opt && strcmp(opt, "pidns") == 0;
    if (!fence || !endpoint || !dl) {
        sendf(ctl_fd, "ERROR %s malformed CLONE", fence ? fence : "?");
        return 0;
    }
    int deadline_ms = atoi(dl);
    if (deadline_ms <= 0) deadline_ms = 50;
    static unsigned char payload[MAX_LINE / 2];
    size_t plen = (hex && strcmp(hex, "-") != 0) ? unhex(hex, payload, sizeof payload) : 0;

    if (npending >= MAX_PENDING) {
        sendf(ctl_fd, "ERROR %s too many clones in flight", fence);
        return 0;
    }
    int rp[2];
    if (pipe2(rp, O_CLOEXEC) < 0) { sendf(ctl_fd, "ERROR %s pipe: %s", fence, strerror(errno)); return 0; }

    int got_pidns = 0;
    pid_t pid = birth(cgroup_fd, want_pidns, &got_pidns);
    if (pid < 0) {
        sendf(ctl_fd, "ERROR %s clone: %s", fence, strerror(errno));
        close(rp[0]); close(rp[1]);
        return 0;
    }
    if (pid == 0) {
        close(rp[0]);
        scrub_and_run(rp[1], fence, endpoint, payload, plen, on_fiber);
        _exit(127); /* not reached */
    }
    close(rp[1]);
    /* Do not wait here: park the child and return to the loop, so the
     * next CLONE in a storm is forked right away. */
    pending[npending].pid = pid;
    pending[npending].ready_fd = rp[0];
    pending[npending].pidns = got_pidns;
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

int fz_serve(int ctl_fd, fz_on_fiber on_fiber) {
    signal(SIGPIPE, SIG_IGN);
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
        int passed_fd;
        ssize_t n = recv_line(ctl_fd, line, sizeof line, &passed_fd);
        if (n <= 0) {
            if (n == 0) { /* agent gone: take the family with us */
                for (int i = 0; i < nkids; i++) kill(kids[i].pid, SIGKILL);
                for (int i = 0; i < npending; i++) kill(pending[i].pid, SIGKILL);
                return 0;
            }
            return -1;
        }
        if (strncmp(line, "CLONE ", 6) == 0) {
            handle_clone(ctl_fd, line, passed_fd, on_fiber);
        } else if (strcmp(line, "PING") == 0) {
            sendf(ctl_fd, "PONG");
        } else if (control_handler) {
            control_handler(line);
        } else {
            sendf(ctl_fd, "ERROR ? unknown message");
        }
        if (passed_fd >= 0) close(passed_fd);
    }
}
