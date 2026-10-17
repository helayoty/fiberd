/* failchild runs a zygote whose children see one system call fail with
 * EPERM, while the zygote itself makes the same call as usual. The
 * zygote takes its own mount namespace and prepares it with the very
 * mounts a child makes again, so a plain seccomp filter, inherited by
 * both, could not tell them apart. This one hands each matching call
 * to a supervisor (seccomp user notification), which lets the call run
 * when a thread of the zygote made it and fails it for anyone else,
 * that is a child forked from it.
 *
 *   failchild <nr> <arg> <value> <mask> <command> [args...]
 *
 * A call matches when its number is nr and, with arg 0 to 5, the low 32
 * bits of that argument ANDed with mask equal value. arg -1 matches on
 * the number alone. The numbers are decimal, or hex with 0x. The
 * command is exec'd in place, so the zygote keeps this process's pid
 * and descriptors. The supervisor is a grandchild that is reparented
 * away, so the zygote never reaps it, and it exits once the zygote is
 * gone.
 *
 * Built by the tests in tests/integration/proc (see
 * exitcodes_linux_test.go). Needs Linux 5.5 for the CONTINUE answer. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define FAILCHILD_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define FAILCHILD_ARCH AUDIT_ARCH_AARCH64
#else
#error "failchild: add this architecture's AUDIT_ARCH"
#endif

/* The low word of argument i, little-endian, as both supported arches are. */
#define ARG_LO(i) (offsetof(struct seccomp_data, args) + 8 * (i))

static long num(const char *s) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 0);
    if (errno || !*s || *end) {
        fprintf(stderr, "failchild: not a number: %s\n", s);
        exit(2);
    }
    return v;
}

/* zygote_thread reports whether tid is a thread of the zygote. */
static int zygote_thread(pid_t zygote, pid_t tid) {
    char path[64];
    struct stat st;
    snprintf(path, sizeof path, "/proc/%d/task/%d", (int)zygote, (int)tid);
    return stat(path, &st) == 0;
}

/* supervise answers every notification on fd until the zygote is gone. */
static void supervise(int fd, pid_t zygote) {
    struct seccomp_notif_sizes sz;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz) < 0) _exit(3);
    struct seccomp_notif *req = calloc(1, sz.seccomp_notif > sizeof *req ? sz.seccomp_notif : sizeof *req);
    struct seccomp_notif_resp *resp = calloc(1, sz.seccomp_notif_resp > sizeof *resp ? sz.seccomp_notif_resp : sizeof *resp);
    if (!req || !resp) _exit(3);
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int n = poll(&p, 1, 1000);
        if (n < 0 && errno != EINTR) _exit(0);
        if (kill(zygote, 0) < 0 && errno == ESRCH) _exit(0);
        if (n <= 0) continue;
        if (p.revents & (POLLHUP | POLLERR | POLLNVAL)) _exit(0);
        memset(req, 0, sz.seccomp_notif);
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) continue;
        memset(resp, 0, sz.seccomp_notif_resp);
        resp->id = req->id;
        if (zygote_thread(zygote, (pid_t)req->pid)) {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        } else {
            resp->error = -EPERM;
        }
        (void)ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp); /* ENOENT when the caller died */
    }
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: failchild <nr> <arg> <value> <mask> <command> [args...]\n");
        return 2;
    }
    long nr = num(argv[1]), arg = num(argv[2]);
    unsigned value = (unsigned)num(argv[3]), mask = (unsigned)num(argv[4]);
    if (arg < -1 || arg > 5) {
        fprintf(stderr, "failchild: arg %ld is not -1 to 5\n", arg);
        return 2;
    }
    pid_t zygote = getpid();

    /* The supervisor is forked before the filter, so it is not under it
     * and the listener hangs up once the zygote and its children are
     * gone. Its parent ends at once, so it is nobody's child here. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) { perror("failchild: socketpair"); return 2; }
    pid_t mid = fork();
    if (mid < 0) { perror("failchild: fork"); return 2; }
    if (mid == 0) {
        if (fork() != 0) _exit(0);
        /* Hold nothing of the zygote's, its control socket and its log
         * least of all, or fiberd would not see them close. */
        for (int fd = 0; fd < 1024; fd++)
            if (fd != sv[1]) close(fd);
        char b;
        struct iovec iov = { .iov_base = &b, .iov_len = 1 };
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
        if (recvmsg(sv[1], &mh, 0) != 1) _exit(0);
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        if (!c || c->cmsg_type != SCM_RIGHTS) _exit(3);
        int fd;
        memcpy(&fd, CMSG_DATA(c), sizeof fd);
        close(sv[1]);
        supervise(fd, zygote);
        _exit(0);
    }
    close(sv[1]);
    int status;
    if (waitpid(mid, &status, 0) < 0) { perror("failchild: waitpid"); return 2; }

    struct sock_filter filter[16];
    unsigned short n = 0;
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FAILCHILD_ARCH, 1, 0);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    if (arg < 0) {
        filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1);
    } else {
        filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 4);
        filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG_LO(arg));
        filter[n++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask);
        filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 1);
    }
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog prog = { .len = n, .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("failchild: PR_SET_NO_NEW_PRIVS"); return 2; }
    int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener < 0) { perror("failchild: seccomp"); return 2; }

    char b = 0;
    struct iovec iov = { .iov_base = &b, .iov_len = 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof cbuf);
    struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &listener, sizeof listener);
    if (sendmsg(sv[0], &mh, 0) != 1) { perror("failchild: sendmsg"); return 2; }
    close(sv[0]);
    close(listener);
    execv(argv[5], argv + 5);
    perror("failchild: exec");
    return 127;
}
