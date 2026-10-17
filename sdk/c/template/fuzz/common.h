/* Shared helpers for the libFuzzer harnesses in this directory. Each
 * harness includes the zygote source it tests, so it reaches the static
 * parsers directly, and hands them the fuzz input through the kind of
 * descriptor they read from, a memfd for a file or a socket for a peer. */
#ifndef FZ_FUZZ_COMMON_H
#define FZ_FUZZ_COMMON_H
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mount.h>
#include <sys/stat.h>

/* The system call hooks. run.sh links the core archive built with its
 * fuzzshim feature, whose sys layer calls these five instead of libc, so
 * a harness can shim what the Rust does as it shims the C with #define.
 * That archive needs all five. A harness that shims one defines
 * FZ_SHIM_<NAME> before it includes this file and writes its own. Every
 * other hook gets the pass-through below, which calls the real function. */
long fz_fuzz_syscall(long nr, ...);
int fz_fuzz_mount(const char *src, const char *target, const char *type, unsigned long flags, const void *opts);
int fz_fuzz_umount2(const char *target, int flags);
int fz_fuzz_mkdir(const char *path, mode_t mode);
int fz_fuzz_open(const char *path, int flags, ...);

#ifndef FZ_SHIM_SYSCALL
/* Only the core calls the hook here (the C reaches syscall itself), and
 * its sys::syscall always passes five arguments, zero past what the call
 * takes. So the pass-through forwards five. */
long fz_fuzz_syscall(long nr, ...) {
    long a[5];
    va_list ap;
    va_start(ap, nr);
    for (int i = 0; i < 5; i++) a[i] = va_arg(ap, long);
    va_end(ap);
    return syscall(nr, a[0], a[1], a[2], a[3], a[4]);
}
#endif

#ifndef FZ_SHIM_MOUNT
int fz_fuzz_mount(const char *src, const char *target, const char *type, unsigned long flags, const void *opts) {
    return mount(src, target, type, flags, opts);
}
#endif

#ifndef FZ_SHIM_UMOUNT2
int fz_fuzz_umount2(const char *target, int flags) {
    return umount2(target, flags);
}
#endif

#ifndef FZ_SHIM_MKDIR
int fz_fuzz_mkdir(const char *path, mode_t mode) {
    return mkdir(path, mode);
}
#endif

#ifndef FZ_SHIM_OPEN
/* open reads a mode only when the flags ask to create a file. */
int fz_fuzz_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, unsigned int);
        va_end(ap);
    }
    return open(path, flags, mode);
}
#endif

/* memfd_of returns a memfd holding data, positioned at its start. The
 * harness cannot run without one, so a refusal aborts. */
static inline int memfd_of(const uint8_t *data, size_t n) {
    int fd = memfd_create("fuzz", MFD_CLOEXEC);
    if (fd < 0) abort();
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, data + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; abort(); }
        off += (size_t)w;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) abort();
    return fd;
}

/* stream_pair makes a connected AF_UNIX pair of the given type. */
static inline void stream_pair(int type, int s[2]) {
    if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, s) < 0) abort();
}

/* send_fds sends data (at least one byte) on sock as one message, with
 * the nfds descriptors in fds riding along in SCM_RIGHTS. */
static inline void send_fds(int sock, const uint8_t *data, size_t n, const int *fds, size_t nfds) {
    if (n == 0) abort();
    struct iovec iov = { .iov_base = (void *)data, .iov_len = n };
    char cbuf[CMSG_SPACE(8 * sizeof(int))];
    struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
    if (nfds > 8) abort();
    if (nfds) {
        memset(cbuf, 0, sizeof cbuf);
        mh.msg_control = cbuf;
        mh.msg_controllen = CMSG_SPACE(nfds * sizeof(int));
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(nfds * sizeof(int));
        memcpy(CMSG_DATA(c), fds, nfds * sizeof(int));
    }
    ssize_t r;
    do r = sendmsg(sock, &mh, MSG_NOSIGNAL); while (r < 0 && errno == EINTR);
    if (r != (ssize_t)n) abort();
}

/* send_scratch_fds is send_fds with nfds throwaway memfds attached, which
 * it closes once they are in flight. */
static inline void send_scratch_fds(int sock, const uint8_t *data, size_t n, size_t nfds) {
    int fds[8];
    for (size_t i = 0; i < nfds; i++) fds[i] = memfd_of(NULL, 0);
    send_fds(sock, data, n, fds, nfds);
    for (size_t i = 0; i < nfds; i++) close(fds[i]);
}

#endif
