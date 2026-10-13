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
