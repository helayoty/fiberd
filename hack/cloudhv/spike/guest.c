/*
 * The spike guest's init, built static by setup.sh and placed alone in the
 * initramfs. It runs as PID 1 and never exits.
 *
 * It prints "spike-guest: READY" on the console once it listens on vsock
 * port 1024. The host reaches that port through the VMM's vsock socket with
 * "CONNECT 1024", then sends one command line per connection.
 *
 *   ping            -> pong
 *   incarnate <n>   -> served <n>       (the served line S4 times)
 *   touch <mib>     -> touched <mib>    (dirties fresh guest pages)
 *   dial            -> dialed | dial err <errno>
 *                      (opens and keeps a connection to host CID 2 port 5000)
 *   send <text>     -> sent ok | sent err <errno>   (on the kept connection)
 *   recv            -> recv <text> | recv eof | recv timeout | recv err <errno>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define LINE_MAX_BYTES 256
#define HOST_PORT 5000
#define GUEST_PORT 1024

static int kept = -1; /* the open connection to host port 5000 */

static void console(void)
{
	mkdir("/dev", 0755);
	mkdir("/proc", 0555);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("proc", "/proc", "proc", 0, NULL);
	int fd = open("/dev/console", O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}
}

static void say(const char *fmt, ...)
{
	char buf[LINE_MAX_BYTES];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof buf - 2)
		n = sizeof buf - 2;
	buf[n++] = '\n';
	(void)write(1, buf, n);
}

static void reply(int c, const char *fmt, ...)
{
	char buf[LINE_MAX_BYTES];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof buf - 2)
		n = sizeof buf - 2;
	buf[n++] = '\n';
	(void)write(c, buf, n);
}

/* Reads one line, without its newline. Returns its length or -1. */
static int read_line(int fd, char *buf, int max, int timeout_ms)
{
	int n = 0;
	while (n < max - 1) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		int r = poll(&p, 1, timeout_ms);
		if (r == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		char ch;
		ssize_t got = read(fd, &ch, 1);
		if (got == 0)
			break;
		if (got < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ch == '\n')
			break;
		buf[n++] = ch;
	}
	buf[n] = 0;
	return n;
}

static void touch(int c, long mib)
{
	if (mib <= 0 || mib > 4096) {
		reply(c, "err size");
		return;
	}
	size_t len = (size_t)mib << 20;
	char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		reply(c, "err mmap %d", errno);
		return;
	}
	long page = sysconf(_SC_PAGESIZE);
	for (size_t off = 0; off < len; off += (size_t)page)
		p[off] = (char)(off / (size_t)page + 1);
	/* Kept mapped on purpose, so the pages stay dirty. */
	reply(c, "touched %ld", mib);
}

static void dial(int c)
{
	if (kept >= 0) {
		close(kept);
		kept = -1;
	}
	int s = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0) {
		reply(c, "dial err %d", errno);
		return;
	}
	struct sockaddr_vm a = { .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = HOST_PORT };
	if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
		int e = errno;
		close(s);
		reply(c, "dial err %d", e);
		return;
	}
	const char hello[] = "hello from the guest\n";
	if (write(s, hello, sizeof hello - 1) < 0) {
		int e = errno;
		close(s);
		reply(c, "dial err %d", e);
		return;
	}
	kept = s;
	reply(c, "dialed");
}

static void send_kept(int c, const char *text)
{
	if (kept < 0) {
		reply(c, "sent err none");
		return;
	}
	char buf[LINE_MAX_BYTES];
	int n = snprintf(buf, sizeof buf, "%s\n", text);
	if (send(kept, buf, (size_t)n, MSG_NOSIGNAL) < 0)
		reply(c, "sent err %d", errno);
	else
		reply(c, "sent ok");
}

static void recv_kept(int c)
{
	if (kept < 0) {
		reply(c, "recv err none");
		return;
	}
	char buf[LINE_MAX_BYTES];
	struct pollfd p = { .fd = kept, .events = POLLIN };
	int r = poll(&p, 1, 2000);
	if (r == 0) {
		reply(c, "recv timeout");
		return;
	}
	if (r < 0) {
		reply(c, "recv err %d", errno);
		return;
	}
	ssize_t got = recv(kept, buf, sizeof buf - 1, MSG_DONTWAIT);
	if (got == 0) {
		reply(c, "recv eof");
		return;
	}
	if (got < 0) {
		reply(c, "recv err %d", errno);
		return;
	}
	buf[got] = 0;
	char *nl = strchr(buf, '\n');
	if (nl)
		*nl = 0;
	reply(c, "recv %s", buf);
}

static void serve(int c)
{
	char line[LINE_MAX_BYTES];
	if (read_line(c, line, sizeof line, 5000) < 0)
		return;
	if (strcmp(line, "ping") == 0)
		reply(c, "pong");
	else if (strncmp(line, "incarnate ", 10) == 0)
		reply(c, "served %s", line + 10);
	else if (strncmp(line, "touch ", 6) == 0)
		touch(c, strtol(line + 6, NULL, 10));
	else if (strcmp(line, "dial") == 0)
		dial(c);
	else if (strncmp(line, "send ", 5) == 0)
		send_kept(c, line + 5);
	else if (strcmp(line, "recv") == 0)
		recv_kept(c);
	else
		reply(c, "err unknown");
}

int main(void)
{
	console();
	say("spike-guest: up");
	int l = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (l < 0) {
		say("spike-guest: socket failed errno=%d", errno);
		for (;;)
			pause();
	}
	struct sockaddr_vm a = { .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_ANY, .svm_port = GUEST_PORT };
	if (bind(l, (struct sockaddr *)&a, sizeof a) < 0 || listen(l, 16) < 0) {
		say("spike-guest: listen failed errno=%d", errno);
		for (;;)
			pause();
	}
	say("spike-guest: READY");
	for (;;) {
		int c = accept4(l, NULL, NULL, SOCK_CLOEXEC);
		if (c < 0)
			continue;
		serve(c);
		close(c);
	}
}
