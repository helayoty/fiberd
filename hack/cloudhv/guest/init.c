/*
 * The guest init of fiberd's cloudhv backend, PID 1 of every micro-VM.
 * hack/cloudhv/build.sh builds it static into the rootfs as /fiberd/init,
 * and the kernel runs it with the template's command after "--".
 *
 * It mounts the guest's own file systems, runs the template as its child
 * with a channel on fd 3, and once the template says READY it serves two
 * vsock ports. Port 1025 takes fiberd's control lines, one per
 * connection. Port 1024 is the fiber's endpoint, spliced to the
 * template's unix socket while an incarnation serves. The protocol is in
 * hack/cloudhv/PROTOCOL.md.
 *
 * Every restored copy of the warm guest holds the same kernel random
 * state, so an INCARNATE first adds its seed to the kernel's pool with
 * RNDADDENTROPY and forces a reseed, then hands the line on to the
 * template, which reseeds its own generators from it.
 *
 * It is C because it parses host input only, needs no allocator and
 * starts in a few hundred microseconds. One process with a poll loop
 * serves control lines in turn, and each endpoint connection is spliced
 * by a forked child, which a park kills.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define ENDPOINT_PORT 1024
#define CONTROL_PORT 1025
#define ENDPOINT "/run/fiberd/fiber.sock"
#define ENGINE "vsock://2:5000"
#define CHANNEL_FD 3
/* An INCARNATE carries a payload of up to 4096 bytes in hex. */
#define LINE_MAX_BYTES 16384
#define MAX_SPLICES 1024
#define CONTROL_TIMEOUT_S 30

enum state { READY, SERVING, PARKED };
static const char *state_names[] = { "ready", "serving", "parked" };

static enum state state = READY;
static pid_t template_pid = -1;
static int channel = -1;
static pid_t splices[MAX_SPLICES];
static int nsplices;

static void say(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("fiberd-init: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/* power_off ends the VM, and with it the VMM. PID 1 never exits, since
 * the kernel would panic and panic=-1 would reboot the guest. */
static void power_off(const char *why)
{
	say("powering off: %s", why);
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}

static void setup(void)
{
	mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL);
	mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755");
	mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");
	mkdir("/run/fiberd", 0755);
	int fd = open("/dev/console", O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}
	signal(SIGPIPE, SIG_IGN);
}

/* read_line reads one line a byte at a time into buf, without its
 * newline, and returns its length, or -1 on an error, an end before the
 * newline, or a line that does not fit. */
static ssize_t read_line(int fd, char *buf, size_t max)
{
	size_t n = 0;
	for (;;) {
		char c;
		ssize_t r = read(fd, &c, 1);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		if (c == '\n') {
			buf[n] = 0;
			return (ssize_t)n;
		}
		if (n + 1 >= max)
			return -1;
		buf[n++] = c;
	}
}

static int write_all(int fd, const char *p, size_t n)
{
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0)
			return -1;
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

static int write_line(int fd, const char *s)
{
	if (write_all(fd, s, strlen(s)) < 0)
		return -1;
	return write_all(fd, "\n", 1);
}

static int vsock_listen(unsigned int port)
{
	int s = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;
	struct sockaddr_vm a = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = port,
	};
	if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 64) < 0) {
		close(s);
		return -1;
	}
	return s;
}

/* splice copies both ways between a and b until both directions end,
 * half-closing the other side when one reaches its end. */
static void splice_fds(int a, int b)
{
	static char buf[65536];
	int open_a = 1, open_b = 1;
	while (open_a || open_b) {
		struct pollfd p[2] = {
			{ .fd = open_a ? a : -1, .events = POLLIN },
			{ .fd = open_b ? b : -1, .events = POLLIN },
		};
		if (poll(p, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		for (int i = 0; i < 2; i++) {
			if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			int from = i == 0 ? a : b, to = i == 0 ? b : a;
			ssize_t r = read(from, buf, sizeof buf);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0) {
				shutdown(to, SHUT_WR);
				if (i == 0)
					open_a = 0;
				else
					open_b = 0;
				continue;
			}
			if (write_all(to, buf, (size_t)r) < 0)
				return;
		}
	}
}

/* splice_endpoint forks a child that splices one vsock connection to the
 * template's endpoint. The parent keeps the child's pid for a park. */
static void splice_endpoint(int c, int listeners[2])
{
	if (nsplices == MAX_SPLICES) {
		close(c);
		return;
	}
	pid_t pid = fork();
	if (pid < 0) {
		close(c);
		return;
	}
	if (pid == 0) {
		close(listeners[0]);
		close(listeners[1]);
		close(channel);
		int u = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		struct sockaddr_un a = { .sun_family = AF_UNIX };
		strncpy(a.sun_path, ENDPOINT, sizeof a.sun_path - 1);
		if (u < 0 || connect(u, (struct sockaddr *)&a, sizeof a) < 0)
			_exit(1);
		splice_fds(c, u);
		_exit(0);
	}
	close(c);
	splices[nsplices++] = pid;
}

/* drop_splices kills every splice, so no connection outlives the
 * incarnation that a park ends. */
static void drop_splices(void)
{
	for (int i = 0; i < nsplices; i++)
		kill(splices[i], SIGKILL);
	for (int i = 0; i < nsplices; i++)
		waitpid(splices[i], NULL, 0);
	nsplices = 0;
}

/* reap collects ended children. The template's end powers the VM off. */
static void reap(void)
{
	int st;
	pid_t pid;
	while ((pid = waitpid(-1, &st, WNOHANG)) > 0) {
		if (pid == template_pid)
			power_off("the template ended");
		for (int i = 0; i < nsplices; i++) {
			if (splices[i] == pid) {
				splices[i] = splices[--nsplices];
				break;
			}
		}
	}
}

static int unhex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* add_entropy mixes the 32-byte seed into the kernel's pool, credited,
 * and forces the CRNG to reseed from it, so getrandom differs in every
 * copy from here on. A kernel without RNDRESEEDCRNG still has the bytes
 * mixed in. */
static int add_entropy(const unsigned char seed[32])
{
	struct {
		int entropy_count;
		int buf_size;
		unsigned char buf[32];
	} info = { .entropy_count = 256, .buf_size = 32 };
	memcpy(info.buf, seed, 32);
	int fd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
	int rc = -1;
	if (fd >= 0) {
		rc = ioctl(fd, RNDADDENTROPY, &info);
		if (rc == 0)
			(void)ioctl(fd, RNDRESEEDCRNG);
		close(fd);
	}
	explicit_bzero(&info, sizeof info);
	return rc;
}

/* tell sends the template one line on its channel and reads its answer
 * into reply. */
static int tell(const char *line, char *reply, size_t max)
{
	if (write_line(channel, line) < 0)
		return -1;
	return read_line(channel, reply, max) < 0 ? -1 : 0;
}

/* incarnate checks an INCARNATE line's seed, adds it to the kernel's
 * pool and hands the whole line to the template. Fields: INCARNATE
 * <generation> <fence> <seed-hex> <payload-hex|-> <session-hex|->. */
static const char *incarnate(char *line, char *reply, size_t max)
{
	char *save = NULL, *copy = strdup(line);
	if (!copy)
		return "error out of memory";
	strtok_r(copy, " ", &save);
	char *gen = strtok_r(NULL, " ", &save);
	char *fence = strtok_r(NULL, " ", &save);
	char *seedhex = strtok_r(NULL, " ", &save);
	const char *why = NULL;
	unsigned char seed[32];
	if (!gen || !fence || !seedhex || atoi(gen) < 1)
		why = "error INCARNATE wants a generation, a fence and a seed";
	else if (strlen(seedhex) != 64)
		why = "error seed is not 32 hex bytes";
	for (int i = 0; !why && i < 32; i++) {
		int hi = unhex(seedhex[2 * i]), lo = unhex(seedhex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			why = "error seed is not 32 hex bytes";
		else
			seed[i] = (unsigned char)(hi << 4 | lo);
	}
	if (!why && add_entropy(seed) < 0)
		why = "error RNDADDENTROPY refused";
	explicit_bzero(seed, sizeof seed);
	explicit_bzero(copy, strlen(copy));
	free(copy);
	if (why)
		return why;
	if (tell(line, reply, max) < 0)
		power_off("the template's channel ended");
	if (strcmp(reply, "SERVED") != 0)
		return NULL;
	state = SERVING;
	return "served";
}

/* control serves one control connection: the state, one command, one
 * answer. A command in the wrong state is refused by name. */
static void control(int c)
{
	static char line[LINE_MAX_BYTES], reply[LINE_MAX_BYTES], out[LINE_MAX_BYTES + 32];
	struct timeval tv = { .tv_sec = CONTROL_TIMEOUT_S };
	setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	if (write_line(c, state_names[state]) < 0)
		return;
	ssize_t n = read_line(c, line, sizeof line);
	if (n < 0)
		return;
	const char *answer = NULL;
	reply[0] = 0;
	if (strncmp(line, "INCARNATE ", 10) == 0) {
		if (state == SERVING)
			answer = "error INCARNATE while serving";
		else
			answer = incarnate(line, reply, sizeof reply);
	} else if (strcmp(line, "PARK") == 0) {
		if (state != SERVING) {
			answer = "error PARK while not serving";
		} else {
			drop_splices();
			if (tell("PARK", reply, sizeof reply) < 0)
				power_off("the template's channel ended");
			if (strcmp(reply, "PARKED") == 0) {
				state = PARKED;
				answer = "parked";
			}
		}
	} else if (strcmp(line, "UNPARK") == 0) {
		if (state != PARKED) {
			answer = "error UNPARK while not parked";
		} else {
			if (tell("UNPARK", reply, sizeof reply) < 0)
				power_off("the template's channel ended");
			if (strcmp(reply, "SERVED") == 0) {
				state = SERVING;
				answer = "served";
			}
		}
	} else {
		answer = "error unknown command";
	}
	explicit_bzero(line, sizeof line);
	if (!answer) {
		snprintf(out, sizeof out, "error template %s", reply);
		answer = out;
	}
	say("control: %s", answer);
	write_line(c, answer);
}

/* start_template runs argv as the template with the channel on fd 3,
 * the endpoint it serves and the engine's address in its environment. */
static void start_template(char **argv)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		power_off("socketpair failed");
	pid_t pid = fork();
	if (pid < 0)
		power_off("fork failed");
	if (pid == 0) {
		/* dup2 clears close-on-exec on the copy. */
		if (dup2(sv[1], CHANNEL_FD) < 0)
			_exit(127);
		char *envp[] = {
			"PATH=/usr/bin:/bin",
			"FIBERD_ENDPOINT=" ENDPOINT,
			"FIBERD_ENGINE=" ENGINE,
			NULL,
		};
		execve(argv[0], argv, envp);
		say("exec %s: %s", argv[0], strerror(errno));
		_exit(127);
	}
	close(sv[1]);
	channel = sv[0];
	template_pid = pid;
}

int main(int argc, char **argv)
{
	setup();
	if (argc < 2)
		power_off("no template command after --");
	start_template(argv + 1);
	char line[256];
	if (read_line(channel, line, sizeof line) < 0 || strcmp(line, "READY") != 0)
		power_off("the template did not say READY");
	int listeners[2] = { vsock_listen(CONTROL_PORT), vsock_listen(ENDPOINT_PORT) };
	if (listeners[0] < 0 || listeners[1] < 0)
		power_off("cannot listen on vsock");
	say("ready, the template is pid %d", (int)template_pid);
	for (;;) {
		struct pollfd p[3] = {
			{ .fd = listeners[0], .events = POLLIN },
			{ .fd = listeners[1], .events = POLLIN },
			{ .fd = channel, .events = POLLIN },
		};
		int n = poll(p, 3, 200);
		reap();
		if (n <= 0)
			continue;
		if (p[2].revents & (POLLIN | POLLHUP | POLLERR)) {
			/* The template speaks only when asked. Anything else is its
			 * end, which reap powers off for once it is collected. */
			char c;
			if (recv(channel, &c, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
				power_off("the template's channel ended");
		}
		if (p[0].revents & POLLIN) {
			int c = accept4(listeners[0], NULL, NULL, SOCK_CLOEXEC);
			if (c >= 0) {
				control(c);
				close(c);
			}
		}
		if (p[1].revents & POLLIN) {
			int c = accept4(listeners[1], NULL, NULL, SOCK_CLOEXEC);
			if (c >= 0) {
				if (state == SERVING)
					splice_endpoint(c, listeners);
				else
					close(c);
			}
		}
	}
}
