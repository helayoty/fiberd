package main

// The device probes, refzygote's gpufill, gpucheck and gpuopen, with its
// answers word for word, so conformance asks every backend's fiber the
// same lines. Each engine request is one connection (dialEngine).

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// engineConn is a connection to the engine. A vsock fd is an *os.File,
// since net.FileConn does not know AF_VSOCK.
type engineConn interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
}

// maxEngineLine is refzygote's bound on a request line, its newline
// included.
const maxEngineLine = 256

// engineSend sends one line to the engine on a fresh connection and is
// its one-line reply, or an "err ..." of the template's own when the
// engine cannot be reached, as refzygote's engine_send has them.
func engineSend(line string) string {
	if _, ok := os.LookupEnv("FIBERD_ENGINE"); !ok {
		return "err no engine"
	}
	if len(line)+1 >= maxEngineLine {
		return "err line too long"
	}
	if _, err := hostPort(); err != nil {
		return "err engine address"
	}
	c, err := dialEngine()
	if err != nil {
		// The reason goes in the reply so a failed C14 shows it.
		return "err engine unreachable " + oneLine(err.Error(), 160)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte(line + "\n"))
	reply, err := bufio.NewReader(c).ReadString('\n')
	if reply == "" && err != nil {
		return "err no reply"
	}
	if i := strings.IndexAny(reply, "\r\n"); i >= 0 {
		reply = reply[:i]
	}
	return reply
}

// oneLine is s with its line breaks as spaces, cut to at most n bytes.
func oneLine(s string, n int) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// engineHash is the hash in an engine reply "ok <hash>", 16 lowercase
// hex digits, and false for any other reply.
func engineHash(reply string) (string, bool) {
	h, ok := strings.CutPrefix(reply, "ok ")
	if !ok || len(h) != 16 {
		return "", false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return h, true
}

// currentFence is the fence the engine files the slice under.
func (f *fiber) currentFence() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fence == "" {
		return "?"
	}
	return f.fence
}

// reserve asks the engine for a slice of bytes under this fiber's fence,
// and is the engine's reply.
func (f *fiber) reserve(bytes uint64) string {
	return engineSend("reserve " + f.currentFence() + " " + strconv.FormatUint(bytes, 10))
}

// reserveBirth takes the payload's device_bytes once the fiber serves,
// as a forked refzygote fiber does after ready.
func (f *fiber) reserveBirth(bytes uint64) {
	f.gpu.Lock()
	defer f.gpu.Unlock()
	_ = f.reserve(bytes)
}

// gpuProbe answers line when it is a device probe, matched on the raw
// line as refzygote matches it, and reports whether it was one.
func (f *fiber) gpuProbe(line string) (string, bool) {
	switch {
	case strings.HasPrefix(line, "gpufill "):
		return f.gpuFill(line[len("gpufill "):]), true
	case line == "gpucheck":
		return f.gpuCheck(), true
	case strings.HasPrefix(line, "gpuopen "):
		path := line[len("gpuopen "):]
		if path == "" {
			return "err proto", true
		}
		return gpuOpen(path), true
	}
	return "", false
}

// gpuFill parses "<seed> <bytes>" strictly, two decimal u64s and bytes
// not 0, reserves bytes under this fiber's fence, has the engine fill the
// slice from seed and keeps the hash it returns. The reserve replaces
// the slice the old hash was of, so the old hash goes first.
func (f *fiber) gpuFill(args string) string {
	first, rest, ok := strings.Cut(args, " ")
	if !ok || len(first) >= 24 {
		return "err proto"
	}
	seed, err := strconv.ParseUint(first, 10, 64)
	if err != nil {
		return "err proto"
	}
	bytes, err := strconv.ParseUint(rest, 10, 64)
	if err != nil || bytes == 0 {
		return "err proto"
	}
	f.gpu.Lock()
	defer f.gpu.Unlock()
	f.gpuHash = ""
	if r := f.reserve(bytes); r != "ok" {
		return r
	}
	r := engineSend("fill " + f.currentFence() + " " + strconv.FormatUint(seed, 10))
	h, ok := engineHash(r)
	if !ok {
		return r
	}
	f.gpuHash = h
	return "ok " + h
}

// gpuCheck asks the engine for the slice's hash under the current fence,
// the new one after a resume, and compares it with the kept one.
func (f *fiber) gpuCheck() string {
	f.gpu.Lock()
	defer f.gpu.Unlock()
	if f.gpuHash == "" {
		return "err none"
	}
	r := engineSend("sum " + f.currentFence())
	now, ok := engineHash(r)
	if !ok {
		return r
	}
	if now == f.gpuHash {
		return "ok"
	}
	return "mismatch " + f.gpuHash + " " + now
}

// gpuOpen opens a GPU node such as /dev/nvidiactl read-write, as a CUDA
// runtime does, and is "ok" or the errno's name. It never sends an
// ioctl, so nothing reaches a driver.
func gpuOpen(path string) string {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOCTTY, 0)
	if err == nil {
		_ = syscall.Close(fd)
		return "ok"
	}
	var e syscall.Errno
	if !errors.As(err, &e) {
		return "errno 0"
	}
	if name, ok := errnoNames[e]; ok {
		return name
	}
	return "errno " + strconv.Itoa(int(e))
}

// errnoNames are the errno names refzygote's errname writes. Any other
// errno is "errno <n>".
var errnoNames = map[syscall.Errno]string{
	syscall.EROFS:           "EROFS",
	syscall.EACCES:          "EACCES",
	syscall.EPERM:           "EPERM",
	syscall.ENOENT:          "ENOENT",
	syscall.ENOSPC:          "ENOSPC",
	syscall.ECONNREFUSED:    "ECONNREFUSED",
	syscall.ENETUNREACH:     "ENETUNREACH",
	syscall.EHOSTUNREACH:    "EHOSTUNREACH",
	syscall.ETIMEDOUT:       "ETIMEDOUT",
	syscall.EINVAL:          "EINVAL",
	syscall.ESRCH:           "ESRCH",
	syscall.EBADF:           "EBADF",
	syscall.EFAULT:          "EFAULT",
	syscall.ENOSYS:          "ENOSYS",
	syscall.EAFNOSUPPORT:    "EAFNOSUPPORT",
	syscall.EPROTONOSUPPORT: "EPROTONOSUPPORT",
	syscall.ENXIO:           "ENXIO",
	syscall.ENODEV:          "ENODEV",
}
