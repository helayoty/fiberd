// Command vmtemplate is the reference template of the cloudhv backend:
// the workload the guest init runs in every micro-VM, and the fake VMM
// runs as its child without one. It speaks the template side of
// hack/cloudhv/PROTOCOL.md on fd 3 and serves a small line protocol on
// FIBERD_ENDPOINT, a subset of sdk/c/template/refzygote.c's.
//
//	ping            -> pong
//	incr            -> <n>       (per-fiber counter, survives a park in a real VM)
//	get             -> <n>
//	random          -> <n>       (math/rand, reseeded in every incarnation)
//	getrandom       -> <hex>     (8 bytes from the kernel)
//	fence           -> <fence>
//	generation      -> <n>
//	session         -> the session, or "-"
//	payload         -> the payload in hex, or "-"
//	dirty <bytes>   -> ok        (grows the working set, charged as W)
//	getenv <NAME>   -> value or "-"
//	engine <line>   -> the engine's one-line reply over vsock
//	gpufill <seed> <bytes> -> "ok <hash>" once a reserve of bytes under
//	                  the fence and the engine's fill from seed succeed
//	gpucheck        -> "ok", "mismatch <kept> <now>", or "err none"
//	gpuopen <path>  -> "ok" or the errno's name of open(O_RDWR)
//
// The device probes answer as refzygote's do (gpu.go), engine errors
// passed through. The payload is JSON. "dirty_bytes" grows the fiber
// right after it serves, which is how conformance case C6 drives a fiber
// over its W budget, "device_bytes" reserves a slice of the grant's
// engine then, and "ready_delay_ms" waits before it binds.
//
// Build it static (CGO_ENABLED=0), since the guest's rootfs and the fake
// VMM's jail hold no libraries.
package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fiber is what the template knows of its current incarnation, and the
// state a park carries over in a real VM.
type fiber struct {
	mu         sync.Mutex
	endpoint   string
	fence      string
	generation int
	session    string
	payload    []byte
	counter    uint64
	rng        *rand.Rand
	dirtied    [][]byte
	ln         net.Listener
	conns      map[net.Conn]struct{}

	// gpu takes the device probes one at a time. gpuHash is the hash of
	// the last fill, which a park carries in a real VM.
	gpu     sync.Mutex
	gpuHash string
}

// heap is the warm state every copy shares, touched once at init.
var heap []byte

func main() {
	heapMB := flag.Int("heap-mb", 32, "memory to allocate and touch at init")
	initMS := flag.Int("init-ms", 0, "extra init time")
	flag.Parse()
	ep := os.Getenv("FIBERD_ENDPOINT")
	if ep == "" {
		fmt.Fprintln(os.Stderr, "vmtemplate: no FIBERD_ENDPOINT")
		os.Exit(2)
	}
	heap = make([]byte, *heapMB<<20)
	for i := 0; i < len(heap); i += 4096 {
		heap[i] = byte(i >> 12)
	}
	time.Sleep(time.Duration(*initMS) * time.Millisecond)
	f := &fiber{endpoint: ep, conns: map[net.Conn]struct{}{}}
	ch := os.NewFile(3, "channel")
	if err := f.run(ch); err != nil {
		fmt.Fprintf(os.Stderr, "vmtemplate: %v\n", err)
		os.Exit(1)
	}
}

// run says READY on the channel and answers the guest init's lines until
// the channel ends, which is the template's end too.
func (f *fiber) run(ch *os.File) error {
	if _, err := ch.WriteString("READY\n"); err != nil {
		return err
	}
	rd := bufio.NewReader(ch)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil
		}
		words := strings.Fields(line)
		reply := "ERROR empty line"
		if len(words) > 0 {
			reply = f.command(words)
		}
		clear(words)
		if _, err := ch.WriteString(reply + "\n"); err != nil {
			return err
		}
	}
}

// command answers one channel line.
func (f *fiber) command(words []string) string {
	switch words[0] {
	case "INCARNATE":
		if err := f.incarnate(words); err != nil {
			return "ERROR " + err.Error()
		}
		return "SERVED"
	case "PARK":
		f.stop()
		return "PARKED"
	case "UNPARK":
		if err := f.listen(); err != nil {
			return "ERROR " + err.Error()
		}
		return "SERVED"
	}
	return "ERROR unknown command " + strconv.Quote(words[0])
}

// incarnate takes INCARNATE <generation> <fence> <seed-hex>
// <payload-hex|-> <session-hex|->, reseeds from the seed mixed with the
// kernel's own bytes, and serves.
func (f *fiber) incarnate(w []string) error {
	if len(w) != 6 {
		return fmt.Errorf("INCARNATE wants 5 fields, got %d", len(w)-1)
	}
	gen, err := strconv.Atoi(w[1])
	if err != nil || gen < 1 {
		return fmt.Errorf("generation %q is not an incarnation", w[1])
	}
	seed, err := hex.DecodeString(w[3])
	if err != nil || len(seed) != 32 {
		return errors.New("seed is not 32 hex bytes")
	}
	payload, err := unhex(w[4])
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	session, err := unhex(w[5])
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	var key [32]byte
	if _, err := crand.Read(key[:]); err != nil {
		return err
	}
	for i := range key {
		key[i] ^= seed[i]
	}
	clear(seed)
	var knobs struct {
		DirtyBytes   uint64 `json:"dirty_bytes"`
		DeviceBytes  uint64 `json:"device_bytes"`
		ReadyDelayMS uint64 `json:"ready_delay_ms"`
	}
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &knobs)
	}
	f.mu.Lock()
	f.generation, f.fence, f.payload, f.session = gen, w[2], payload, string(session)
	f.rng = rand.New(rand.NewChaCha8(key))
	f.mu.Unlock()
	clear(key[:])
	if knobs.ReadyDelayMS > 0 {
		time.Sleep(time.Duration(knobs.ReadyDelayMS) * time.Millisecond)
	}
	if err := f.listen(); err != nil {
		return err
	}
	if knobs.DirtyBytes > 0 {
		go f.dirty(knobs.DirtyBytes)
	}
	if knobs.DeviceBytes > 0 {
		go f.reserveBirth(knobs.DeviceBytes)
	}
	return nil
}

func unhex(s string) ([]byte, error) {
	if s == "-" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// listen binds the endpoint, replacing a stale socket, and serves it.
func (f *fiber) listen() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		return nil
	}
	_ = os.Remove(f.endpoint)
	ln, err := net.Listen("unix", f.endpoint)
	if err != nil {
		return err
	}
	f.ln = ln
	go f.accept(ln)
	return nil
}

// stop closes the endpoint and every connection on it, as a park needs.
func (f *fiber) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
	for c := range f.conns {
		_ = c.Close()
		delete(f.conns, c)
	}
	_ = os.Remove(f.endpoint)
}

func (f *fiber) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.ln != ln {
			f.mu.Unlock()
			_ = c.Close()
			return
		}
		f.conns[c] = struct{}{}
		f.mu.Unlock()
		go f.serve(c)
	}
}

// serve answers one connection's lines until it ends.
func (f *fiber) serve(c net.Conn) {
	defer func() {
		f.mu.Lock()
		delete(f.conns, c)
		f.mu.Unlock()
		_ = c.Close()
	}()
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		reply, ok := f.gpuProbe(sc.Text())
		if !ok {
			reply = f.answer(strings.Fields(sc.Text()))
		}
		if _, err := fmt.Fprintln(c, reply); err != nil {
			return
		}
	}
}

// answer is the reply to one endpoint line.
func (f *fiber) answer(w []string) string {
	if len(w) == 0 {
		return "err empty"
	}
	if w[0] == "engine" {
		return engineSend(strings.Join(w[1:], " "))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch w[0] {
	case "ping":
		return "pong"
	case "incr":
		f.counter++
		return strconv.FormatUint(f.counter, 10)
	case "get":
		return strconv.FormatUint(f.counter, 10)
	case "random":
		if f.rng == nil {
			return "-"
		}
		return strconv.FormatUint(f.rng.Uint64(), 10)
	case "getrandom":
		b := make([]byte, 8)
		if _, err := crand.Read(b); err != nil {
			return "err " + err.Error()
		}
		return hex.EncodeToString(b)
	case "fence":
		return f.fence
	case "generation":
		return strconv.Itoa(f.generation)
	case "session":
		return orDash(f.session)
	case "payload":
		return orDash(hex.EncodeToString(f.payload))
	case "getenv":
		if len(w) < 2 {
			return "err usage"
		}
		return orDash(os.Getenv(w[1]))
	case "dirty":
		if len(w) < 2 {
			return "err usage"
		}
		n, err := strconv.ParseUint(w[1], 10, 64)
		if err != nil {
			return "err bytes"
		}
		go f.dirty(n)
		return "ok"
	}
	return "err unknown"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// dirty grows the working set by n bytes and keeps them.
func (f *fiber) dirty(n uint64) {
	b := make([]byte, n)
	for i := 0; i < len(b); i += 4096 {
		b[i] = 1
	}
	f.mu.Lock()
	f.dirtied = append(f.dirtied, b)
	f.mu.Unlock()
}

// hostPort reads FIBERD_ENGINE, "vsock://2:<port>", the host's CID and
// the engine's port.
func hostPort() (uint32, error) {
	rest, ok := strings.CutPrefix(os.Getenv("FIBERD_ENGINE"), "vsock://2:")
	if !ok {
		return 0, errors.New("FIBERD_ENGINE is not vsock://2:<port>")
	}
	p, err := strconv.ParseUint(rest, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("FIBERD_ENGINE port: %w", err)
	}
	return uint32(p), nil
}
