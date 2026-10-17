// Package helper serves hack/hyperlight/PROTOCOL.md without a
// hypervisor, each fiber a goroutine and each park a JSON file. The
// fakehelper binary runs it as a process, and the backend's unit tests
// run it as a goroutine, so everything it starts ends when Serve returns.
// It logs every command as the Rust helper does, the seed and the
// payload by size alone.
package helper

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Facts mirrors the Rust helper's snapshot facts (helper, hyperlight_host,
// hypervisor, cpu). The fake has none of the last three.
const Facts = "fakehelper/2 none none none"

// SeedBytes is the seed every CLONE and RESUME carries, as hex.
const SeedBytes = 32

// Helper is one run of the protocol over a control connection.
type Helper struct {
	out chan string
	log io.Writer

	mu      sync.Mutex
	boxes   map[string]*sandbox
	stopped bool // Serve is ending, so a late clone must not register

	stop chan struct{}  // closed when Serve ends, so a delayed clone gives up
	wg   sync.WaitGroup // every goroutine the helper started
}

type sandbox struct {
	h        *Helper
	fence    string
	endpoint string
	ln       net.Listener

	mu      sync.Mutex
	counter uint64
	dirtied uint64
	conns   map[net.Conn]struct{}
	ended   bool // the sandbox was killed, so a late client is turned away

	// What the sandbox was born as, in place of the guest's Incarnate:
	// the kind of copy, the host's generation and a generator seeded
	// from the host's bytes. The seed's hex is kept only under the
	// payload's "keep_seed" key, for the tests that look for it in the
	// logs.
	kind       string
	generation int
	rng        *rand.ChaCha8
	keptSeed   string
}

// birth is what CLONE and RESUME carry for the sandbox.
type birth struct {
	kind       string
	generation int
	seed       [SeedBytes]byte
}

// parseIncarnation reads the generation and the seed, fields 5 and 6 of
// a CLONE or a RESUME, and refuses by name what a guest would be wrong
// to take.
func parseIncarnation(f []string) (birth, error) {
	var b birth
	if len(f) < 7 {
		return b, fmt.Errorf("%s needs 6 fields, got %d", f[0], len(f)-1)
	}
	g, err := strconv.Atoi(f[5])
	if err != nil || g < 1 || f[5][0] == '0' {
		return b, fmt.Errorf("generation %q is not an incarnation", f[5])
	}
	seed, err := hex.DecodeString(f[6])
	if err != nil || len(seed) != SeedBytes {
		return b, fmt.Errorf("seed is not %d hex bytes", SeedBytes)
	}
	b.generation = g
	copy(b.seed[:], seed)
	clear(seed)
	return b, nil
}

// redact is the command line as the log shows it. A CLONE or RESUME
// carries the fiber's seed, and a CLONE its payload; both are shown by
// size. Every other line is shown whole.
func redact(f []string) string {
	payload, seed := -1, -1
	switch f[0] {
	case "CLONE":
		payload, seed = 4, 6
	case "RESUME":
		seed = 6
	}
	out := make([]string, len(f))
	for i, v := range f {
		switch {
		case i == payload && v != "-":
			out[i] = fmt.Sprintf("payload:%dB", len(v)/2)
		case i == seed:
			out[i] = fmt.Sprintf("seed:%dB", len(v)/2)
		default:
			out[i] = v
		}
	}
	return strings.Join(out, " ")
}

type state struct {
	Counter uint64 `json:"counter"`
	Dirtied uint64 `json:"dirtied"`
	// KeepSeed is the payload's "keep_seed" key, which a resumed sandbox
	// honours as a resumed process honours its payload. The seed itself
	// is never written.
	KeepSeed bool `json:"keep_seed,omitempty"`
}

// Serve says READY on ctl and answers commands until ctl's read side
// ends, logging each one on log (the helper's stderr, which fiberd
// points at the grant's zygote.log). Every sandbox, endpoint and
// goroutine is gone when it returns.
func Serve(ctl net.Conn, log io.Writer) error {
	h := &Helper{out: make(chan string, 256), log: log, boxes: map[string]*sandbox{}, stop: make(chan struct{})}
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		w := bufio.NewWriter(ctl)
		for line := range h.out {
			// A write to a control socket fiberd closed fails, and the
			// lines still have to drain so nothing blocks on say.
			_, _ = w.WriteString(line + "\n")
			_ = w.Flush()
		}
	}()
	h.say("READY " + Facts)
	sc := bufio.NewScanner(ctl)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(log, "helper: < %s\n", redact(f))
		switch f[0] {
		case "CLONE", "RESUME":
			if len(f) < 2 {
				continue
			}
			b, err := parseIncarnation(f)
			if err != nil {
				h.say("ERROR %s %v", f[1], err)
				continue
			}
			if f[0] == "CLONE" {
				b.kind = "clone"
				h.spawn(func() { h.clone(f[1], f[2], f[4], nil, b) })
			} else {
				b.kind = "resume"
				h.spawn(func() { h.resume(f[1], f[2], f[3], b) })
			}
		case "PARK":
			if len(f) < 4 {
				continue
			}
			h.spawn(func() { h.park(f[1], f[2], f[3] == "1") })
		case "KILL":
			if len(f) >= 2 {
				h.kill(f[1], "exit:137")
			}
		}
	}
	err := sc.Err()
	close(h.stop)
	h.mu.Lock()
	h.stopped = true
	boxes := h.boxes
	h.boxes = map[string]*sandbox{}
	h.mu.Unlock()
	for _, b := range boxes {
		b.end()
	}
	h.wg.Wait()
	close(h.out)
	<-wrote
	return err
}

func (h *Helper) say(format string, a ...any) { h.out <- fmt.Sprintf(format, a...) }

// spawn runs fn as a goroutine Serve waits for before it returns.
func (h *Helper) spawn(fn func()) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		fn()
	}()
}

func payloadNum(p []byte, key string) uint64 {
	s := string(p)
	i := strings.Index(s, key)
	if i < 0 {
		return 0
	}
	s = s[i+len(key):]
	if j := strings.Index(s, ":"); j >= 0 {
		s = strings.TrimSpace(s[j+1:])
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

func (h *Helper) clone(fence, endpoint, payloadHex string, st *state, born birth) {
	var payload []byte
	if payloadHex != "-" {
		payload, _ = hex.DecodeString(payloadHex)
	}
	if d := payloadNum(payload, `"ready_delay_ms"`); d > 0 {
		select {
		case <-time.After(time.Duration(d) * time.Millisecond):
		case <-h.stop:
			return
		}
	}
	// The sandbox learns who it is before anything can reach it, and
	// the helper's copy of the seed is gone once the generator has it.
	b := &sandbox{h: h, fence: fence, endpoint: endpoint, conns: map[net.Conn]struct{}{},
		kind: born.kind, generation: born.generation, rng: rand.NewChaCha8(born.seed)}
	if payloadNum(payload, `"keep_seed"`) > 0 || (st != nil && st.KeepSeed) {
		b.keptSeed = hex.EncodeToString(born.seed[:])
	}
	clear(born.seed[:])
	_ = os.Remove(endpoint)
	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		h.say("ERROR %s bind: %v", fence, err)
		return
	}
	b.ln = ln
	if st != nil {
		b.counter, b.dirtied = st.Counter, st.Dirtied
	}
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		b.end()
		return
	}
	h.boxes[fence] = b
	h.mu.Unlock()
	h.say("CLONED %s", fence)
	if db := payloadNum(payload, `"dirty_bytes"`); db > 0 {
		b.mu.Lock()
		b.dirtied += db
		b.mu.Unlock()
	}
	h.say("W %s %d", fence, b.w())
	h.spawn(b.serve)
}

func (b *sandbox) w() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dirtied
}

func (b *sandbox) count() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.counter
}

func (b *sandbox) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		if b.ended {
			b.mu.Unlock()
			_ = c.Close()
			return
		}
		b.conns[c] = struct{}{}
		b.mu.Unlock()
		b.h.spawn(func() { b.client(c) })
	}
}

func (b *sandbox) client(c net.Conn) {
	defer func() {
		_ = c.Close()
		b.mu.Lock()
		delete(b.conns, c)
		b.mu.Unlock()
	}()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		var reply string
		switch {
		case line == "ping":
			reply = "pong"
		case strings.HasPrefix(line, "dirty "):
			n, _ := strconv.ParseUint(strings.TrimPrefix(line, "dirty "), 10, 64)
			b.mu.Lock()
			b.dirtied += n
			b.mu.Unlock()
			b.h.say("W %s %d", b.fence, b.w())
			reply = fmt.Sprintf("ok %d", n)
		case line == "incr":
			b.mu.Lock()
			b.counter++
			reply = strconv.FormatUint(b.counter, 10)
			b.mu.Unlock()
		case line == "get":
			reply = strconv.FormatUint(b.count(), 10)
		case line == "fence":
			reply = b.fence
		case line == "random":
			b.mu.Lock()
			reply = strconv.FormatUint(b.rng.Uint64(), 10)
			b.mu.Unlock()
		case line == "generation":
			reply = strconv.Itoa(b.generation)
		case line == "kind":
			reply = b.kind
		case line == "seed":
			reply = "-"
			if b.keptSeed != "" {
				reply = b.keptSeed
			}
		case line == "pid":
			reply = "0"
		case strings.HasPrefix(line, "getenv "):
			reply = "-"
		case line == "rss":
			reply = strconv.FormatUint(b.w(), 10)
		case line == "quit":
			return
		default:
			reply = "err unknown command"
		}
		if _, err := fmt.Fprintln(c, reply); err != nil {
			return
		}
	}
}

// stopServing closes the endpoint. Clients already connected keep their
// connection, as a parked guest's would until it is killed.
func (b *sandbox) stopServing() {
	_ = b.ln.Close()
	_ = os.Remove(b.endpoint)
}

// end stops serving and cuts every client, so no goroutine of the
// sandbox outlives it.
func (b *sandbox) end() {
	b.stopServing()
	b.mu.Lock()
	b.ended = true
	for c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
}

func (h *Helper) take(fence string) *sandbox {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.boxes[fence]
	delete(h.boxes, fence)
	return b
}

func (h *Helper) kill(fence, status string) {
	b := h.take(fence)
	if b == nil {
		return
	}
	b.end()
	h.say("EXITED %s %s", fence, status)
}

func (h *Helper) park(fence, dir string, sync bool) {
	h.mu.Lock()
	b := h.boxes[fence]
	h.mu.Unlock()
	if b == nil {
		h.say("ERROR %s unknown fiber", fence)
		return
	}
	// Stop serving before the state is written.
	b.stopServing()
	b.mu.Lock()
	st := state{Counter: b.counter, Dirtied: b.dirtied, KeepSeed: b.keptSeed != ""}
	b.mu.Unlock()
	data, _ := json.Marshal(st)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.say("ERROR %s %v", fence, err)
		return
	}
	// A park costs what the guest dirtied; pad the file to say so.
	pad := make([]byte, st.Dirtied)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o644); err != nil {
		h.say("ERROR %s %v", fence, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "pages.bin"), pad, 0o644); err != nil {
		h.say("ERROR %s %v", fence, err)
		return
	}
	h.say("PARKED %s %d", fence, st.Dirtied+uint64(len(data)))
	if !sync {
		h.kill(fence, "exit:0")
	}
}

func (h *Helper) resume(fence, dir, endpoint string, born birth) {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		h.say("ERROR %s %v", fence, err)
		return
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		h.say("ERROR %s %v", fence, err)
		return
	}
	h.clone(fence, endpoint, "-", &st, born)
}
