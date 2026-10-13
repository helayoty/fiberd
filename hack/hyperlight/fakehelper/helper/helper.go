// Package helper serves hack/hyperlight/PROTOCOL.md without a
// hypervisor, each fiber a goroutine and each park a JSON file. The
// fakehelper binary runs it as a process, and the backend's unit tests
// run it as a goroutine, so everything it starts ends when Serve returns.
package helper

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
const Facts = "fakehelper/1 none none none"

// Helper is one run of the protocol over a control connection.
type Helper struct {
	out chan string

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
}

type state struct {
	Counter uint64 `json:"counter"`
	Dirtied uint64 `json:"dirtied"`
}

// Serve says READY on ctl and answers commands until ctl's read side
// ends. Every sandbox, endpoint and goroutine is gone when it returns.
func Serve(ctl net.Conn) error {
	h := &Helper{out: make(chan string, 256), boxes: map[string]*sandbox{}, stop: make(chan struct{})}
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
		switch f[0] {
		case "CLONE":
			if len(f) < 5 {
				continue
			}
			h.spawn(func() { h.clone(f[1], f[2], f[4], nil) })
		case "PARK":
			if len(f) < 4 {
				continue
			}
			h.spawn(func() { h.park(f[1], f[2], f[3] == "1") })
		case "RESUME":
			if len(f) < 5 {
				continue
			}
			h.spawn(func() { h.resume(f[1], f[2], f[3]) })
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

func (h *Helper) clone(fence, endpoint, payloadHex string, st *state) {
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
	_ = os.Remove(endpoint)
	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		h.say("ERROR %s bind: %v", fence, err)
		return
	}
	b := &sandbox{h: h, fence: fence, endpoint: endpoint, ln: ln, conns: map[net.Conn]struct{}{}}
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
	st := state{Counter: b.counter, Dirtied: b.dirtied}
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

func (h *Helper) resume(fence, dir, endpoint string) {
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
	h.clone(fence, endpoint, "-", &st)
}
