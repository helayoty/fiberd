// Command fakehelper implements hack/hyperlight/PROTOCOL.md without a
// hypervisor: every fiber is a goroutine serving the reference workload's
// line protocol (ping, dirty, incr, get, fence, pid, getenv, rss) on its
// endpoint, its state is a counter and a dirtied byte count, and a park
// is a JSON file. It exists so fiberd's hyperlight backend, the host
// runtime and the conformance suite can run in the Linux dev container;
// the Rust helper replaces it where KVM exists.
//
//	fakehelper --guest <path> [--init-ms N]      (fd 3 is the control socket)
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sandbox struct {
	fence    string
	endpoint string
	mu       sync.Mutex
	counter  uint64
	dirtied  uint64
	ln       net.Listener
	closed   chan struct{}
}

type state struct {
	Counter uint64 `json:"counter"`
	Dirtied uint64 `json:"dirtied"`
}

var (
	out   = make(chan string, 256)
	boxes = map[string]*sandbox{}
	bmu   sync.Mutex
)

func say(format string, a ...any) { out <- fmt.Sprintf(format, a...) }

func main() {
	guest := flag.String("guest", "", "guest binary (checked for existence only)")
	initMS := flag.Int("init-ms", 20, "pretend init time")
	flag.Parse()
	if _, err := os.Stat(*guest); err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: guest: %v\n", err)
		os.Exit(2)
	}
	ctl := os.NewFile(3, "ctl")
	time.Sleep(time.Duration(*initMS) * time.Millisecond)
	go func() {
		w := bufio.NewWriter(ctl)
		for line := range out {
			_, _ = w.WriteString(line + "\n")
			_ = w.Flush()
		}
	}()
	say("READY fake-1")
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
			go clone(f[1], f[2], f[3], f[4], nil)
		case "PARK":
			if len(f) < 4 {
				continue
			}
			go park(f[1], f[2], f[3] == "1")
		case "RESUME":
			if len(f) < 5 {
				continue
			}
			go resume(f[1], f[2], f[3], f[4])
		case "KILL":
			if len(f) >= 2 {
				kill(f[1], "exit:137")
			}
		}
	}
	os.Exit(0)
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

func clone(fence, endpoint, deadlineMS, payloadHex string, st *state) {
	var payload []byte
	if payloadHex != "-" {
		payload, _ = hex.DecodeString(payloadHex)
	}
	if d := payloadNum(payload, `"ready_delay_ms"`); d > 0 {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
	_ = os.Remove(endpoint)
	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		say("ERROR %s bind: %v", fence, err)
		return
	}
	b := &sandbox{fence: fence, endpoint: endpoint, ln: ln, closed: make(chan struct{})}
	if st != nil {
		b.counter, b.dirtied = st.Counter, st.Dirtied
	}
	bmu.Lock()
	boxes[fence] = b
	bmu.Unlock()
	say("CLONED %s", fence)
	if db := payloadNum(payload, `"dirty_bytes"`); db > 0 {
		b.mu.Lock()
		b.dirtied += db
		b.mu.Unlock()
	}
	say("W %s %d", fence, b.w())
	go b.serve()
}

func (b *sandbox) w() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dirtied
}

func (b *sandbox) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.client(c)
	}
}

func (b *sandbox) client(c net.Conn) {
	defer func() { _ = c.Close() }()
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
			say("W %s %d", b.fence, b.w())
			reply = fmt.Sprintf("ok %d", n)
		case line == "incr":
			b.mu.Lock()
			b.counter++
			reply = strconv.FormatUint(b.counter, 10)
			b.mu.Unlock()
		case line == "get":
			reply = strconv.FormatUint(b.w2(), 10)
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

func (b *sandbox) w2() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.counter
}

func take(fence string) *sandbox {
	bmu.Lock()
	defer bmu.Unlock()
	b := boxes[fence]
	delete(boxes, fence)
	return b
}

func kill(fence, status string) {
	b := take(fence)
	if b == nil {
		return
	}
	_ = b.ln.Close()
	_ = os.Remove(b.endpoint)
	say("EXITED %s %s", fence, status)
}

func park(fence, dir string, sync bool) {
	bmu.Lock()
	b := boxes[fence]
	bmu.Unlock()
	if b == nil {
		say("ERROR %s unknown fiber", fence)
		return
	}
	// Stop serving before the state is written.
	_ = b.ln.Close()
	_ = os.Remove(b.endpoint)
	b.mu.Lock()
	st := state{Counter: b.counter, Dirtied: b.dirtied}
	b.mu.Unlock()
	data, _ := json.Marshal(st)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		say("ERROR %s %v", fence, err)
		return
	}
	// A park costs what the guest dirtied; pad the file to say so.
	pad := make([]byte, st.Dirtied)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o644); err != nil {
		say("ERROR %s %v", fence, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "pages.bin"), pad, 0o644); err != nil {
		say("ERROR %s %v", fence, err)
		return
	}
	say("PARKED %s %d", fence, st.Dirtied+uint64(len(data)))
	if !sync {
		kill(fence, "exit:0")
	}
}

func resume(fence, dir, endpoint, deadlineMS string) {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		say("ERROR %s %v", fence, err)
		return
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		say("ERROR %s %v", fence, err)
		return
	}
	clone(fence, endpoint, deadlineMS, "-", &st)
}
