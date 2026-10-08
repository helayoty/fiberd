package compare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Record is one JSON line. Activation lines carry Burst and the two
// timings. Hold lines (Kind "hold") are the activations made to hold an
// instance for resume or density, with the same fields, and are not
// latency samples. Run lines (Kind "run") carry the host load and
// control-plane deltas around one run. Setup lines (Kind "setup") carry
// the one-time cost. Density and resume lines are the remaining kinds.
type Record struct {
	Kind   string `json:"kind"`
	System string `json:"system"`
	Class  string `json:"class"`
	Host   string `json:"host,omitempty"`
	// Run is the run index. Run 0 is the discarded cold run.
	Run  int  `json:"run"`
	Cold bool `json:"cold,omitempty"`
	// Burst is how many activations were in flight together.
	Burst int    `json:"burst,omitempty"`
	ID    string `json:"id,omitempty"`
	// T0 is the wall clock just before the activation request, for the
	// record only. Latencies are differences of monotonic readings.
	T0 string `json:"t0,omitempty"`
	// TAddrMs is when the system returned an address, from T0.
	TAddrMs float64 `json:"t_addr_ms,omitempty"`
	// TFirstByteMs is when the first byte of the first 200 arrived.
	TFirstByteMs float64 `json:"t_first_byte_ms,omitempty"`
	// Attempts is how many probes got no reply first. PollMs is the
	// interval between them, the quantization bound.
	Attempts int     `json:"attempts,omitempty"`
	PollMs   float64 `json:"poll_ms,omitempty"`
	Error    string  `json:"error,omitempty"`
	// WallMs is a burst's wall time, on the "burst" line.
	WallMs float64 `json:"wall_ms,omitempty"`
	// Run lines.
	LoadBefore string             `json:"load_before,omitempty"`
	LoadAfter  string             `json:"load_after,omitempty"`
	Deltas     map[string]float64 `json:"deltas,omitempty"`
	// Setup lines.
	SetupMs float64 `json:"setup_ms,omitempty"`
	// Density lines. Standing is Density(nil), Bytes is Density(handles).
	N        int   `json:"n,omitempty"`
	Bytes    int64 `json:"bytes,omitempty"`
	Standing int64 `json:"standing_bytes,omitempty"`
}

// Sampler reads control-plane counters. Delta is what changed since the
// last call, keyed by a short name.
type Sampler interface {
	Delta(ctx context.Context) (map[string]float64, error)
}

// Runner drives one adapter through the protocol of docs/design/compare.md.
type Runner struct {
	Adapter Adapter
	System  string
	Class   string
	// Runs is how many runs after the cold one. Three is the design.
	Runs int
	// Bursts are the concurrent activation counts per run.
	Bursts []int
	// Poll is recorded on every activation line.
	Poll time.Duration
	// Timeout bounds one activation to ready.
	Timeout time.Duration
	// Resume measures park and resume on one instance per run when set.
	Resume bool
	// Density holds N idle instances for Idle before reading their cost.
	Density int
	Idle    time.Duration
	// ControlPlane, when set, is sampled around every run.
	ControlPlane Sampler
	Out          io.Writer
	Log          io.Writer
	// Load reads the host load. Nil means HostLoad.
	Load func() string
	// Now is the clock. Nil means time.Now.
	Now func() time.Time

	mu sync.Mutex
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) load() string {
	if r.Load != nil {
		return r.Load()
	}
	return HostLoad()
}

func (r *Runner) logf(format string, a ...any) {
	if r.Log != nil {
		_, _ = fmt.Fprintf(r.Log, format+"\n", a...)
	}
}

// emit writes one line. Lines from concurrent activations are
// serialized here.
func (r *Runner) emit(rec Record) {
	rec.System, rec.Class = r.System, r.Class
	if rec.Host == "" {
		rec.Host, _ = os.Hostname()
	}
	b, _ := json.Marshal(rec)
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.Out.Write(append(b, '\n'))
}

// Run is setup, one cold run, then Runs timed runs. Every run does each
// burst size once, releases everything between bursts, and keeps
// nothing between runs. It returns the first error that stopped a run,
// while per-activation errors go into the records. An adapter's Cleanup
// runs last, whatever stopped the runs.
func (r *Runner) Run(ctx context.Context) (err error) {
	defer func() {
		c, ok := r.Adapter.(Cleaner)
		if !ok {
			return
		}
		cctx, cancel := r.outlive(ctx)
		defer cancel()
		if cerr := c.Cleanup(cctx); cerr != nil && err == nil {
			err = fmt.Errorf("cleanup: %w", cerr)
		}
	}()
	runs, bursts := r.Runs, r.Bursts
	if runs <= 0 {
		runs = 3
	}
	if len(bursts) == 0 {
		bursts = []int{1}
	}
	t := r.now()
	if err := r.Adapter.Setup(ctx); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	r.emit(Record{Kind: "setup", SetupMs: ms(r.now().Sub(t))})
	if r.ControlPlane != nil {
		if _, err := r.ControlPlane.Delta(ctx); err != nil {
			return fmt.Errorf("control plane: %w", err)
		}
	}
	for run := 0; run <= runs; run++ {
		rec := Record{Kind: "run", Run: run, Cold: run == 0, LoadBefore: r.load()}
		for _, n := range bursts {
			if err := r.burst(ctx, run, n); err != nil {
				return err
			}
		}
		if r.Resume {
			if err := r.resume(ctx, run); err != nil {
				return err
			}
		}
		if r.Density > 0 {
			if err := r.density(ctx, run); err != nil {
				return err
			}
		}
		// A cancelled run stops here, after its instances are released.
		if err := ctx.Err(); err != nil {
			return err
		}
		rec.LoadAfter = r.load()
		if r.ControlPlane != nil {
			d, err := r.ControlPlane.Delta(ctx)
			if err != nil {
				return fmt.Errorf("control plane: %w", err)
			}
			rec.Deltas = d
		}
		r.emit(rec)
		r.logf("%s run %d done (cold=%v)", r.System, run, run == 0)
	}
	return nil
}

// prepare runs the adapter's untimed pre-step, if it has one.
func (r *Runner) prepare(ctx context.Context, id string) error {
	if p, ok := r.Adapter.(Preparer); ok {
		return p.Prepare(ctx, id)
	}
	return nil
}

// one is a single activation to first byte, recorded under kind. prep
// is what the pre-step answered, which fails the activation before its
// clock starts. The handle comes back for the release, nil when
// activation failed.
func (r *Runner) one(ctx context.Context, kind string, run, burst int, id string, prep error) *Handle {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	rec := Record{Kind: kind, Run: run, Cold: run == 0, Burst: burst, ID: id, PollMs: ms(r.Poll)}
	if prep != nil {
		rec.Error = "prepare: " + prep.Error()
		r.emit(rec)
		return nil
	}
	t0 := r.now()
	rec.T0 = t0.Format(time.RFC3339Nano)
	h, err := r.Adapter.Activate(ctx, id)
	if err != nil {
		rec.Error = "activate: " + err.Error()
		r.emit(rec)
		return nil
	}
	rec.TAddrMs = ms(r.now().Sub(t0))
	h, fb, err := r.Adapter.Ready(ctx, h)
	if err != nil {
		rec.Error = "ready: " + err.Error()
	} else {
		rec.TFirstByteMs = ms(fb.Sub(t0))
		if a, ok := h.Meta["attempts"]; ok {
			_, _ = fmt.Sscan(a, &rec.Attempts)
		}
	}
	r.emit(rec)
	return &h
}

func (r *Runner) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 2 * time.Minute
}

// outlive is a context for releasing and cleaning up, which must happen
// when the run's context was cancelled.
func (r *Runner) outlive(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), r.timeout())
}

// burst activates n instances at once, waits for all, then releases
// them all. Nothing runs between bursts. Every pre-step ends before the
// first clock starts, so none runs inside another activation's window.
func (r *Runner) burst(ctx context.Context, run, n int) error {
	ids := make([]string, n)
	prep := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		ids[i] = fmt.Sprintf("r%d-b%d-%d", run, n, i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prep[i] = r.prepare(ctx, ids[i])
		}(i)
	}
	wg.Wait()
	hs := make([]*Handle, n)
	start := r.now()
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hs[i] = r.one(ctx, "activation", run, n, ids[i], prep[i])
		}(i)
	}
	wg.Wait()
	r.emit(Record{Kind: "burst", Run: run, Cold: run == 0, Burst: n, WallMs: ms(r.now().Sub(start))})
	return r.releaseAll(ctx, hs)
}

// releaseAll releases every live handle, with a context that outlives
// a cancelled run so nothing is left behind.
func (r *Runner) releaseAll(ctx context.Context, hs []*Handle) error {
	var first error
	for _, h := range hs {
		if h == nil {
			continue
		}
		if err := r.release(ctx, *h); err != nil && first == nil {
			first = fmt.Errorf("release %s: %w", h.ID, err)
		}
	}
	return first
}

func (r *Runner) release(ctx context.Context, h Handle) error {
	rctx, cancel := r.outlive(ctx)
	defer cancel()
	return r.Adapter.Release(rctx, h)
}

// resume activates one instance, parks it untimed, then times its
// resume to first byte.
func (r *Runner) resume(ctx context.Context, run int) error {
	id := fmt.Sprintf("r%d-resume", run)
	h := r.one(ctx, "hold", run, 0, id, r.prepare(ctx, id))
	if h == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	rec := Record{Kind: "resume", Run: run, Cold: run == 0, ID: id, PollMs: ms(r.Poll)}
	if err := r.Adapter.Park(rctx, *h); err != nil {
		rec.Error = "park: " + err.Error()
		if errors.Is(err, ErrUnsupported) {
			rec.Error = ErrUnsupported.Error()
		}
		r.emit(rec)
		return r.release(ctx, *h)
	}
	t0 := r.now()
	rec.T0 = t0.Format(time.RFC3339Nano)
	nh, err := r.Adapter.Resume(rctx, *h)
	if err != nil {
		rec.Error = "resume: " + err.Error()
		r.emit(rec)
		return r.release(ctx, *h)
	}
	rec.TAddrMs = ms(r.now().Sub(t0))
	nh, fb, err := r.Adapter.Ready(rctx, nh)
	if err != nil {
		rec.Error = "ready: " + err.Error()
	} else {
		rec.TFirstByteMs = ms(fb.Sub(t0))
	}
	r.emit(rec)
	return r.release(ctx, nh)
}

// density holds Density idle instances for Idle, then reads what they
// are charged and what the system keeps standing.
func (r *Runner) density(ctx context.Context, run int) error {
	hs := make([]*Handle, r.Density)
	var wg sync.WaitGroup
	for i := range r.Density {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("r%d-d%d", run, i)
			hs[i] = r.one(ctx, "hold", run, 0, id, r.prepare(ctx, id))
		}(i)
	}
	wg.Wait()
	live := make([]Handle, 0, len(hs))
	for _, h := range hs {
		if h != nil {
			live = append(live, *h)
		}
	}
	idle := r.Idle
	if idle <= 0 {
		idle = 30 * time.Second
	}
	select {
	case <-ctx.Done():
		return r.releaseAll(ctx, hs)
	case <-time.After(idle):
	}
	rec := Record{Kind: "density", Run: run, Cold: run == 0, N: len(live)}
	standing, err := r.Adapter.Density(ctx, nil)
	if err == nil {
		rec.Standing = standing
		rec.Bytes, err = r.Adapter.Density(ctx, live)
	}
	if err != nil {
		rec.Error = err.Error()
	}
	r.emit(rec)
	return r.releaseAll(ctx, hs)
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

// HostLoad is the 1, 5 and 15 minute load averages, as /proc/loadavg
// prints them. On macOS it comes from sysctl.
func HostLoad() string {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			return strings.Join(f[:3], " ")
		}
	}
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
		if err == nil {
			return strings.Trim(strings.TrimSpace(string(out)), "{} ")
		}
	}
	return "unknown"
}
