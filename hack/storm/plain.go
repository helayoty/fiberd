package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// The baseline without fiberd (-plain). The same storm runs on plain
// processes, with the same heap, the same growth and the same memory
// limit, and nothing parks. Only the kernel's OOM killer acts.
//
//	shared    one parent touches the template's heap, then forks every
//	          worker, so they share it copy-on-write as fibers share
//	          their zygote's. The headline.
//	separate  every worker is a process started on its own, touching a
//	          heap of its own. What running the app as separate
//	          processes gives, recorded as a note.
//
// Go cannot fork without an exec, so the processes are storm-grower
// (hack/storm/grower), a small C program, and storm drives each worker
// over a pair of pipes. A worker's answer pipe ends when it dies, which
// is when the storm counts it gone.

// maxForks is storm-grower's MAX_FORKS.
const maxForks = 64

// layout is how the baseline's workers hold the template's heap: how
// many grower processes start, and how many workers each forks (0: the
// process is its one worker).
type layout struct {
	name         string
	procs, forks int
}

func parseLayout(name string, n int) (layout, error) {
	if n < 1 {
		return layout{}, fmt.Errorf("-fibers %d: want at least 1", n)
	}
	switch name {
	case "shared":
		if n > maxForks {
			return layout{}, fmt.Errorf("-fibers %d: the shared layout forks at most %d", n, maxForks)
		}
		return layout{name: name, procs: 1, forks: n}, nil
	case "separate":
		return layout{name: name, procs: n}, nil
	}
	return layout{}, fmt.Errorf("-layout %q: want shared or separate", name)
}

// workersOf is how many workers one grower process serves.
func (l layout) workersOf() int {
	if l.forks == 0 {
		return 1
	}
	return l.forks
}

// tally is the kill accounting of one baseline run.
type tally struct {
	growth   time.Time   // growth began (zero: it never did)
	deaths   []time.Time // when each worker's answer pipe ended, zero while alive
	firstOOM time.Time   // the round the OOM counter was first seen above where it started
}

func (t tally) survivors() int {
	n := 0
	for _, d := range t.deaths {
		if d.IsZero() {
			n++
		}
	}
	return n
}

// killedBeforeGrowth counts workers gone before the first step, which
// in the separate layout is the heaps alone not fitting.
func (t tally) killedBeforeGrowth() int {
	n := 0
	for _, d := range t.deaths {
		if !d.IsZero() && since(d, t.growth).early {
			n++
		}
	}
	return n
}

// firstKill is the earliest of a worker's death and the OOM counter's
// first rise. A worker's pipe ends the moment it dies. The counter also
// sees a kill that is not a worker, the shared layout's parent.
func (t tally) firstKill() time.Time {
	first := t.firstOOM
	for _, d := range t.deaths {
		if !d.IsZero() && (first.IsZero() || d.Before(first)) {
			first = d
		}
	}
	return first
}

// worker is one plain process the storm grows.
type worker struct {
	cmd     *os.File // storm writes commands here
	ans     *os.File // and reads answers here
	ready   chan struct{}
	acks    chan uint64 // the totals the worker answered
	done    chan struct{}
	died    time.Time // set before done closes
	dirtied uint64
}

func newWorker() *worker {
	return &worker{ready: make(chan struct{}), acks: make(chan uint64, 64), done: make(chan struct{})}
}

// read follows the answers until the pipe ends.
func (w *worker) read() {
	sc := bufio.NewScanner(w.ans)
	isReady := false
	for sc.Scan() {
		line := sc.Text()
		if line == "ready" && !isReady {
			isReady = true
			close(w.ready)
			continue
		}
		if v, ok := strings.CutPrefix(line, "ok "); ok {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				select {
				case w.acks <- n:
				default: // nobody waits for an old answer
				}
			}
		}
	}
	w.died = time.Now()
	_ = w.ans.Close()
	close(w.done)
}

func (w *worker) gone() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// dirty asks for a total of n and waits up to to for it. A worker that
// takes longer is stalled in reclaim, and the round goes on without it,
// as the fiberd side does with a throttled fiber.
func (w *worker) dirty(n uint64, to time.Duration) {
	if _, err := fmt.Fprintf(w.cmd, "dirty %d\n", n); err != nil {
		return
	}
	t := time.NewTimer(to)
	defer t.Stop()
	for {
		select {
		case got := <-w.acks:
			if got >= n {
				return
			}
		case <-w.done:
			return
		case <-t.C:
			return
		}
	}
}

// growerPath is storm-grower beside this binary, as make storm-grower
// and the Slurm image place it.
func growerPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "storm-grower"
	}
	return filepath.Join(filepath.Dir(exe), "storm-grower")
}

// plainCgroup makes the child cgroup the workers run in, under root, or
// under the cgroup storm runs in when root is "own" (a Slurm job step,
// delegated as fiberd delegates it). It sets no limit of its own, so the
// container's or the allocation's limit is the one that applies. Swap
// is closed, as on fiberd's grant cgroups, so neither side swaps.
func plainCgroup(root, name string) (cgroup.Dir, error) {
	parent := cgroup.Root(root)
	if root == "own" {
		g, err := cgroup.Delegate(cgroup.Own("/sys/fs/cgroup"), "memory")
		if err != nil {
			return cgroup.Dir{}, err
		}
		parent = g
	}
	if err := parent.Ensure("memory"); err != nil {
		return cgroup.Dir{}, err
	}
	d := parent.Child("plain-" + name)
	if d.Exists() { // left by an earlier run
		_ = d.Kill()
		removeCgroup(d)
	}
	if err := d.Create(0, false); err != nil {
		return cgroup.Dir{}, err
	}
	_ = os.WriteFile(filepath.Join(d.Path, "memory.swap.max"), []byte("0"), 0o644)
	return d, nil
}

// removeCgroup removes d once the kill has emptied it.
func removeCgroup(d cgroup.Dir) {
	for range 50 {
		if d.Remove() == nil {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
}

// startGrower starts one grower process for ws, moves it into cg, and
// lets it go. Its workers' pipes are ExtraFiles, so worker i gets fds
// 3+2i and 4+2i.
func startGrower(path string, heapMB uint64, forks int, ws []*worker, cg cgroup.Dir) (*exec.Cmd, io.WriteCloser, error) {
	cmd := exec.Command(path, "--heap-mb", strconv.FormatUint(heapMB, 10), "--forks", strconv.Itoa(forks))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	var theirs []*os.File
	closeTheirs := func() {
		for _, f := range theirs {
			_ = f.Close()
		}
	}
	for _, w := range ws {
		cr, cw, err := os.Pipe()
		if err != nil {
			closeTheirs()
			return nil, nil, err
		}
		ar, aw, err := os.Pipe()
		if err != nil {
			_ = cr.Close()
			_ = cw.Close()
			closeTheirs()
			return nil, nil, err
		}
		w.cmd, w.ans = cw, ar
		theirs = append(theirs, cr, aw)
	}
	cmd.ExtraFiles = theirs
	err = cmd.Start()
	closeTheirs()
	if err != nil {
		return nil, nil, err
	}
	for _, w := range ws {
		go w.read()
	}
	if err := os.WriteFile(filepath.Join(cg.Path, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, fmt.Errorf("move pid %d into %s: %w", cmd.Process.Pid, cg.Path, err)
	}
	if _, err := io.WriteString(stdin, "go\n"); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, err
	}
	return cmd, stdin, nil
}

func runPlain(o opts) int {
	lay, err := parseLayout(o.layout, o.fibers)
	if err != nil {
		return fatal("%v", err)
	}
	if o.grower == "" {
		o.grower = growerPath()
	}
	share := perInstance(o.ceiling, o.overcommit, o.fibers)
	cg, err := plainCgroup(o.cgRoot, lay.name)
	if err != nil {
		return fatal("cgroup: %v", err)
	}
	oomBefore := oomKills(o.rootEvents)
	fmt.Printf("storm: plain %s layout, %d processes, heap=%dMiB demand=%dMiB (%.1fx of %dMiB) per-process=%dMiB, in %s, nothing parks\n",
		lay.name, o.fibers, o.heapMB, uint64(float64(o.ceiling)*o.overcommit)>>20, o.overcommit, o.ceiling>>20, share>>20, cg.Path)

	var ws []*worker
	var cmds []*exec.Cmd
	var stdins []io.WriteCloser
	defer func() {
		for _, w := range ws {
			if w.cmd != nil {
				_ = w.cmd.Close()
			}
		}
		for _, s := range stdins {
			_ = s.Close()
		}
		if cg.Kill() != nil { // a kernel before 5.14 has no cgroup.kill
			for _, c := range cmds {
				_ = c.Process.Kill()
			}
		}
		for _, c := range cmds {
			_ = c.Wait()
		}
		removeCgroup(cg)
	}()
	setup := time.Now()
	for range lay.procs {
		group := make([]*worker, lay.workersOf())
		for i := range group {
			group[i] = newWorker()
		}
		cmd, stdin, err := startGrower(o.grower, o.heapMB, lay.forks, group, cg)
		if err != nil {
			return fatal("start %s: %v", o.grower, err)
		}
		ws = append(ws, group...)
		cmds = append(cmds, cmd)
		stdins = append(stdins, stdin)
	}
	// Every worker touches its heap (separate) or the parent touches the
	// one heap (shared) before the first step. One that dies here is
	// killed before growth.
	deadline := time.After(o.timeout)
	for _, w := range ws {
		select {
		case <-w.ready:
		case <-w.done:
		case <-deadline:
			return fatal("workers not ready within %s", o.timeout)
		}
	}
	t := tally{growth: time.Now()}
	if oomKills(o.rootEvents) > oomBefore {
		t.firstOOM = setup
	}
	fmt.Printf("storm: %d of %d workers ready after %s; dirtying %dMiB per round per worker\n",
		alive(ws), len(ws), t.growth.Sub(setup).Round(100*time.Millisecond), o.step>>20)

	var maxCurrent uint64
	fmt.Printf("%8s %10s %8s %8s %10s\n", "t", "cg.cur", "alive", "killed", "demand")
	for time.Since(t.growth) < o.timeout {
		var wg sync.WaitGroup
		allDone := true
		for _, w := range ws {
			if w.gone() {
				continue
			}
			next, ok := nextStep(w.dirtied, share, o.step)
			if !ok {
				continue
			}
			allDone = false
			w.dirtied = next
			wg.Add(1)
			go func(w *worker, n uint64) {
				defer wg.Done()
				w.dirty(n, time.Second)
			}(w, next)
		}
		wg.Wait()
		cur, _ := cg.MemoryCurrent()
		maxCurrent = max(maxCurrent, cur)
		killed := rise(oomKills(o.rootEvents), oomBefore)
		if killed > 0 && t.firstOOM.IsZero() {
			t.firstOOM = time.Now()
		}
		var demand uint64
		for _, w := range ws {
			demand += w.dirtied
		}
		fmt.Printf("%8s %8dMiB %8d %8d %8dMiB\n", time.Since(t.growth).Round(100*time.Millisecond), cur>>20, alive(ws), killed, demand>>20)
		if allDone {
			break
		}
		time.Sleep(o.round)
	}
	time.Sleep(2 * time.Second) // let late kills land, as the fiberd side lets the ladder settle
	oomAfter := oomKills(o.rootEvents)
	if rise(oomAfter, oomBefore) > 0 && t.firstOOM.IsZero() {
		t.firstOOM = time.Now()
	}
	for _, w := range ws {
		if w.gone() {
			t.deaths = append(t.deaths, w.died)
		} else {
			t.deaths = append(t.deaths, time.Time{})
		}
	}
	fmt.Println()
	fmt.Printf("storm: plain max cgroup memory.current = %d MiB; OOM kills before=%d after=%d\n", maxCurrent>>20, oomBefore, oomAfter)
	fmt.Printf("storm: plain survivors=%d of %d, killed before growth=%d, first kill at %s\n",
		t.survivors(), len(ws), t.killedBeforeGrowth(), since(t.firstKill(), t.growth))
	fmt.Println(summary{side: "plain", layout: lay.name, n: len(ws), demand: uint64(float64(o.ceiling) * o.overcommit), oomKills: rise(oomAfter, oomBefore),
		survivors: t.survivors(), firstKill: since(t.firstKill(), t.growth), killedBeforeGrowth: t.killedBeforeGrowth()})
	// The baseline measures. It never fails on kills, which are expected.
	return 0
}

func alive(ws []*worker) int {
	n := 0
	for _, w := range ws {
		if !w.gone() {
			n++
		}
	}
	return n
}
