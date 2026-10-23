//go:build linux

package host

// The device engine. fiberd starts one per grant with a device budget,
// when the home names one (Config.Engine), and speaks to it on fd 3 in
// the reference engine's protocol. The engine owns the device and each
// fiber's slice of it. fiberd tells it which cgroup leaf is which fence
// (LEAF, UNLEAF), drops slices (EVICT), and reads its DEVICE lines into
// the accounting the sampler, Stats and the pressure ladder use.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

const (
	// engineLineMax is the longest line either side sends on fd 3, with
	// its newline.
	engineLineMax = 256
	// enginePidsMax is pids.max of the engine's leaf.
	enginePidsMax = 64
	// engineStartTimeout bounds a start from the spawn to READY. A CUDA
	// engine allocates and zeroes its whole pool first.
	engineStartTimeout = 60 * time.Second
	// engineWriteTimeout bounds one line to the engine, so a stuck
	// engine cannot hold a Clone.
	engineWriteTimeout = time.Second
	// A restart waits engineBackoffMin, doubling up to engineBackoffMax.
	// An engine that ran engineHealthy before it ended starts the wait
	// over.
	engineBackoffMin = 100 * time.Millisecond
	engineBackoffMax = 30 * time.Second
	engineHealthy    = time.Minute
)

// errEngineDown is what a line to an engine that is not running gets.
var errEngineDown = errors.New("host: the device engine is down")

// engine is one grant's device engine, across its restarts.
type engine struct {
	grantUID string
	argv     []string   // the command line, with --grant and --socket
	devices  []string   // FIBERD_DEVICES, the home's device channel
	dir      string     // <RunDir>/<grant>/engine, the engine uid's
	sock     string     // <dir>/engine.sock, which the engine binds
	logPath  string     // engineLog, where no fiber sees it
	cg       cgroup.Dir // <grant>/engine
	uid      uint32
	memMax   uint64

	first    chan struct{} // closed when the first start has ended
	firstErr error         // set before first is closed
	stopc    chan struct{} // closed by stop
	stopOnce sync.Once
	done     chan struct{} // closed when run returns

	// wmu orders every line to the engine. It is held across a write,
	// and across the LEAF lines a restart sends again, so an UNLEAF
	// never overtakes the LEAF it undoes. mu is never held across I/O.
	wmu sync.Mutex
	mu  sync.Mutex
	// conn is fd 3 of the running engine and proc its process, both nil
	// while it is down. up is set once it said READY.
	conn *net.UnixConn
	proc *os.Process
	up   bool
	// class, layout and capacity are what the first engine declared.
	// Every restart must declare the same class and layout.
	class    string
	layout   string
	capacity uint64
	used     uint64            // from DEVICE - lines, 0 while down
	slices   map[string]uint64 // fence -> slice bytes, from DEVICE lines
	// leaves maps each fence that has a LEAF to its cgroup path as the
	// engine names it. A restart sends them all again.
	leaves map[string]string
	// cgRoot is the cgroup mount as fiberd sees it, so a leaf's path
	// less cgRoot is the path the engine reads in /proc/<pid>/cgroup.
	cgRoot string
}

// engineResult is what a start in the background hands back.
type engineResult struct {
	e       *engine
	started bool
	err     error
}

// wantsEngine reports whether g gets a device engine on this home.
func (r *Runtime) wantsEngine(g core.Grant) bool {
	return len(r.cfg.Engine) > 0 && g.DeviceBudget.Bytes > 0
}

func (r *Runtime) engineOf(grantUID string) *engine {
	r.enginesMu.Lock()
	defer r.enginesMu.Unlock()
	return r.engines[grantUID]
}

// engineDir is the grant's engine directory, which holds its socket.
func (r *Runtime) engineDir(grantUID string) string {
	return filepath.Join(r.cfg.RunDir, grantUID, "engine")
}

// enginePath is the socket the grant's engine binds, which the warm
// instance hands its fibers.
func (r *Runtime) enginePath(grantUID string) string {
	return filepath.Join(r.engineDir(grantUID), "engine.sock")
}

// engineUID is the uid and gid every engine runs as.
func (r *Runtime) engineUID() uint32 {
	if r.cfg.EngineUID == 0 {
		return DefaultEngineUID
	}
	return r.cfg.EngineUID
}

// engineLog is the grant's engine log. It sits in fiberd's private
// directory, else beside the deltas, both hidden from every fiber and
// outside the run directory, so no fiber can write or replace it.
func (r *Runtime) engineLog(grantUID string) string {
	dir := filepath.Join(r.cfg.DeltaDir, ".engine-logs")
	if r.cfg.PrivateDir != "" {
		dir = filepath.Join(r.cfg.PrivateDir, "engine-logs")
	}
	return filepath.Join(dir, grantUID+".log")
}

// ensureEngineDir makes the grant's engine directory once, before its
// warm instance starts, since the zygote binds it read-only over itself
// as it prepares its fibers' mount namespace. It then stays as it is
// while the grant lives. An engine's restart keeps it and replaces only
// its socket. DropTemplate and Close remove it (dropEngineDir).
func (r *Runtime) ensureEngineDir(grantUID string) error {
	r.enginesMu.Lock()
	defer r.enginesMu.Unlock()
	if r.engineDirs[grantUID] {
		return nil
	}
	if err := makeEngineDir(r.engineDir(grantUID), r.engineUID()); err != nil {
		return err
	}
	if r.engineDirs == nil {
		r.engineDirs = map[string]bool{}
	}
	r.engineDirs[grantUID] = true
	return nil
}

// dropEngineDir removes the grant's engine directory, once its engine
// and warm instance are gone.
func (r *Runtime) dropEngineDir(grantUID string) {
	r.enginesMu.Lock()
	defer r.enginesMu.Unlock()
	if !r.engineDirs[grantUID] {
		return
	}
	delete(r.engineDirs, grantUID)
	if err := removeEngineDir(r.engineDir(grantUID)); err != nil {
		log.Printf("host: device engine of %s: %v", grantUID, err)
	}
}

// ensureEngine starts the grant's engine in gcg unless it has one, and
// waits until its first start has ended. started says this call made
// it. An engine that is down and restarting is returned as it is, since
// it said READY once. One that is stopping is waited out first, so the
// new engine never shares its leaf with the old one's removal.
func (r *Runtime) ensureEngine(ctx context.Context, g core.Grant, gcg cgroup.Dir) (*engine, bool, error) {
	r.enginesMu.Lock()
	e := r.engines[g.UID]
	for e != nil && e.stopping() {
		r.enginesMu.Unlock()
		select {
		case <-e.done:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
		r.enginesMu.Lock()
		if r.engines[g.UID] == e {
			delete(r.engines, g.UID)
		}
		// Another call may have made the grant's next engine meanwhile.
		e = r.engines[g.UID]
	}
	started := false
	if e == nil {
		memMax := r.cfg.EngineMemoryMax
		if memMax == 0 {
			memMax = DefaultEngineMemoryMax
		}
		e = &engine{
			grantUID: g.UID, dir: r.engineDir(g.UID), sock: r.enginePath(g.UID),
			logPath: r.engineLog(g.UID), cg: gcg.Child("engine"),
			uid: r.engineUID(), memMax: memMax, devices: r.devicesOf(g.UID).Devices,
			first: make(chan struct{}), stopc: make(chan struct{}), done: make(chan struct{}),
			slices: map[string]uint64{}, leaves: map[string]string{},
		}
		e.argv = append([]string{r.cfg.Engine[0], "--grant", g.UID, "--socket", e.sock}, r.cfg.Engine[1:]...)
		if r.engines == nil {
			r.engines = map[string]*engine{}
		}
		r.engines[g.UID] = e
		started = true
		go e.run()
	}
	r.enginesMu.Unlock()
	select {
	case <-e.first:
	case <-ctx.Done():
		if started {
			r.dropEngine(e)
		}
		return nil, false, ctx.Err()
	}
	if e.firstErr != nil {
		r.dropEngine(e)
		return nil, false, fmt.Errorf("host: device engine of %s: %w", g.UID, e.firstErr)
	}
	return e, started, nil
}

// dropEngine stops e and forgets it once it is gone, unless the grant
// has another engine by then. Lines sent meanwhile find it down.
func (r *Runtime) dropEngine(e *engine) {
	e.stop()
	r.enginesMu.Lock()
	if r.engines[e.grantUID] == e {
		delete(r.engines, e.grantUID)
	}
	r.enginesMu.Unlock()
}

// stopEngine stops the grant's engine, if it has one.
func (r *Runtime) stopEngine(grantUID string) {
	if e := r.engineOf(grantUID); e != nil {
		r.dropEngine(e)
	}
}

// DeviceOffer implements core.DeviceCapable with what the grant's
// engine declared before READY.
func (r *Runtime) DeviceOffer(grantUID string) (string, uint64) {
	e := r.engineOf(grantUID)
	if e == nil {
		return "", 0
	}
	return e.offer()
}

// deviceLeaf sends LEAF for a fiber of g about to run under fence in
// leaf. It must come before the fiber can run, at every birth and
// resume. A grant without a device budget needs none. While the engine
// is down the birth is refused as the grant's own pressure, which the
// caller retries.
func (r *Runtime) deviceLeaf(g core.Grant, fence string, leaf cgroup.Dir) error {
	if !r.wantsEngine(g) {
		return nil
	}
	e := r.engineOf(g.UID)
	if e == nil {
		return fmt.Errorf("%w: grant %s: %w", core.ErrPressure, g.UID, errEngineDown)
	}
	if err := e.leaf(fence, leaf); err != nil {
		if errors.Is(err, errEngineDown) {
			return fmt.Errorf("%w: grant %s: %w", core.ErrPressure, g.UID, err)
		}
		return fmt.Errorf("host: LEAF %s: %w", fence, err)
	}
	return nil
}

// endDevice drops a fiber's leaf's mapping and then its slice, UNLEAF
// then EVICT, when it ends or parks or a birth fails after its LEAF. A
// request racing the end so finds no mapping and cannot take a slice
// the EVICT would miss. An engine that is down holds none.
func (r *Runtime) endDevice(grantUID, fence string) {
	e := r.engineOf(grantUID)
	if e == nil {
		return
	}
	e.unleaf(fence)
	if err := e.send("EVICT " + fence); err != nil && !errors.Is(err, errEngineDown) {
		log.Printf("host: evict device slice of %s: %v", fence, err)
	}
}

// evictDevice drops the device slice of a fiber about to be parked, and
// its mapping first. Only a fiber with a device budget can hold one. A
// park that fails maps the fiber again (releafDevice).
func (r *Runtime) evictDevice(f *fiber) {
	if f.devMax == 0 {
		return
	}
	r.endDevice(f.grantUID, f.id)
}

// releafDevice maps a fiber's leaf again after its park failed, since
// the fiber runs on. An engine that is down gets it with the replay of
// its restart.
func (r *Runtime) releafDevice(f *fiber) {
	if f.devMax == 0 {
		return
	}
	e := r.engineOf(f.grantUID)
	if e == nil {
		return
	}
	if err := e.releaf(f.id, f.cg); err != nil {
		log.Printf("host: LEAF %s again after its park failed: %v", f.id, err)
	}
	// A fiber that ended meanwhile was unmapped before this mapping, so
	// it is dropped again.
	r.mu.Lock()
	live := r.fibers[f.id] == f
	r.mu.Unlock()
	if !live {
		r.endDevice(f.grantUID, f.id)
	}
}

// fiberDevice is the fiber's slice as its engine last reported it.
func (r *Runtime) fiberDevice(f *fiber) uint64 {
	if f.devMax == 0 {
		return 0
	}
	e := r.engineOf(f.grantUID)
	if e == nil {
		return 0
	}
	return e.slice(f.id)
}

// DevicePressure is the ladder's second input: the engine's occupancy in
// percent of its capacity, for grants with an engine, and 0 for the rest.
// Combine with the PSI source through core.MaxPressure.
func (r *Runtime) DevicePressure() core.PressureSource { return devicePressure{r} }

type devicePressure struct{ r *Runtime }

func (d devicePressure) Pressure(grantUID string) (float64, error) {
	e := d.r.engineOf(grantUID)
	if e == nil {
		return 0, nil
	}
	used, capacity := e.usage()
	if capacity == 0 {
		return 0, nil
	}
	return 100 * float64(used) / float64(capacity), nil
}

// run starts the engine and starts it again after every exit, with
// backoff, until stop. A first start that fails ends it, since the warm
// that asked fails with it. On the way out it removes the engine's leaf,
// so done means no engine process is left.
func (e *engine) run() {
	defer close(e.done)
	defer e.cleanup()
	backoff := engineBackoffMin
	for first := true; ; first = false {
		t0 := time.Now()
		conn, proc, err := e.launch()
		if first {
			e.firstErr = err
			close(e.first)
			if err != nil {
				return
			}
		}
		if err == nil {
			class, capacity := e.offer()
			log.Printf("host: device engine of %s ready class=%s capacity=%d pid=%d", e.grantUID, class, capacity, proc.Pid)
			why := e.serve(conn)
			e.down(conn, proc)
			log.Printf("host: device engine of %s ended (%v); every slice is zero until it is back", e.grantUID, why)
			if time.Since(t0) > engineHealthy {
				backoff = engineBackoffMin
			}
		} else {
			log.Printf("host: device engine of %s: %v; next try in %s", e.grantUID, err, backoff)
		}
		select {
		case <-e.stopc:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, engineBackoffMax)
	}
}

// stopping reports whether stop was called.
func (e *engine) stopping() bool {
	select {
	case <-e.stopc:
		return true
	default:
		return false
	}
}

// cleanup removes the engine's leaf, after killing whatever is left in
// it. It runs once, as run returns. The engine's directory stays with
// the grant (ensureEngineDir).
func (e *engine) cleanup() {
	if e.cg.Exists() {
		_ = e.cg.Kill()
		_ = removeSoon(e.cg)
	}
}

// serve reads the running engine's lines until fd 3 breaks, and returns
// why it did.
func (e *engine) serve(conn *net.UnixConn) error {
	buf := make([]byte, engineLineMax+1)
	for {
		line, err := readLine(conn, buf)
		if err != nil {
			return err
		}
		e.apply(line)
	}
}

// down marks the engine gone. Every slice reads zero, no line reaches
// it, and the process and anything left in its leaf are killed and
// reaped.
func (e *engine) down(conn *net.UnixConn, proc *os.Process) {
	e.mu.Lock()
	if e.conn == conn {
		e.conn, e.proc, e.up = nil, nil, false
		e.used = 0
		clear(e.slices)
	}
	e.mu.Unlock()
	_ = conn.Close()
	e.kill(proc)
	_, _ = proc.Wait()
}

// kill ends the engine and anything it left in its leaf. cgroup.kill
// needs no CAP_KILL, which a signal to another uid would. The signal is
// for an engine that is not in its leaf, which cannot happen, and its
// refusal is ignored.
func (e *engine) kill(proc *os.Process) {
	_ = e.cg.Kill()
	_ = proc.Kill()
}

// stop ends the engine for good and waits until nothing of it is left.
// It ends a start in progress, a serve or a backoff wait, and holds no
// lock while it waits, so DropTemplate and Close cannot deadlock on it.
// Every caller returns once run has cleaned up.
func (e *engine) stop() {
	e.stopOnce.Do(func() { close(e.stopc) })
	e.mu.Lock()
	conn, proc := e.conn, e.proc
	e.mu.Unlock()
	// Closing fd 3 ends a serve or a handshake in progress, and the kill
	// makes sure the process goes with it. A launch that has not set
	// them yet sees stopc before it hands them over.
	if conn != nil {
		_ = conn.Close()
	}
	if proc != nil {
		e.kill(proc)
	}
	<-e.done
}

// offer is the class and capacity the engine declared.
func (e *engine) offer() (string, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.class, e.capacity
}

// usage is the engine's whole use and its capacity, use 0 while down.
func (e *engine) usage() (used, capacity uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.used, e.capacity
}

// slice is the fence's slice, 0 while the engine is down.
func (e *engine) slice(fence string) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.slices[fence]
}

// send writes one line to the running engine.
func (e *engine) send(line string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	return e.write(line)
}

// write sends one line. The caller holds wmu. A line that cannot be
// written means the engine is gone or stuck, and either way its fd 3 is
// closed here, so serve ends and run starts it again. The caller sees
// it as down, which a Clone retries.
func (e *engine) write(line string) error {
	if len(line)+1 > engineLineMax || strings.ContainsAny(line, "\n\x00") {
		return fmt.Errorf("host: line to the engine too long or not one line: %q", line)
	}
	e.mu.Lock()
	conn, up := e.conn, e.up
	e.mu.Unlock()
	if !up || conn == nil {
		return errEngineDown
	}
	_ = conn.SetWriteDeadline(time.Now().Add(engineWriteTimeout))
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		log.Printf("host: device engine of %s: line %q not taken (%v); ending it", e.grantUID, line, err)
		_ = conn.Close()
		return errEngineDown
	}
	return nil
}

// leaf maps leaf to fence in the engine (LEAF) and keeps the mapping, so
// a restart sends it again.
func (e *engine) leaf(fence string, leaf cgroup.Dir) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	e.mu.Lock()
	path, err := e.cgPath(leaf)
	e.mu.Unlock()
	if err != nil {
		return err
	}
	if err := token(fence); err != nil {
		return err
	}
	if err := e.write("LEAF " + fence + " " + path); err != nil {
		return err
	}
	e.mu.Lock()
	e.leaves[fence] = path
	e.mu.Unlock()
	return nil
}

// unleaf drops the fence's mapping (UNLEAF), here and in the engine. Its
// slice is forgotten here too, since the fiber is gone.
func (e *engine) unleaf(fence string) {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	e.mu.Lock()
	_, had := e.leaves[fence]
	delete(e.leaves, fence)
	delete(e.slices, fence)
	e.mu.Unlock()
	if !had {
		return
	}
	if err := e.write("UNLEAF " + fence); err != nil && !errors.Is(err, errEngineDown) {
		log.Printf("host: UNLEAF %s: %v", fence, err)
	}
}

// releaf maps leaf to fence again for a fiber that runs on, keeping the
// mapping even while the engine is down, so the replay of its restart
// sends it.
func (e *engine) releaf(fence string, leaf cgroup.Dir) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if err := token(fence); err != nil {
		return err
	}
	e.mu.Lock()
	path, err := e.cgPath(leaf)
	if err == nil {
		e.leaves[fence] = path
	}
	e.mu.Unlock()
	if err != nil {
		return err
	}
	if err := e.write("LEAF " + fence + " " + path); err != nil && !errors.Is(err, errEngineDown) {
		return err
	}
	return nil
}

// cgPath is leaf's path as the engine reads it in /proc/<pid>/cgroup.
// The caller holds mu.
func (e *engine) cgPath(leaf cgroup.Dir) (string, error) {
	if e.cgRoot == "" {
		return "", errEngineDown
	}
	rel, ok := strings.CutPrefix(leaf.Path, e.cgRoot)
	if !ok || !strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("host: leaf %s is not under the cgroup mount %s", leaf.Path, e.cgRoot)
	}
	if err := token(rel); err != nil {
		return "", err
	}
	return rel, nil
}

// token refuses a word that would not be one word of a line.
func token(s string) error {
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00") {
		return fmt.Errorf("host: %q cannot be one word of a line to the engine", s)
	}
	return nil
}

// launch starts one engine and waits for its READY. fd 3 and the
// process are e's from the spawn on, so stop can end a start in
// progress, and down undoes a start that fails.
func (e *engine) launch() (*net.UnixConn, *os.Process, error) {
	if err := e.prepareLeaf(); err != nil {
		return nil, nil, err
	}
	// Close-on-exec, so a zygote started meanwhile never holds the
	// engine's end. The spawn puts it at fd 3 of the engine alone.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("host: engine socket pair: %w", err)
	}
	parentF := os.NewFile(uintptr(fds[0]), "engine-ctl")
	childF := os.NewFile(uintptr(fds[1]), "engine-fd3")
	proc, err := e.spawn(childF)
	// The engine holds its own copy. Ours goes now, so its exit is an
	// EOF here.
	_ = childF.Close()
	if err != nil {
		_ = parentF.Close()
		return nil, nil, err
	}
	c, err := net.FileConn(parentF)
	_ = parentF.Close()
	if err != nil {
		e.kill(proc)
		_, _ = proc.Wait()
		return nil, nil, fmt.Errorf("host: engine fd 3: %w", err)
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		e.kill(proc)
		_, _ = proc.Wait()
		return nil, nil, errors.New("host: engine fd 3 is not a unix socket")
	}
	// From here stop sees the process and fd 3, or the launch sees stop.
	// Both run under mu, so neither can miss the other.
	e.mu.Lock()
	if e.stopping() {
		e.mu.Unlock()
		_ = conn.Close()
		e.kill(proc)
		_, _ = proc.Wait()
		return nil, nil, errors.New("host: engine stopped while starting")
	}
	e.conn, e.proc = conn, proc
	e.mu.Unlock()
	fail := func(err error) (*net.UnixConn, *os.Process, error) {
		e.down(conn, proc)
		return nil, nil, err
	}
	root, err := cgroupRoot(e.cg, proc.Pid)
	if err != nil {
		return fail(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(engineStartTimeout))
	d, err := handshake(conn)
	if err != nil {
		return fail(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	// A restart must be the same kind of engine, since the fibers' slices
	// and the grant's offer are of that kind. Only launch writes class
	// and layout, and one launch runs at a time, so the check needs no
	// lock across the switch below.
	e.mu.Lock()
	was, wasLayout := e.class, e.layout
	e.mu.Unlock()
	if was != "" && (d.class != was || d.layout != wasLayout) {
		return fail(fmt.Errorf("host: the restarted engine declares class %s layout %s, the grant's engine was class %s layout %s", d.class, d.layout, was, wasLayout))
	}
	// Up, and every live fiber's LEAF again, in one hold of wmu, so no
	// line from a Clone or an end goes between. A LEAF that fails here
	// closed fd 3, so this engine ends and the next restart sends them
	// all again.
	e.wmu.Lock()
	defer e.wmu.Unlock()
	e.mu.Lock()
	e.class, e.layout, e.capacity = d.class, d.layout, d.capacity
	e.cgRoot = root
	e.up, e.used = true, 0
	clear(e.slices)
	leaves := make(map[string]string, len(e.leaves))
	maps.Copy(leaves, e.leaves)
	e.mu.Unlock()
	for fence, path := range leaves {
		if err := e.write("LEAF " + fence + " " + path); err != nil {
			log.Printf("host: LEAF %s again after the engine's restart: %v", fence, err)
			break
		}
	}
	log.Printf("host: device engine of %s is %s on %s cc %s driver %s", e.grantUID, d.class, d.gpu, d.cc, d.driver)
	return conn, proc, nil
}

// prepareLeaf makes the engine's leaf, <grant>/engine, with its memory
// and task limits, and empties it of anything an earlier engine left.
func (e *engine) prepareLeaf() error {
	if err := e.cg.Create(e.memMax, true); err != nil {
		return err
	}
	if err := e.cg.SetPidsMax(enginePidsMax); err != nil {
		return err
	}
	if pids, _ := e.cg.Procs(); len(pids) == 0 {
		return nil
	}
	_ = e.cg.Kill()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if pids, err := e.cg.Procs(); err != nil || len(pids) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("host: an earlier engine in %s did not die", e.cg.Path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cgroupRoot is the cgroup mount as fiberd sees it: the engine's leaf
// less the path its own /proc/<pid>/cgroup names. The engine runs in
// fiberd's cgroup namespace, so other leaves are named the same way.
func cgroupRoot(leaf cgroup.Dir, pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("host: the engine's cgroup: %w", err)
	}
	path := cgroup.ScopeOf(string(b))
	if path == "" || !strings.HasSuffix(leaf.Path, path) {
		return "", fmt.Errorf("host: the engine runs in cgroup %q, not in its leaf %s", path, leaf.Path)
	}
	return strings.TrimSuffix(leaf.Path, path), nil
}

// makeEngineDir makes the engine's directory afresh, <RunDir>/<grant>/engine,
// mode 0755 and owned by the engine's uid, so the engine can bind its
// socket there and no fiber can. Its parent stays fiberd's, so the
// engine's uid cannot rename the directory away or put a link in its
// place. Whatever is at the name first goes, so a stale socket or a
// link planted by a fiber never becomes the engine's.
//
// The directory is made with fiberd's mode and handed over through a
// descriptor opened without following links, after a check that it is
// what fiberd just made. A fiber that can write the parent could still
// swap a directory of fiberd's uid in between the mkdir and the open.
// Under the proc runtime a uid 0 fiber is such a writer, and under runc
// the grant's mapped root has group write on the parent. The engine uid
// then owns that directory, which is as much as it owns by design, and
// the engine's socket ends up where no fiber finds it.
func makeEngineDir(dir string, uid uint32) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if err := removeEngineDir(dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("host: engine directory: %w", err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("host: open the engine directory: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
		return fmt.Errorf("host: engine directory %s is not the one fiberd made", dir)
	}
	// The mode is set while fiberd still owns the directory. Once it is
	// the engine uid's, a chmod needs CAP_FOWNER, which NarrowCaps does
	// not keep.
	if err := unix.Fchmod(fd, 0o755); err != nil {
		return fmt.Errorf("host: engine directory mode: %w", err)
	}
	if err := unix.Fchown(fd, int(uid), int(uid)); err != nil {
		return fmt.Errorf("host: give the engine directory to uid %d: %w", uid, err)
	}
	return nil
}

// removeEngineDir removes whatever is at the engine's directory. The engine's
// uid owns the directory, and fiberd may lack CAP_DAC_OVERRIDE to
// unlink the socket inside, so fiberd takes the directory back first
// (CAP_CHOWN), through a descriptor that follows no link. A link or a
// file at the name is unlinked as it is.
func removeEngineDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil
	case errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("host: remove what is at the engine directory: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("host: open the engine directory: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err == nil && st.Uid != uint32(os.Geteuid()) {
		_ = unix.Fchown(fd, os.Geteuid(), os.Getegid())
	}
	_ = unix.Close(fd)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("host: remove the engine directory: %w", err)
	}
	return nil
}

// spawn starts the engine with child as its fd 3. It runs as the
// engine's uid and gid with no supplementary groups and no capabilities
// in any set, under no_new_privs, born in its own leaf, in a session of
// its own, in its directory, with PATH and FIBERD_DEVICES alone. Its
// fds are 0 on /dev/null, 1 and 2 on the grant's engine log and 3,
// since everything else fiberd holds is close-on-exec.
func (e *engine) spawn(child *os.File) (*os.Process, error) {
	logf, err := e.openLog()
	if err != nil {
		return nil, err
	}
	defer func() { _ = logf.Close() }()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	defer func() { _ = devnull.Close() }()
	cgf, err := e.cg.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = cgf.Close() }()
	env := []string{"PATH=/usr/bin:/bin"}
	if len(e.devices) > 0 {
		env = append(env, "FIBERD_DEVICES="+strings.Join(e.devices, ","))
	}
	// The child drops to the engine's uid and gid before its exec, with
	// setgroups(0), setgid and setuid, in that order. The kernel empties
	// its permitted, effective and ambient sets when uid 0 is left. No
	// Pdeathsig, since that signal fires when the forking thread ends,
	// which is right after the start here.
	cmd := &exec.Cmd{
		Path: e.argv[0], Args: e.argv, Env: env, Dir: e.dir,
		Stdin: devnull, Stdout: logf, Stderr: logf,
		ExtraFiles: []*os.File{child},
		SysProcAttr: &syscall.SysProcAttr{
			Setsid:      true,
			Credential:  &syscall.Credential{Uid: e.uid, Gid: e.uid, Groups: []uint32{}},
			UseCgroupFD: true,
			CgroupFD:    int(cgf.Fd()),
		},
	}
	// no_new_privs, the bounding set and the inheritable and ambient
	// sets belong to a thread, and a child takes them from the thread
	// that clones it. os/exec clones on the calling goroutine's thread,
	// so the start runs on a thread of its own that is stripped first.
	// The thread is never unlocked, so it is destroyed when the goroutine
	// returns, and the runtime makes new threads from its template
	// thread rather than from a locked one, so no other goroutine ever
	// runs stripped.
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := stripThread(); err != nil {
			errc <- err
			return
		}
		errc <- cmd.Start()
	}()
	if err := <-errc; err != nil {
		return nil, fmt.Errorf("host: start engine %v: %w", e.argv, err)
	}
	return cmd.Process, nil
}

// openLog opens the grant's engine log for appending, in a directory
// that is fiberd's alone. It must still be a regular file of fiberd's.
func (e *engine) openLog() (*os.File, error) {
	if err := ownerDir(filepath.Dir(e.logPath)); err != nil {
		return nil, fmt.Errorf("host: engine log directory: %w", err)
	}
	fd, err := unix.Open(e.logPath, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("host: engine log: %w", err)
	}
	f := os.NewFile(uintptr(fd), e.logPath)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("host: engine log: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, fmt.Errorf("host: engine log %s is not a regular file of fiberd's", e.logPath)
	}
	return f, nil
}

// stripThread leaves the calling thread, which the caller has locked,
// with nothing a child could keep across its exec. The ambient set goes
// first, since the inheritable set must contain it. Then the
// inheritable set is emptied, every capability leaves the bounding set
// (CAP_SETPCAP, which fiberd keeps), and no_new_privs is set, which
// nothing can undo. The thread's own permitted and effective sets stay,
// since the clone into the engine's leaf still needs them.
//
// After the child's setuid and exec its permitted set is what the file
// grants masked by the empty bounding set, or what the empty
// inheritable set grants, or the empty ambient set. So it is empty by
// arithmetic alone. no_new_privs on top keeps a setuid file from
// changing its uid and lets the engine install seccomp without
// CAP_SYS_ADMIN.
func stripThread() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("host: clear the ambient set for the engine: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("host: capget for the engine: %w", err)
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("host: clear the inheritable set for the engine: %w", err)
	}
	for c := 0; c < 64; c++ {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		if errors.Is(err, unix.EINVAL) {
			break // past the last capability this kernel has
		}
		if err != nil {
			return fmt.Errorf("host: drop capability %d from the engine's bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("host: no_new_privs for the engine: %w", err)
	}
	return nil
}

// declared is what an engine said before READY.
type declared struct {
	class, layout   string
	capacity        uint64
	gpu, cc, driver string
}

// handshake reads ENGINE, GPU and READY, in that order. Anything else
// before READY, an ERROR among them, fails the start.
func handshake(conn *net.UnixConn) (declared, error) {
	var d declared
	buf := make([]byte, engineLineMax+1)
	for _, want := range []string{"ENGINE", "GPU", "READY"} {
		line, err := readLine(conn, buf)
		if err != nil {
			return d, fmt.Errorf("host: engine before READY: %w", err)
		}
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != want {
			return d, fmt.Errorf("host: engine said %q, want %s", line, want)
		}
		switch want {
		case "ENGINE":
			if len(f) != 5 || !validClass(f[1]) || f[3] != "1" {
				return d, fmt.Errorf("host: engine said %q, want ENGINE <class> <capacity> 1 <layout>", line)
			}
			c, err := strconv.ParseUint(f[2], 10, 64)
			if err != nil {
				return d, fmt.Errorf("host: engine capacity %q: %w", f[2], err)
			}
			d.class, d.capacity, d.layout = f[1], c, f[4]
		case "GPU":
			if len(f) != 4 {
				return d, fmt.Errorf("host: engine said %q, want GPU <name> <cc> <driver>", line)
			}
			d.gpu, d.cc, d.driver = f[1], f[2], f[3]
		case "READY":
			if len(f) != 1 {
				return d, fmt.Errorf("host: engine said %q, want READY", line)
			}
		}
	}
	return d, nil
}

// validClass is a device class, 1 to 32 characters of a-z, 0-9 and -.
func validClass(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// readLine reads one message from fd 3, which must be one line of at
// most engineLineMax bytes with its newline. It returns the line
// without it. Descriptors the engine sends are dropped by the kernel,
// since the read takes none.
func readLine(conn *net.UnixConn, buf []byte) (string, error) {
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	switch {
	case n == 0:
		return "", io.EOF
	case n > engineLineMax:
		return "", fmt.Errorf("host: engine line longer than %d bytes", engineLineMax)
	case buf[n-1] != '\n' || bytes.IndexByte(buf[:n-1], '\n') >= 0:
		return "", fmt.Errorf("host: engine message %q is not one line", buf[:n])
	}
	return string(buf[:n-1]), nil
}

// apply takes one line the running engine sent.
func (e *engine) apply(line string) {
	f := strings.Fields(line)
	switch {
	case len(f) == 4 && f[0] == "DEVICE":
		n, err := strconv.ParseUint(f[2], 10, 64)
		if err != nil {
			log.Printf("host: device engine of %s: bad line %q", e.grantUID, line)
			return
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		switch {
		case f[1] == "-":
			e.used = n
		case n == 0:
			delete(e.slices, f[1])
		default:
			// A report for a fence with no mapping is a race with its
			// end, and the slice is no live fiber's.
			if _, ok := e.leaves[f[1]]; ok {
				e.slices[f[1]] = n
			}
		}
	case len(f) >= 2 && f[0] == "ERROR":
		log.Printf("host: device engine of %s: %s", e.grantUID, line)
	default:
		log.Printf("host: device engine of %s: unknown line %q", e.grantUID, line)
	}
}
