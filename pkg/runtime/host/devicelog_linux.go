//go:build linux

package host

import (
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// deviceLogSize is how many device events the ring holds.
const deviceLogSize = 256

// deviceTime is how an event's time is written, in UTC.
const deviceTime = "2006-01-02T15:04:05.000000Z07:00"

var _ core.DeviceReporter = (*Runtime)(nil)

// deviceLog is the ring of the last device events, parks that saved a
// slice and resumes that restored one. seq rises from 1 and is the
// number of events ever added. mu is never held across I/O.
type deviceLog struct {
	mu   sync.Mutex
	seq  uint64
	ring [deviceLogSize]core.DeviceEvent
}

// devEvents is fiberd's one device log, so seq rises once per process.
var devEvents deviceLog

// parked adds a park that saved fence's slice, under the session the
// fiber was cloned or resumed under.
func (l *deviceLog) parked(grant, session, fence string, delta, slice uint64, save time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.add(core.DeviceEvent{Kind: "park", Grant: grant, Session: session, Fence: fence,
		DeltaBytes: delta, SliceBytes: slice, MS: deviceMillis(save)})
}

// restored adds a resume that restored a slice under fence.
func (l *deviceLog) restored(grant, session, fence string, slice uint64, restore time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.add(core.DeviceEvent{Kind: "restore", Grant: grant, Session: session, Fence: fence,
		SliceBytes: slice, MS: deviceMillis(restore)})
}

// add stamps ev with the next seq and the time and puts it in the ring
// over the oldest event. The caller holds mu.
func (l *deviceLog) add(ev core.DeviceEvent) {
	l.seq++
	ev.Seq = l.seq
	ev.T = time.Now().UTC().Format(deviceTime)
	l.ring[(l.seq-1)%deviceLogSize] = ev
}

// since is every event held with a seq above seq, oldest first.
func (l *deviceLog) since(seq uint64) []core.DeviceEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []core.DeviceEvent{}
	if seq >= l.seq {
		return out
	}
	first := seq + 1
	if l.seq > deviceLogSize {
		first = max(first, l.seq-deviceLogSize+1)
	}
	for q := first; q <= l.seq; q++ {
		out = append(out, l.ring[(q-1)%deviceLogSize])
	}
	return out
}

// deviceMillis is d in milliseconds, to the microsecond.
func deviceMillis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// DeviceReport implements core.DeviceReporter: every grant's engine,
// sorted by grant, and the device events after since.
func (r *Runtime) DeviceReport(since uint64) core.DeviceReport {
	r.enginesMu.Lock()
	es := slices.Collect(maps.Values(r.engines))
	r.enginesMu.Unlock()
	engines := make([]core.DeviceEngine, 0, len(es))
	for _, e := range es {
		engines = append(engines, e.deviceReport())
	}
	slices.SortFunc(engines, func(a, b core.DeviceEngine) int { return strings.Compare(a.Grant, b.Grant) })
	return core.DeviceReport{Engines: engines, Events: devEvents.since(since)}
}

// deviceReport is the engine as it last declared itself. The version
// is known once it has declared a class.
func (e *engine) deviceReport() core.DeviceEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	d := core.DeviceEngine{Grant: e.grantUID, Up: e.up, Class: e.class, Layout: e.layout,
		GPU: e.gpu, CC: e.cc, Driver: e.driver, Capacity: e.capacity, Used: e.used}
	if e.class != "" {
		d.Version = engineVersion
	}
	return d
}
