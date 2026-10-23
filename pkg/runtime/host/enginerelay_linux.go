//go:build linux

package host

import (
	"errors"
	"log"

	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// engineRelayer is a backend whose fibers have no process of their own,
// so their engine requests come from the warm instance, which puts each
// fiber's fence in the line itself. The Hyperlight helper is one. The
// engine lets the warm instance's cgroup name any fence that has a LEAF
// (RELAY), and every fiber still gets its LEAF, so only live fibers of
// the grant can be named.
type engineRelayer interface {
	RelaysEngine() bool
}

// relayDevice sends RELAY for the warm instance's cgroup when the
// backend relays its fibers' engine requests. It goes once the engine
// and the warm instance are up and before the warm instance is
// published, so before any of its fibers runs. A grant without an engine
// needs none.
func (r *Runtime) relayDevice(e *engine, zcg cgroup.Dir) error {
	if e == nil {
		return nil
	}
	if rl, ok := r.be.(engineRelayer); !ok || !rl.RelaysEngine() {
		return nil
	}
	return e.relay(zcg)
}

// relay lets peers in cg name any fence that has a LEAF (RELAY) and keeps
// the cgroup, so a restart sends it again. An engine that is down gets
// it with the replay of its restart.
func (e *engine) relay(cg cgroup.Dir) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	e.mu.Lock()
	path, err := e.cgPath(cg)
	e.mu.Unlock()
	if err != nil {
		return err
	}
	if err := e.write("RELAY " + path); err != nil && !errors.Is(err, errEngineDown) {
		return err
	}
	e.mu.Lock()
	if e.relays == nil {
		e.relays = map[string]bool{}
	}
	e.relays[path] = true
	e.mu.Unlock()
	return nil
}

// rerelay sends every kept RELAY again, after a restart. The caller holds
// wmu, so no line from a Clone goes between. A line that fails closed fd
// 3, so the next restart sends them all again.
func (e *engine) rerelay() {
	e.mu.Lock()
	paths := make([]string, 0, len(e.relays))
	for path := range e.relays {
		paths = append(paths, path)
	}
	e.mu.Unlock()
	for _, path := range paths {
		if err := e.write("RELAY " + path); err != nil {
			log.Printf("host: RELAY %s again after the engine's restart: %v", path, err)
			return
		}
	}
}
