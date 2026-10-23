//go:build linux

package host

import (
	"fmt"
	"log"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// engineVersion is the protocol version every engine declares. The
// handshake refuses any other.
const engineVersion = "1"

// engineFacts is what a parked slice assumes of the engine that saved
// it. A park publishes them beside the delta, and a claiming home
// compares the class and layout with its own engine's before it claims.
// The version and the GPU are only logged, since a move to another GPU
// is the point.
type engineFacts struct {
	class, layout, version string
	gpu, cc, driver        string
}

// facts is what the engine declared at its first start. A restart must
// declare the same class and layout, so they hold while it is down. The
// class is empty until the first start has ended. The GPU name, compute
// capability and driver are from the engine's last GPU line, carried
// only to be logged and published.
func (e *engine) facts() engineFacts {
	e.mu.Lock()
	defer e.mu.Unlock()
	return engineFacts{class: e.class, layout: e.layout, version: engineVersion,
		gpu: e.gpu, cc: e.cc, driver: e.driver}
}

// annotate adds the facts to a delta's annotations. Facts without a
// class add nothing.
func (f engineFacts) annotate(m map[string]string) {
	if f.class == "" {
		return
	}
	m[artifact.AnnotationEngineClass] = f.class
	m[artifact.AnnotationEngineLayout] = f.layout
	m[artifact.AnnotationEngineVersion] = f.version
	if f.gpu != "" {
		m[artifact.AnnotationGPUName] = f.gpu
		m[artifact.AnnotationGPUCC] = f.cc
		m[artifact.AnnotationGPUDriver] = f.driver
	}
}

// engineFactsFrom reads the facts back. ok is false when the delta
// carries none, as a delta of a grant without an engine does.
func engineFactsFrom(m map[string]string) (engineFacts, bool) {
	f := engineFacts{
		class: m[artifact.AnnotationEngineClass], layout: m[artifact.AnnotationEngineLayout],
		version: m[artifact.AnnotationEngineVersion], gpu: m[artifact.AnnotationGPUName],
		cc: m[artifact.AnnotationGPUCC], driver: m[artifact.AnnotationGPUDriver],
	}
	return f, f != engineFacts{}
}

// checkEngine is the device half of the gate before a claim. A delta
// whose annotations name an engine is taken only where the grant's
// engine declares the same class and layout. A refusal wraps
// core.ErrDeviceMismatch and names both sides, and the session stays in
// the registry. An engine that is not up gives a miss the caller
// retries, since its facts are not known yet. Admission waits for the
// engine's READY, so that is only a race with the grant's yield.
func (r *Runtime) checkEngine(g core.Grant, session string, rd core.RemoteDelta, ann map[string]string) error {
	made, ok := engineFactsFrom(ann)
	if !ok {
		return nil
	}
	if !r.wantsEngine(g) {
		return engineRefusal(g, session, rd, fmt.Sprintf("no engine here, class %s layout %s in the delta", made.class, made.layout))
	}
	var here engineFacts
	if e := r.engineOf(g.UID); e != nil {
		here = e.facts()
	}
	if here.class == "" {
		return &core.RemoteMiss{
			Err:           fmt.Errorf("%w: %s/%s needs the grant's device engine, which is not up here", core.ErrNotReady, g.UID, session),
			PreferredHome: rd.Home,
		}
	}
	switch {
	case made.class != here.class:
		return engineRefusal(g, session, rd, fmt.Sprintf("engine class %s here, %s in the delta", here.class, made.class))
	case made.layout != here.layout:
		return engineRefusal(g, session, rd, fmt.Sprintf("engine layout %s here, %s in the delta", here.layout, made.layout))
	}
	log.Printf("host: %s/%s fits engine %s %s here: saved by version %s on %s cc %s driver %s, here version %s on %s cc %s driver %s",
		g.UID, session, here.class, here.layout, made.version, made.gpu, made.cc, made.driver, here.version, here.gpu, here.cc, here.driver)
	return nil
}

// engineRefusal is checkEngine's refusal, which names the home that holds
// the session.
func engineRefusal(g core.Grant, session string, rd core.RemoteDelta, why string) error {
	return &core.RemoteMiss{
		Err:           fmt.Errorf("%w: %s/%s parked on %s: %s", core.ErrDeviceMismatch, g.UID, session, rd.Home, why),
		PreferredHome: rd.Home,
	}
}
