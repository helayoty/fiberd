//go:build !fiberd_testhooks

package fiberd

import (
	"flag"
	"net/http"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/home"
)

// testHooks is empty in a release build, with no -admin-unsafe or
// cadence flags and no test-only admin handlers. Build with -tags
// fiberd_testhooks for them.
type testHooks struct{}

func (*testHooks) bind(*flag.FlagSet, *Timing) {}

func (*testHooks) register(*http.ServeMux, home.Home, *core.Core, func() map[string]any) {}
