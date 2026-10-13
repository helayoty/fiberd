//go:build !fiberd_testhooks

package fiberd

import (
	"flag"
	"net/http"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/home"
)

// testHooks is empty in a release build, with no -admin-unsafe flag and
// no test-only admin handlers. Build with -tags fiberd_testhooks for them.
type testHooks struct{}

func (*testHooks) bind(*flag.FlagSet) {}

func (*testHooks) register(*http.ServeMux, home.Home, *core.Core, func() map[string]any) {}
