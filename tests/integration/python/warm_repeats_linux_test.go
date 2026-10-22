//go:build linux && integration

package pythontest

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

// TestWarmRepeats warms the Python reference template over and over and
// clones each warm instance once. It reproduces a warm whose image was
// taken before the template registered for the checkpoint, which shows
// as the footprint probe timing out and then every clone of the instance
// failing with "sent no token". The race needs a loaded host, as CI is
// when its suites overlap, so FIBERD_PYTHON_WARM_PARALLEL workers (4
// when unset) each warm FIBERD_PYTHON_WARM_REPEATS times. Off unless
// the count is set, since it is slow.
//
// On the VM, as root in the dev container:
//
//	FIBERD_PYTHON_WARM_REPEATS=25 FIBERD_PYTHON_WARM_PARALLEL=6 \
//	  go test -tags integration -run 'TestWarmRepeats/gvisor' -v -timeout 60m ./tests/integration/python/
func TestWarmRepeats(t *testing.T) {
	repeats, _ := strconv.Atoi(os.Getenv("FIBERD_PYTHON_WARM_REPEATS"))
	if repeats <= 0 {
		t.Skip("set FIBERD_PYTHON_WARM_REPEATS to the warms per worker")
	}
	workers, _ := strconv.Atoi(os.Getenv("FIBERD_PYTHON_WARM_PARALLEL"))
	if workers <= 0 {
		workers = 4
	}
	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			for w := 0; w < workers; w++ {
				t.Run(fmt.Sprintf("worker %d", w), func(t *testing.T) {
					t.Parallel()
					for i := 0; i < repeats; i++ {
						// A subtest per warm, so its runtime and fiber are
						// released before the next.
						t.Run(fmt.Sprintf("warm %d", i), func(t *testing.T) {
							rt := be.open(t, be.template)
							g := prepare(t, rt, "grep")
							h := clone(t, rt, g, 1, "", nil)
							if got := talk(t, h.Endpoint, "ping"); got != "pong" {
								t.Fatalf("ping = %q, want pong", got)
							}
						})
					}
				})
			}
		})
	}
}
