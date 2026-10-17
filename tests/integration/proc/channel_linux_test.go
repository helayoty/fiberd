//go:build linux && integration

package proctest

import (
	"encoding/hex"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/backend"
)

// sendClone writes one CLONE line to a raw zygote with a channel riding
// along, the record for the fence, endpoint, payload and session the
// line names queued on it, as the backend does. A record the library
// would refuse (a fence too long) leaves the channel empty, for a line
// the zygote refuses before any child reads it. The host's end stays
// open until the test ends.
func sendClone(t *testing.T, uc *net.UnixConn, line string) {
	t.Helper()
	fields := strings.Fields(line)
	inc := backend.Incarnation{Generation: 1, Kind: "fork"}
	if len(fields) >= 3 {
		inc.Fence, inc.Endpoint = fields[1], fields[2]
	}
	if len(fields) >= 5 && fields[4] != "-" {
		inc.Payload, _ = hex.DecodeString(fields[4])
	}
	if len(fields) >= 6 && fields[5] != "-" {
		s, _ := hex.DecodeString(fields[5])
		inc.Session = string(s)
	}
	host, fiber, err := backend.Channel(nil, inc)
	if err != nil {
		if host, fiber, err = backend.Channel(nil, backend.Incarnation{}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = host.Close(); _ = fiber.Close() })
	if _, _, err := uc.WriteMsgUnix([]byte(line+"\n"), syscall.UnixRights(int(fiber.Fd())), nil); err != nil {
		t.Fatal(err)
	}
}
