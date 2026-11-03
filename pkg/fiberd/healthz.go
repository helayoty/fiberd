package fiberd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Healthz asks the admin socket for /healthz. It returns nil on a 200 and
// otherwise an error with the status and the body, as when the audit
// spool is poisoned. A liveness probe gates on it, since a 503 here
// means fiberd needs a restart.
func (c *Config) Healthz(ctx context.Context) error { return c.probe(ctx, "healthz") }

// Readyz asks the admin socket for /readyz. It answers like Healthz, and
// also returns an error while fiberd drains, when /readyz answers 503
// with "draining": true. A readiness probe gates on it, so traffic stops
// before the fibers park.
func (c *Config) Readyz(ctx context.Context) error { return c.probe(ctx, "readyz") }

// probe asks the admin socket for GET /name. The error starts with name.
func (c *Config) probe(ctx context.Context, name string) error {
	sock := c.AdminSocket()
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://admin/"+name, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return fmt.Errorf("%s: %s: %s", name, resp.Status, strings.TrimSpace(string(body)))
}
