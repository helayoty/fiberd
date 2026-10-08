package agent

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
// spool is poisoned. A binary that embeds the agent gates its own
// readiness on it.
func (c *Config) Healthz(ctx context.Context) error {
	sock := c.AdminSocket()
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://admin/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("healthz: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return fmt.Errorf("healthz: %s: %s", resp.Status, strings.TrimSpace(string(body)))
}
