package artifact

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// awaitReady reads the zygote's first line from its control channel and
// returns once it is READY. The zygote exiting first (its exit on
// waited), the timeout and ctx each end the wait with an error. An exit
// taken from waited is put back, since the caller waits on it too.
func awaitReady(ctx context.Context, ctl io.Reader, waited chan error, timeout time.Duration) error {
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(ctl).ReadString('\n')
		if err != nil {
			ready <- err
			return
		}
		if line = strings.TrimSpace(line); line != "READY" {
			ready <- fmt.Errorf("zygote said %q, not READY", line)
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			return fmt.Errorf("artifact: zygote did not become ready: %w", err)
		}
		return nil
	case err := <-waited:
		waited <- err
		if err == nil {
			return errors.New("artifact: zygote exited before READY")
		}
		return fmt.Errorf("artifact: zygote exited before READY: %w", err)
	case <-time.After(timeout):
		return errors.New("artifact: zygote did not become ready in time")
	case <-ctx.Done():
		return ctx.Err()
	}
}
