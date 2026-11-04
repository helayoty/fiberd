package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/utils/clock"

	"github.com/Azure/fiberd/pkg/grant"
)

const (
	// grantPath is where the controller serves grants under the issuer.
	grantPath = "/v1/grant"
	// fetchRequestTimeout bounds one request, its answer included.
	fetchRequestTimeout = 10 * time.Second
	// maxAnswerBytes bounds the answer body read.
	maxAnswerBytes = 1 << 20
	// maxReasonBytes bounds the controller's error reason as logged.
	maxReasonBytes = 200

	// minFetchWait is the shortest wait between two requests.
	minFetchWait = time.Second
	// maxBackoff is the longest backoff after a failure.
	maxBackoff = 30 * time.Second
	// refusedRetry is the wait after the controller refused the Pod's
	// token.
	refusedRetry = 30 * time.Second
	// unprocessableRetry is the wait after the controller said the grant
	// cannot be issued as specified.
	unprocessableRetry = 5 * time.Minute
	// maxRetryAfter caps Retry-After while no grant is held.
	maxRetryAfter = 5 * time.Minute
	// jitterFraction is how far a backoff may move either way.
	jitterFraction = 0.25
)

// grantRequest is the body of a request. Previous is the grant fiberd
// holds, sent on a renewal and on a restart.
type grantRequest struct {
	Previous string `json:"previous,omitempty"`
}

// grantAnswer is the part of a 200's body the home checks. The audience
// it also carries is the verifier's to check.
type grantAnswer struct {
	Token     string    `json:"token"`
	UID       string    `json:"uid"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// fetcher fetches and renews the Pod's grant from the controller with
// the Pod's bound service-account token, and writes it into the grants
// directory. New drives the first fetch and run the rest, one after the
// other, so the loop state needs no lock.
type fetcher struct {
	endpoint  string
	tokenFile string
	dir       string
	podUID    string
	client    *http.Client
	clock     clock.WithTicker
	log       logr.Logger
	// jitter draws a value in [0, 1). Tests fix it.
	jitter func() float64
	// syncDir flushes the grants directory after a rename. Tests make it
	// fail.
	syncDir func(dir string) error

	// previous is the grant fiberd last wrote, or the one found in the
	// directory at the start. It is sent with the next request.
	previous string
	// expiresAt is when the held grant's lease ends. Zero holds none.
	expiresAt time.Time
	// failures counts the failed requests since the last grant.
	failures int
	// nextAt is when the next request is due.
	nextAt time.Time
	// stopped is set once the controller answered 409. No request
	// follows.
	stopped bool
	// last describes the last failure. It never holds a token.
	last string
}

// newFetcher builds the fetcher of cfg and reads the grant the directory
// already holds for the Pod, if any.
func newFetcher(cfg Config, log logr.Logger) (*fetcher, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.GrantCAFile != "" {
		pem, err := os.ReadFile(cfg.GrantCAFile)
		if err != nil {
			return nil, fmt.Errorf("read the grant CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the grant CA file %s holds no PEM certificate", cfg.GrantCAFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	f := &fetcher{
		endpoint:  strings.TrimSuffix(cfg.GrantIssuerURL, "/") + grantPath,
		tokenFile: cfg.GrantTokenFile,
		dir:       cfg.GrantsDir,
		podUID:    cfg.PodUID,
		// The client follows no redirect, so the Pod's token is never
		// sent on to a host the issuer URL does not name.
		client: &http.Client{
			Transport:     transport,
			Timeout:       fetchRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		clock:   cfg.Clock,
		log:     log,
		jitter:  rand.Float64,
		syncDir: fsyncDir,
	}
	if tok, exp, ok := f.held(); ok {
		f.previous, f.expiresAt = tok, exp
	}
	return f, nil
}

// path is the Pod's grant file.
func (f *fetcher) path() string { return filepath.Join(f.dir, f.podUID+".jwt") }

// held reads the Pod's grant file. ok is false when there is none, or
// it holds a token for another UID. exp is zero when the token has none.
func (f *fetcher) held() (token string, exp time.Time, ok bool) {
	b, err := os.ReadFile(f.path())
	if err != nil {
		return "", time.Time{}, false
	}
	token = strings.TrimSpace(string(b))
	if uid, err := grant.PeekUID(token); err != nil || uid != f.podUID {
		return "", time.Time{}, false
	}
	exp, _ = grant.PeekExpiry(token)
	return token, exp, true
}

// start runs the first fetch, retrying until a grant is written, the
// controller stops the renewal, or timeout passes on the clock. A 409 or
// a timeout with an unexpired grant file in the directory is a start on
// that file. After a timeout run keeps retrying. After a 409 it does not.
func (f *fetcher) start(ctx context.Context, timeout time.Duration) error {
	deadline := f.clock.Now().Add(timeout)
	for !f.fetchOnce(ctx) {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("kubernetes home: first grant fetch: %w", err)
		}
		now := f.clock.Now()
		if f.stopped {
			if tok, exp, ok := f.held(); ok && exp.After(now) {
				f.previous, f.expiresAt = tok, exp
				f.log.Info("Started on the grant file already in the directory, renewal is stopped",
					"uid", f.podUID, "expiresAt", exp)
				return nil
			}
			return fmt.Errorf("kubernetes home: the controller refused the Pod's first grant, %s", f.last)
		}
		if !now.Before(deadline) {
			// Another writer may have replaced the file during the
			// retries, so run sends what the file holds now.
			if tok, exp, ok := f.held(); ok && exp.After(now) {
				f.previous, f.expiresAt = tok, exp
				f.log.Info("Started on the unexpired grant file, the controller did not answer in time",
					"uid", f.podUID, "expiresAt", exp, "timeout", timeout)
				return nil
			}
			return fmt.Errorf("kubernetes home: no grant from %s within %s, the last failure was %s", f.endpoint, timeout, f.last)
		}
		if !f.wait(ctx, min(f.nextAt.Sub(now), deadline.Sub(now))) {
			return fmt.Errorf("kubernetes home: first grant fetch: %w", ctx.Err())
		}
	}
	return nil
}

// run renews the grant until ctx ends, from the state start left. Once
// the controller stops the renewal, it only waits for ctx.
func (f *fetcher) run(ctx context.Context) {
	for !f.stopped {
		if !f.wait(ctx, f.nextAt.Sub(f.clock.Now())) {
			return
		}
		f.fetchOnce(ctx)
	}
	<-ctx.Done()
}

// wait waits d on the clock, and at least minFetchWait. It reports
// false when ctx ended first.
func (f *fetcher) wait(ctx context.Context, d time.Duration) bool {
	t := f.clock.NewTimer(max(d, minFetchWait))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C():
		return true
	}
}

// fetchOnce sends one request, logs what it ended in and sets when the
// next one is due. It reports whether a grant was written.
func (f *fetcher) fetchOnce(ctx context.Context) bool {
	a := f.request(ctx)
	now := f.clock.Now()
	if a.err == nil {
		f.failures = 0
		f.nextAt = now.Add(nextDelay(delayInput{wrote: true, remaining: f.expiresAt.Sub(now)}))
		f.log.Info("Wrote the Pod's grant", "uid", f.podUID, "expiresAt", f.expiresAt, "renewAt", f.nextAt)
		return true
	}
	f.failures++
	f.last = a.err.Error()
	if a.status == http.StatusConflict {
		f.stopped = true
		f.log.Info("The controller stopped the grant's renewal", "uid", f.podUID, "status", a.status, "reason", a.reason)
		return false
	}
	d := nextDelay(delayInput{
		status: a.status, retryAfter: a.retryAfter, hasRetryAfter: a.hasRetryAfter,
		failures: f.failures, remaining: f.expiresAt.Sub(now), jitter: f.jitter(),
	})
	f.nextAt = now.Add(d)
	if ctx.Err() != nil {
		// Close or the end of Run cancelled the request. That is no
		// failure to report.
		return false
	}
	switch a.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		f.log.Error(a.err, "The controller refused the Pod's token, the next request reads the token file again", "uid", f.podUID, "retryIn", d)
	default:
		f.log.Error(a.err, "Grant fetch failed", "uid", f.podUID, "retryIn", d)
	}
	return false
}

// attempt is what one request ended in. err never holds a token.
type attempt struct {
	status        int // the answer's status, zero when none came
	reason        string
	retryAfter    time.Duration
	hasRetryAfter bool
	err           error
}

// request sends one request and, on a 200, checks and writes the grant.
func (f *fetcher) request(ctx context.Context) attempt {
	bearer, err := f.bearer()
	if err != nil {
		return attempt{err: err}
	}
	body, err := json.Marshal(grantRequest{Previous: f.previous})
	if err != nil {
		return attempt{err: fmt.Errorf("encode the request: %w", err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return attempt{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return attempt{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return attempt{status: resp.StatusCode, err: fmt.Errorf("read the controller's %d answer: %w", resp.StatusCode, err)}
	}
	if resp.StatusCode != http.StatusOK {
		a := attempt{status: resp.StatusCode, reason: errorReason(raw)}
		a.retryAfter, a.hasRetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), f.clock.Now())
		a.err = fmt.Errorf("the controller answered %d", resp.StatusCode)
		if a.reason != "" {
			a.err = fmt.Errorf("the controller answered %d, %s", resp.StatusCode, a.reason)
		}
		return a
	}
	return attempt{status: resp.StatusCode, err: f.accept(raw)}
}

// bearer reads the Pod's token. The kubelet rotates the file, so it is
// read on every request.
func (f *fetcher) bearer() (string, error) {
	b, err := os.ReadFile(f.tokenFile)
	if err != nil {
		return "", fmt.Errorf("read the Pod's token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("the Pod's token file %s is empty", f.tokenFile)
	}
	return tok, nil
}

// accept checks a 200's grant and writes it. Once the file is renamed
// into place the grant is held. A failed directory sync after the rename
// is logged and is no failure, so the grant is not fetched again.
func (f *fetcher) accept(raw []byte) error {
	var g grantAnswer
	if err := json.Unmarshal(raw, &g); err != nil {
		return fmt.Errorf("decode the controller's grant: %w", err)
	}
	if g.UID != f.podUID {
		return fmt.Errorf("the controller answered for uid %q, this Pod is %q", g.UID, f.podUID)
	}
	if len(g.Token) > grant.MaxTokenBytes {
		return fmt.Errorf("the grant is %d bytes, over the %d a token may take", len(g.Token), grant.MaxTokenBytes)
	}
	jti, err := grant.PeekUID(g.Token)
	if err != nil {
		return fmt.Errorf("the grant does not parse: %w", err)
	}
	if jti != g.UID {
		return fmt.Errorf("the grant's jti %q is not its uid %q", jti, g.UID)
	}
	if !g.ExpiresAt.After(g.IssuedAt) {
		return fmt.Errorf("the grant's lease ends at %s, not after it starts at %s",
			g.ExpiresAt.Format(time.RFC3339), g.IssuedAt.Format(time.RFC3339))
	}
	renamed, err := writeGrant(f.dir, g.UID, g.Token, f.syncDir)
	if renamed {
		f.previous, f.expiresAt = g.Token, g.ExpiresAt
		if err != nil {
			f.log.Info("The grant is written, the grants directory sync failed", "uid", g.UID, "err", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("write the grant: %w", err)
	}
	return nil
}

// writeGrant replaces <dir>/<uid>.jwt with token in one rename, so a
// reader sees the old token or the new one and never a part. The
// temporary name does not end in .jwt, so the directory's poll never
// reads it. os.CreateTemp makes the file 0600 already. A failure before
// the rename removes only the temporary file. syncDir flushes dir after
// the rename. renamed reports whether the grant file now holds token.
func writeGrant(dir, uid, token string, syncDir func(dir string) error) (renamed bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".grant-*.tmp")
	if err != nil {
		return false, err
	}
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.WriteString(token); err != nil {
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, uid+".jwt")); err != nil {
		return false, err
	}
	return true, syncDir(dir)
}

// fsyncDir flushes dir, so a rename in it survives a crash.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// errorReason is the error reason of a failure's body, cut to
// maxReasonBytes. A body that is not one yields nothing, and the body
// itself is never logged.
func errorReason(raw []byte) string {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	reason := body.Error
	if len(reason) > maxReasonBytes {
		reason = reason[:maxReasonBytes]
	}
	return strings.ToValidUTF8(reason, "")
}

// parseRetryAfter reads a Retry-After header, delay seconds or an HTTP
// date, as a wait from now. ok is false when there is none or it does
// not parse.
func parseRetryAfter(v string, now time.Time) (d time.Duration, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if s, err := strconv.ParseInt(v, 10, 64); err == nil {
		if s < 0 {
			return 0, false
		}
		// A day is past every cap, and keeps the product in range.
		return time.Duration(min(s, int64(24*time.Hour/time.Second))) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(now), true
	}
	return 0, false
}

// delayInput is what the wait before the next request depends on.
type delayInput struct {
	// wrote is set when the request wrote a grant.
	wrote bool
	// status is a failed request's status, zero when no answer came.
	status int
	// retryAfter is the answer's Retry-After, when hasRetryAfter.
	retryAfter    time.Duration
	hasRetryAfter bool
	// failures counts the failed requests in a row, this one included.
	failures int
	// remaining is the held grant's lease left. Zero or less holds none.
	remaining time.Duration
	// jitter is a draw in [0, 1).
	jitter float64
}

// nextDelay is the wait before the next request. A written grant renews
// at half its lease. A refused token waits refusedRetry, and a grant
// that cannot be issued unprocessableRetry. A 429 or 503 waits its
// Retry-After, cut to a quarter of the held lease, or to maxRetryAfter
// with none held. Everything else backs off from minFetchWait, doubling
// per failure, cut to maxBackoff and to a quarter of the held lease,
// then moved by up to jitterFraction either way. No wait is shorter than
// minFetchWait.
func nextDelay(in delayInput) time.Duration {
	var d time.Duration
	switch {
	case in.wrote:
		d = in.remaining / 2
	case in.status == http.StatusUnauthorized || in.status == http.StatusForbidden:
		d = refusedRetry
	case in.status == http.StatusUnprocessableEntity:
		d = unprocessableRetry
	case (in.status == http.StatusTooManyRequests || in.status == http.StatusServiceUnavailable) && in.hasRetryAfter:
		limit := maxRetryAfter
		if in.remaining > 0 {
			limit = in.remaining / 4
		}
		d = min(in.retryAfter, limit)
	default:
		limit := maxBackoff
		if in.remaining > 0 {
			limit = min(maxBackoff, in.remaining/4)
		}
		d = minFetchWait
		for i := 1; i < in.failures && d < limit; i++ {
			d *= 2
		}
		d = min(d, limit)
		d = time.Duration(float64(d) * (1 + jitterFraction*(2*in.jitter-1)))
	}
	return max(d, minFetchWait)
}
