package grant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Cache holds an issuer's public keys, found through OIDC discovery:
// <issuer>/.well-known/openid-configuration names the jwks_uri, which
// serves the key set. Keys are looked up by kid. An unknown kid triggers
// one refresh, rate-limited, so a flood of bad tokens cannot hammer the
// issuer. Every successful refresh is timestamped; the Verifier turns a
// timestamp older than the lease TTL into a hard failure.
type Cache struct {
	IssuerURL string
	HTTP      *http.Client
	// MinRefresh rate-limits refreshes triggered by unknown kids or
	// staleness (default one minute). Explicit Refresh calls ignore it.
	MinRefresh time.Duration
	// OnRefresh, when set, is called after every successful refresh. The
	// standalone home uses it as its control-plane liveness signal.
	OnRefresh func(at time.Time)
	Now       func() time.Time

	mu          sync.Mutex
	keys        map[string]jose.JSONWebKey
	jwksURI     string
	lastRefresh time.Time
	lastAttempt time.Time
}

var (
	ErrUnknownKey  = errors.New("grant: no key for kid")
	ErrNeverLoaded = errors.New("grant: key set never loaded")
)

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cache) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (c *Cache) minRefresh() time.Duration {
	if c.MinRefresh > 0 {
		return c.MinRefresh
	}
	return time.Minute
}

// LastRefresh is when the key set was last fetched successfully; zero if
// never.
func (c *Cache) LastRefresh() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRefresh
}

// Key returns the public key for kid. A miss triggers a rate-limited
// refresh; a miss after that is ErrUnknownKey. If the set was never
// loaded and cannot be loaded now, the fetch error is returned wrapped
// in ErrNeverLoaded so callers can tell "offline" from "bad kid".
func (c *Cache) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	c.mu.Lock()
	k, ok := c.keys[kid]
	loaded := !c.lastRefresh.IsZero()
	c.mu.Unlock()
	if ok {
		return &k, nil
	}
	if err := c.refreshRateLimited(ctx); err != nil && !loaded {
		return nil, fmt.Errorf("%w: %w", ErrNeverLoaded, err)
	}
	c.mu.Lock()
	k, ok = c.keys[kid]
	c.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownKey, kid)
	}
	return &k, nil
}

// RefreshIfDue refreshes unless a refresh was attempted within MinRefresh.
// It reports whether an attempt was made.
func (c *Cache) RefreshIfDue(ctx context.Context) (bool, error) {
	c.mu.Lock()
	if c.now().Sub(c.lastAttempt) < c.minRefresh() {
		c.mu.Unlock()
		return false, nil
	}
	c.mu.Unlock()
	return true, c.Refresh(ctx)
}

func (c *Cache) refreshRateLimited(ctx context.Context) error {
	_, err := c.RefreshIfDue(ctx)
	return err
}

// Refresh performs discovery (once; the jwks_uri is remembered) and
// reloads the key set.
func (c *Cache) Refresh(ctx context.Context) error {
	c.mu.Lock()
	c.lastAttempt = c.now()
	uri := c.jwksURI
	c.mu.Unlock()

	if uri == "" {
		var err error
		uri, err = c.discover(ctx)
		if err != nil {
			return err
		}
	}
	var set jose.JSONWebKeySet
	if err := c.getJSON(ctx, uri, &set); err != nil {
		return fmt.Errorf("grant: fetch jwks %s: %w", uri, err)
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.KeyID == "" || !k.IsPublic() || !k.Valid() {
			continue
		}
		keys[k.KeyID] = k
	}
	if len(keys) == 0 {
		return fmt.Errorf("grant: jwks at %s holds no usable public keys", uri)
	}
	at := c.now()
	c.mu.Lock()
	c.keys = keys
	c.jwksURI = uri
	c.lastRefresh = at
	hook := c.OnRefresh
	c.mu.Unlock()
	if hook != nil {
		hook(at)
	}
	return nil
}

type discovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func (c *Cache) discover(ctx context.Context) (string, error) {
	if c.IssuerURL == "" {
		return "", errors.New("grant: cache has no issuer URL")
	}
	url := strings.TrimSuffix(c.IssuerURL, "/") + "/.well-known/openid-configuration"
	var d discovery
	if err := c.getJSON(ctx, url, &d); err != nil {
		return "", fmt.Errorf("grant: discovery %s: %w", url, err)
	}
	// OIDC discovery: the document's issuer must be the URL we asked.
	if strings.TrimSuffix(d.Issuer, "/") != strings.TrimSuffix(c.IssuerURL, "/") {
		return "", fmt.Errorf("grant: discovery issuer %q does not match %q", d.Issuer, c.IssuerURL)
	}
	if d.JWKSURI == "" {
		return "", errors.New("grant: discovery document has no jwks_uri")
	}
	return d.JWKSURI, nil
}

func (c *Cache) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

// Run refreshes every interval until ctx ends, keeping the cache warm and
// driving OnRefresh. Failures are logged by the caller through the hook's
// absence; Run itself never stops on error.
func (c *Cache) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	_ = c.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Refresh(ctx)
		}
	}
}
