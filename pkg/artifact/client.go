package artifact

import (
	"errors"
	"net/http"

	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// maxRedirects is how many redirects one registry request may follow,
// so a request is sent at most maxRedirects+1 times.
const maxRedirects = 5

// tlsClient and plainClient are built once. Tests swap them.
var (
	tlsClient   = newClient(nil, false)
	plainClient = newClient(nil, true)
)

// registryClient is the client for a registry named with https:// or no
// scheme, or with plainHTTP the one for a registry named with http://.
func registryClient(plainHTTP bool) *auth.Client {
	if plainHTTP {
		return plainClient
	}
	return tlsClient
}

// newClient is an auth client over base with the retry policy and the
// redirect policy below. It copies auth.DefaultClient for its header and
// token cache and never writes to that process-wide value. A registry
// reached over TLS stays on TLS across every redirect, and a redirect to
// another TLS host is allowed because blobs are served from storage hosts.
func newClient(base http.RoundTripper, plainHTTP bool) *auth.Client {
	c := *auth.DefaultClient
	c.Client = &http.Client{
		Transport: retry.NewTransport(base),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// via holds the requests already sent, so via[0] is where this
			// one started, the registry or its token service.
			host := via[0].URL.Host
			if len(via) > maxRedirects {
				return &redirectError{host: host, reason: "too many redirects"}
			}
			if !plainHTTP && req.URL.Scheme != "https" {
				return &redirectError{host: host, reason: "redirect leaves TLS"}
			}
			return nil
		},
	}
	return &c
}

// redirectError is a redirect the policy refused. It names only the
// registry host, never a Location, which may carry a signed query.
type redirectError struct {
	host   string
	reason string
}

func (e *redirectError) Error() string {
	return "registry " + e.host + ": " + e.reason
}

// refusal returns the *redirectError in err's chain alone, because net/http
// wraps it in a url.Error that carries the raw Location, else err as is.
func refusal(err error) error {
	var re *redirectError
	if errors.As(err, &re) {
		return re
	}
	return err
}
