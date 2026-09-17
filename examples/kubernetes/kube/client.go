// Package kube is the slice of the Kubernetes API fiberd touches, as plain
// HTTPS requests with the projected service-account token: get, list,
// create, patch and delete on a handful of resources. The agent is PID 1
// of every grant Pod and the issuer controller is one small Deployment;
// neither carries client-go for a dozen calls.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	saDir            = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultTokenFile = saDir + "/token"
	defaultCAFile    = saDir + "/ca.crt"
	// NamespaceFile is where the projected service account tells a Pod
	// which namespace it runs in.
	NamespaceFile = saDir + "/namespace"
	// TokenFile is the projected service-account token.
	TokenFile = defaultTokenFile
)

// Client talks to one API server.
type Client struct {
	// Base is the API server URL (https://host:port).
	Base string
	// TokenFile is the projected service-account token, re-read on every
	// request because bound tokens rotate. Empty means no bearer token.
	TokenFile string
	// HTTP is the client; nil means http.DefaultClient with a timeout.
	HTTP *http.Client
}

// InCluster reads the API server address and credentials a Pod is given.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kube: not in a cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	ca, err := os.ReadFile(defaultCAFile)
	if err != nil {
		return nil, fmt.Errorf("kube: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kube: no certificate in " + defaultCAFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &Client{
		Base:      "https://" + net.JoinHostPort(host, port),
		TokenFile: defaultTokenFile,
		HTTP:      &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}, nil
}

// Namespace is the Pod's own namespace from the projected file.
func Namespace() (string, error) {
	b, err := os.ReadFile(NamespaceFile)
	if err != nil {
		return "", fmt.Errorf("kube: namespace: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// StatusError is a non-2xx answer from the API server.
type StatusError struct {
	Code   int
	Reason string
	Body   string
}

func (e *StatusError) Error() string { return fmt.Sprintf("kube: %d %s", e.Code, e.Body) }

// IsNotFound reports a 404.
func IsNotFound(err error) bool { return code(err) == http.StatusNotFound }

// IsConflict reports a 409 (already exists, or a stale resource version).
func IsConflict(err error) bool { return code(err) == http.StatusConflict }

func code(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.TokenFile != "" {
		tok, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return fmt.Errorf("kube: token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		se := &StatusError{Code: resp.StatusCode, Body: string(out)}
		var st struct {
			Message string `json:"message"`
			Reason  string `json:"reason"`
		}
		if json.Unmarshal(out, &st) == nil && st.Message != "" {
			se.Body, se.Reason = st.Message, st.Reason
		}
		return se
	}
	if dst != nil && len(out) > 0 {
		return json.Unmarshal(out, dst)
	}
	return nil
}

// Get fetches one object (or a collection) as JSON into dst.
func (c *Client) Get(ctx context.Context, path string, dst any) error {
	return c.do(ctx, http.MethodGet, path, "", nil, dst)
}

// Create posts obj to a collection path; the created object lands in dst
// when non-nil.
func (c *Client) Create(ctx context.Context, path string, obj, dst any) error {
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, "application/json", body, dst)
}

// Delete removes one object.
func (c *Client) Delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, "", nil, nil)
}

// PatchStrategic applies a strategic merge patch (what keeps Pod
// conditions keyed by type instead of replacing the list). Core types
// only.
func (c *Client) PatchStrategic(ctx context.Context, path string, patch any) error {
	return c.patch(ctx, path, "application/strategic-merge-patch+json", patch)
}

// PatchMerge applies an RFC 7386 merge patch (custom resources, status
// subresources, Secrets).
func (c *Client) PatchMerge(ctx context.Context, path string, patch any) error {
	return c.patch(ctx, path, "application/merge-patch+json", patch)
}

func (c *Client) patch(ctx context.Context, path, contentType string, patch any) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPatch, path, contentType, body, nil)
}

// ObjectMeta is the metadata every object carries, cut to what fiberd
// reads and writes.
type ObjectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	DeletionTimestamp string            `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
}

// OwnerReference makes the garbage collector delete dependents with
// their owner.
type OwnerReference struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	Controller         bool   `json:"controller,omitempty"`
	BlockOwnerDeletion bool   `json:"blockOwnerDeletion,omitempty"`
}

// Condition is the shape Pod and custom resources share for conditions.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}
