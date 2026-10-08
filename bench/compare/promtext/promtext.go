// Package promtext reads the control-plane counters that
// docs/design/compare.md charges per activation: API server writes,
// stored objects, scheduler attempts and audit events. It parses the Prometheus text format just far enough
// to sum one metric's samples under a label filter, and counts lines of
// the audit log. A Sampler takes the deltas between calls.
package promtext

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Sum adds every sample of metric whose labels pass keep. keep nil keeps
// all. Lines are "name{k="v",...} value [timestamp]".
func Sum(text, metric string, keep func(labels map[string]string) bool) float64 {
	var total float64
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' || !strings.HasPrefix(line, metric) {
			continue
		}
		rest := line[len(metric):]
		labels := map[string]string{}
		switch {
		case rest == "":
			continue
		case rest[0] == '{':
			end := strings.Index(rest, "}")
			if end < 0 {
				continue
			}
			labels = parseLabels(rest[1:end])
			rest = rest[end+1:]
		case rest[0] != ' ':
			continue // a longer metric name with this prefix
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		if keep == nil || keep(labels) {
			total += v
		}
	}
	return total
}

// parseLabels reads k="v",k2="v2". Escaped quotes inside values are
// kept as they are, which is enough for the metrics read here.
func parseLabels(s string) map[string]string {
	out := map[string]string{}
	for s != "" {
		eq := strings.Index(s, "=\"")
		if eq < 0 {
			break
		}
		k := strings.TrimSpace(s[:eq])
		s = s[eq+2:]
		end := strings.Index(s, "\"")
		if end < 0 {
			break
		}
		out[k] = s[:end]
		s = strings.TrimPrefix(strings.TrimPrefix(s[end+1:], ","), " ")
	}
	return out
}

// Writes keeps the mutating verbs.
func Writes(l map[string]string) bool {
	switch l["verb"] {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// Source is one counter to sample.
type Source struct {
	Name string
	Read func(ctx context.Context) (float64, error)
}

// Sampler takes deltas of its sources between calls. The first call
// only primes it.
type Sampler struct {
	Sources []Source
	last    map[string]float64
}

// Delta is each source's change since the previous call.
func (s *Sampler) Delta(ctx context.Context) (map[string]float64, error) {
	out := map[string]float64{}
	now := map[string]float64{}
	for _, src := range s.Sources {
		v, err := src.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		now[src.Name] = v
		if s.last != nil {
			out[src.Name] = v - s.last[src.Name]
		}
	}
	s.last = now
	return out, nil
}

// Fetch is an HTTP GET of a metrics page. Insecure TLS, because the
// scheduler's serving certificate is kind's own.
func Fetch(client *http.Client, url, token string) func(ctx context.Context) (string, error) {
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // kind's self-signed scheduler endpoint
		client = &http.Client{Transport: tr}
	}
	return func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("%s: %s", url, resp.Status)
		}
		return string(b), nil
	}
}

// Metric is a Source summing one metric of a fetched page.
func Metric(name string, fetch func(ctx context.Context) (string, error), metric string, keep func(map[string]string) bool) Source {
	return Source{Name: name, Read: func(ctx context.Context) (float64, error) {
		text, err := fetch(ctx)
		if err != nil {
			return 0, err
		}
		return Sum(text, metric, keep), nil
	}}
}

// AuditLines is a Source counting lines of an audit log, one event each.
func AuditLines(name, path string) Source {
	return Source{Name: name, Read: func(context.Context) (float64, error) {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer func() { _ = f.Close() }()
		var n float64
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			n++
		}
		return n, sc.Err()
	}}
}
