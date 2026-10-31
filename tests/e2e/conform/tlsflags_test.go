//go:build integration

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

func TestCallerTLS(t *testing.T) {
	dir := t.TempDir()
	ca := tlsconftest.NewCA(t, "ca")
	caFile, _ := ca.Write(t, dir, "ca")
	cert, key := ca.Client(t, "caller").Write(t, dir, "caller")
	wantThumb, err := tlsconf.ThumbprintFile(cert)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name           string
		ca, cert, key  string
		serverName     string
		wantNil        bool
		wantThumb      string
		wantServerName string
		wantErr        error
		wantMsg        string // substring of the error, when there is no sentinel
	}{
		{name: "no files dials plaintext", wantNil: true},
		{name: "all files", ca: caFile, cert: cert, key: key, wantThumb: wantThumb},
		{name: "server name with files", ca: caFile, cert: cert, key: key, serverName: "fiberd.example", wantThumb: wantThumb, wantServerName: "fiberd.example"},
		{name: "server name without files", serverName: "fiberd.example", wantNil: true, wantMsg: "-tls-server-name"},
		{name: "certificate only", cert: cert, wantNil: true, wantErr: tlsconf.ErrPartialTLS},
		{name: "ca only", ca: caFile, wantNil: true, wantErr: tlsconf.ErrPartialTLS},
		{name: "server name with partial files", ca: caFile, serverName: "fiberd.example", wantNil: true, wantErr: tlsconf.ErrPartialTLS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, thumb, err := callerTLS(tc.ca, tc.cert, tc.key, tc.serverName)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantMsg != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantMsg)
				}
			case err != nil:
				t.Fatalf("callerTLS: %v", err)
			}
			if tc.wantNil {
				if cfg != nil {
					t.Fatalf("cfg = %v, want nil", cfg)
				}
			} else if cfg == nil {
				t.Fatal("cfg is nil, want a TLS config")
			} else if cfg.ServerName != tc.wantServerName {
				t.Fatalf("ServerName = %q, want %q", cfg.ServerName, tc.wantServerName)
			}
			if thumb != tc.wantThumb {
				t.Fatalf("thumbprint = %q, want %q", thumb, tc.wantThumb)
			}
		})
	}
}

func TestGrantCallerThumbprint(t *testing.T) {
	cases := []struct {
		name  string
		thumb string
		mut   func(g *core.Grant)
		want  string
	}{
		{name: "bound to the harness certificate", thumb: "harness-x5t", want: "harness-x5t"},
		{name: "empty leaves the grant unbound", want: ""},
		{name: "a case override wins", thumb: "harness-x5t", mut: func(g *core.Grant) { g.CallerThumbprint = "other-x5t" }, want: "other-x5t"},
		{name: "a case can unbind", thumb: "harness-x5t", mut: func(g *core.Grant) { g.CallerThumbprint = "" }, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var minted []core.Grant
			c := &client{d: Driver{
				NodeID:           "n",
				Template:         "sha256:t",
				CallerThumbprint: tc.thumb,
				Mint: func(g core.Grant) (string, error) {
					minted = append(minted, g)
					return "tok", nil
				},
			}}
			g, tok := c.grant(t, "g", tc.mut)
			if tok != "tok" {
				t.Fatalf("token = %q, want tok", tok)
			}
			if len(minted) != 1 {
				t.Fatalf("Mint called %d times, want once", len(minted))
			}
			if g.CallerThumbprint != tc.want || minted[0].CallerThumbprint != tc.want {
				t.Fatalf("CallerThumbprint = returned %q, minted %q, want %q", g.CallerThumbprint, minted[0].CallerThumbprint, tc.want)
			}
		})
	}
}
