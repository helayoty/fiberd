package tlsconf

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

const keptMsg = "tlsconf: keeping the previous server certificate and client CA"

// clock is a fake time source the reloader checks the files against.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// fixture is a reloader over a CA and a leaf on disk, with a fake clock
// and the standard logger captured. The log writer is global, so these
// tests must stay serial and never call t.Parallel.
type fixture struct {
	t                         *testing.T
	clk                       *clock
	ca, leaf                  tlsconftest.Pair
	certFile, keyFile, caFile string
	r                         *reloader
	logs                      *bytes.Buffer
	mtime                     time.Time // the last mtime handed out by bump
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, clk: &clock{t: time.Unix(1_800_000_000, 0)}, logs: &bytes.Buffer{}}
	f.ca = tlsconftest.NewCA(t, "ca")
	f.leaf = f.ca.Server(t)
	f.caFile, _ = f.ca.Write(t, dir, "ca")
	f.certFile, f.keyFile = f.leaf.Write(t, dir, "srv")
	// Deterministic stamps from the start, whatever the filesystem's
	// mtime granularity.
	f.mtime = time.Now().Add(time.Hour).Truncate(time.Second)
	f.bump(f.certFile, f.keyFile, f.caFile)
	prev := log.Writer()
	log.SetOutput(f.logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	r, err := newReloader(f.certFile, f.keyFile, f.caFile, f.clk.now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	return f
}

// bump gives each path a distinct, strictly later mtime.
func (f *fixture) bump(paths ...string) {
	f.t.Helper()
	f.mtime = f.mtime.Add(time.Second)
	f.setTime(f.mtime, paths...)
}

func (f *fixture) setTime(at time.Time, paths ...string) {
	f.t.Helper()
	for _, p := range paths {
		if err := os.Chtimes(p, at, at); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) write(path string, content []byte) {
	f.t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// renewLeaf rewrites the certificate and key files with p.
func (f *fixture) renewLeaf(p tlsconftest.Pair) {
	f.t.Helper()
	p.Write(f.t, filepath.Dir(f.certFile), strings.TrimSuffix(filepath.Base(f.certFile), ".crt"))
	f.bump(f.certFile, f.keyFile)
}

// renewCA rewrites the client CA file with p.
func (f *fixture) renewCA(p tlsconftest.Pair) {
	f.t.Helper()
	f.write(f.caFile, p.CertPEM())
	f.bump(f.caFile)
}

func (f *fixture) advance(d time.Duration) { f.clk.t = f.clk.t.Add(d) }

// snap is the snapshot a handshake would get now.
func (f *fixture) snap() *tls.Config {
	f.t.Helper()
	cfg, err := f.r.getConfigForClient(nil)
	if err != nil || cfg == nil {
		f.t.Fatalf("GetConfigForClient = %v, %v", cfg, err)
	}
	return cfg
}

// serial is the serial number of the certificate a handshake serves now.
func (f *fixture) serial() int64 {
	f.t.Helper()
	cert, err := f.r.getCertificate(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		f.t.Fatal(err)
	}
	return leaf.SerialNumber.Int64()
}

func (f *fixture) logged() int { return strings.Count(f.logs.String(), keptMsg) }

func (f *fixture) wantSame(before *tls.Config) {
	f.t.Helper()
	if got := f.snap(); got != before {
		f.t.Fatal("snapshot was replaced, want the previous one kept")
	}
}

func (f *fixture) wantNew(before *tls.Config) *tls.Config {
	f.t.Helper()
	got := f.snap()
	if got == before {
		f.t.Fatal("snapshot was kept, want a new one")
	}
	return got
}

func (f *fixture) wantSerial(want int64) {
	f.t.Helper()
	if got := f.serial(); got != want {
		f.t.Fatalf("served serial %d, want %d", got, want)
	}
}

func (f *fixture) wantPool(want tlsconftest.Pair) {
	f.t.Helper()
	if !f.snap().ClientCAs.Equal(want.Pool()) {
		f.t.Fatalf("client CA pool is not %s's", want.Cert.Subject.CommonName)
	}
}

func (f *fixture) wantLogged(want int) {
	f.t.Helper()
	if got := f.logged(); got != want {
		f.t.Fatalf("logged %q %d times, want %d\n%s", keptMsg, got, want, f.logs.String())
	}
}

func TestReloaderFollowsFileChanges(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, f *fixture)
	}{
		{name: "unchanged files are not reloaded", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			for range 3 {
				f.advance(time.Second)
				f.wantSame(before)
			}
			f.wantLogged(0)
		}},
		{name: "a renewed pair is picked up after the interval", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			renewed := f.ca.Server(t)
			f.renewLeaf(renewed)
			f.advance(time.Second)
			f.wantNew(before)
			f.wantSerial(renewed.Cert.SerialNumber.Int64())
			f.wantPool(f.ca)
			f.wantLogged(0)
		}},
		{name: "a renewed ca is picked up after the interval", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			newCA := tlsconftest.NewCA(t, "ca2")
			f.renewCA(newCA)
			f.advance(time.Second)
			f.wantNew(before)
			f.wantPool(newCA)
			f.wantSerial(f.leaf.Cert.SerialNumber.Int64())
			f.wantLogged(0)
		}},
		{name: "a change before the interval elapses waits for the clock", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			renewed := f.ca.Server(t)
			f.renewLeaf(renewed)
			f.advance(time.Second - time.Millisecond)
			f.wantSame(before)
			f.wantSerial(f.leaf.Cert.SerialNumber.Int64())
			f.advance(time.Millisecond)
			f.wantNew(before)
			f.wantSerial(renewed.Cert.SerialNumber.Int64())
		}},
		{name: "a truncated certificate keeps the previous snapshot", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			pem := f.leaf.CertPEM()
			f.write(f.certFile, pem[:len(pem)/2])
			f.bump(f.certFile)
			f.advance(time.Second)
			f.wantSame(before)
			f.wantSerial(f.leaf.Cert.SerialNumber.Int64())
			f.wantLogged(1)
			// Retried at every check while broken, logged once.
			f.advance(time.Second)
			f.wantSame(before)
			f.wantLogged(1)
		}},
		{name: "a failed load is retried until the file is repaired in place", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			_, otherKey := f.ca.Server(t).Write(t, t.TempDir(), "other")
			bad, err := os.ReadFile(otherKey)
			if err != nil {
				t.Fatal(err)
			}
			good, err := os.ReadFile(f.keyFile)
			if err != nil {
				t.Fatal(err)
			}
			if len(bad) != len(good) {
				t.Fatalf("P-256 keys differ in PEM size (%d vs %d), the equal-stamp check needs them alike", len(bad), len(good))
			}
			f.write(f.keyFile, bad)
			f.bump(f.keyFile)
			f.advance(time.Second)
			f.wantSame(before)
			f.wantLogged(1)
			broken := f.r.stat()
			// The right key back with the very same stamp is still picked
			// up, because a failed load is retried at every check.
			f.write(f.keyFile, good)
			f.setTime(f.mtime, f.keyFile)
			if repaired := f.r.stat(); !repaired.equal(broken) {
				t.Fatal("the repair changed the stamps, so this case would not prove a retry")
			}
			f.advance(time.Second)
			f.wantNew(before)
			f.wantSerial(f.leaf.Cert.SerialNumber.Int64())
			f.wantLogged(1)
		}},
		{name: "a different failure is logged again, the same one is not", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			if err := os.Remove(f.caFile); err != nil {
				t.Fatal(err)
			}
			f.advance(time.Second)
			f.wantSame(before)
			f.wantLogged(1)
			f.advance(time.Second)
			f.wantLogged(1)
			// The pair is loaded before the pool, so a broken key is a
			// new error text.
			_, otherKey := f.ca.Server(t).Write(t, t.TempDir(), "other")
			bad, err := os.ReadFile(otherKey)
			if err != nil {
				t.Fatal(err)
			}
			f.write(f.keyFile, bad)
			f.bump(f.keyFile)
			f.advance(time.Second)
			f.wantSame(before)
			f.wantLogged(2)
			f.advance(time.Second)
			f.wantLogged(2)
		}},
		{name: "a file swapped for another with the same size and mtime is a change", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			was := f.r.stat()
			other := f.caFile + ".new"
			f.write(other, f.ca.CertPEM())
			f.setTime(was[2].info.ModTime(), other)
			if err := os.Rename(other, f.caFile); err != nil {
				t.Fatal(err)
			}
			now := f.r.stat()
			if now[2].info.Size() != was[2].info.Size() || !now[2].info.ModTime().Equal(was[2].info.ModTime()) {
				t.Fatal("the swapped file differs in size or mtime, so this case would not prove the identity check")
			}
			if os.SameFile(now[2].info, was[2].info) {
				t.Fatal("rename kept the same file, so this case would not prove the identity check")
			}
			f.advance(time.Second)
			f.wantNew(before)
			f.wantPool(f.ca)
			f.wantLogged(0)
		}},
		{name: "a missing ca file after a successful load keeps the previous snapshot", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			if err := os.Remove(f.caFile); err != nil {
				t.Fatal(err)
			}
			f.advance(time.Second)
			f.wantSame(before)
			f.wantPool(f.ca)
			f.wantLogged(1)
			// Still missing is retried and still logged once.
			f.advance(time.Second)
			f.wantSame(before)
			f.wantLogged(1)
			// Written again, it is loaded.
			newCA := tlsconftest.NewCA(t, "ca2")
			f.renewCA(newCA)
			f.advance(time.Second)
			f.wantNew(before)
			f.wantPool(newCA)
			f.wantLogged(1)
		}},
		{name: "a missing key file keeps the previous snapshot", run: func(t *testing.T, f *fixture) {
			before := f.snap()
			if err := os.Remove(f.keyFile); err != nil {
				t.Fatal(err)
			}
			f.advance(time.Second)
			f.wantSame(before)
			f.wantSerial(f.leaf.Cert.SerialNumber.Int64())
			f.wantLogged(1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newFixture(t))
		})
	}
}

// The snapshot a handshake gets has the certificate and pool inline and
// no hooks, and the base config fiberd serves from has only the hooks.
func TestReloaderSnapshotShape(t *testing.T) {
	f := newFixture(t)
	// Taken here, not in a subtest, so a fixture failure reports on the
	// test that owns it.
	first, second := f.snap(), f.snap()
	cases := []struct {
		name string
		cfg  *tls.Config
		want func(cfg *tls.Config) bool
	}{
		{name: "snapshot carries the pair and pool", cfg: f.snap(), want: func(cfg *tls.Config) bool {
			return len(cfg.Certificates) == 1 && cfg.ClientCAs != nil && cfg.GetCertificate == nil && cfg.GetConfigForClient == nil
		}},
		{name: "snapshot requires verified clients over tls 1.3 with alpn", cfg: f.snap(), want: func(cfg *tls.Config) bool {
			return cfg.MinVersion == tls.VersionTLS13 && cfg.ClientAuth == tls.RequireAndVerifyClientCert && strings.Join(cfg.NextProtos, ",") == "h2,http/1.1"
		}},
		{name: "base has no stale certificate and both hooks", cfg: f.r.base(), want: func(cfg *tls.Config) bool {
			return len(cfg.Certificates) == 0 && cfg.GetCertificate != nil && cfg.GetConfigForClient != nil && cfg.ClientCAs != nil
		}},
		{name: "base matches the snapshot's version, auth and alpn", cfg: f.r.base(), want: func(cfg *tls.Config) bool {
			return cfg.MinVersion == tls.VersionTLS13 && cfg.ClientAuth == tls.RequireAndVerifyClientCert && strings.Join(cfg.NextProtos, ",") == "h2,http/1.1"
		}},
		{name: "every handshake shares one snapshot", cfg: first, want: func(cfg *tls.Config) bool {
			return cfg == second
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.want(tc.cfg) {
				t.Fatalf("cfg = %+v", tc.cfg)
			}
		})
	}
}

// The hooks never return (nil, nil). Without a snapshot they fail the
// handshake closed instead of letting crypto/tls use the base config.
func TestReloaderHooksFailClosed(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	empty := &reloader{now: clk.now, interval: time.Second, next: clk.t.Add(time.Hour)}
	loaded := newFixture(t).r
	cases := []struct {
		name    string
		r       *reloader
		wantErr bool
	}{
		{name: "no snapshot is an error", r: empty, wantErr: true},
		{name: "a loaded reloader serves its snapshot", r: loaded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.r.getConfigForClient(nil)
			if (err != nil) != tc.wantErr || (cfg == nil) != tc.wantErr {
				t.Fatalf("GetConfigForClient = %v, %v, want error=%v", cfg, err, tc.wantErr)
			}
			cert, err := tc.r.getCertificate(nil)
			if (err != nil) != tc.wantErr || (cert == nil) != tc.wantErr {
				t.Fatalf("GetCertificate = %v, %v, want error=%v", cert, err, tc.wantErr)
			}
			if cfg != nil && cert != &cfg.Certificates[0] {
				t.Fatal("GetCertificate does not point into the snapshot")
			}
		})
	}
}
