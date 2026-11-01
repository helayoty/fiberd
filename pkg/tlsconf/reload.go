package tlsconf

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// errNoSnapshot fails a handshake closed when no certificate was ever
// loaded, which newReloader prevents. Returning nil instead would make
// crypto/tls fall back to the base config and verify callers against
// the system roots.
var errNoSnapshot = errors.New("tlsconf: no server certificate loaded")

// alpn is what both of fiberd's servers negotiate. crypto/tls replaces
// the whole handshake config with the one GetConfigForClient returns,
// including ALPN, so the snapshot has to carry it. grpc's
// credentials.NewTLS and http.Server.ServeTLS clone the base config and
// append "h2" and "http/1.1" only when missing, so listing both on the
// base keeps the snapshot and the consumers' clones identical. The
// Kubernetes apiserver's dynamic serving certificate works the same way.
func alpn() []string { return []string{"h2", "http/1.1"} }

// stamp is what a file looked like at the last load attempt. A nil
// info means the stat failed.
type stamp struct{ info os.FileInfo }

func stampOf(path string) stamp {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}
	}
	return stamp{info: fi}
}

// equal is false when the file was swapped for another one, as the
// kubelet's atomic writer does by pointing a symlink at a new file, or
// when its mtime or size changed. The inode is the strongest signal.
func (s stamp) equal(o stamp) bool {
	if s.info == nil || o.info == nil {
		return s.info == nil && o.info == nil
	}
	return os.SameFile(s.info, o.info) && s.info.Size() == o.info.Size() && s.info.ModTime().Equal(o.info.ModTime())
}

// stamps are the certificate, key and CA file in that order.
type stamps [3]stamp

func (s stamps) equal(o stamps) bool {
	return s[0].equal(o[0]) && s[1].equal(o[1]) && s[2].equal(o[2])
}

// reloader serves the server certificate and client CA pool from files
// that cert-manager renews in place. It re-reads them when their
// identity, mtime or size changes, checked at most once per interval,
// and keeps the previous snapshot when a renewal fails to load.
type reloader struct {
	certFile, keyFile, caFile string
	now                       func() time.Time
	interval                  time.Duration

	mu       sync.Mutex
	seen     stamps      // the files at the last load attempt
	snapshot *tls.Config // the config every handshake gets until the next load
	next     time.Time   // when the files are next checked
	dirty    bool        // the last load failed, so retry at every check
	lastErr  string      // what was logged for the failure, to log it once
}

// newReloader loads the files once and fails the way Server always has
// when they cannot be loaded.
func newReloader(certFile, keyFile, caFile string, now func() time.Time, interval time.Duration) (*reloader, error) {
	r := &reloader{certFile: certFile, keyFile: keyFile, caFile: caFile, now: now, interval: interval}
	// Stat before reading, so a file rewritten in between is seen as a
	// change on the next check rather than missed.
	seen := r.stat()
	snap, err := r.load()
	if err != nil {
		return nil, err
	}
	r.seen, r.snapshot, r.next = seen, snap, now().Add(interval)
	return r, nil
}

// base is the config fiberd's gRPC and HTTP servers are built from.
// Certificates stays empty so there is no stale fallback. The hooks
// serve the current snapshot. ClientCAs is set as well, in case a
// consumer ever reads it from the base.
func (r *reloader) base() *tls.Config {
	r.mu.Lock()
	pool := r.snapshot.ClientCAs
	r.mu.Unlock()
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		NextProtos:         alpn(),
		ClientCAs:          pool,
		GetCertificate:     r.getCertificate,
		GetConfigForClient: r.getConfigForClient,
	}
}

func (r *reloader) getConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	return r.current()
}

func (r *reloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	snap, err := r.current()
	if err != nil {
		return nil, err
	}
	return &snap.Certificates[0], nil
}

// current is the snapshot for one handshake. Once per interval it
// checks the files first. The snapshot must not be modified by callers,
// since every handshake shares it.
func (r *reloader) current() (*tls.Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); !now.Before(r.next) {
		r.next = now.Add(r.interval)
		r.refresh()
	}
	if r.snapshot == nil {
		return nil, errNoSnapshot
	}
	return r.snapshot, nil
}

// refresh reloads when any file changed since the last attempt, and at
// every check after a failed load, so a half-written renewal or a
// transient read error is retried without waiting for the files to
// change again. A failure is logged when it first happens and again
// only when its text changes, so a persistently bad file does not log
// every second. Called with mu held.
func (r *reloader) refresh() {
	seen := r.stat()
	if !r.dirty && seen.equal(r.seen) {
		return
	}
	r.seen = seen
	snap, err := r.load()
	if err != nil {
		r.dirty = true
		if msg := err.Error(); msg != r.lastErr {
			r.lastErr = msg
			log.Printf("tlsconf: keeping the previous server certificate and client CA: %v", err)
		}
		return
	}
	r.dirty, r.lastErr = false, ""
	r.snapshot = snap
}

func (r *reloader) stat() stamps {
	return stamps{stampOf(r.certFile), stampOf(r.keyFile), stampOf(r.caFile)}
}

// load reads the files into a snapshot with no hooks, so crypto/tls
// uses its certificate and pool as they are.
func (r *reloader) load() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: server certificate: %w", err)
	}
	pool, err := loadPool(r.caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   alpn(),
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
	}, nil
}
