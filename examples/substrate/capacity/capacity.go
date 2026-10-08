// Package capacity tells Substrate what a worker can host. The control
// plane places an actor only on a worker that has reported its capacity,
// so a worker that never reports sits idle forever and every resume fails
// with "no free workers available". Substrate's own herders report once at
// startup to the atelet on their node, and this package does the same for
// ateom-fiberd:
//
//	downward API files ──Read──▶ one actor, cpu, memory
//	                                 │
//	         SetWorkerCapacity over the node's AteomSupport socket (mTLS)
//	                                 ▼
//	              atelet ──▶ the control plane's Worker record
//
// The report retries until atelet accepts it, because the Worker record
// may not exist yet when the worker first comes up.
package capacity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	ateletpb "github.com/helayoty/fiberd/examples/substrate/proto/atelet"
)

const (
	// Dir is where Substrate's controller projects the worker container's
	// limits from the downward API.
	Dir = "/run/ateom-capacity"
	// CPUFile holds the cpu limit in milli-cores.
	CPUFile = "cpu_milli"
	// MemoryFile holds the memory limit in bytes.
	MemoryFile = "memory_bytes"
	// Actors is how many actors a worker hosts at once. The herder holds
	// one, as Substrate's Worker record assumes today.
	Actors = 1
	// AteletID is the SPIFFE id atelet's certificate must carry.
	AteletID = "spiffe://cluster.local/ns/ate-system/sa/atelet"
)

// oidPodIdentity names Substrate's PodIdentity certificate extension, a
// JSON object (internal/substratex509 in Substrate).
var oidPodIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 12, 1}

// Read returns what this worker can supply. That is one actor and the
// container's cpu and memory limits from dir. A limit that is missing,
// unparseable or not positive is left out, which the control plane reads
// as none of that dimension.
func Read(dir string) *ateletpb.WorkerResources {
	var limits []*ateletpb.Limits
	if v := readLimit(filepath.Join(dir, CPUFile)); v > 0 {
		limits = append(limits, &ateletpb.Limits{Name: "cpu", Quantity: strconv.FormatInt(v, 10) + "m"})
	}
	if v := readLimit(filepath.Join(dir, MemoryFile)); v > 0 {
		limits = append(limits, &ateletpb.Limits{Name: "memory", Quantity: strconv.FormatInt(v, 10)})
	}
	wr := &ateletpb.WorkerResources{Actors: Actors}
	if len(limits) > 0 {
		wr.Resources = &ateletpb.Resources{Limits: limits}
	}
	return wr
}

func readLimit(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("capacity: ignoring %s: %v", path, err)
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v <= 0 {
		log.Printf("capacity: ignoring %s: %q is not a positive integer", path, strings.TrimSpace(string(b)))
		return 0
	}
	return v
}

// Config says where atelet is and how to reach it.
type Config struct {
	Socket string // atelet's AteomSupport unix socket
	// CredentialBundle is the PEM with this Pod's key and certificate, and
	// TrustBundle the PEM with the CAs atelet's certificate chains to.
	// Both empty means plaintext (tests).
	CredentialBundle, TrustBundle string
	Dir                           string        // the limits (default Dir)
	Backoff                       time.Duration // the first retry's wait (default 500ms)
}

// Reporter sends one capacity report.
type Reporter struct {
	cfg   Config
	creds credentials.TransportCredentials
}

// New checks the TLS material, so a worker with a broken bundle stops
// before it serves.
func New(cfg Config) (*Reporter, error) {
	if cfg.Dir == "" {
		cfg.Dir = Dir
	}
	if cfg.Backoff == 0 {
		cfg.Backoff = 500 * time.Millisecond
	}
	r := &Reporter{cfg: cfg, creds: insecure.NewCredentials()}
	if cfg.CredentialBundle == "" && cfg.TrustBundle == "" {
		return r, nil
	}
	tc, err := clientTLS(cfg.CredentialBundle, cfg.TrustBundle)
	if err != nil {
		return nil, err
	}
	r.creds = credentials.NewTLS(tc)
	return r, nil
}

const maxBackoff = 30 * time.Second

// Run reports the capacity, retrying with a doubling wait until atelet
// accepts it or ctx ends.
func (r *Reporter) Run(ctx context.Context) error {
	req := &ateletpb.SetWorkerCapacityRequest{Capacity: Read(r.cfg.Dir)}
	for wait := r.cfg.Backoff; ; wait = min(2*wait, maxBackoff) {
		err := r.once(ctx, req)
		if err == nil {
			log.Printf("capacity: reported %v to atelet", req.GetCapacity())
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("capacity: report to atelet at %s: %v (retrying in %s)", r.cfg.Socket, err, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (r *Reporter) once(ctx context.Context, req *ateletpb.SetWorkerCapacityRequest) error {
	sock := r.cfg.Socket
	conn, err := grpc.NewClient("passthrough:///atelet",
		grpc.WithTransportCredentials(r.creds),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err = ateletpb.NewAteomSupportClient(conn).SetWorkerCapacity(ctx, req)
	return err
}

// podIdentity is the part of Substrate's PodIdentity extension this
// worker checks: the node incarnation.
type podIdentity struct {
	NodeName, NodeUID string
}

func identityOf(cert *x509.Certificate) (*podIdentity, error) {
	var found *podIdentity
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidPodIdentity) {
			continue
		}
		if found != nil {
			return nil, errors.New("more than one PodIdentity extension")
		}
		found = &podIdentity{}
		if err := json.Unmarshal(ext.Value, found); err != nil {
			return nil, fmt.Errorf("PodIdentity extension: %w", err)
		}
	}
	if found == nil || found.NodeName == "" || found.NodeUID == "" {
		return nil, errors.New("no PodIdentity with a node")
	}
	return found, nil
}

func loadBundle(path string) (*tls.Certificate, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("capacity: credential bundle: %w", err)
	}
	cert, err := tls.X509KeyPair(pem, pem)
	if err != nil {
		return nil, fmt.Errorf("capacity: credential bundle %s: %w", path, err)
	}
	return &cert, nil
}

// clientTLS presents this Pod's certificate and accepts only atelet on
// the same node incarnation. Atelet's certificate has no DNS name, so the
// chain, the SPIFFE id and the node are checked by hand, as Substrate's
// own herders do (internal/ateletdial).
func clientTLS(credBundle, trustBundle string) (*tls.Config, error) {
	if credBundle == "" || trustBundle == "" {
		return nil, errors.New("capacity: both the credential bundle and the trust bundle are required")
	}
	own, err := loadBundle(credBundle)
	if err != nil {
		return nil, err
	}
	local, err := identityOf(own.Leaf)
	if err != nil {
		return nil, fmt.Errorf("capacity: this Pod's certificate: %w", err)
	}
	pem, err := os.ReadFile(trustBundle)
	if err != nil {
		return nil, fmt.Errorf("capacity: trust bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("capacity: trust bundle %s holds no certificates", trustBundle)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Verified in VerifyConnection, since atelet's certificate names
		// no host.
		InsecureSkipVerify: true, //nolint:gosec // see VerifyConnection
		// Reloaded per handshake: the kubelet rotates the projected bundle.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return loadBundle(credBundle) },
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("capacity: atelet presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return fmt.Errorf("capacity: atelet's certificate: %w", err)
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != AteletID {
				return fmt.Errorf("capacity: the peer is not %s", AteletID)
			}
			peer, err := identityOf(leaf)
			if err != nil {
				return fmt.Errorf("capacity: atelet's certificate: %w", err)
			}
			if *peer != *local {
				return fmt.Errorf("capacity: atelet is on node %s (%s), not this Pod's %s (%s)",
					peer.NodeName, peer.NodeUID, local.NodeName, local.NodeUID)
			}
			return nil
		},
	}, nil
}
