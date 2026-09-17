package herder

import "path/filepath"

// Paths is the directory tree atelet and a worker's herder share through
// the hostPath volume mounted at Base (Substrate's ateompath, kept to
// the same names). atelet dials the herder at SocketPath, prepares an
// actor's state under ActorDir, ships every regular file directly under
// CheckpointStateDir after a checkpoint and places a downloaded snapshot
// under RestoreStateDir before a restore.
type Paths struct {
	// Base is the shared root (Substrate mounts its hostPath there); empty
	// means DefaultBase.
	Base string
}

// DefaultBase is what Substrate's worker Pods mount, named after the
// first herder.
const DefaultBase = "/var/lib/ateom-gvisor"

func (p Paths) base() string {
	if p.Base == "" {
		return DefaultBase
	}
	return p.Base
}

// AteomDir is this worker's directory; atelet lists the parent to find
// every herder on the node (the name is the worker Pod's uid).
func (p Paths) AteomDir(podUID string) string { return filepath.Join(p.base(), "ateoms", podUID) }

// SocketPath is the plaintext gRPC unix socket atelet dials.
func (p Paths) SocketPath(podUID string) string {
	return filepath.Join(p.AteomDir(podUID), "ateom.sock")
}

// SupportSocket is atelet's own socket on the node (the AteomSupport
// service: capacity reports, actor certificates), mTLS with Pod
// certificates. Reaching it is this home's liveness signal.
func (p Paths) SupportSocket() string { return filepath.Join(p.base(), "ateom-support.sock") }

// ActorDir holds one actor's on-node state.
func (p Paths) ActorDir(actorUID string) string { return filepath.Join(p.base(), "actors", actorUID) }

// CheckpointStateDir is where a checkpoint leaves its files for atelet.
func (p Paths) CheckpointStateDir(actorUID string) string {
	return filepath.Join(p.ActorDir(actorUID), "checkpoint-state")
}

// RestoreStateDir is where atelet puts a snapshot's files before a restore.
func (p Paths) RestoreStateDir(actorUID string) string {
	return filepath.Join(p.ActorDir(actorUID), "restore-state")
}
