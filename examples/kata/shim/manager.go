package shim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/shutdown"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"

	"github.com/helayoty/fiberd/pkg/consumer"
)

// RuntimeName is the runtime_type containerd's config names.
const RuntimeName = "io.containerd.fiberd.v1"

// Manager is the shim's process manager: containerd calls Start to get a
// shim for a container (one per Pod, grouped by the sandbox id) and Stop
// to clean up after one that died.
type Manager struct{ name string }

func NewManager() shim.Manager { return Manager{name: RuntimeName} }

func (m Manager) Name() string { return m.name }

func (m Manager) Info(context.Context, io.Reader) (*types.RuntimeInfo, error) {
	return &types.RuntimeInfo{Name: m.name, Version: &types.RuntimeVersion{Version: "0.1"}}, nil
}

// Start spawns the shim daemon (this binary, in daemon mode) for the
// container, or hands back the running one of the same Pod.
func (m Manager) Start(ctx context.Context, id string, opts shim.StartOpts) (shim.BootstrapParams, error) {
	params := shim.BootstrapParams{Version: 3, Protocol: "ttrpc"}
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return params, err
	}
	self, err := os.Executable()
	if err != nil {
		return params, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return params, err
	}
	grouping := id
	if spec, err := readSpec(cwd); err == nil {
		if sb := spec.Annotations[criSandboxID]; sb != "" {
			grouping = sb
		}
	}
	address, err := shim.SocketAddress(ctx, opts.Address, grouping, false)
	if err != nil {
		return params, err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		if !shim.SocketEaddrinuse(err) {
			return params, fmt.Errorf("shim socket: %w", err)
		}
		if shim.CanConnect(address) {
			params.Address = address // the Pod's shim is up
			return params, nil
		}
		if err := shim.RemoveSocket(address); err != nil {
			return params, fmt.Errorf("remove stale shim socket: %w", err)
		}
		if socket, err = shim.NewSocket(address); err != nil {
			return params, fmt.Errorf("shim socket: %w", err)
		}
	}
	f, err := socket.File()
	if err != nil {
		_ = socket.Close()
		return params, err
	}
	args := []string{"-namespace", ns, "-id", id, "-address", opts.Address}
	if opts.Debug {
		args = append(args, "-debug")
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		_ = socket.Close()
		_ = shim.RemoveSocket(address)
		return params, err
	}
	go func() { _ = cmd.Wait() }()
	_ = f.Close()
	_ = shim.AdjustOOMScore(cmd.Process.Pid)
	params.Address = address
	return params, nil
}

// Stop is called for a container whose shim is gone: the fiber it held
// is released from the bundle's record, so no fiber outlives its
// container.
func (m Manager) Stop(ctx context.Context, id string) (shim.StopStatus, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return shim.StopStatus{}, err
	}
	bundle := filepath.Join(filepath.Dir(cwd), id)
	if raw, err := os.ReadFile(filepath.Join(bundle, StateFile)); err == nil {
		var st State
		if json.Unmarshal(raw, &st) == nil && st.FiberID != "" {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if c, err := consumer.Dial(cctx, st.Home); err == nil {
				if st.OnStop == "park" {
					_ = c.Park(cctx, st.FiberID, false)
				} else {
					_ = c.Release(cctx, st.FiberID, false)
				}
				_ = c.Close()
			}
		}
		_ = os.Remove(filepath.Join(bundle, StateFile))
	}
	return shim.StopStatus{ExitedAt: time.Now(), ExitStatus: 137}, nil
}

// RegisterPlugin registers the task service with containerd's shim
// plugin registry; the binary calls it before shim.Run.
func RegisterPlugin() {
	registry.Register(&plugin.Registration{
		Type:     plugins.TTRPCPlugin,
		ID:       "task",
		Requires: []plugin.Type{plugins.EventPlugin, plugins.InternalPlugin},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			pp, err := ic.GetByID(plugins.EventPlugin, "publisher")
			if err != nil {
				return nil, err
			}
			ss, err := ic.GetByID(plugins.InternalPlugin, "shutdown")
			if err != nil {
				return nil, err
			}
			pub, ok := pp.(shim.Publisher)
			if !ok {
				return nil, fmt.Errorf("publisher plugin: %w", errdefs.ErrInvalidArgument)
			}
			return NewService(ic.Context, pub, ss.(shutdown.Service)), nil
		},
	})
}
