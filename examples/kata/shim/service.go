// Package shim is a containerd shim (the runtime-v2 task service) whose
// containers are fibers: what a Kata shim does with a micro-VM, done
// with fiberd's protocol. Create clones (or resumes) the container's
// session on a fiberd home, Kill parks or releases it, Delete forgets
// it. The Pod's sandbox container (the pause container) is a shim-side
// record with nothing behind it: fibers are the workload. The shim is a
// consumer: it holds the grant the Pod carries and speaks only Clone,
// Park and Release.
//
// Pod annotations, passed into the OCI spec by containerd's
// pod_annotations setting for the runtime handler:
//
//	io.fiberd/grant    the signed grant (required for every non-sandbox container)
//	io.fiberd/home     the home's gRPC address (default 127.0.0.1:8484)
//	io.fiberd/session  the session name (default <pod name>/<container name>)
//	io.fiberd/on-stop  park (keep the state) or release (default)
//	io.fiberd/payload  data the fiber receives at clone (optional)
package shim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	eventstypes "github.com/containerd/containerd/api/events"
	taskAPI "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/shutdown"
	"github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/fifo"
	"github.com/containerd/ttrpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/helayoty/fiberd/pkg/consumer"
)

// Annotation keys.
const (
	AnnotGrant   = "io.fiberd/grant"
	AnnotHome    = "io.fiberd/home"
	AnnotSession = "io.fiberd/session"
	AnnotOnStop  = "io.fiberd/on-stop"
	AnnotPayload = "io.fiberd/payload"

	criContainerType = "io.kubernetes.cri.container-type"
	criSandboxID     = "io.kubernetes.cri.sandbox-id"
	criSandboxName   = "io.kubernetes.cri.sandbox-name"
	criContainerName = "io.kubernetes.cri.container-name"

	// DefaultHome is where the shim looks for a home when the Pod names
	// none: the node's own agent.
	DefaultHome = "127.0.0.1:8484"
	// StateFile in the bundle records the fiber, for the manager's Stop
	// after a shim crash.
	StateFile = "fiberd.json"
)

// State is what a container's bundle records.
type State struct {
	Home    string `json:"home"`
	FiberID string `json:"fiber_id"`
	Session string `json:"session"`
	OnStop  string `json:"on_stop"`
}

// ociSpec is the slice of config.json the shim reads.
type ociSpec struct {
	Annotations map[string]string `json:"annotations,omitempty"`
}

func readSpec(bundle string) (*ociSpec, error) {
	f, err := os.Open(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var s ociSpec
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	return &s, nil
}

type container struct {
	id, bundle string
	sandbox    bool
	stdout     string
	home       string
	session    string
	onStop     string
	fiber      *consumer.Fiber
	client     *consumer.Client

	status     task.Status
	exitStatus uint32
	exitedAt   time.Time
	exited     chan struct{}
}

// Service is the task service.
type Service struct {
	// DialHome connects to a home by address; tests inject one.
	DialHome func(ctx context.Context, addr string) (*consumer.Client, error)

	pid       int
	publisher shim.Publisher
	sd        shutdown.Service
	ns        string

	mu         sync.Mutex
	containers map[string]*container
	homes      map[string]*consumer.Client
}

var (
	_     taskAPI.TTRPCTaskService = (*Service)(nil)
	_     shim.TTRPCService        = (*Service)(nil)
	empty                          = &emptypb.Empty{}
)

// NewService builds the task service; ctx carries containerd's namespace.
func NewService(ctx context.Context, publisher shim.Publisher, sd shutdown.Service) *Service {
	ns, _ := namespaces.Namespace(ctx)
	s := &Service{
		DialHome:   consumer.Dial,
		pid:        os.Getpid(),
		publisher:  publisher,
		sd:         sd,
		ns:         ns,
		containers: map[string]*container{},
		homes:      map[string]*consumer.Client{},
	}
	if sd != nil {
		sd.RegisterCallback(func(context.Context) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, c := range s.homes {
				_ = c.Close()
			}
			if publisher != nil {
				_ = publisher.Close()
			}
			return nil
		})
	}
	return s
}

// RegisterTTRPC implements shim.TTRPCService.
func (s *Service) RegisterTTRPC(server *ttrpc.Server) error {
	taskAPI.RegisterTTRPCTaskService(server, s)
	return nil
}

func (s *Service) publish(ctx context.Context, e any) {
	if s.publisher == nil {
		return
	}
	pctx := namespaces.WithNamespace(context.Background(), s.ns)
	if s.ns == "" {
		pctx = ctx
	}
	_ = s.publisher.Publish(pctx, runtime.GetTopic(e), e)
}

func (s *Service) home(ctx context.Context, addr string) (*consumer.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.homes[addr]; ok {
		return c, nil
	}
	c, err := s.DialHome(ctx, addr)
	if err != nil {
		return nil, err
	}
	s.homes[addr] = c
	return c, nil
}

func (s *Service) get(id string) (*container, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.containers[id]
	if !ok {
		return nil, errgrpc.ToGRPC(fmt.Errorf("container %s: %w", id, errdefs.ErrNotFound))
	}
	return c, nil
}

// Create: a sandbox container is recorded; any other container is a
// Clone of its session on the Pod's home.
func (s *Service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (*taskAPI.CreateTaskResponse, error) {
	spec, err := readSpec(r.Bundle)
	if err != nil {
		return nil, errgrpc.ToGRPC(fmt.Errorf("bundle %s: %w", r.Bundle, err))
	}
	an := spec.Annotations
	c := &container{id: r.ID, bundle: r.Bundle, stdout: r.Stdout, status: task.Status_CREATED, exited: make(chan struct{})}
	if an[criContainerType] == "sandbox" || (an[criContainerType] == "" && an[AnnotGrant] == "") {
		c.sandbox = true
	} else {
		grant := an[AnnotGrant]
		if grant == "" {
			return nil, errgrpc.ToGRPC(fmt.Errorf("container %s: no %s annotation: %w", r.ID, AnnotGrant, errdefs.ErrInvalidArgument))
		}
		c.home = an[AnnotHome]
		if c.home == "" {
			c.home = DefaultHome
		}
		c.session = an[AnnotSession]
		if c.session == "" {
			c.session = an[criSandboxName] + "/" + an[criContainerName]
			if c.session == "/" {
				c.session = r.ID
			}
		}
		c.onStop = an[AnnotOnStop]
		if c.onStop == "" {
			c.onStop = "release"
		}
		client, err := s.home(ctx, c.home)
		if err != nil {
			return nil, errgrpc.ToGRPC(fmt.Errorf("home %s: %w", c.home, err))
		}
		f, err := client.Clone(ctx, grant, c.session, 5*time.Second, []byte(an[AnnotPayload]))
		if err != nil {
			return nil, errgrpc.ToGRPC(classify(err))
		}
		c.fiber, c.client = &f, client
		st, _ := json.Marshal(State{Home: c.home, FiberID: f.ID, Session: c.session, OnStop: c.onStop})
		_ = os.WriteFile(filepath.Join(r.Bundle, StateFile), st, 0o600)
		s.log(ctx, c, fmt.Sprintf("fiber %s %s session=%s endpoint=%s fence=%s", f.ID, f.Kind, c.session, f.Endpoint, f.Fence))
	}
	s.mu.Lock()
	s.containers[r.ID] = c
	s.mu.Unlock()
	s.publish(ctx, &eventstypes.TaskCreate{ContainerID: r.ID, Bundle: r.Bundle, Pid: uint32(s.pid),
		IO: &eventstypes.TaskIO{Stdin: r.Stdin, Stdout: r.Stdout, Stderr: r.Stderr, Terminal: r.Terminal}})
	return &taskAPI.CreateTaskResponse{Pid: uint32(s.pid)}, nil
}

// classify makes the consumer's typed errors legible in containerd's
// error space: a miss is ResourceExhausted / Unavailable, a tier gap is
// FailedPrecondition.
func classify(err error) error {
	var shed *consumer.Shed
	var def *consumer.Deferred
	var gap *consumer.TierGap
	switch {
	case errors.As(err, &shed):
		return fmt.Errorf("%w: %w", errdefs.ErrUnavailable, err)
	case errors.As(err, &def):
		return fmt.Errorf("%w: %w", errdefs.ErrUnavailable, err)
	case errors.As(err, &gap):
		return fmt.Errorf("%w: %w", errdefs.ErrFailedPrecondition, err)
	}
	return err
}

// log writes one line to the container's stdout fifo, so kubectl logs
// shows which fiber the container is.
func (s *Service) log(ctx context.Context, c *container, line string) {
	if c.stdout == "" {
		return
	}
	go func() {
		// Without WithoutCancel this outlives its request: containerd
		// cancels the Create context as soon as the call returns, and
		// opening the fifo then fails, so the line appears only when the
		// goroutine wins that race. Keep the deadline, drop the cancel.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		f, err := fifo.OpenFifo(wctx, c.stdout, syscall.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintln(f, line)
		_ = f.Close()
	}()
}

func (s *Service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	c, err := s.get(r.ID)
	if err != nil {
		return nil, err
	}
	if r.ExecID != "" {
		return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
	}
	s.mu.Lock()
	c.status = task.Status_RUNNING
	s.mu.Unlock()
	s.publish(ctx, &eventstypes.TaskStart{ContainerID: r.ID, Pid: uint32(s.pid)})
	return &taskAPI.StartResponse{Pid: uint32(s.pid)}, nil
}

// stop ends the container: the fiber is parked or released as the Pod
// asked; the container is then exited with status.
func (s *Service) stop(ctx context.Context, c *container, status uint32) {
	s.mu.Lock()
	if c.status == task.Status_STOPPED {
		s.mu.Unlock()
		return
	}
	c.status = task.Status_STOPPED
	c.exitStatus = status
	c.exitedAt = time.Now()
	fiber, client, onStop := c.fiber, c.client, c.onStop
	s.mu.Unlock()
	if fiber != nil && client != nil {
		var err error
		if onStop == "park" {
			err = client.Park(ctx, fiber.ID, false)
		} else {
			err = client.Release(ctx, fiber.ID, false)
		}
		if err != nil && !consumer.NotFound(err) {
			s.log(ctx, c, fmt.Sprintf("%s %s: %v", onStop, fiber.ID, err))
		}
	}
	close(c.exited)
	s.publish(ctx, &eventstypes.TaskExit{ContainerID: c.id, ID: c.id, Pid: uint32(s.pid), ExitStatus: status, ExitedAt: timestamppb.New(c.exitedAt)})
}

func (s *Service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*emptypb.Empty, error) {
	c, err := s.get(r.ID)
	if err != nil {
		return nil, err
	}
	status := uint32(0)
	if r.Signal == uint32(syscall.SIGKILL) {
		status = 137
	}
	s.stop(ctx, c, status)
	return empty, nil
}

func (s *Service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	c, err := s.get(r.ID)
	if err != nil {
		return nil, err
	}
	select {
	case <-c.exited:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &taskAPI.WaitResponse{ExitStatus: c.exitStatus, ExitedAt: timestamppb.New(c.exitedAt)}, nil
}

func (s *Service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	c, err := s.get(r.ID)
	if err != nil {
		return nil, err
	}
	if r.ExecID != "" {
		return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
	}
	s.stop(ctx, c, 137)
	s.mu.Lock()
	delete(s.containers, r.ID)
	s.mu.Unlock()
	_ = os.Remove(filepath.Join(c.bundle, StateFile))
	s.publish(ctx, &eventstypes.TaskDelete{ContainerID: r.ID, Pid: uint32(s.pid), ExitStatus: c.exitStatus, ExitedAt: timestamppb.New(c.exitedAt)})
	return &taskAPI.DeleteResponse{Pid: uint32(s.pid), ExitStatus: c.exitStatus, ExitedAt: timestamppb.New(c.exitedAt)}, nil
}

func (s *Service) State(_ context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	c, err := s.get(r.ID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := &taskAPI.StateResponse{ID: c.id, Bundle: c.bundle, Pid: uint32(s.pid), Status: c.status, Stdout: c.stdout, ExitStatus: c.exitStatus}
	if !c.exitedAt.IsZero() {
		resp.ExitedAt = timestamppb.New(c.exitedAt)
	}
	return resp, nil
}

func (s *Service) Pids(_ context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
	if _, err := s.get(r.ID); err != nil {
		return nil, err
	}
	return &taskAPI.PidsResponse{Processes: []*task.ProcessInfo{{Pid: uint32(s.pid)}}}, nil
}

func (s *Service) Connect(_ context.Context, _ *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	return &taskAPI.ConnectResponse{ShimPid: uint32(s.pid), TaskPid: uint32(s.pid)}, nil
}

func (s *Service) Shutdown(_ context.Context, _ *taskAPI.ShutdownRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	n := len(s.containers)
	s.mu.Unlock()
	if n > 0 {
		return empty, nil
	}
	if s.sd != nil {
		s.sd.Shutdown()
	}
	return empty, nil
}

// Fibers report no cgroup metrics of their own to containerd; the home
// prices them. Exec, ptys, pause and checkpoint are the home's verbs,
// not the shim's.
func (s *Service) Stats(context.Context, *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}
func (s *Service) Exec(context.Context, *taskAPI.ExecProcessRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}
func (s *Service) ResizePty(context.Context, *taskAPI.ResizePtyRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}
func (s *Service) CloseIO(context.Context, *taskAPI.CloseIORequest) (*emptypb.Empty, error) {
	return empty, nil
}
func (s *Service) Pause(context.Context, *taskAPI.PauseRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}
func (s *Service) Resume(context.Context, *taskAPI.ResumeRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}
func (s *Service) Checkpoint(context.Context, *taskAPI.CheckpointTaskRequest) (*emptypb.Empty, error) {
	return nil, errgrpc.ToGRPC(errdefs.ErrNotImplemented)
}
func (s *Service) Update(context.Context, *taskAPI.UpdateTaskRequest) (*emptypb.Empty, error) {
	return empty, nil
}
