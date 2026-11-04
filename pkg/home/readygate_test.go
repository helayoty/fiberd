package home_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Azure/fiberd/pkg/home"
)

// publisher records every publish a ReadyGate made and fails the ones it
// is told to.
type publisher struct {
	mu   sync.Mutex
	sent [][]string
	errs []error // consumed in order, nil means success
}

func (p *publisher) publish(_ context.Context, warm []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, slices.Clone(warm))
	if len(p.errs) == 0 {
		return nil
	}
	err := p.errs[0]
	p.errs = p.errs[1:]
	return err
}

func (p *publisher) got() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent
}

type readyCall struct {
	uid   string
	ready bool
}

func equalSent(a, b [][]string) bool {
	return slices.EqualFunc(a, b, slices.Equal)
}

// TestReadyGatePublishes checks which PublishReady calls reach the
// control plane: the first one, and every flip of "any template is warm".
func TestReadyGatePublishes(t *testing.T) {
	failed := errors.New("patch refused")
	cases := []struct {
		name      string
		calls     []readyCall
		errs      []error
		want      [][]string
		wantErrs  []error
		wantReady bool
	}{
		{name: "the first call publishes", calls: []readyCall{{"g1", true}},
			want: [][]string{{"g1"}}, wantErrs: []error{nil}, wantReady: true},
		{name: "a first call that is not ready publishes not ready", calls: []readyCall{{"g1", false}},
			want: [][]string{{}}, wantErrs: []error{nil}},
		{name: "a second warm grant does not flip the gate", calls: []readyCall{{"g1", true}, {"g2", true}},
			want: [][]string{{"g1"}}, wantErrs: []error{nil, nil}, wantReady: true},
		{name: "the last warm grant going cold flips the gate", calls: []readyCall{{"g1", true}, {"g1", false}},
			want: [][]string{{"g1"}, {}}, wantErrs: []error{nil, nil}},
		{name: "a grant going cold while another is warm does not flip", calls: []readyCall{{"g1", true}, {"g2", true}, {"g1", false}},
			want: [][]string{{"g1"}}, wantErrs: []error{nil, nil, nil}, wantReady: true},
		{name: "a failed publish is sent again by the next call", calls: []readyCall{{"g1", true}, {"g2", true}}, errs: []error{failed},
			want: [][]string{{"g1"}, {"g1", "g2"}}, wantErrs: []error{failed, nil}, wantReady: true},
		{name: "a state that came back to what is published is not re-sent", calls: []readyCall{{"b", true}, {"b", false}, {"a", true}}, errs: []error{nil, failed},
			want: [][]string{{"b"}, {}}, wantErrs: []error{nil, failed, nil}, wantReady: true},
		{name: "warm grants are listed sorted", calls: []readyCall{{"b", true}, {"a", true}}, errs: []error{failed},
			want: [][]string{{"b"}, {"a", "b"}}, wantErrs: []error{failed, nil}, wantReady: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &publisher{errs: c.errs}
			g := &home.ReadyGate{Publish: p.publish}
			for i, call := range c.calls {
				if err := g.PublishReady(context.Background(), call.uid, call.ready); !errors.Is(err, c.wantErrs[i]) {
					t.Fatalf("call %d: PublishReady = %v, want %v", i, err, c.wantErrs[i])
				}
			}
			if got := p.got(); !equalSent(got, c.want) {
				t.Fatalf("published %v, want %v", got, c.want)
			}
			if g.Ready() != c.wantReady {
				t.Fatalf("Ready = %v, want %v", g.Ready(), c.wantReady)
			}
		})
	}
}

// TestReadyGateRepublish checks what Republish sends and when it says
// the outcome changed.
func TestReadyGateRepublish(t *testing.T) {
	e1, e2 := errors.New("patch refused"), errors.New("no route")
	cases := []struct {
		name        string
		calls       []readyCall
		errs        []error // for the PublishReady calls and then each Republish
		republishes int
		want        [][]string
		wantChanged []bool
		wantErrs    []error
	}{
		{name: "nothing to republish before the first call", republishes: 1,
			want: nil, wantChanged: []bool{false}, wantErrs: []error{nil}},
		{name: "nothing pending after a success", calls: []readyCall{{"g1", true}}, republishes: 1,
			want: [][]string{{"g1"}}, wantChanged: []bool{false}, wantErrs: []error{nil}},
		{name: "a failed publish is re-sent and the recovery reported once", calls: []readyCall{{"g1", true}}, errs: []error{e1}, republishes: 2,
			want: [][]string{{"g1"}, {"g1"}}, wantChanged: []bool{true, false}, wantErrs: []error{nil, nil}},
		{name: "the same failure is reported once and a new message again", calls: []readyCall{{"g1", true}}, errs: []error{e1, e1, e2, e2}, republishes: 3,
			want: [][]string{{"g1"}, {"g1"}, {"g1"}, {"g1"}}, wantChanged: []bool{false, true, false}, wantErrs: []error{e1, e2, e2}},
		{name: "a republish carries the newest state", calls: []readyCall{{"g1", true}, {"g1", false}}, errs: []error{e1, e1}, republishes: 1,
			want: [][]string{{"g1"}, {}, {}}, wantChanged: []bool{true}, wantErrs: []error{nil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &publisher{errs: c.errs}
			g := &home.ReadyGate{Publish: p.publish}
			for _, call := range c.calls {
				_ = g.PublishReady(context.Background(), call.uid, call.ready)
			}
			for i := range c.republishes {
				changed, err := g.Republish(context.Background())
				if changed != c.wantChanged[i] || !errors.Is(err, c.wantErrs[i]) {
					t.Fatalf("republish %d = (%v, %v), want (%v, %v)", i, changed, err, c.wantChanged[i], c.wantErrs[i])
				}
			}
			if got := p.got(); !equalSent(got, c.want) {
				t.Fatalf("published %v, want %v", got, c.want)
			}
		})
	}
}

// TestReadyGateCoalesces checks that a call made while a publish is in
// flight neither waits for it nor is lost: the publisher in flight sends
// the newest state next, so the control plane sees the states in order.
func TestReadyGateCoalesces(t *testing.T) {
	cases := []struct {
		name   string
		second readyCall
		want   [][]string
	}{
		{name: "a flip while in flight is sent next", second: readyCall{"g1", false}, want: [][]string{{"g1"}, {}}},
		{name: "a change that does not flip is not sent", second: readyCall{"g2", true}, want: [][]string{{"g1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			p := &publisher{}
			g := &home.ReadyGate{Publish: func(ctx context.Context, warm []string) error {
				entered <- struct{}{}
				<-release
				return p.publish(ctx, warm)
			}}
			first := make(chan error, 1)
			go func() { first <- g.PublishReady(context.Background(), "g1", true) }()
			<-entered

			// Nothing waits on the publish in flight: not a reader, not a
			// second call.
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				if err := g.PublishReady(context.Background(), c.second.uid, c.second.ready); err != nil {
					t.Errorf("the second call failed: %v", err)
				}
			}()
			select {
			case <-returned:
			case <-time.After(10 * time.Second):
				t.Fatal("the second call waited for the publish in flight")
			}
			_ = g.Ready()

			release <- struct{}{}
			if len(c.want) > 1 {
				<-entered
				release <- struct{}{}
			}
			if err := <-first; err != nil {
				t.Fatalf("the first call failed: %v", err)
			}
			if got := p.got(); !equalSent(got, c.want) {
				t.Fatalf("published %v, want %v", got, c.want)
			}
		})
	}
}
