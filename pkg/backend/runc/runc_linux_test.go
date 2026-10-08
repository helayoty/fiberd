//go:build linux

package runc_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/backend/runc"
)

// TestNew: what the backend refuses at open, the defaults it fills in,
// and the surface it offers the host.
func TestNew(t *testing.T) {
	cases := []struct {
		name    string
		opt     func(t *testing.T, state string) runc.Options
		wantErr string
		check   func(t *testing.T, be backend.Backend, state string)
	}{
		{name: "a pool inside the host's own ids", wantErr: "userns pool",
			opt: func(_ *testing.T, state string) runc.Options {
				return runc.Options{Rootfs: "/tpl", StateDir: state, Pool: runc.IDPool{Start: 1000, Slots: 1}}
			}},
		{name: "a pool the host handed out in /etc/subuid", wantErr: "overlaps",
			opt: func(t *testing.T, state string) runc.Options {
				subuid := filepath.Join(t.TempDir(), "subuid")
				if err := os.WriteFile(subuid, []byte(fmt.Sprintf("alice:%d:65536\n", 1<<20)), 0o644); err != nil {
					t.Fatal(err)
				}
				return runc.Options{Rootfs: "/tpl", StateDir: state, Pool: runc.IDPool{Start: 1 << 20, Slots: 2}, SubIDFiles: []string{subuid}}
			}},
		{name: "a state directory that cannot be made", wantErr: "state directory",
			opt: func(t *testing.T, state string) runc.Options {
				if err := os.WriteFile(state, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return runc.Options{Rootfs: "/tpl", StateDir: filepath.Join(state, "sub"), Pool: runc.IDPool{Start: 1 << 20, Slots: 2}}
			}},
		{name: "the defaults: runc, the default pool, and the state directory made searchable",
			opt: func(_ *testing.T, state string) runc.Options {
				return runc.Options{Rootfs: "/tpl/alpine", StateDir: state, CRIU: "/nonexistent/criu"}
			},
			check: func(t *testing.T, be backend.Backend, state string) {
				if be.Name() != "runc" {
					t.Errorf("Name = %q", be.Name())
				}
				if got := be.(backend.EndpointSchemer).EndpointSchemes(); !reflect.DeepEqual(got, []string{"unix"}) {
					t.Errorf("EndpointSchemes = %v, want unix alone", got)
				}
				if got := be.(backend.Platformer).Platform(); got != (artifact.Platform{Libc: "rootfs-alpine"}) {
					t.Errorf("Platform = %+v, want the rootfs name as the libc", got)
				}
				def, _ := runc.ParsePool(runc.DefaultPool)
				if got, err := be.(backend.IDMapper).MappedRoot("g1"); err != nil || got != def.Range("g1").Start {
					t.Errorf("MappedRoot = %d, %v, want %d from the default pool", got, err, def.Range("g1").Start)
				}
				if st, err := os.Stat(state); err != nil || st.Mode().Perm() != 0o755 {
					t.Errorf("state directory = %v, %v, want mode 755", st, err)
				}
			}},
		{name: "leftovers of a previous life are swept at open",
			opt: func(t *testing.T, state string) runc.Options {
				for _, sub := range []string{"rootfs", "bundles"} {
					if err := os.MkdirAll(filepath.Join(state, sub, "w-old"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				return runc.Options{Rootfs: "/tpl", StateDir: state, CRIU: "/nonexistent/criu", Pool: runc.IDPool{Start: 1 << 20, Slots: 2}}
			},
			check: func(t *testing.T, _ backend.Backend, state string) {
				for _, sub := range []string{"rootfs", "bundles"} {
					if _, err := os.Stat(filepath.Join(state, sub, "w-old")); err == nil {
						t.Errorf("%s/w-old survived the open", sub)
					}
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			be, err := runc.New(tc.opt(t, state))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer be.Close()
			tc.check(t, be, state)
		})
	}
}
