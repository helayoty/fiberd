//go:build linux

package hyperlight

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	fakehelper "github.com/Azure/fiberd/hack/hyperlight/fakehelper/helper"
	"github.com/Azure/fiberd/pkg/artifact"
	"github.com/Azure/fiberd/pkg/backend"
)

// restoring is a fake starter whose helper reports facts and, on
// --version, the line that advertises it restores a template's snapshot.
func restoring(facts string) *fakeStarter {
	s := says(facts)
	s.version += "\n" + restoresLine
	return s
}

// TestTemplateSnapshot checks that a usable helper that advertises it
// restores Hyperlight snapshots says so, and any other none, that
// --template-dir never reaches a helper that did not advertise it, and
// that a template's snapshot reaches one that did as --template-dir, after
// the helper's own arguments and before the template's.
func TestTemplateSnapshot(t *testing.T) {
	t.Run("the format a helper restores", func(t *testing.T) {
		for name, tc := range map[string]struct {
			s    *fakeStarter
			want string
		}{
			"a usable helper that advertises it":       {restoring(kvmIntel), artifact.ImagesFormatHyperlight},
			"the fake helper":                          {&fakeStarter{version: fakehelper.Version}, artifact.ImagesFormatHyperlight},
			"a usable helper that does not":            {says(kvmIntel), ""},
			"a helper that names it on the facts line": {says(kvmIntel + " " + restoresLine), ""},
			"an unusable helper":                       {&fakeStarter{version: kvmIntel + "\n" + restoresLine, versionErr: errors.New("exit status 1")}, ""},
		} {
			if got := newFake(t, Options{Helper: "helper"}, tc.s).ImagesFormat(); got != tc.want {
				t.Errorf("%s restores %q, want %q", name, got, tc.want)
			}
		}
	})
	t.Run("a helper that does not advertise it is never given a snapshot", func(t *testing.T) {
		s := says(kvmIntel)
		be := newFake(t, Options{Helper: "helper"}, s)
		sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
		sp.Template = backend.Template{Digest: "sha256:t", Argv: []string{""}, Dir: "/cache/t", SnapshotDir: t.TempDir()}
		if _, err := be.Warm(warmCtx(t), sp); err == nil || !strings.Contains(err.Error(), "does not advertise template-dir") {
			t.Fatalf("Warm = %v, want the snapshot refused", err)
		}
		if n := len(s.started()); n != 0 {
			t.Fatalf("%d helpers started", n)
		}
	})
	t.Run("the helper is given the snapshot", func(t *testing.T) {
		snap := t.TempDir()
		engine := filepath.Join(t.TempDir(), "engine.sock")
		s := restoring(kvmIntel)
		be := newFake(t, Options{Helper: "helper"}, s)
		sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
		sp.EnginePath = engine
		sp.Template = backend.Template{Digest: "sha256:t", Argv: []string{"", "--port-range", "1-2"}, SnapshotDir: snap}
		if _, err := be.Warm(warmCtx(t), sp); err != nil {
			t.Fatalf("Warm: %v", err)
		}
		want := []string{"--engine", engine, "--template-dir", snap, "--port-range", "1-2"}
		if got := s.started()[0].args; !reflect.DeepEqual(got, want) {
			t.Fatalf("helper args = %q, want %q", got, want)
		}
	})
}

// TestTemplateArgsNeverNameTheSnapshot checks that a template's own
// arguments, which its author writes, cannot pass --template-dir, --guest
// or --engine, in any spelling the protocol's argument grammar reads as
// one, so no helper takes what the author named in place of what fiberd
// gave it.
func TestTemplateArgsNeverNameTheSnapshot(t *testing.T) {
	for _, a := range []string{"--template-dir", "-template-dir", "--template-dir=/etc", "-template-dir=/x", "--guest", "-guest=/etc/passwd", "--engine", "-engine",
		"--engine=/run/other.sock"} {
		t.Run(a, func(t *testing.T) {
			s := restoring(kvmIntel)
			be := newFake(t, Options{Helper: "helper"}, s)
			sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
			sp.Template = backend.Template{Digest: "sha256:t", Argv: []string{"", a, "/elsewhere"}, Dir: "/cache/t", SnapshotDir: t.TempDir()}
			if _, err := be.Warm(warmCtx(t), sp); err == nil || !strings.Contains(err.Error(), "fiberd's alone") {
				t.Fatalf("Warm = %v, want the argument refused", err)
			}
			if n := len(s.started()); n != 0 {
				t.Fatalf("%d helpers started", n)
			}
		})
	}
}

// TestARegistryTemplateNeedsItsSnapshot checks that a registry template
// without a snapshot is refused before a helper starts, since the helper
// would warm its own guest under the template's digest.
func TestARegistryTemplateNeedsItsSnapshot(t *testing.T) {
	s := says(kvmIntel)
	be := newFake(t, Options{Helper: "helper"}, s)
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	sp.Template = backend.Template{Digest: "sha256:t", Argv: []string{"/cache/t/zygote"}, Dir: "/cache/t", ZygoteSHA256: strings.Repeat("a", 64)}
	if _, err := be.Warm(warmCtx(t), sp); err == nil || !strings.Contains(err.Error(), "without a Hyperlight snapshot") {
		t.Fatalf("Warm = %v, want the template refused", err)
	}
	if n := len(s.started()); n != 0 {
		t.Fatalf("%d helpers started", n)
	}
}

// TestAnOperatorsTemplateMayPassHelperFlags checks that the refusal is for
// a registry template's author alone: an operator's own -template command
// passes what it likes.
func TestAnOperatorsTemplateMayPassHelperFlags(t *testing.T) {
	s := says(kvmIntel)
	be := newFake(t, Options{Helper: "helper"}, s)
	sp := warmSpec(filepath.Join(t.TempDir(), "run", "g1"))
	sp.Template = backend.Template{Digest: "sha256:local", Argv: []string{"guest", "--engine", "/run/e.sock"}}
	if _, err := be.Warm(warmCtx(t), sp); err != nil {
		t.Fatalf("Warm: %v", err)
	}
}

// TestHelperFlag checks that HelperFlag takes exactly what the protocol's
// argument grammar reads as one of fiberd's flags: one dash or two, the
// name, then = and a value or nothing. Three dashes, an abbreviation, a
// name with more after it and a bare dash are no flag of the grammar's,
// and so no helper's.
func TestHelperFlag(t *testing.T) {
	for arg, want := range map[string]bool{
		"--template-dir": true, "-template-dir": true, "--template-dir=/x": true, "-template-dir=/x": true, "--guest": true, "-guest": true, "--guest=": true,
		"-guest=/etc": true, "--engine": true, "-engine": true, "--engine=/e": true, "--engine==/e": true,
		"---guest": false, "--gu": false, "--templ": false, "--te=/x": false, "--g": false, "-g": false, "--e=/e": false, "--guests": false, "--guest-x": false,
		"--Guest": false, "guest": false, "/guest": false, "--=guest": false, "-": false, "--": false, "--port-range": false, "--heap-mb": false, "--init-ms": false,
	} {
		if got := HelperFlag(arg); got != want {
			t.Errorf("HelperFlag(%q) = %v, want %v", arg, got, want)
		}
	}
}
