package artifact_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// fakeELF is a 64-bit little-endian ELF executable with the given
// program headers and nothing else: enough for debug/elf to parse, not
// enough to run.
func fakeELF(t *testing.T, progs ...elf.ProgType) []byte {
	t.Helper()
	var b bytes.Buffer
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	hdr := elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: uint16(len(progs)), Shentsize: 64}
	if err := binary.Write(&b, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	for _, p := range progs {
		ph := elf.Prog64{Type: uint32(p), Flags: uint32(elf.PF_R), Align: 1}
		if err := binary.Write(&b, binary.LittleEndian, ph); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

// TestLinking checks that only an ELF without a program interpreter is
// static, and that Build records the answer in the config.
func TestLinking(t *testing.T) {
	cases := []struct {
		name    string
		content func(t *testing.T) []byte // nil for no file at all
		want    string
	}{
		{name: "an ELF with no interpreter", content: func(t *testing.T) []byte { return fakeELF(t, elf.PT_LOAD, elf.PT_DYNAMIC) }, want: artifact.LinkStatic},
		{name: "an ELF with an interpreter", content: func(t *testing.T) []byte { return fakeELF(t, elf.PT_INTERP, elf.PT_LOAD) }, want: artifact.LinkDynamic},
		{name: "a shell script", content: func(*testing.T) []byte { return []byte("#!/bin/sh\nexit 0\n") }, want: artifact.LinkDynamic},
		{name: "an empty file", content: func(*testing.T) []byte { return nil }, want: artifact.LinkDynamic},
		{name: "a missing file", want: artifact.LinkDynamic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			zygote := filepath.Join(root, "z")
			if tc.content != nil {
				if err := os.WriteFile(zygote, tc.content(t), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if got := artifact.Linking(zygote); got != tc.want {
				t.Fatalf("Linking = %q, want %q", got, tc.want)
			}
			if tc.content == nil {
				return
			}
			out := filepath.Join(root, "out")
			if _, err := artifact.Build(context.Background(), artifact.BuildOptions{Zygote: zygote, Out: out, SkipImages: true}); err != nil {
				t.Fatalf("Build: %v", err)
			}
			cfg, err := artifact.ReadConfig(out)
			if err != nil || cfg.Linking != tc.want {
				t.Fatalf("built config linking = %q (%v), want %q", cfg.Linking, err, tc.want)
			}
		})
	}
}
