package criu

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestMountPoints(t *testing.T) {
	cases := []struct {
		name, info string
		want       []string
	}{
		{name: "empty", info: ""},
		{name: "table order", info: "22 1 0:21 / / rw - overlay overlay rw\n" +
			"40 22 254:1 /docker/x/resolv.conf /etc/resolv.conf rw - ext4 /dev/vda1 rw\n",
			want: []string{"/", "/etc/resolv.conf"}},
		{name: "escapes undone", info: `41 22 0:50 / /mnt/a\040b rw - tmpfs tmpfs rw` + "\n" + `42 22 0:51 / /mnt/back\134slash rw - tmpfs tmpfs rw`,
			want: []string{"/mnt/a b", `/mnt/back\slash`}},
		{name: "short lines skipped", info: "garbage\n43 22 0:52 / /x rw - tmpfs tmpfs rw\n", want: []string{"/x"}},
		{name: "escapes that are not three octal digits are kept", info: `44 22 0:53 / /mnt/x\4 rw - tmpfs tmpfs rw` + "\n" +
			`45 22 0:54 / /mnt/y\9zz rw - tmpfs tmpfs rw` + "\n" + `46 22 0:55 / /mnt/z\400 rw - tmpfs tmpfs rw`,
			want: []string{`/mnt/x\4`, `/mnt/y\9zz`, `/mnt/z\400`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MountPoints(tc.info); !slices.Equal(got, tc.want) {
				t.Fatalf("MountPoints = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRestoreMounts(t *testing.T) {
	cases := []struct {
		name    string
		sidecar string // contents of MountsFile, "" for none
		asDir   bool   // MountsFile is a directory, so it cannot be read
		want    []string
		wantErr bool
	}{
		{name: "no mount namespace", want: nil},
		{name: "no file mounts", sidecar: "null", want: []string{"--root", "/r", "--external", "mnt[]"}},
		{name: "file mounts by name", sidecar: `[{"name":"fm0","path":"/etc/resolv.conf"},{"name":"fm1","path":"/etc/hosts"}]`,
			want: []string{"--root", "/r", "--external", "mnt[]", "--external", "mnt[fm0]:/etc/resolv.conf", "--external", "mnt[fm1]:/etc/hosts"}},
		{name: "corrupt", sidecar: "{", wantErr: true},
		{name: "unreadable", asDir: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.sidecar != "" {
				if err := os.WriteFile(filepath.Join(dir, MountsFile), []byte(tc.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.asDir {
				if err := os.Mkdir(filepath.Join(dir, MountsFile), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			got, err := RestoreMounts(dir, "/r")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("RestoreMounts = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDumpMountsIn checks that each single-file mount of a tree's mount
// table is named in the dump arguments, in table order, and recorded
// beside the images for RestoreMounts to hand back by name. Directory
// mounts and mount points the tree's root does not have are left to
// criu's own detection.
func TestDumpMountsIn(t *testing.T) {
	line := func(mp string) string { return "40 22 254:1 / " + mp + " rw - ext4 /dev/vda1 rw\n" }
	cases := []struct {
		name     string
		info     string   // the mount table, "" for no mountinfo at all
		files    []string // regular files under the tree's root
		dirs     []string // directories under the tree's root
		dir      func(t *testing.T) string
		wantArgs []string
		wantSide string // the sidecar's contents
		wantIs   error
	}{
		{name: "file mounts are named and recorded, directory mounts skipped",
			info:     line("/") + line("/etc/resolv.conf") + line("/proc") + line("/missing") + line("/etc/hosts"),
			files:    []string{"etc/resolv.conf", "etc/hosts"},
			dirs:     []string{"proc"},
			wantArgs: []string{"--external", "mnt[]", "--external", "mnt[/etc/resolv.conf]:fm0", "--external", "mnt[/etc/hosts]:fm1"},
			wantSide: `[{"name":"fm0","path":"/etc/resolv.conf"},{"name":"fm1","path":"/etc/hosts"}]`},
		{name: "an escaped mount point is unescaped", info: line(`/mnt/a\040b`), files: []string{"mnt/a b"},
			wantArgs: []string{"--external", "mnt[]", "--external", "mnt[/mnt/a b]:fm0"},
			wantSide: `[{"name":"fm0","path":"/mnt/a b"}]`},
		{name: "no file mounts", info: line("/") + line("/proc"), dirs: []string{"proc"},
			wantArgs: []string{"--external", "mnt[]"}, wantSide: "null"},
		{name: "no mount table", wantIs: os.ErrNotExist},
		{name: "the image directory cannot be made", info: line("/"), dir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "images")
		}, wantIs: syscall.ENOTDIR},
		{name: "the sidecar cannot be written", info: line("/"), dir: func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, MountsFile), 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantIs: syscall.EISDIR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procDir := t.TempDir()
			if tc.info != "" {
				if err := os.WriteFile(filepath.Join(procDir, "mountinfo"), []byte(tc.info), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, d := range append(slices.Clone(tc.dirs), "") {
				if err := os.MkdirAll(filepath.Join(procDir, "root", d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tc.files {
				path := filepath.Join(procDir, "root", f)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("mounted"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(t.TempDir(), "images")
			if tc.dir != nil {
				dir = tc.dir(t)
			}
			args, err := dumpMountsIn(procDir, dir)
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("dumpMountsIn = %q, %v, want %v", args, err, tc.wantIs)
				}
				return
			}
			if err != nil || !slices.Equal(args, tc.wantArgs) {
				t.Fatalf("dumpMountsIn = %q, %v, want %q", args, err, tc.wantArgs)
			}
			if side, err := os.ReadFile(filepath.Join(dir, MountsFile)); err != nil || string(side) != tc.wantSide {
				t.Fatalf("sidecar = %q, %v, want %q", side, err, tc.wantSide)
			}
			var restore []string
			for i := 2; i+1 < len(args); i += 2 {
				name, path, _ := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(args[i+1], "mnt["), "]"), "]:")
				restore = append(restore, "--external", "mnt["+path+"]:"+name)
			}
			got, err := RestoreMounts(dir, "/newroot")
			if want := append([]string{"--root", "/newroot", "--external", "mnt[]"}, restore...); err != nil || !slices.Equal(got, want) {
				t.Fatalf("RestoreMounts = %q, %v, want %q", got, err, want)
			}
		})
	}
}
