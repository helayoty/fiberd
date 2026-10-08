package criu

import (
	"os"
	"path/filepath"
	"slices"
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
		sidecar string // contents of MountsFile; "" for none
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
