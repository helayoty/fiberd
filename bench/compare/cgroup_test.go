package compare

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCgroup(t *testing.T, dir, current string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCgroups(t *testing.T) {
	cases := []struct {
		name    string
		dirs    map[string]string // relative dir -> memory.current
		needle  string
		wantDir string
		wantSum int64
		wantErr bool
	}{
		{name: "pod uid with dashes under a systemd slice", dirs: map[string]string{
			"kubepods.slice/kubepods-pod1234_abcd.slice": "4096\n", "other": "1\n"},
			needle: "1234-abcd", wantDir: "kubepods.slice/kubepods-pod1234_abcd.slice", wantSum: 4096},
		{name: "cgroupfs driver keeps the dashes", dirs: map[string]string{"kubepods/burstable/pod1234-abcd": "8192\n"},
			needle: "1234-abcd", wantDir: "kubepods/burstable/pod1234-abcd", wantSum: 8192},
		{name: "missing", dirs: map[string]string{"a": "1\n"}, needle: "zzz", wantErr: true},
		{name: "unparsable memory.current", dirs: map[string]string{"pod1": "lots\n"}, needle: "pod1", wantDir: "pod1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for d, v := range tc.dirs {
				writeCgroup(t, filepath.Join(root, d), v)
			}
			dir, err := FindCgroup(root, tc.needle)
			if tc.wantDir == "" {
				if err == nil {
					t.Fatalf("found %s, want an error", dir)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if dir != filepath.Join(root, tc.wantDir) {
				t.Errorf("dir %s, want %s", dir, tc.wantDir)
			}
			sum, err := SumCgroups([]string{dir})
			if (err != nil) != tc.wantErr {
				t.Fatalf("sum err %v, want error %v", err, tc.wantErr)
			}
			if sum != tc.wantSum {
				t.Errorf("sum %d, want %d", sum, tc.wantSum)
			}
		})
	}
}
