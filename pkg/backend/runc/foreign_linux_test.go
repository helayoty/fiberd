//go:build linux

package runc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/backend/proc"
)

// The container init in every dump test, and its mount table. Ids 200
// to 208 are the container's. The fiber's own copies carry 300 and up,
// and internal mounts anything under 20, neither of which the table
// holds.
const (
	zygotePID = 100
	fiberPID  = 110
)

const containerTable = `200 199 0:50 / / rw,relatime - overlay overlay rw
201 200 0:51 / /proc rw,nosuid - proc proc rw
202 200 0:52 / /dev rw,nosuid - tmpfs tmpfs rw,mode=755
203 200 0:53 / /sys ro,nosuid - sysfs sysfs ro
204 200 8:1 /run/w1 /host rw,relatime - ext4 /dev/sda1 rw
205 200 8:1 /cache/tpl /fiberd/template ro,nosuid,nodev - ext4 /dev/sda1 rw
206 202 0:6 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw
207 202 0:6 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw
208 201 0:51 /sys /proc/sys ro,nosuid - proc proc rw
`

// The mount ids the fake entries sit on. The container's are in the
// table above. The fiber's own copies and the internal mounts are not.
const (
	mntRootfs   = 200
	mntProc     = 201
	mntDev      = 202
	mntSys      = 203
	mntHost     = 204
	mntTemplate = 205
	mntNull     = 206
	mntURandom  = 207
	mntProcSys  = 208
	mntOwn      = 310 // a mount of the fiber's own namespace
	mntSock     = 8
	mntPipe     = 12
	mntAnon     = 14
	mntMemfd    = 15
)

func reg(mnt int, ino uint64) entryInfo  { return entryInfo{mntID: mnt, ino: ino, mode: unix.S_IFREG} }
func dirI(mnt int, ino uint64) entryInfo { return entryInfo{mntID: mnt, ino: ino, mode: unix.S_IFDIR} }
func chr(mnt int, ino uint64) entryInfo  { return entryInfo{mntID: mnt, ino: ino, mode: unix.S_IFCHR} }
func fifo(mnt int, ino uint64) entryInfo { return entryInfo{mntID: mnt, ino: ino, mode: unix.S_IFIFO} }

// Open flags as fdinfo prints them, octal.
const (
	flRead    = unix.O_RDONLY | unix.O_CLOEXEC
	flRW      = unix.O_RDWR | unix.O_CLOEXEC
	flLog     = unix.O_WRONLY | unix.O_APPEND | unix.O_CLOEXEC
	flReadDir = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
)

// fakeProc lays a /proc out under root for foreignDump. Each process
// has its tasks with their children lists, its maps, its map_files and
// fd entries as symlinks (so readlink gives the target) and the fdinfo
// of each descriptor. inspect answers from what the layout declared.
type fakeProc struct {
	t     *testing.T
	root  string
	infos map[string]entryInfo // entry path under root
}

func newFakeProc(t *testing.T) *fakeProc {
	f := &fakeProc{t: t, root: t.TempDir(), infos: map[string]entryInfo{}}
	f.write(fmt.Sprintf("%d/mountinfo", zygotePID), containerTable)
	f.process(fiberPID)
	return f
}

func (f *fakeProc) path(rel string) string { return filepath.Join(f.root, rel) }

func (f *fakeProc) write(rel, data string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.path(rel)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.path(rel), []byte(data), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) appendTo(rel, line string) {
	f.t.Helper()
	fh, err := os.OpenFile(f.path(rel), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.WriteString(line); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) link(rel, target string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.path(rel)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, f.path(rel)); err != nil {
		f.t.Fatal(err)
	}
}

// process makes pid with the given tasks, the leader alone by default,
// each with no children yet, and empty maps, map_files and fd.
func (f *fakeProc) process(pid int, tids ...int) {
	f.t.Helper()
	if len(tids) == 0 {
		tids = []int{pid}
	}
	for _, tid := range tids {
		f.write(fmt.Sprintf("%d/task/%d/children", pid, tid), "")
	}
	f.write(fmt.Sprintf("%d/maps", pid), "")
	for _, d := range []string{"map_files", "fd", "fdinfo"} {
		if err := os.MkdirAll(f.path(fmt.Sprintf("%d/%s", pid, d)), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
}

// children lists kids as task tid's children, the way the kernel does,
// space-separated with a trailing space.
func (f *fakeProc) children(pid, tid int, kids ...int) {
	f.t.Helper()
	var sb strings.Builder
	for _, k := range kids {
		fmt.Fprintf(&sb, "%d ", k)
	}
	f.write(fmt.Sprintf("%d/task/%d/children", pid, tid), sb.String())
}

// mapping gives pid a mapping of target with perms as maps prints them.
func (f *fakeProc) mapping(pid int, start, end uint64, perms, target string, info entryInfo) {
	f.t.Helper()
	name := fmt.Sprintf("%x-%x", start, end)
	f.appendTo(fmt.Sprintf("%d/maps", pid), fmt.Sprintf("%08x-%08x %s 00000000 00:78 %d   %s\n", start, end, perms, info.ino, target))
	rel := fmt.Sprintf("%d/map_files/%s", pid, name)
	f.link(rel, target)
	f.infos[rel] = info
}

// fd gives pid descriptor n of target, opened with flags.
func (f *fakeProc) fd(pid, n, flags int, target string, info entryInfo) {
	f.t.Helper()
	rel := fmt.Sprintf("%d/fd/%d", pid, n)
	f.link(rel, target)
	f.write(fmt.Sprintf("%d/fdinfo/%d", pid, n), fmt.Sprintf("pos:\t0\nflags:\t0%o\nmnt_id:\t%d\n", flags, info.mntID))
	f.infos[rel] = info
}

func (f *fakeProc) inspect(p string) (entryInfo, error) {
	rel, err := filepath.Rel(f.root, p)
	if err != nil {
		return entryInfo{}, err
	}
	info, ok := f.infos[rel]
	if !ok {
		return entryInfo{}, unix.ENOENT
	}
	return info, nil
}

func (f *fakeProc) launcher() *launcher { return &launcher{procRoot: f.root, inspect: f.inspect} }

// TestForeignDump pins what a park records and names of the files a
// fiber holds through the container's mounts, and what refuses it.
func TestForeignDump(t *testing.T) {
	cases := []struct {
		name string
		tree func(f *fakeProc)
		// want is the record in order. Nil with wantErr "" is an empty
		// record.
		want    []foreignEntry
		wantErr string
	}{
		{
			name: "a static template holds its text mapping alone",
			tree: func(f *fakeProc) {
				f.mapping(fiberPID, 0x400000, 0x47e000, "r-xp", "/zyg", reg(mntRootfs, 0x13))
				// The fiber's own namespace and the internal mounts are
				// criu's business. A memfd reads as deleted, and is set
				// aside by its mount before its name is looked at.
				f.fd(fiberPID, 3, flRW, "/workspace/data", reg(mntOwn, 5))
				f.fd(fiberPID, 4, flRead, "pipe:[77]", fifo(mntPipe, 77))
				f.fd(fiberPID, 5, flRW, "socket:[88]", entryInfo{mntID: mntSock, ino: 88, mode: unix.S_IFSOCK})
				f.fd(fiberPID, 6, flRW, "anon_inode:[eventpoll]", entryInfo{mntID: mntAnon, ino: 9})
				f.mapping(fiberPID, 0x7f0000000000, 0x7f0000001000, "rw-s", "/memfd:arena (deleted)", reg(mntMemfd, 3))
			},
			want: []foreignEntry{{Key: "file[c8:13]", Path: "/zyg", Mount: mountRootfs, Type: typeFile, Access: "r"}},
		},
		{
			name: "a dynamic template with children holds files on every mount",
			tree: func(f *fakeProc) {
				f.process(fiberPID, fiberPID, 111)
				f.children(fiberPID, fiberPID, 130, 140) // 140 is already gone
				f.children(fiberPID, 111, 130)           // listed twice, walked once
				f.process(130)
				f.children(130, 130, 131)
				f.process(131)
				f.mapping(fiberPID, 0x400000, 0x47e000, "r-xp", "/usr/bin/python3", reg(mntRootfs, 0x100))
				f.mapping(fiberPID, 0x7f0000000000, 0x7f0000100000, "r--p", "/usr/lib/libpython.so", reg(mntRootfs, 0x101))
				f.mapping(fiberPID, 0x7f0010000000, 0x7f0010001000, "rw-s", "/host/shared.bin", reg(mntHost, 0x200))
				f.mapping(fiberPID, 0x7f0020000000, 0x7f0020001000, "r--p", "/host/data.bin", reg(mntHost, 0x201))
				f.fd(fiberPID, 0, flRead, "/dev/null", chr(mntNull, 3))
				f.fd(fiberPID, 2, flLog, "/host/zygote.log", reg(mntHost, 0x2a))
				f.fd(fiberPID, 3, flRW, "socket:[999]", entryInfo{mntID: mntSock, ino: 999, mode: unix.S_IFSOCK})
				f.fd(fiberPID, 4, flRead, "/fiberd/template/app.pyc", reg(mntTemplate, 0x300))
				f.fd(fiberPID, 5, flRead, "/dev/urandom", chr(mntURandom, 9))
				f.fd(fiberPID, 6, flRW, "/host/shared.bin", reg(mntHost, 0x200))
				f.fd(fiberPID, 7, flReadDir, "/usr/lib", dirI(mntRootfs, 0x102))
				f.fd(fiberPID, 8, flRW, "/workspace/data", reg(mntOwn, 5))
				// The child shares the text and the log. The grandchild
				// appends to the file the root only maps for reading.
				f.mapping(130, 0x400000, 0x47e000, "r-xp", "/usr/bin/python3", reg(mntRootfs, 0x100))
				f.fd(130, 1, flLog, "/host/zygote.log", reg(mntHost, 0x2a))
				f.fd(131, 11, flLog, "/host/data.bin", reg(mntHost, 0x201))
			},
			want: []foreignEntry{
				{Key: "file[c8:100]", Path: "/usr/bin/python3", Mount: mountRootfs, Type: typeFile, Access: "r"},
				{Key: "file[c8:101]", Path: "/usr/lib/libpython.so", Mount: mountRootfs, Type: typeFile, Access: "r"},
				{Key: "file[c8:102]", Path: "/usr/lib", Mount: mountRootfs, Type: typeDir, Access: "r"},
				{Key: "file[cc:200]", Path: "/host/shared.bin", Mount: mountHost, Type: typeFile, Access: "rw"},
				{Key: "file[cc:201]", Path: "/host/data.bin", Mount: mountHost, Type: typeFile, Access: "rw", Append: true},
				{Key: "file[cc:2a]", Path: "/host/zygote.log", Mount: mountHost, Type: typeFile, Access: "w", Append: true},
				{Key: "file[cd:300]", Path: "/fiberd/template/app.pyc", Mount: mountTemplate, Type: typeFile, Access: "r"},
				{Key: "file[ce:3]", Path: "/dev/null", Mount: mountDev, Type: typeDev, Access: "r"},
				{Key: "file[cf:9]", Path: "/dev/urandom", Mount: mountDev, Type: typeDev, Access: "r"},
			},
		},
		{
			name: "a fiber with nothing foreign writes an empty record",
			tree: func(f *fakeProc) {
				f.fd(fiberPID, 3, flRW, "/workspace/data", reg(mntOwn, 5))
				f.mapping(fiberPID, 0x400000, 0x47e000, "r-xp", "/zyg", reg(mntOwn, 0x13))
			},
		},
		{
			name: "a deleted file is refused",
			tree: func(f *fakeProc) {
				f.mapping(fiberPID, 0x7f0000000000, 0x7f0000100000, "r--p", "/usr/lib/libx.so (deleted)", reg(mntRootfs, 0x55))
			},
			wantErr: "is deleted",
		},
		{
			name:    "a file on the container's /proc is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/proc/110/status", reg(mntProc, 7)) },
			wantErr: "on the container's /proc mount",
		},
		{
			name:    "a file on the container's /sys is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/sys/kernel/mm/x", reg(mntSys, 7)) },
			wantErr: "on the container's /sys mount",
		},
		{
			name:    "a file on the /dev tmpfs is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRW, "/dev/shm/x", reg(mntDev, 7)) },
			wantErr: "on the container's /dev mount",
		},
		{
			name:    "a file on a read-only /proc bind is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/proc/sys/kernel/x", reg(mntProcSys, 7)) },
			wantErr: "on the container's /proc/sys mount",
		},
		{
			name:    "a path off its mount is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/etc/passwd", reg(mntHost, 7)) },
			wantErr: "is not under its mount /host",
		},
		{
			name:    "an unclean path is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/host/../etc/passwd", reg(mntHost, 7)) },
			wantErr: "not absolute and clean",
		},
		{
			name:    "a fifo on the rootfs is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/tmp/pipe", fifo(mntRootfs, 44)) },
			wantErr: "a fifo, not a regular file or directory",
		},
		{
			name:    "a device bind holding another path is refused",
			tree:    func(f *fakeProc) { f.fd(fiberPID, 3, flRead, "/dev/null", chr(mntURandom, 3)) },
			wantErr: "on the device bind at /dev/urandom",
		},
		{
			name: "a tree that is gone is an error",
			tree: func(f *fakeProc) {
				if err := os.RemoveAll(f.path(strconv.Itoa(fiberPID))); err != nil {
					f.t.Fatal(err)
				}
			},
			wantErr: "foreign files of 110",
		},
		{
			name: "a container init without a mount table is an error",
			tree: func(f *fakeProc) {
				if err := os.Remove(f.path(fmt.Sprintf("%d/mountinfo", zygotePID))); err != nil {
					f.t.Fatal(err)
				}
			},
			wantErr: "container mounts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeProc(t)
			tc.tree(f)
			dir := filepath.Join(t.TempDir(), "images", "fiber")
			got, err := f.launcher().foreignDump(proc.Dumped{PID: fiberPID, Zygote: zygotePID, Workspace: true}, dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("foreignDump = %q, %v, want an error with %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("foreignDump: %v", err)
			}
			var wantArgs []string
			for _, e := range tc.want {
				wantArgs = append(wantArgs, "--external", e.Key)
			}
			if !reflect.DeepEqual(got, wantArgs) {
				t.Fatalf("args\n got %q\nwant %q", got, wantArgs)
			}
			b, err := os.ReadFile(filepath.Join(dir, foreignFile))
			if err != nil {
				t.Fatalf("record: %v", err)
			}
			rec, err := decodeForeign(b)
			if err != nil {
				t.Fatalf("record %s: %v", b, err)
			}
			want := tc.want
			if want == nil {
				want = []foreignEntry{}
			}
			if !reflect.DeepEqual(rec, want) {
				t.Fatalf("record\n got %+v\nwant %+v", rec, want)
			}
			// The same tree lists the same, in the same order.
			again, err := f.launcher().foreignDump(proc.Dumped{PID: fiberPID, Zygote: zygotePID, Workspace: true}, dir)
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Fatalf("second listing = %q, %v, want %q", again, err, got)
			}
		})
	}
}

// home is where a restore test lays this home's files out.
type home struct {
	rootfs, work, staged, dev, outside string
}

func (h home) file(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h home) symlink(t *testing.T, target, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// record marshals entries as a dump would write them.
func record(t *testing.T, entries ...foreignEntry) string {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// requireOpenat2 skips where the kernel has no openat2, which the
// reopen refuses to do without.
func requireOpenat2(t *testing.T) {
	t.Helper()
	fd, err := unix.Openat2(unix.AT_FDCWD, ".", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if errors.Is(err, unix.ENOSYS) {
		t.Skip("no openat2 on this kernel")
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
}

// openFDs counts this process's descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// sameFile says f is the file at p.
func sameFile(t *testing.T, f *os.File, p string) bool {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	pi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(fi, pi)
}

// TestForeignInherit pins how a restore reopens the recorded files on
// this home, and what it refuses.
func TestForeignInherit(t *testing.T) {
	requireOpenat2(t)
	type wantFile struct {
		key   string
		flags int    // O_ACCMODE and O_APPEND bits
		at    string // the host path the file must be, relative to the home root
		dir   bool
	}
	cases := []struct {
		name    string
		staged  bool // the grant has a staged template here
		fakeDev bool // reopen devices from the home's dev directory instead of /dev
		layout  func(t *testing.T, h home)
		// record is the file beside the images. "" leaves none, and a
		// value starting with "[" or "{" or "n" is written as is.
		record  func(t *testing.T) string
		want    []wantFile
		wantErr string
	}{
		{
			name:   "no record restores nothing",
			record: func(*testing.T) string { return "" },
		},
		{
			name:   "a regular file reopens read-only",
			layout: func(t *testing.T, h home) { h.file(t, filepath.Join(h.rootfs, "usr/lib/libc.so"), "libc") },
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/usr/lib/libc.so", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			want: []wantFile{{key: "file[c8:1]", flags: unix.O_RDONLY, at: "rootfs/usr/lib/libc.so"}},
		},
		{
			name:   "a run directory file reopens for writing with append kept",
			layout: func(t *testing.T, h home) { h.file(t, filepath.Join(h.work, "zygote.log"), "log") },
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[cc:2a]", Path: "/host/zygote.log", Mount: mountHost, Type: typeFile, Access: "w", Append: true})
			},
			want: []wantFile{{key: "file[cc:2a]", flags: unix.O_WRONLY | unix.O_APPEND, at: "work/zygote.log"}},
		},
		{
			name:   "a shared file reopens read-write",
			layout: func(t *testing.T, h home) { h.file(t, filepath.Join(h.work, "shared.bin"), "data") },
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[cc:200]", Path: "/host/shared.bin", Mount: mountHost, Type: typeFile, Access: "rw"})
			},
			want: []wantFile{{key: "file[cc:200]", flags: unix.O_RDWR, at: "work/shared.bin"}},
		},
		{
			name: "directories reopen as directories, the mount root too",
			layout: func(t *testing.T, h home) {
				if err := os.MkdirAll(filepath.Join(h.rootfs, "usr/lib"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			record: func(t *testing.T) string {
				return record(t,
					foreignEntry{Key: "file[c8:102]", Path: "/usr/lib", Mount: mountRootfs, Type: typeDir, Access: "r"},
					foreignEntry{Key: "file[cc:1]", Path: "/host", Mount: mountHost, Type: typeDir, Access: "r"})
			},
			want: []wantFile{
				{key: "file[c8:102]", flags: unix.O_RDONLY, at: "rootfs/usr/lib", dir: true},
				{key: "file[cc:1]", flags: unix.O_RDONLY, at: "work", dir: true},
			},
		},
		{
			name: "a link in the middle resolves inside the root, absolute or not",
			layout: func(t *testing.T, h home) {
				h.file(t, filepath.Join(h.rootfs, "usr/lib/libc.so"), "libc")
				h.symlink(t, "usr/lib", filepath.Join(h.rootfs, "lib"))
				h.symlink(t, "/usr/lib", filepath.Join(h.rootfs, "lib64"))
			},
			record: func(t *testing.T) string {
				return record(t,
					foreignEntry{Key: "file[c8:1]", Path: "/lib/libc.so", Mount: mountRootfs, Type: typeFile, Access: "r"},
					foreignEntry{Key: "file[c8:2]", Path: "/lib64/libc.so", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			want: []wantFile{
				{key: "file[c8:1]", flags: unix.O_RDONLY, at: "rootfs/usr/lib/libc.so"},
				{key: "file[c8:2]", flags: unix.O_RDONLY, at: "rootfs/usr/lib/libc.so"},
			},
		},
		{
			name: "a link at the path is refused",
			layout: func(t *testing.T, h home) {
				h.file(t, filepath.Join(h.rootfs, "etc/hosts"), "hosts")
				h.symlink(t, "hosts", filepath.Join(h.rootfs, "etc/passwd"))
			},
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/etc/passwd", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "is a symlink, not file",
		},
		{
			name: "a link at the path to a host file outside is refused",
			layout: func(t *testing.T, h home) {
				h.file(t, filepath.Join(h.outside, "secret"), "host secret")
				h.symlink(t, filepath.Join(h.outside, "secret"), filepath.Join(h.rootfs, "etc/shadow"))
			},
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/etc/shadow", Mount: mountRootfs, Type: typeFile, Access: "rw"})
			},
			wantErr: "is a symlink, not file",
		},
		{
			name: "a link in the middle that points out of the root finds nothing",
			layout: func(t *testing.T, h home) {
				h.file(t, filepath.Join(h.outside, "secret"), "host secret")
				h.symlink(t, "../outside", filepath.Join(h.rootfs, "up"))
			},
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/up/secret", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "no such file",
		},
		{
			name: "a fifo is refused without blocking",
			layout: func(t *testing.T, h home) {
				if err := os.MkdirAll(filepath.Join(h.rootfs, "tmp"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(h.rootfs, "tmp/pipe"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/tmp/pipe", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "is a fifo, not file",
		},
		{
			name:   "a file of another type than recorded is refused",
			layout: func(t *testing.T, h home) { h.file(t, filepath.Join(h.rootfs, "usr/lib"), "not a directory") },
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/usr/lib", Mount: mountRootfs, Type: typeDir, Access: "r"})
			},
			wantErr: "is a regular file, not dir",
		},
		{
			name: "a missing file is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[c8:1]", Path: "/usr/lib/libc.so", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "no such file",
		},
		{
			name: "a staged template this home lacks is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[cd:300]", Path: "/fiberd/template/app.pyc", Mount: mountTemplate, Type: typeFile, Access: "r"})
			},
			wantErr: "does not have here",
		},
		{
			name:   "a template file reopens from the staged copy",
			staged: true,
			layout: func(t *testing.T, h home) { h.file(t, filepath.Join(h.staged, "app.pyc"), "pyc") },
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[cd:300]", Path: "/fiberd/template/app.pyc", Mount: mountTemplate, Type: typeFile, Access: "r"})
			},
			want: []wantFile{{key: "file[cd:300]", flags: unix.O_RDONLY, at: "staged/app.pyc"}},
		},
		{
			name: "device binds reopen from the host's nodes",
			record: func(t *testing.T) string {
				return record(t,
					foreignEntry{Key: "file[ce:3]", Path: "/dev/null", Mount: mountDev, Type: typeDev, Access: "rw"},
					foreignEntry{Key: "file[cf:9]", Path: "/dev/urandom", Mount: mountDev, Type: typeDev, Access: "r"})
			},
			want: []wantFile{
				{key: "file[ce:3]", flags: unix.O_RDWR, at: "/dev/null"},
				{key: "file[cf:9]", flags: unix.O_RDONLY, at: "/dev/urandom"},
			},
		},
		{
			name:    "a node in the dev directory that is no device is refused",
			fakeDev: true,
			layout:  func(t *testing.T, h home) { h.file(t, filepath.Join(h.dev, "null"), "") },
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[ce:3]", Path: "/dev/null", Mount: mountDev, Type: typeDev, Access: "rw"})
			},
			wantErr: "is a regular file, not dev",
		},
		{
			name: "a path that is no device bind is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[ce:3]", Path: "/dev/bogus", Mount: mountDev, Type: typeDev, Access: "r"})
			},
			wantErr: "is not a device bind",
		},
		{
			name:    "a malformed record is refused",
			record:  func(*testing.T) string { return "{" },
			wantErr: "malformed",
		},
		{
			name:    "a null record is refused",
			record:  func(*testing.T) string { return "null" },
			wantErr: "malformed",
		},
		{
			name: "a record with a field the restore does not know is refused",
			record: func(*testing.T) string {
				return `[{"key":"file[1:1]","path":"/x","mount":"rootfs","type":"file","access":"r","owner":"root"}]`
			},
			wantErr: "malformed",
		},
		{
			name:    "a record with something after the list is refused",
			record:  func(*testing.T) string { return `[] []` },
			wantErr: "malformed",
		},
		{
			name: "a key of another shape is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[zz:1]", Path: "/x", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "is not file[<hex>:<hex>]",
		},
		{
			name: "a mount key is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "mnt[/host]", Path: "/x", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "is not file[<hex>:<hex>]",
		},
		{
			name: "an unknown mount is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[1:1]", Path: "/tmp/x", Mount: "tmp", Type: typeFile, Access: "r"})
			},
			wantErr: `unknown mount "tmp"`,
		},
		{
			name: "an unknown access is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[1:1]", Path: "/x", Mount: mountRootfs, Type: typeFile, Access: "x"})
			},
			wantErr: `unknown access "x"`,
		},
		{
			name: "a type its mount cannot hold is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[1:1]", Path: "/x", Mount: mountRootfs, Type: typeDev, Access: "r"})
			},
			wantErr: "a device cannot be on the rootfs mount",
		},
		{
			name: "a path off its mount is refused",
			record: func(t *testing.T) string {
				return record(t, foreignEntry{Key: "file[1:1]", Path: "/etc/x", Mount: mountHost, Type: typeFile, Access: "r"})
			},
			wantErr: "is not under its mount /host",
		},
		{
			name: "a repeated key is refused",
			record: func(t *testing.T) string {
				return record(t,
					foreignEntry{Key: "file[1:1]", Path: "/x", Mount: mountRootfs, Type: typeFile, Access: "r"},
					foreignEntry{Key: "file[1:1]", Path: "/y", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "repeats",
		},
		{
			name:   "what was opened is closed when a later file fails",
			layout: func(t *testing.T, h home) { h.file(t, filepath.Join(h.rootfs, "usr/lib/libc.so"), "libc") },
			record: func(t *testing.T) string {
				return record(t,
					foreignEntry{Key: "file[c8:1]", Path: "/usr/lib/libc.so", Mount: mountRootfs, Type: typeFile, Access: "r"},
					foreignEntry{Key: "file[c8:2]", Path: "/usr/lib/libm.so", Mount: mountRootfs, Type: typeFile, Access: "r"})
			},
			wantErr: "no such file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			h := home{
				rootfs:  filepath.Join(base, "rootfs"),
				work:    filepath.Join(base, "work"),
				staged:  filepath.Join(base, "staged"),
				dev:     filepath.Join(base, "dev"),
				outside: filepath.Join(base, "outside"),
			}
			for _, d := range []string{h.rootfs, h.work, h.staged, h.dev, h.outside} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.layout != nil {
				tc.layout(t, h)
			}
			dir := filepath.Join(base, "images")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if rec := tc.record(t); rec != "" {
				if err := os.WriteFile(filepath.Join(dir, foreignFile), []byte(rec), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			spec := backend.WarmSpec{GrantUID: "g1", WorkDir: h.work}
			l := &launcher{}
			if tc.fakeDev {
				l.devDir = h.dev
			}
			if tc.staged {
				l.setStaged(spec, h.staged)
			}
			before := openFDs(t)
			got, err := l.foreignInherit(spec, dir, h.rootfs)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					for _, g := range got {
						_ = g.File.Close()
					}
					t.Fatalf("foreignInherit = %v, %v, want an error with %q", got, err, tc.wantErr)
				}
				if after := openFDs(t); after != before {
					t.Fatalf("%d descriptors open after the failure, %d before", after, before)
				}
				return
			}
			if err != nil {
				t.Fatalf("foreignInherit: %v", err)
			}
			defer func() {
				for _, g := range got {
					_ = g.File.Close()
				}
			}()
			if len(got) != len(tc.want) {
				t.Fatalf("got %d files, want %d", len(got), len(tc.want))
			}
			for i, w := range tc.want {
				g := got[i]
				if g.Key != w.key {
					t.Errorf("file %d: key %q, want %q", i, g.Key, w.key)
				}
				fl, err := unix.FcntlInt(g.File.Fd(), unix.F_GETFL, 0)
				if err != nil {
					t.Fatal(err)
				}
				if fl&(unix.O_ACCMODE|unix.O_APPEND) != w.flags {
					t.Errorf("file %d (%s): flags %#o, want %#o", i, w.key, fl&(unix.O_ACCMODE|unix.O_APPEND), w.flags)
				}
				at := w.at
				if !filepath.IsAbs(at) {
					at = filepath.Join(base, at)
				}
				if !sameFile(t, g.File, at) {
					t.Errorf("file %d (%s) is not %s", i, w.key, at)
				}
				fi, err := g.File.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if fi.IsDir() != w.dir {
					t.Errorf("file %d (%s): directory %v, want %v", i, w.key, fi.IsDir(), w.dir)
				}
			}
		})
	}
}

// TestForeignEntryChecks pins the shape checks both sides of a
// checkpoint apply to an entry.
func TestForeignEntryChecks(t *testing.T) {
	cases := []struct {
		name    string
		entry   foreignEntry
		wantErr string
	}{
		{name: "a file on the rootfs", entry: foreignEntry{Path: "/usr/lib/libc.so", Mount: mountRootfs, Type: typeFile, Access: "r"}},
		{name: "the run directory itself", entry: foreignEntry{Path: "/host", Mount: mountHost, Type: typeDir, Access: "r"}},
		{name: "a template file", entry: foreignEntry{Path: backend.TemplateMount + "/app", Mount: mountTemplate, Type: typeFile, Access: "rw", Append: true}},
		{name: "a device bind", entry: foreignEntry{Path: "/dev/zero", Mount: mountDev, Type: typeDev, Access: "r"}},
		{name: "a relative path", entry: foreignEntry{Path: "usr/lib", Mount: mountRootfs, Type: typeFile, Access: "r"}, wantErr: "not absolute and clean"},
		{name: "a path with a trailing slash", entry: foreignEntry{Path: "/usr/lib/", Mount: mountRootfs, Type: typeDir, Access: "r"}, wantErr: "not absolute and clean"},
		{name: "a path with a dot segment", entry: foreignEntry{Path: "/host/./x", Mount: mountHost, Type: typeFile, Access: "r"}, wantErr: "not absolute and clean"},
		{name: "a prefix that is not a directory", entry: foreignEntry{Path: "/hostile", Mount: mountHost, Type: typeFile, Access: "r"}, wantErr: "is not under its mount /host"},
		{name: "a file on a device bind", entry: foreignEntry{Path: "/dev/null", Mount: mountDev, Type: typeFile, Access: "r"}, wantErr: "a file cannot be on a device bind"},
		{name: "a directory that writes", entry: foreignEntry{Path: "/usr/lib", Mount: mountRootfs, Type: typeDir, Access: "rw"}, wantErr: "a directory opens read-only"},
		{name: "an unknown type", entry: foreignEntry{Path: "/x", Mount: mountRootfs, Type: "socket", Access: "r"}, wantErr: `unknown type "socket"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkEntry(tc.entry)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkEntry: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkEntry = %v, want an error with %q", err, tc.wantErr)
			}
		})
	}
}

// TestForeignAccess pins how a mapping's and a descriptor's needs are
// read and joined.
func TestForeignAccess(t *testing.T) {
	cases := []struct {
		name  string
		maps  string
		entry string
		fd    int // fdinfo flags, -1 for a mapping
		want  string
		app   bool
	}{
		{name: "text maps read", maps: "00400000-0047e000 r-xp 00000000 00:78 19   /zyg\n", entry: "400000-47e000", fd: -1, want: "r"},
		{name: "a private writable mapping reads", maps: "00600000-00601000 rw-p 00000000 00:78 19   /zyg\n", entry: "600000-601000", fd: -1, want: "r"},
		{name: "a shared writable mapping reads and writes", maps: "7f00000000-7f00001000 rw-s 00000000 00:78 20   /host/shm\n", entry: "7f00000000-7f00001000", fd: -1, want: "rw"},
		{name: "a mapping gone from the table reads", maps: "", entry: "400000-47e000", fd: -1, want: "r"},
		{name: "a descriptor open for reading", fd: flRead, want: "r"},
		{name: "a log descriptor appends", fd: flLog, want: "w", app: true},
		{name: "a descriptor open both ways", fd: flRW | unix.O_APPEND, want: "rw", app: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.fd < 0 {
				if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(tc.maps), 0o600); err != nil {
					t.Fatal(err)
				}
				m, err := readMaps(filepath.Join(dir, "maps"))
				if err != nil {
					t.Fatal(err)
				}
				if got := m.access(tc.entry); got != tc.want {
					t.Fatalf("access = %q, want %q", got, tc.want)
				}
				return
			}
			if err := os.WriteFile(filepath.Join(dir, "fdinfo"), []byte(fmt.Sprintf("pos:\t0\nflags:\t0%o\nmnt_id:\t29\n", tc.fd)), 0o600); err != nil {
				t.Fatal(err)
			}
			got, app, err := fdAccess(filepath.Join(dir, "fdinfo"))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want || app != tc.app {
				t.Fatalf("fdAccess = %q, %v, want %q, %v", got, app, tc.want, tc.app)
			}
		})
	}
	t.Run("the union keeps every need", func(t *testing.T) {
		cases := []struct{ a, b, want string }{
			{"r", "r", "r"}, {"r", "w", "rw"}, {"w", "r", "rw"}, {"w", "w", "w"}, {"rw", "r", "rw"}, {"r", "rw", "rw"},
		}
		for _, tc := range cases {
			if got := unionAccess(tc.a, tc.b); got != tc.want {
				t.Errorf("unionAccess(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		}
	})
}

// TestReopenLease checks that a lease the tenant holds on a recorded
// file refuses the restore at once, where a plain open would wait out
// the lease break time (45 s by default) for every such file, and that
// the file criu is handed carries no O_NONBLOCK. The test takes the
// lease itself, which needs only to own the file.
func TestReopenLease(t *testing.T) {
	cases := []struct {
		name    string
		lease   int // F_RDLCK, or F_UNLCK for none
		access  string
		wantErr error
	}{
		{name: "no lease reopens for writing without O_NONBLOCK", lease: unix.F_UNLCK, access: "w"},
		{name: "a read lease lets a read through", lease: unix.F_RDLCK, access: "r"},
		{name: "a read lease refuses a write at once", lease: unix.F_RDLCK, access: "w", wantErr: unix.EWOULDBLOCK},
		{name: "a read lease refuses read-write at once", lease: unix.F_RDLCK, access: "rw", wantErr: unix.EWOULDBLOCK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x.pyc")
			if err := os.WriteFile(p, []byte("pyc"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.lease != unix.F_UNLCK {
				holder, err := os.Open(p)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = holder.Close() })
				if _, err := unix.FcntlInt(holder.Fd(), unix.F_SETLEASE, tc.lease); err != nil {
					t.Skipf("no lease on this file system: %v", err)
				}
				t.Cleanup(func() { _, _ = unix.FcntlInt(holder.Fd(), unix.F_SETLEASE, unix.F_UNLCK) })
			}
			pfd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(pfd) }()
			start := time.Now()
			f, err := reopen(pfd, foreignEntry{Key: "file[c8:1]", Path: "/x.pyc", Mount: mountRootfs, Type: typeFile, Access: tc.access})
			if took := time.Since(start); took > 5*time.Second {
				t.Fatalf("reopen took %s, want it bounded well under the lease break time", took)
			}
			if tc.wantErr != nil {
				if f != nil {
					_ = f.Close()
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("reopen = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer func() { _ = f.Close() }()
			fl, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			if fl&unix.O_NONBLOCK != 0 {
				t.Fatalf("flags %#o carry O_NONBLOCK, want it cleared before criu gets the file", fl)
			}
		})
	}
}
