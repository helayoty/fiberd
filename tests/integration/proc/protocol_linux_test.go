//go:build linux && integration

package proctest

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// rawZygote starts refzygote the way the backend does, with one end of a
// socketpair at fd 3 and its stdio on a log file under dir, sends it
// PREPARE none as its whole setup, and returns fiberd's end once
// READY was read. Closing the connection ends the zygote and every child
// it has.
func rawZygote(t *testing.T, dir string) (*net.UnixConn, *bufio.Reader) {
	t.Helper()
	return rawZygoteWith(t, dir, nil, "PREPARE none\n")
}

// rawZygoteWith is rawZygote with the zygote wrapped in the given
// command (strace, setpriv) and the setup lines given, sent before READY
// is awaited. An empty setup sends nothing, for a test of the setup
// phase itself, and READY is then not awaited either.
func rawZygoteWith(t *testing.T, dir string, wrap []string, setup string) (*net.UnixConn, *bufio.Reader) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours := os.NewFile(uintptr(fds[0]), "ctl")
	theirs := os.NewFile(uintptr(fds[1]), "ctl-child")
	logf, err := os.Create(filepath.Join(dir, "zygote.log"))
	if err != nil {
		t.Fatal(err)
	}
	argv := append(append([]string{}, wrap...), zygoteBin, "--heap-mb", "4")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.ExtraFiles = []*os.File{theirs}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = []string{"PATH=/usr/bin:/bin", "FIBERD_OWN_MNTNS=1"} // as the proc backend starts it
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", zygoteBin, err)
	}
	_ = theirs.Close()
	_ = logf.Close()
	conn, err := net.FileConn(ours)
	_ = ours.Close()
	if err != nil {
		t.Fatal(err)
	}
	uc := conn.(*net.UnixConn)
	t.Cleanup(func() {
		_ = uc.Close()
		_ = cmd.Wait()
	})
	rd := bufio.NewReader(uc)
	if setup == "" {
		return uc, rd
	}
	if _, err := uc.Write([]byte(setup)); err != nil {
		t.Fatal(err)
	}
	if got := readLine(t, uc, rd); got != "READY" {
		t.Fatalf("first line %q, want READY", got)
	}
	return uc, rd
}

// send writes one line to a raw zygote. A CLONE line takes the channel
// fiberd would attach, with the record queued on it.
func send(t *testing.T, uc *net.UnixConn, line string) {
	t.Helper()
	if strings.HasPrefix(line, "CLONE ") {
		sendClone(t, uc, line)
		return
	}
	if _, err := uc.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
}

// readLine returns the zygote's next line, or "" when none comes within
// two seconds.
func readLine(t *testing.T, uc *net.UnixConn, rd *bufio.Reader) string {
	t.Helper()
	_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := rd.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(line, "\n")
}

// tcpEndpoint is a "tcp://host:0" endpoint of exactly n characters. The
// host is padding, since refzygote binds the wildcard address.
func tcpEndpoint(n int) string {
	const head, tail = "tcp://", ":0"
	return head + strings.Repeat("h", n-len(head)-len(tail)) + tail
}

// TestControlProtocolLines sends the zygote lines the backend never would
// and checks the exact answers. A fence over 127 characters is refused,
// never cut, because a cut fence would not match fiberd's and its fiber
// would run unknown to it.
func TestControlProtocolLines(t *testing.T) {
	long := strings.Repeat("f", 2000)
	cases := []struct {
		name string
		// line is sent with the test's directory substituted for %s.
		line string
		want string
	}{
		{
			name: "a fence of 127 characters is born",
			line: "CLONE " + strings.Repeat("a", 127) + " %s/a.sock 2000 - -",
			want: "CLONED " + strings.Repeat("a", 127) + " ",
		},
		{
			name: "a fence of 128 characters is refused, not cut",
			line: "CLONE " + strings.Repeat("b", 128) + " %s/b.sock 2000 - -",
			want: "ERROR " + strings.Repeat("b", 127) + " fence too long",
		},
		{
			name: "an over-long fence gets its ERROR line, cut to 127 characters",
			line: "CLONE " + long + " %s/c.sock 2000 - -",
			want: "ERROR " + long[:127] + " fence too long",
		},
		{
			name: "an over-long fence on a malformed CLONE is cut the same way",
			line: "CLONE " + long,
			want: "ERROR " + long[:127] + " malformed CLONE",
		},
		{
			// A tcp endpoint binds the wildcard whatever its host says,
			// so the length is all that is checked here.
			name: "an endpoint of 1023 characters is born",
			line: "CLONE ep1023 " + tcpEndpoint(1023) + " 2000 - -",
			want: "CLONED ep1023 ",
		},
		{
			name: "an endpoint of 1024 characters is refused",
			line: "CLONE ep1024 " + tcpEndpoint(1024) + " 2000 - -",
			want: "ERROR ep1024 endpoint too long (at most 1023 characters)",
		},
		{
			// The session field is hex, so one with a space is one field.
			name: "a session is born and named",
			line: "CLONE s1 %s/s1.sock 2000 - " + hex.EncodeToString([]byte("conv 42")),
			want: "CLONED s1 ",
		},
		{
			name: "a session of 1023 bytes is born",
			line: "CLONE s2 %s/s2.sock 2000 - " + strings.Repeat("61", 1023),
			want: "CLONED s2 ",
		},
		{
			name: "a session of 1024 bytes is refused",
			line: "CLONE s3 %s/s3.sock 2000 - " + strings.Repeat("61", 1024),
			want: "ERROR s3 session too long (at most 1023 bytes)",
		},
		{
			name: "a session with a NUL byte is refused",
			line: "CLONE s4 %s/s4.sock 2000 - 610062",
			want: "ERROR s4 session holds a NUL byte",
		},
		{
			name: "a CLONE without the session field is malformed",
			line: "CLONE s5 %s/s5.sock 2000 -",
			want: "ERROR s5 malformed CLONE",
		},
		{
			name: "PING is not a message",
			line: "PING",
			want: "ERROR ? unknown message",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			uc, rd := rawZygote(t, dir)
			line := tc.line
			if strings.Contains(line, "%s") {
				line = fmt.Sprintf(line, dir)
			}
			send(t, uc, line)
			got := readLine(t, uc, rd)
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("reply %.200q, want it to start with %.200q", got, tc.want)
			}
		})
	}
}

// TestSetupPhase pins the lines around READY. fiberd's setup lines
// come first and PREPARE ends them, so READY means the zygote's own mount
// namespace, the one every mntns fiber copies, is built. A line out of
// place is a protocol error. Before PREPARE it ends the zygote, since the
// fiberd is not the one the zygote was written for. After READY a setup
// line would leave a path uncovered that fiberd asked for, so it
// refuses every later mntns CLONE instead (fail closed), while a CLONE
// without mntns is still born. All of this is new with the zygote's own
// namespace. The old zygote said READY first and took HIDE at any time.
func TestSetupPhase(t *testing.T) {
	cases := []struct {
		name string
		// setup is sent before READY is awaited. Empty means the test
		// sends its own lines and expects no READY.
		setup string
		// lines are sent after READY, each answered by the next reply,
		// which must start with want. %s is the test's directory.
		lines []string
		want  []string
		// gone means the zygote ends without a READY, so its first
		// reply is end of stream.
		gone bool
	}{
		{
			name:  "PREPARE none refuses a mntns CLONE and births the rest",
			setup: "PREPARE none\n",
			lines: []string{"CLONE a %s/a.sock 2000 - - pidns,mntns", "CLONE b %s/b.sock 2000 - - pidns"},
			want:  []string{"ERROR a refused: no mount namespace was prepared before READY", "CLONED b "},
		},
		{
			name:  "a setup line after READY refuses every mntns CLONE",
			setup: "PREPARE mntns\n",
			lines: []string{"HIDE /etc", "CLONE c %s/c.sock 2000 - - pidns,mntns", "CLONE d %s/d.sock 2000 - - pidns"},
			want: []string{
				"ERROR ? HIDE after READY refused",
				"ERROR c refused: the mount namespace cannot hide what fiberd asked (a setup line (HIDE, DROP, RUNDIR or PREPARE) came after READY)",
				"CLONED d ",
			},
		},
		{
			name:  "a second PREPARE is refused the same way",
			setup: "PREPARE mntns\n",
			lines: []string{"PREPARE mntns", "CLONE e %s/e.sock 2000 - - pidns,mntns"},
			want:  []string{"ERROR ? PREPARE after READY refused", "ERROR e refused"},
		},
		{
			name:  "a CLONE before PREPARE ends the zygote without READY",
			lines: []string{"CLONE f %s/f.sock 2000 - - pidns"},
			gone:  true,
		},
		{
			name:  "an unknown line before PREPARE ends the zygote without READY",
			lines: []string{"PING"},
			gone:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			uc, rd := rawZygoteWith(t, dir, nil, tc.setup)
			for i, line := range tc.lines {
				if strings.Contains(line, "%s") {
					line = fmt.Sprintf(line, dir)
				}
				send(t, uc, line)
				got := readLine(t, uc, rd)
				if tc.gone {
					if got != "" {
						t.Fatalf("reply %q to %q, want the zygote gone without a word", got, line)
					}
					continue
				}
				if !strings.HasPrefix(got, tc.want[i]) {
					t.Fatalf("reply %.200q to %q, want it to start with %.200q", got, line, tc.want[i])
				}
			}
			if tc.gone {
				b, _ := os.ReadFile(filepath.Join(dir, "zygote.log"))
				if !strings.Contains(string(b), "before READY") {
					t.Fatalf("zygote log %q, want it to name the line that came before READY", b)
				}
			}
		})
	}
}

// TestSetupPathTooLong pins that the zygote keeps a HIDE or DROP path
// whole or refuses it, never cuts it. A path of PATH_MAX (4096) bytes or
// more is refused as it arrives, with a reason naming the line, and the
// warm fails closed, as it does for more paths than the zygote holds. A
// path one byte shorter is kept whole, so a fiber is born. The stage 4
// zygote kept every path in a slot the size of a line, so a long one got
// as far as the mounts and failed there with "File name too long".
// Since the slot is PATH_MAX now, the refusal pins that nothing is cut
// to fit it.
func TestSetupPathTooLong(t *testing.T) {
	// below is an absolute path of exactly n bytes under dir, made of
	// components short enough for the kernel, which need not exist.
	below := func(dir string, n int) string {
		p := dir
		for len(p)+1+200 < n-1 {
			p += "/" + strings.Repeat("d", 200)
		}
		return p + "/" + strings.Repeat("e", n-len(p)-1)
	}
	cases := []struct {
		name string
		// setup is sent before READY, with %s the path of n bytes under
		// the test's directory.
		setup string
		n     int
		// want is the zygote's first line. On READY a mntns CLONE
		// follows, which must be born.
		want string
	}{
		{name: "a HIDE path of 4095 bytes is kept whole", setup: "HIDE %s\nPREPARE mntns\n", n: 4095, want: "READY"},
		{name: "a HIDE path of 4096 bytes is refused", setup: "HIDE %s\nPREPARE mntns\n", n: 4096, want: "ERROR ? HIDE: path too long"},
		{name: "a HIDE path of 5000 bytes is refused", setup: "HIDE %s\nPREPARE mntns\n", n: 5000, want: "ERROR ? HIDE: path too long"},
		{name: "a HIDE path of 5000 bytes is refused without a namespace too", setup: "HIDE %s\nPREPARE none\n", n: 5000, want: "ERROR ? HIDE: path too long"},
		{name: "a DROP path of 4096 bytes is refused", setup: "DROP %s\nPREPARE mntns\n", n: 4096, want: "ERROR ? DROP: path too long"},
		{name: "a DROP path of 5000 bytes is refused", setup: "DROP %s\nPREPARE mntns\n", n: 5000, want: "ERROR ? DROP: path too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := below(dir, tc.n)
			if len(path) != tc.n {
				t.Fatalf("the path is %d bytes, want %d", len(path), tc.n)
			}
			uc, rd := rawZygoteWith(t, dir, nil, "")
			if _, err := uc.Write([]byte(fmt.Sprintf(tc.setup, path))); err != nil {
				t.Fatal(err)
			}
			if got := readLine(t, uc, rd); got != tc.want {
				t.Fatalf("first line %.300q, want %q", got, tc.want)
			}
			if tc.want == "READY" {
				send(t, uc, fmt.Sprintf("CLONE a %s/a.sock 2000 - - pidns,mntns", dir))
				if got := readLine(t, uc, rd); !strings.HasPrefix(got, "CLONED a ") {
					t.Fatalf("reply %.300q to a mntns CLONE, want CLONED a", got)
				}
				return
			}
			// The zygote ends on the refusal, and its log names it.
			if got := readLine(t, uc, rd); got != "" {
				t.Fatalf("reply %.300q after the refusal, want the zygote gone", got)
			}
			b, _ := os.ReadFile(filepath.Join(dir, "zygote.log"))
			if why := strings.TrimPrefix(tc.want, "ERROR ? "); !strings.Contains(string(b), why+" refused") {
				t.Fatalf("zygote log %.300q, want it to say %q", b, why+" refused")
			}
		})
	}
}
