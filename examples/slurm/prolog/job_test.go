package prolog_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestJobRestartsUnhealthyAgent runs fiberd-job.sh with a fake
// fiberd-slurm and a fake curl that answers /healthz with a fixed code.
// A 503, which a poisoned audit spool answers, makes the script stop the
// agent and start it again in the same allocation. A 200, or a socket
// that does not answer (000), leaves the agent running. SIGTERM then ends
// the script cleanly.
func TestJobRestartsUnhealthyAgent(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script, err := filepath.Abs("fiberd-job.sh")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		code     string
		restarts bool
	}{
		{name: "a healthy agent keeps running", code: "200"},
		{name: "an agent not answering yet is left alone", code: "000"},
		{name: "a 503 restarts the agent", code: "503", restarts: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			starts := filepath.Join(dir, "starts")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"fiberd-slurm": "echo start >> " + starts + "\nexec sleep 30\n",
				"curl":         "printf %s " + tc.code + "\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "SLURM_JOB_ID=7",
				"FIBERD_STATE_ROOT="+filepath.Join(dir, "state"), "FIBERD_HEALTH_EVERY=0.1")
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			cmd.WaitDelay = 5 * time.Second
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			count := func() int {
				b, _ := os.ReadFile(starts)
				return strings.Count(string(b), "start")
			}
			if tc.restarts {
				for deadline := time.Now().Add(10 * time.Second); count() < 2; time.Sleep(20 * time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatalf("agent started %d times, want a restart\n%s", count(), out.String())
					}
				}
			} else {
				time.Sleep(1500 * time.Millisecond)
				if n := count(); n != 1 {
					t.Fatalf("agent started %d times, want 1\n%s", n, out.String())
				}
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("script = %v, want exit 0\n%s", err, out.String())
				}
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("script kept running after SIGTERM\n%s", out.String())
			}
			if tc.restarts != strings.Contains(out.String(), "/healthz is 503") {
				t.Fatalf("restart log = %v, want %v\n%s", !tc.restarts, tc.restarts, out.String())
			}
		})
	}
}
