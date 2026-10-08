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
// that does not answer (000), leaves the agent running. An agent that
// crashes is started again. One that exits 0 by itself left because its
// job ended, so the script ends with it. SIGTERM otherwise ends the
// script cleanly, and only once the agent has drained.
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
		// drains makes the fake agent take a while to stop on SIGTERM and
		// write a marker when done. The script must not exit before that,
		// or slurmstepd kills the drain.
		drains bool
		// exit makes the fake agent exit with this code at once. A
		// "term" agent exits 0 on SIGTERM, as fiberd-slurm does.
		exit string
		// ends means the script exits by itself, with no SIGTERM.
		ends bool
	}{
		{name: "a healthy agent keeps running", code: "200"},
		{name: "an agent not answering yet is left alone", code: "000"},
		{name: "a 503 restarts the agent", code: "503", restarts: true},
		{name: "a 503 restarts an agent that exits 0 on SIGTERM", code: "503", exit: "term", restarts: true},
		{name: "SIGTERM waits for the agent to drain", code: "200", drains: true},
		{name: "a crashing agent is restarted", code: "200", exit: "1", restarts: true},
		{name: "an agent whose job ended is not restarted", code: "200", exit: "0", ends: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			starts := filepath.Join(dir, "starts")
			drained := filepath.Join(dir, "drained")
			agent := "echo start >> " + starts + "\nexec sleep 30\n"
			if tc.drains {
				// Its output goes elsewhere, so the test's pipes close when
				// the script exits, not when the agent does.
				agent = "exec >/dev/null 2>&1\necho start >> " + starts +
					"\ntrap 'kill $s; sleep 0.5; echo done > " + drained + "; exit 0' TERM\nsleep 30 & s=$!\nwait $s\n"
			}
			switch tc.exit {
			case "":
			case "term":
				agent = "echo start >> " + starts + "\ntrap 'kill $s; exit 0' TERM\nsleep 30 & s=$!\nwait $s\n"
			default:
				agent = "echo start >> " + starts + "\nexit " + tc.exit + "\n"
			}
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"fiberd-slurm": agent,
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
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
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
			if !tc.ends {
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("script = %v, want exit 0\n%s", err, out.String())
				}
			case <-time.After(15 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("script kept running, SIGTERM sent = %v\n%s", !tc.ends, out.String())
			}
			if _, err := os.Stat(drained); tc.drains && err != nil {
				t.Fatalf("script exited before the agent drained: %v\n%s", err, out.String())
			}
			if health := tc.code == "503"; health != strings.Contains(out.String(), "/healthz is 503") {
				t.Fatalf("restart log = %v, want %v\n%s", !health, health, out.String())
			}
		})
	}
}
