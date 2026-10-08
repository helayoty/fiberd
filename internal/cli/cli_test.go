package cli

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"regexp"
	"slices"
	"testing"
)

// TestRun checks the exit code for each outcome and what reaches stderr.
// The one command is "go". It parses a -n flag and fails when told to.
func TestRun(t *testing.T) {
	const usage = "usage: tool go -n N"
	cases := []struct {
		name       string
		args       []string
		want       int
		wantArgs   []string // what the command was given; nil if not run
		wantStderr string   // a pattern stderr must match
	}{
		{name: "no subcommand is a usage error", want: 2, wantStderr: `^` + usage + `\n$`},
		{name: "help prints usage", args: []string{"help"}, want: 0, wantStderr: `^` + usage + `\n$`},
		{name: "-h prints usage", args: []string{"-h"}, want: 0, wantStderr: `^` + usage + `\n$`},
		{name: "--help prints usage", args: []string{"--help"}, want: 0, wantStderr: `^` + usage + `\n$`},
		{name: "an unknown subcommand prints usage and fails", args: []string{"stop"}, want: 1,
			wantStderr: `^` + usage + `\n\d{4}/\d\d/\d\d \d\d:\d\d:\d\d unknown subcommand "stop"\n$`},
		{name: "a command gets the arguments after its name", args: []string{"go", "-n", "3", "x"}, want: 0,
			wantArgs: []string{"-n", "3", "x"}, wantStderr: `^$`},
		{name: "-h on a command prints its flags and succeeds", args: []string{"go", "-h"}, want: 0,
			wantArgs: []string{"-h"}, wantStderr: `-n int`},
		{name: "a bad flag is a usage error the flag package reports", args: []string{"go", "-n", "x"}, want: 2,
			wantArgs: []string{"-n", "x"}, wantStderr: `^invalid value "x" for flag -n`},
		{name: "a failing command is logged with the time and fails", args: []string{"go", "fail"}, want: 1,
			wantArgs: []string{"fail"}, wantStderr: `^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d boom\n$`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var got []string
			cmds := map[string]Command{"go": func(args []string) error {
				got = args
				fs := flag.NewFlagSet("go", flag.ContinueOnError)
				fs.Int("n", 0, "a number")
				if err := ParseFlags(fs, args, &stderr); err != nil {
					return err
				}
				if fs.Arg(0) == "fail" {
					return errors.New("boom")
				}
				return nil
			}}
			code := Run(tc.args, usage, cmds, &stderr)
			if code != tc.want || !slices.Equal(got, tc.wantArgs) {
				t.Fatalf("exit %d, args %q, want %d, %q", code, got, tc.want, tc.wantArgs)
			}
			if !regexp.MustCompile(tc.wantStderr).MatchString(stderr.String()) {
				t.Fatalf("stderr %q, want it to match %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

// TestParseFlags checks which flag errors ParseFlags marks as usage
// errors. Help is not one, so Run can tell it apart.
func TestParseFlags(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantErr   bool
		wantHelp  bool
		wantUsage bool
	}{
		{name: "good flags are no error", args: []string{"-v"}},
		{name: "-h is flag.ErrHelp and not a usage error", args: []string{"-h"}, wantErr: true, wantHelp: true},
		{name: "an unknown flag is a usage error", args: []string{"-x"}, wantErr: true, wantUsage: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.Bool("v", false, "verbose")
			err := ParseFlags(fs, tc.args, io.Discard)
			var ue usageError
			if (err != nil) != tc.wantErr || errors.Is(err, flag.ErrHelp) != tc.wantHelp || errors.As(err, &ue) != tc.wantUsage {
				t.Fatalf("err = %v, want error %v, help %v, usage %v", err, tc.wantErr, tc.wantHelp, tc.wantUsage)
			}
		})
	}
}
