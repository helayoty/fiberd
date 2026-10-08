// Package cli is the plumbing fiberd's commands share. Run picks the
// subcommand of grant-issuer or zygotectl and turns its outcome into an
// exit code. ParseFlags marks a flag error as a usage error. Version is
// what every command's -version prints.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
)

// Command runs one subcommand on the arguments after its name.
type Command func(args []string) error

// Run dispatches args[0] to its command and returns the exit code. It is
// 0 on success or -h, 2 for a usage error, and 1 when the command fails.
// No subcommand, help, or an unknown one prints usage to stderr. A
// failure is logged to stderr.
func Run(args []string, usage string, cmds map[string]Command, stderr io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	switch cmd, ok := cmds[args[0]]; {
	case ok:
		err = cmd(args[1:])
	case args[0] == "-h", args[0] == "--help", args[0] == "help":
		_, _ = fmt.Fprintln(stderr, usage)
		return 0
	default:
		_, _ = fmt.Fprintln(stderr, usage)
		err = fmt.Errorf("unknown subcommand %q", args[0])
	}
	var ue usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		return 2
	}
	log.New(stderr, "", log.LstdFlags).Print(err)
	return 1
}

// usageError is a flag error the flag package has already reported.
type usageError struct{ error }

// ParseFlags parses args into fs, which reports its own errors to stderr.
func ParseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) error {
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	return nil
}
