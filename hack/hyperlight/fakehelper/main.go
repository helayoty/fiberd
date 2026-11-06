// Command fakehelper runs hack/hyperlight/fakehelper/helper as a process:
// hack/hyperlight/PROTOCOL.md without a hypervisor, so fiberd's hyperlight
// backend, the host runtime and the conformance suite can run in the
// Linux dev container. The Rust helper replaces it where KVM exists.
//
//	fakehelper --guest <path> [--init-ms N] [--engine <sock>] [--template-dir <dir>]  (fd 3 is the control socket)
//	fakehelper --version                                       (the facts READY carries, then template-dir)
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/fiberd/hack/hyperlight/fakehelper/helper"
)

func main() {
	guest := flag.String("guest", "", "guest binary (checked for existence only)")
	initMS := flag.Int("init-ms", 20, "pretend init time")
	engine := flag.String("engine", "", "the grant's device engine socket, which fibers reach through the helper")
	templateDir := flag.String("template-dir", "", "the template's snapshot, read-only (checked to be a directory only)")
	version := flag.Bool("version", false, "print the snapshot facts, and that it restores a template's snapshot, and exit")
	flag.Parse()
	if *version {
		fmt.Println(helper.Version)
		return
	}
	if _, err := os.Stat(*guest); err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: guest: %v\n", err)
		os.Exit(2)
	}
	var template string
	if *templateDir != "" {
		if st, err := os.Stat(*templateDir); err != nil {
			fmt.Fprintf(os.Stderr, "fakehelper: template-dir: %v\n", err)
			os.Exit(2)
		} else if !st.IsDir() {
			fmt.Fprintf(os.Stderr, "fakehelper: template-dir %s is not a directory\n", *templateDir)
			os.Exit(2)
		}
		// What the snapshot says of itself, which a fiber answers with.
		if b, err := os.ReadFile(filepath.Join(*templateDir, "metadata.json")); err == nil {
			template = strings.TrimSpace(string(b))
		}
	}
	ctl, err := net.FileConn(os.NewFile(3, "ctl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: fd 3 is not the control socket: %v\n", err)
		os.Exit(2)
	}
	time.Sleep(time.Duration(*initMS) * time.Millisecond)
	if err := helper.ServeTemplate(ctl, os.Stderr, *engine, template); err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: %v\n", err)
	}
}
