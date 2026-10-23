// Command fakehelper runs hack/hyperlight/fakehelper/helper as a process:
// hack/hyperlight/PROTOCOL.md without a hypervisor, so fiberd's hyperlight
// backend, the host runtime and the conformance suite can run in the
// Linux dev container. The Rust helper replaces it where KVM exists.
//
//	fakehelper --guest <path> [--init-ms N] [--engine <sock>]  (fd 3 is the control socket)
//	fakehelper --version                                       (the facts READY carries)
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/helayoty/fiberd/hack/hyperlight/fakehelper/helper"
)

func main() {
	guest := flag.String("guest", "", "guest binary (checked for existence only)")
	initMS := flag.Int("init-ms", 20, "pretend init time")
	engine := flag.String("engine", "", "the grant's device engine socket, which fibers reach through the helper")
	version := flag.Bool("version", false, "print the snapshot facts and exit")
	flag.Parse()
	if *version {
		fmt.Println(helper.Facts)
		return
	}
	if _, err := os.Stat(*guest); err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: guest: %v\n", err)
		os.Exit(2)
	}
	ctl, err := net.FileConn(os.NewFile(3, "ctl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: fd 3 is not the control socket: %v\n", err)
		os.Exit(2)
	}
	time.Sleep(time.Duration(*initMS) * time.Millisecond)
	if err := helper.Serve(ctl, os.Stderr, *engine); err != nil {
		fmt.Fprintf(os.Stderr, "fakehelper: %v\n", err)
	}
}
