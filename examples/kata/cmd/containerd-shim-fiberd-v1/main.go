// Command containerd-shim-fiberd-v1 is a containerd runtime-v2 shim whose
// containers are fibers on a fiberd home: the Kata shape (a shim that
// creates a sandbox instead of a process) with fiberd's protocol behind
// it. Install it on the node's PATH and name it in containerd's config:
//
//	[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fiberd]
//	  runtime_type = "io.containerd.fiberd.v1"
//	  pod_annotations = ["io.fiberd/*"]
//
// then a RuntimeClass with handler `fiberd` makes a Pod's containers
// fibers of the session and home its annotations name.
package main

import (
	"context"

	"github.com/containerd/containerd/v2/pkg/shim"

	fshim "github.com/helayoty/fiberd/examples/kata/shim"
)

func main() {
	fshim.RegisterPlugin()
	shim.Run(context.Background(), fshim.NewManager())
}
