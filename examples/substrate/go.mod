// The Agent Substrate example: a sandbox-class herder (ateom-fiberd) whose
// actors are fibers. Its own module, so Substrate's proto and this
// example's dependencies never land in fiberd's go.mod. It builds against
// the checkout it sits in.
module github.com/helayoty/fiberd/examples/substrate

go 1.26

toolchain go1.26.7

require (
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/helayoty/fiberd v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	oras.land/oras-go/v2 v2.6.2 // indirect
)

replace github.com/helayoty/fiberd => ../..
