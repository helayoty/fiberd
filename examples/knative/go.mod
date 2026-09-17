// The Knative-over-Hyperlight example: its own module, so what it needs
// never lands in fiberd's own go.mod. It builds against the checkout it
// sits in.
module github.com/helayoty/fiberd/examples/knative

go 1.26

toolchain go1.26.7

require (
	github.com/helayoty/fiberd v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/helayoty/fiberd => ../..
