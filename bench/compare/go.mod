// The activation comparison benchmark (docs/design/compare.md): its
// own module, so what it needs never lands in fiberd's own go.mod. It
// builds against the checkout it sits in, and borrows the Kubernetes
// example's small API client instead of client-go.
module github.com/Azure/fiberd/bench/compare

go 1.26.0

toolchain go1.26.7

require (
	github.com/Azure/fiberd v0.0.0
	github.com/Azure/fiberd/examples/kubernetes v0.0.0
	go.uber.org/goleak v1.3.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/go-jose/go-jose/v4 v4.1.8 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace (
	github.com/Azure/fiberd => ../..
	github.com/Azure/fiberd/examples/kubernetes => ../../examples/kubernetes
)
