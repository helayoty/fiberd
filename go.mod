module github.com/helayoty/fiberd

go 1.26

// buf v1.73 (hack/tools) needs a 1.26.7 toolchain; `go tool -modfile` picks
// the toolchain from this file, so pin it here and let GOTOOLCHAIN=auto fetch it.
toolchain go1.26.7

require (
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/google/go-containerregistry v0.22.1
	github.com/opencontainers/image-spec v1.1.1
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	oras.land/oras-go/v2 v2.6.2
)

require (
	github.com/opencontainers/go-digest v1.0.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
