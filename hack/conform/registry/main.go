// Command registry serves an OCI registry for conformance runs. Blobs
// are files under -dir, one per digest at <dir>/sha256/<hex>, so a run
// can read everything the registry holds (hack/conform/stub.sh
// seal-check). Manifests live in memory.
//
//	go run ./hack/conform/registry -addr 127.0.0.1:18500 -dir /tmp/blobs
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18500", "address to serve plain HTTP on")
	dir := flag.String("dir", "", "directory the blobs are kept in (required)")
	flag.Parse()
	if *dir == "" {
		log.Fatal("registry: -dir is required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}
	h := registry.New(registry.WithBlobHandler(registry.NewDiskBlobHandler(*dir)), registry.Logger(log.New(io.Discard, "", 0)))
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
