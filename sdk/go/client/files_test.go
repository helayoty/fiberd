package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/sdk/go/client"
)

// fakeFiles serves the file calls from what a case set, and records what
// each call received. The other calls stay unimplemented.
type fakeFiles struct {
	grantv1.UnimplementedFibersServer
	// err answers every file call once it read its request, or once
	// Download sent its chunks.
	err error
	// chunks are what Download sends.
	chunks []*grantv1.FileChunk
	// hold keeps Download open after its chunks until the caller leaves.
	hold bool
	// list is what ListFiles answers.
	list []*grantv1.FileInfo

	mu       sync.Mutex
	header   *grantv1.UploadHeader
	sizes    []int // the length of each upload data message
	data     []byte
	complete bool // an upload reached the caller's end and was answered
	download *grantv1.DownloadRequest
	listed   *grantv1.ListFilesRequest
	ended    chan struct{} // closed when Upload returns
}

func (f *fakeFiles) Upload(stream grantv1.Fibers_UploadServer) error {
	defer close(f.ended)
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		f.mu.Lock()
		if h := m.GetHeader(); h != nil {
			f.header = h
		} else {
			f.sizes = append(f.sizes, len(m.GetData()))
			f.data = append(f.data, m.GetData()...)
		}
		f.mu.Unlock()
		if f.err != nil {
			return f.err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.complete = true
	sum := sha256.Sum256(f.data)
	return stream.SendAndClose(&grantv1.FileInfo{Path: f.header.GetPath(), Size: uint64(len(f.data)), Mode: f.header.GetMode(), Sha256: sum[:]})
}

func (f *fakeFiles) Download(req *grantv1.DownloadRequest, stream grantv1.Fibers_DownloadServer) error {
	f.mu.Lock()
	f.download = req
	f.mu.Unlock()
	for _, c := range f.chunks {
		if err := stream.Send(c); err != nil {
			return err
		}
	}
	if f.hold {
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	return f.err
}

func (f *fakeFiles) ListFiles(_ context.Context, req *grantv1.ListFilesRequest) (*grantv1.ListFilesResponse, error) {
	f.mu.Lock()
	f.listed = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &grantv1.ListFilesResponse{Files: f.list}, nil
}

// serveFiles serves f over bufconn and returns a client of it.
func serveFiles(t *testing.T, f *fakeFiles) *client.Client {
	t.Helper()
	f.ended = make(chan struct{})
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	grantv1.RegisterFibersServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := client.New(conn)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// homeError is the status fiberd's own mapping gives code.
func homeError(code core.StatusCode, msg string) error {
	return (&rpc.Server{Issuer: "https://issuer.test", RetryAfter: 2 * time.Second}).ToError(code, errors.New(msg))
}

// isA reports whether err is or wraps a T.
func isA[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// is reports whether an error is or wraps target.
func is(target error) func(error) bool {
	return func(err error) bool { return errors.Is(err, target) }
}

// pattern is n bytes that differ from their neighbors, so a chunk out of
// order shows.
func pattern(n int64) []byte {
	b := make([]byte, max(n, 0))
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// sameInfo compares two FileInfos field by field.
func sameInfo(a, b client.FileInfo) bool {
	return a.Path == b.Path && a.Size == b.Size && a.Mode == b.Mode && a.Directory == b.Directory && bytes.Equal(a.SHA256, b.SHA256)
}

// Upload sends the header, then exactly size bytes in chunks of at most
// 1 MiB. A reader that does not hold size bytes fails on the caller's
// side, and fiberd never sees the upload complete.
func TestUpload(t *testing.T) {
	const mib = rpc.MaxChunk
	sum := sha256.Sum256(pattern(3))
	errDisk := errors.New("disk gone")
	cases := []struct {
		name string
		size int64
		// body is the reader. Unset, it is pattern(size).
		body      func() io.Reader
		opts      []client.UploadOption
		serverErr error
		// noStream means the call fails before it opens a stream.
		noStream  bool
		wantSizes []int
		wantMode  uint32
		wantSHA   []byte
		// wantErr checks the error. Unset, the upload succeeds.
		wantErr func(error) bool
	}{
		{name: "an empty file sends the header alone, its size set to zero", size: 0},
		{name: "a nil reader is an empty file", size: 0, body: func() io.Reader { return nil }},
		{name: "one byte is one chunk", size: 1, wantSizes: []int{1}},
		{name: "exactly 1 MiB is one full chunk", size: mib, wantSizes: []int{mib}},
		{name: "1 MiB and one byte is a full chunk and a one-byte chunk", size: mib + 1, wantSizes: []int{mib, 1}},
		{name: "3 MiB is three full chunks", size: 3 * mib, wantSizes: []int{mib, mib, mib}},
		{name: "mode and sha256 reach the header", size: 3, opts: []client.UploadOption{client.WithMode(0o600), client.WithSHA256(sum[:])},
			wantSizes: []int{3}, wantMode: 0o600, wantSHA: sum[:]},
		{name: "a mode keeps only its permission bits", size: 3, opts: []client.UploadOption{client.WithMode(fs.ModeDir | fs.ModeSetuid | 0o755)},
			wantSizes: []int{3}, wantMode: 0o755},
		{name: "a short reader fails on the caller's side", size: 10, body: func() io.Reader { return bytes.NewReader(pattern(5)) },
			wantErr: is(client.ErrSize)},
		{name: "a reader short by a whole chunk fails on the caller's side", size: mib + 1, body: func() io.Reader { return bytes.NewReader(pattern(mib)) },
			wantErr: is(client.ErrSize)},
		{name: "a long reader fails on the caller's side", size: 4, body: func() io.Reader { return bytes.NewReader(pattern(5)) },
			wantErr: is(client.ErrSize)},
		{name: "a reader with data for a size of zero is long, and no stream opens", size: 0, body: func() io.Reader { return bytes.NewReader(pattern(1)) },
			noStream: true, wantErr: is(client.ErrSize)},
		{name: "the reader's own error fails the upload", size: 4, body: func() io.Reader { return iotest.ErrReader(errDisk) },
			wantErr: func(err error) bool { return errors.Is(err, errDisk) && !errors.Is(err, client.ErrSize) }},
		{name: "a negative size fails before any stream opens", size: -1, body: func() io.Reader { return bytes.NewReader(nil) },
			noStream: true, wantErr: is(client.ErrSize)},
		{name: "an unknown fiber is NotFound", size: 3, serverErr: homeError(core.NotFound, "fiber f is unknown"),
			wantErr: client.NotFound},
		{name: "a grant without a workspace is *NoWorkspace", size: 0, serverErr: homeError(core.NoWorkspace, "fiber f has no workspace"),
			wantErr: isA[*client.NoWorkspace]},
		{name: "a file over the budget is *QuotaExceeded while its data is still going", size: 3 * mib,
			serverErr: homeError(core.OverBudget, "the file is larger than the grant's disk budget"),
			wantErr:   isA[*client.QuotaExceeded]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFiles{err: tc.serverErr}
			c := serveFiles(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			want := pattern(tc.size)
			var body io.Reader = bytes.NewReader(want)
			if tc.body != nil {
				body = tc.body()
			}
			info, err := c.Upload(ctx, "fiber-1", "data/in.bin", tc.size, body, tc.opts...)
			if tc.wantErr != nil {
				if !tc.wantErr(err) {
					t.Fatalf("Upload = %+v, %v (%T)", info, err, err)
				}
				if !tc.noStream {
					// The handler ends once the stream does. Should it never
					// have started, it saw nothing either.
					select {
					case <-f.ended:
					case <-time.After(2 * time.Second):
					}
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.complete {
					t.Fatal("fiberd saw the upload complete")
				}
				// A reader that broke its size stops short of fiberd
				// holding every declared byte.
				if errors.Is(err, client.ErrSize) && f.header != nil && int64(len(f.data)) >= tc.size {
					t.Fatalf("fiberd got all %d declared bytes of a reader that broke its size", tc.size)
				}
				if tc.noStream && f.header != nil {
					t.Fatalf("fiberd got header %v", f.header)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			h := f.header
			if h.GetFiberId() != "fiber-1" || h.GetPath() != "data/in.bin" || h.Size == nil || h.GetSize() != uint64(tc.size) ||
				h.GetMode() != tc.wantMode || !bytes.Equal(h.GetSha256(), tc.wantSHA) {
				t.Fatalf("header = %v, want size %d set, mode %o and sha256 %x", h, tc.size, tc.wantMode, tc.wantSHA)
			}
			if !slices.Equal(f.sizes, tc.wantSizes) {
				t.Fatalf("chunks = %v, want %v", f.sizes, tc.wantSizes)
			}
			if !bytes.Equal(f.data, want) {
				t.Fatalf("fiberd got %d bytes that differ from the %d sent", len(f.data), len(want))
			}
			got := sha256.Sum256(want)
			wantInfo := client.FileInfo{Path: "data/in.bin", Size: uint64(tc.size), Mode: fs.FileMode(tc.wantMode), SHA256: got[:]}
			if !sameInfo(info, wantInfo) {
				t.Fatalf("info = %+v, want %+v", info, wantInfo)
			}
		})
	}
}

// readIn drains r through a buffer of n bytes and stops at io.EOF.
func readIn(r io.Reader, n int) ([]byte, error) {
	var out []byte
	buf := make([]byte, n)
	for {
		k, err := r.Read(buf)
		out = append(out, buf[:k]...)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// Download waits for the first chunk, so a refusal comes from Download
// itself. The reader serves every chunk's data in order and describes the
// file as the first chunk did.
func TestDownload(t *testing.T) {
	info := &grantv1.FileInfo{Path: "out/result.bin", Size: 6, Mode: 0o640}
	wantInfo := client.FileInfo{Path: "out/result.bin", Size: 6, Mode: 0o640}
	data := func(s string) *grantv1.FileChunk { return &grantv1.FileChunk{Data: []byte(s)} }
	cases := []struct {
		name      string
		offset    uint64
		chunks    []*grantv1.FileChunk
		serverErr error
		// buf is the size of each Read.
		buf  int
		want string
		// wantErr checks Download's error, wantReadErr the reader's.
		wantErr     func(error) bool
		wantReadErr func(error) bool
	}{
		{name: "chunks are put back together in order", buf: 64,
			chunks: []*grantv1.FileChunk{{Info: info, Data: []byte("ab")}, data("cd"), data(""), data("ef")}, want: "abcdef"},
		{name: "a one-byte buffer drains every chunk", buf: 1,
			chunks: []*grantv1.FileChunk{{Info: info, Data: []byte("abc")}, data("def")}, want: "abcdef"},
		{name: "a first chunk without data still carries the info", buf: 4,
			chunks: []*grantv1.FileChunk{{Info: info}, data("abcdef")}, want: "abcdef"},
		{name: "an empty file is the info alone", buf: 4, chunks: []*grantv1.FileChunk{{Info: info}}},
		{name: "the offset reaches fiberd", offset: 4, buf: 4,
			chunks: []*grantv1.FileChunk{{Info: info, Data: []byte("ef")}}, want: "ef"},
		{name: "a missing file is NotFound from Download", serverErr: homeError(core.NotFound, "out/result.bin: file does not exist"),
			wantErr: client.NotFound},
		{name: "a grant without a workspace is *NoWorkspace from Download", serverErr: homeError(core.NoWorkspace, "fiber f has no workspace"),
			wantErr: isA[*client.NoWorkspace]},
		{name: "a stream that ends before any chunk fails Download", wantErr: is(io.ErrUnexpectedEOF)},
		{name: "a first chunk without info fails Download", chunks: []*grantv1.FileChunk{data("ab")},
			wantErr: func(err error) bool { return err != nil }},
		{name: "an error after the first chunk comes from Read", buf: 4,
			chunks:      []*grantv1.FileChunk{{Info: info, Data: []byte("ab")}}, serverErr: homeError(core.Internal, "disk gone"), want: "ab",
			wantReadErr: func(err error) bool { return status.Code(err) == codes.Internal }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFiles{chunks: tc.chunks, err: tc.serverErr}
			c := serveFiles(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := c.Download(ctx, "fiber-1", "out/result.bin", tc.offset)
			if tc.wantErr != nil {
				if r != nil || !tc.wantErr(err) {
					t.Fatalf("Download = %v, %v (%T)", r, err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			if !sameInfo(r.Info(), wantInfo) {
				t.Fatalf("info = %+v, want %+v", r.Info(), wantInfo)
			}
			got, err := readIn(r, tc.buf)
			if string(got) != tc.want {
				t.Fatalf("read %q, want %q", got, tc.want)
			}
			switch {
			case tc.wantReadErr != nil && !tc.wantReadErr(err):
				t.Fatalf("read error = %v (%T)", err, err)
			case tc.wantReadErr == nil && err != nil:
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if req := f.download; req.GetFiberId() != "fiber-1" || req.GetPath() != "out/result.bin" || req.GetOffset() != tc.offset {
				t.Fatalf("request = %v, want offset %d", req, tc.offset)
			}
		})
	}
}

// Close ends a download at any point, ends a Read that waits, and does
// nothing the second time. Read after Close is fs.ErrClosed.
func TestFileReaderClose(t *testing.T) {
	info := &grantv1.FileInfo{Path: "out/result.bin", Size: 6}
	cases := []struct {
		name string
		// hold keeps the stream open after the first chunk.
		hold bool
		// readToEnd reads the whole file before Close.
		readToEnd bool
		// closeDuringRead closes while a Read waits for the next chunk.
		closeDuringRead bool
	}{
		{name: "closing before reading", hold: true},
		{name: "closing after the end", readToEnd: true},
		{name: "closing while a Read waits ends that Read", hold: true, closeDuringRead: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFiles{chunks: []*grantv1.FileChunk{{Info: info, Data: []byte("abc")}}, hold: tc.hold}
			c := serveFiles(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := c.Download(ctx, "fiber-1", "out/result.bin", 0)
			if err != nil {
				t.Fatal(err)
			}
			if tc.readToEnd {
				if got, err := io.ReadAll(r); err != nil || string(got) != "abc" {
					t.Fatalf("read %q, %v", got, err)
				}
			}
			if tc.closeDuringRead {
				buf := make([]byte, 3)
				if n, err := r.Read(buf); n != 3 || err != nil {
					t.Fatalf("first read = %d, %v", n, err)
				}
				done := make(chan error, 1)
				go func() {
					_, err := r.Read(buf)
					done <- err
				}()
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if !errors.Is(err, fs.ErrClosed) {
						t.Fatalf("waiting read = %v, want fs.ErrClosed", err)
					}
				case <-ctx.Done():
					t.Fatal("Close did not end the waiting Read")
				}
			}
			for i := range 2 {
				if err := r.Close(); err != nil {
					t.Fatalf("close %d = %v", i+1, err)
				}
			}
			if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, fs.ErrClosed) {
				t.Fatalf("read after Close = %d, %v, want fs.ErrClosed", n, err)
			}
		})
	}
}

// ListFiles converts every entry and passes the directory through.
func TestListFiles(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		list []*grantv1.FileInfo
		want []client.FileInfo
	}{
		{name: "files and directories convert", dir: "data",
			list: []*grantv1.FileInfo{{Path: "data/a.txt", Size: 3, Mode: 0o644}, {Path: "data/sub", Mode: 0o755, Directory: true}},
			want: []client.FileInfo{{Path: "data/a.txt", Size: 3, Mode: 0o644}, {Path: "data/sub", Mode: 0o755, Directory: true}}},
		{name: "only the permission bits of a mode are kept",
			list: []*grantv1.FileInfo{{Path: "a.txt", Mode: uint32(fs.ModeSetuid) | 0o40755}},
			want: []client.FileInfo{{Path: "a.txt", Mode: 0o755}}},
		{name: "an empty workspace lists nothing", want: []client.FileInfo{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFiles{list: tc.list}
			c := serveFiles(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			got, err := c.ListFiles(ctx, "fiber-1", tc.dir)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(got, tc.want, sameInfo) {
				t.Fatalf("ListFiles = %+v, want %+v", got, tc.want)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.listed.GetFiberId() != "fiber-1" || f.listed.GetDir() != tc.dir {
				t.Fatalf("request = %v, want dir %q", f.listed, tc.dir)
			}
		})
	}
}

// A file call's refusals come back typed. The NoWorkspace detail tells
// the zero-budget refusal from a tier gap, and the Miss detail tells a
// shed from a file over the budget.
func TestFileErrorsAreTyped(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want func(error) bool
	}{
		{name: "FailedPrecondition with the NoWorkspace detail is *NoWorkspace", err: homeError(core.NoWorkspace, "fiber f has no workspace"),
			want: func(err error) bool {
				var e *client.NoWorkspace
				return errors.As(err, &e) && e.Reason == "fiber f has no workspace" && !isA[*client.TierGap](err)
			}},
		{name: "a bare FailedPrecondition is still *TierGap", err: homeError(core.NeedsTier, "needs CHECKPOINT"),
			want: func(err error) bool { return isA[*client.TierGap](err) && !isA[*client.NoWorkspace](err) }},
		{name: "ResourceExhausted without a Miss is *QuotaExceeded", err: homeError(core.OverBudget, "the file is larger than the grant's disk budget"),
			want: func(err error) bool {
				var e *client.QuotaExceeded
				return errors.As(err, &e) && e.Reason == "the file is larger than the grant's disk budget" && !isA[*client.Shed](err)
			}},
		{name: "ResourceExhausted with a SHED Miss is still *Shed", err: homeError(core.Shed, "grant g is at pids.max"),
			want: func(err error) bool {
				var e *client.Shed
				return errors.As(err, &e) && e.RetryAfter == 2*time.Second && !isA[*client.QuotaExceeded](err)
			}},
		{name: "Unavailable with a DEFERRED_FALLBACK Miss is still *Deferred", err: homeError(core.DeferredFallback, "grant full"),
			want: isA[*client.Deferred]},
		{name: "NotFound stays recognizable", err: homeError(core.NotFound, "fiber f is unknown"), want: client.NotFound},
		{name: "another code stays the raw status", err: homeError(core.Invalid, "the path has .."),
			want: func(err error) bool { return status.Code(err) == codes.InvalidArgument }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := serveFiles(t, &fakeFiles{err: tc.err})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			got, err := c.ListFiles(ctx, "fiber-1", "")
			if got != nil || !tc.want(err) {
				t.Fatalf("ListFiles = %v, %v (%T)", got, err, err)
			}
		})
	}
}
