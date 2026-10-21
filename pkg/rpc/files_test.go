package rpc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/host/wsfs"
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

// memFiles is a core.FileStore in memory over the stub runtime. It takes
// an upload's bytes as the workspace file layer does: the declared size,
// then one byte more refused as a size mismatch, and the sha256 checked
// before the file appears.
type memFiles struct {
	core.Runtime
	mu    sync.Mutex
	files map[string]map[string][]byte // fiber id -> path -> content
	fail  error                        // what every call answers when set
}

func (m *memFiles) HoldsWorkspaces() bool { return true }

// IsolatesTenants is the wrapped runtime's answer, which embedding an
// interface does not carry over.
func (m *memFiles) IsolatesTenants() bool {
	i, ok := m.Runtime.(core.Isolator)
	return ok && i.IsolatesTenants()
}

func (m *memFiles) Upload(_ context.Context, fiberID, path string, size int64, mode fs.FileMode, sum []byte, r io.Reader) (core.FileInfo, error) {
	if m.fail != nil {
		return core.FileInfo{}, m.fail
	}
	if strings.Contains(path, "..") {
		return core.FileInfo{}, fmt.Errorf("%w: %s", wsfs.ErrPath, path)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return core.FileInfo{}, err
	}
	switch n, err := r.Read(make([]byte, 1)); {
	case n > 0:
		return core.FileInfo{}, wsfs.ErrSize
	case err != nil && !errors.Is(err, io.EOF):
		return core.FileInfo{}, err
	}
	h := sha256.Sum256(buf)
	if sum != nil && !bytes.Equal(sum, h[:]) {
		return core.FileInfo{}, wsfs.ErrChecksum
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string]map[string][]byte{}
	}
	if m.files[fiberID] == nil {
		m.files[fiberID] = map[string][]byte{}
	}
	m.files[fiberID][path] = buf
	return core.FileInfo{Path: path, Size: size, Mode: mode, SHA256: h[:]}, nil
}

// memReader is one downloaded file.
type memReader struct {
	*bytes.Reader
	info core.FileInfo
}

func (r memReader) Close() error        { return nil }
func (r memReader) Info() core.FileInfo { return r.info }

func (m *memFiles) Download(_ context.Context, fiberID, path string, offset int64) (core.FileReader, error) {
	if m.fail != nil {
		return nil, m.fail
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[fiberID][path]
	if !ok {
		return nil, fmt.Errorf("%w: %s", fs.ErrNotExist, path)
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	return memReader{Reader: bytes.NewReader(data[offset:]), info: core.FileInfo{Path: path, Size: int64(len(data)), Mode: 0o644}}, nil
}

func (m *memFiles) ListFiles(_ context.Context, fiberID, dir string) ([]core.FileInfo, error) {
	if m.fail != nil {
		return nil, m.fail
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	var out []core.FileInfo
	seen := map[string]bool{}
	for p, data := range m.files[fiberID] {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok {
			continue
		}
		name, _, isDir := strings.Cut(rest, "/")
		if seen[name] {
			continue
		}
		seen[name] = true
		info := core.FileInfo{Path: prefix + name, Size: int64(len(data)), Mode: 0o644}
		if isDir {
			info = core.FileInfo{Path: prefix + name, Mode: fs.ModeDir | 0o755}
		}
		out = append(out, info)
	}
	if out == nil && dir != "" {
		return nil, fmt.Errorf("%w: %s", fs.ErrNotExist, dir)
	}
	slices.SortFunc(out, func(a, b core.FileInfo) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// withFiles wraps the harness's runtime in a memFiles store.
func withFiles(store *memFiles) func(*core.Core) {
	return func(a *core.Core) {
		store.Runtime = a.Runtime
		a.Runtime = store
	}
}

// uploadStream feeds an Upload handler its messages and counts how many
// it read.
type uploadStream struct {
	grpc.ServerStream // only Context, Recv and SendAndClose are used
	ctx               context.Context
	msgs              []*grantv1.UploadRequest
	read              int
}

func (s *uploadStream) Context() context.Context { return s.ctx }

func (s *uploadStream) Recv() (*grantv1.UploadRequest, error) {
	if s.read == len(s.msgs) {
		return nil, io.EOF
	}
	s.read++
	return s.msgs[s.read-1], nil
}

func (s *uploadStream) SendAndClose(*grantv1.FileInfo) error { return nil }

// downloadStream is a Download handler's stream. It keeps what was sent.
type downloadStream struct {
	grpc.ServerStream // only Context and Send are used
	ctx               context.Context
	chunks            []*grantv1.FileChunk
}

func (s *downloadStream) Context() context.Context { return s.ctx }
func (s *downloadStream) Send(c *grantv1.FileChunk) error {
	s.chunks = append(s.chunks, proto.Clone(c).(*grantv1.FileChunk))
	return nil
}

// body is the bytes the stream carried.
func (s *downloadStream) body() []byte {
	var out []byte
	for _, c := range s.chunks {
		out = append(out, c.GetData()...)
	}
	return out
}

func header(fiberID, path string, size uint64) *grantv1.UploadRequest {
	return &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{Header: &grantv1.UploadHeader{FiberId: fiberID, Path: path, Size: &size}}}
}

func chunk(n int) *grantv1.UploadRequest {
	return &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Data{Data: make([]byte, n)}}
}

// TestFileCalls checks how Upload, Download and ListFiles authorize,
// validate and answer. Each is authorized like Park, so another caller's
// fiber and an unknown one both answer NotFound. A grant with no disk
// budget answers FailedPrecondition with a NoWorkspace detail. A call
// that passes every check reaches the runtime's file store, and what the
// store answers maps to one code each.
func TestFileCalls(t *testing.T) {
	const budget = 4 << 20
	owner := tlsconf.Caller{Thumbprint: "owner-x5t"}
	other := tlsconf.Caller{Thumbprint: "other-x5t"}
	store := &memFiles{}
	h := newHarness(t, core.TierCheckpoint, withFiles(store), func(a *core.Core) { a.Verify = boundVerifier{thumbprint: owner.Thumbprint} })
	fibers := map[string]string{}
	for uid, disk := range map[string]uint64{"gw": budget, "gn": 0} {
		g := jsonGrant(t, core.Grant{UID: uid, Audience: "node-a", Tenant: "acme", DiskBudgetBytes: disk})
		r, err := h.server.Clone(rpc.WithCaller(context.Background(), owner), &grantv1.CloneRequest{GrantJwt: g})
		if err != nil {
			t.Fatalf("clone under %s: %v", uid, err)
		}
		fibers[uid] = r.GetFiberId()
	}
	withWS, noWS := fibers["gw"], fibers["gn"]
	seed := []byte("seed bytes\n")
	seedSum := sha256.Sum256(seed)
	store.files = map[string]map[string][]byte{withWS: {"seed.txt": seed, "out/result.bin": {1, 2, 3, 4}, "out/log": {}}}

	// upload runs an Upload over msgs and reports how many it read.
	upload := func(msgs ...*grantv1.UploadRequest) func(context.Context) (int, []byte, error) {
		return func(ctx context.Context) (int, []byte, error) {
			s := &uploadStream{ctx: ctx, msgs: msgs}
			err := h.server.Upload(s)
			return s.read, nil, err
		}
	}
	download := func(req *grantv1.DownloadRequest) func(context.Context) (int, []byte, error) {
		return func(ctx context.Context) (int, []byte, error) {
			s := &downloadStream{ctx: ctx}
			err := h.server.Download(req, s)
			if err == nil && (len(s.chunks) == 0 || s.chunks[0].GetInfo() == nil) {
				return 0, nil, errors.New("the first chunk carries no info")
			}
			return 0, s.body(), err
		}
	}
	list := func(req *grantv1.ListFilesRequest) func(context.Context) (int, []byte, error) {
		return func(ctx context.Context) (int, []byte, error) {
			resp, err := h.server.ListFiles(ctx, req)
			var names []string
			for _, f := range resp.GetFiles() {
				n := f.GetPath()
				if f.GetDirectory() {
					n += "/"
				}
				names = append(names, n)
			}
			return 0, []byte(strings.Join(names, " ")), err
		}
	}
	data := func(b []byte) *grantv1.UploadRequest {
		return &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Data{Data: b}}
	}
	summed := func(path string, body []byte, sum []byte) *grantv1.UploadRequest {
		size := uint64(len(body))
		return &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{Header: &grantv1.UploadHeader{FiberId: withWS, Path: path, Size: &size, Sha256: sum}}}
	}
	cases := []struct {
		name            string
		caller          *tlsconf.Caller // nil is plaintext with no caller identity
		fail            error           // what the store answers
		op              func(context.Context) (int, []byte, error)
		want            codes.Code
		wantNoWorkspace bool
		wantRead        int    // for an upload, how many messages the handler read
		wantBody        string // for a download, the bytes; for a listing, the names
	}{
		{name: "the owner's upload passes every check and lands", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.OK, wantRead: 2},
		{name: "plaintext has no caller to check", op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.OK, wantRead: 2},
		{name: "another caller's upload is NotFound", caller: &other,
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.NotFound, wantRead: 1},
		{name: "an upload to an unknown fiber is NotFound", caller: &owner,
			op: upload(header("gw/1/99", "a.txt", 3), chunk(3)), want: codes.NotFound, wantRead: 1},
		{name: "an upload under a grant without a workspace is NoWorkspace", caller: &owner,
			op: upload(header(noWS, "a.txt", 3), chunk(3)), want: codes.FailedPrecondition, wantNoWorkspace: true, wantRead: 1},
		{name: "another caller learns nothing about the workspace", caller: &other,
			op: upload(header(noWS, "a.txt", 3), chunk(3)), want: codes.NotFound, wantRead: 1},
		{name: "an empty upload has no header", caller: &owner, op: upload(), want: codes.InvalidArgument},
		{name: "an upload that starts with data has no header", caller: &owner,
			op: upload(chunk(3), header(withWS, "a.txt", 3)), want: codes.InvalidArgument, wantRead: 1},
		{name: "an upload without a path is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "", 3), chunk(3)), want: codes.InvalidArgument, wantRead: 1},
		{name: "an upload that declares no size is InvalidArgument", caller: &owner,
			op:   upload(&grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{Header: &grantv1.UploadHeader{FiberId: withWS, Path: "a.txt"}}}),
			want: codes.InvalidArgument, wantRead: 1},
		{name: "an empty file declares size zero", caller: &owner, op: upload(header(withWS, "empty", 0)), want: codes.OK, wantRead: 1},
		{name: "a file of the whole budget passes", caller: &owner,
			op:   upload(header(withWS, "big", budget), chunk(rpc.MaxChunk), chunk(rpc.MaxChunk), chunk(rpc.MaxChunk), chunk(rpc.MaxChunk)),
			want: codes.OK, wantRead: 5},
		{name: "an oversize header is refused before any data is read", caller: &owner,
			op: upload(header(withWS, "a.txt", budget+1), chunk(3)), want: codes.ResourceExhausted, wantRead: 1},
		{name: "a chunk over 1 MiB is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "a.txt", 2<<20), chunk(rpc.MaxChunk+1)), want: codes.InvalidArgument, wantRead: 2},
		{name: "a second header is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), header(withWS, "b.txt", 3)), want: codes.InvalidArgument, wantRead: 2},
		{name: "a message with no part is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), &grantv1.UploadRequest{}), want: codes.InvalidArgument, wantRead: 2},
		{name: "more data than declared is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), chunk(2), chunk(2), chunk(9)), want: codes.InvalidArgument, wantRead: 3},
		{name: "a chunk after the declared size is InvalidArgument, with nothing in place", caller: &owner,
			op: upload(header(withWS, "late", 3), chunk(3), chunk(1)), want: codes.InvalidArgument, wantRead: 3},
		{name: "less data than declared is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), chunk(2)), want: codes.InvalidArgument, wantRead: 2},
		{name: "a path the store refuses is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "../etc/passwd", 3), chunk(3)), want: codes.InvalidArgument, wantRead: 1},
		{name: "a sha256 that matches passes", caller: &owner,
			op: upload(summed("sum.txt", seed, seedSum[:]), data(seed)), want: codes.OK, wantRead: 2},
		{name: "a sha256 that does not match is InvalidArgument", caller: &owner,
			op: upload(summed("sum.txt", seed, make([]byte, 32)), data(seed)), want: codes.InvalidArgument, wantRead: 2},
		{name: "a store over its budget is ResourceExhausted without a Miss", caller: &owner, fail: wsfs.ErrBudget,
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.ResourceExhausted, wantRead: 1},
		{name: "a store over its entries is ResourceExhausted", caller: &owner, fail: wsfs.ErrEntries,
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.ResourceExhausted, wantRead: 1},
		{name: "a store without openat2 is Unimplemented", caller: &owner, fail: wsfs.ErrUnsupported,
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.Unimplemented, wantRead: 1},
		{name: "any other store failure is Internal", caller: &owner, fail: errors.New("disk on fire"),
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.Internal, wantRead: 1},
		{name: "the owner's download carries the bytes behind the info", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "seed.txt"}), want: codes.OK, wantBody: string(seed)},
		{name: "a download from an offset", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "seed.txt", Offset: 5}), want: codes.OK, wantBody: string(seed[5:])},
		{name: "an empty file downloads as its info alone", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "out/log"}), want: codes.OK},
		{name: "a download of a missing file is NotFound", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "nope.txt"}), want: codes.NotFound},
		{name: "a download the store refuses as no regular file is InvalidArgument", caller: &owner, fail: wsfs.ErrNotRegular,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "seed.txt"}), want: codes.InvalidArgument},
		{name: "another caller's download is NotFound", caller: &other,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "seed.txt"}), want: codes.NotFound},
		{name: "a download from an unknown fiber is NotFound", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: "gw/1/99", Path: "seed.txt"}), want: codes.NotFound},
		{name: "a download under a grant without a workspace is NoWorkspace", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: noWS, Path: "seed.txt"}), want: codes.FailedPrecondition, wantNoWorkspace: true},
		{name: "a download without a path is InvalidArgument", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS}), want: codes.InvalidArgument},
		{name: "the owner lists the workspace itself", caller: &owner,
			op: list(&grantv1.ListFilesRequest{FiberId: withWS}), want: codes.OK, wantBody: "a.txt big empty out/ seed.txt sum.txt"},
		{name: "the owner lists one directory", caller: &owner,
			op: list(&grantv1.ListFilesRequest{FiberId: withWS, Dir: "out"}), want: codes.OK, wantBody: "out/log out/result.bin"},
		{name: "a listing of a missing directory is NotFound", caller: &owner,
			op: list(&grantv1.ListFilesRequest{FiberId: withWS, Dir: "nope"}), want: codes.NotFound},
		{name: "another caller's listing is NotFound", caller: &other,
			op: list(&grantv1.ListFilesRequest{FiberId: withWS, Dir: "out"}), want: codes.NotFound},
		{name: "a listing under a grant without a workspace is NoWorkspace", caller: &owner,
			op: list(&grantv1.ListFilesRequest{FiberId: noWS}), want: codes.FailedPrecondition, wantNoWorkspace: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller != nil {
				ctx = rpc.WithCaller(ctx, *tc.caller)
			}
			store.fail = tc.fail
			defer func() { store.fail = nil }()
			read, body, err := tc.op(ctx)
			if status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if rpc.IsNoWorkspace(err) != tc.wantNoWorkspace {
				t.Fatalf("IsNoWorkspace(%v) = %v, want %v", err, !tc.wantNoWorkspace, tc.wantNoWorkspace)
			}
			if rpc.IsMiss(err) {
				t.Fatalf("err = %v carries a Miss, but no file call is a capacity miss", err)
			}
			if read != tc.wantRead {
				t.Fatalf("the handler read %d messages, want %d", read, tc.wantRead)
			}
			if err == nil && string(body) != tc.wantBody {
				t.Fatalf("body = %q, want %q", body, tc.wantBody)
			}
		})
	}
	// What the uploads above left in the store: the files that passed,
	// and nothing of the ones refused after their header.
	if _, late := store.files[withWS]["late"]; late {
		t.Fatal("a file whose upload sent more than it declared is in place")
	}
	for _, name := range []string{"a.txt", "empty", "big", "sum.txt"} {
		if _, ok := store.files[withWS][name]; !ok {
			t.Fatalf("%s is not in the store after its upload passed", name)
		}
	}
}

// TestFileCallsWithoutStore pins that a runtime with no file store (the
// stub) answers Unimplemented once every check passed, reading no data.
func TestFileCallsWithoutStore(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	r, err := h.server.Clone(context.Background(), &grantv1.CloneRequest{GrantJwt: jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme", DiskBudgetBytes: 1 << 20})})
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetFiberId()
	cases := []struct {
		name     string
		op       func(context.Context) (int, error)
		wantRead int
	}{
		{name: "upload", op: func(ctx context.Context) (int, error) {
			s := &uploadStream{ctx: ctx, msgs: []*grantv1.UploadRequest{header(id, "a.txt", 3), chunk(3)}}
			return s.read, h.server.Upload(s)
		}, wantRead: 1},
		{name: "download", op: func(ctx context.Context) (int, error) {
			return 0, h.server.Download(&grantv1.DownloadRequest{FiberId: id, Path: "a.txt"}, &downloadStream{ctx: ctx})
		}},
		{name: "list", op: func(ctx context.Context) (int, error) {
			_, err := h.server.ListFiles(ctx, &grantv1.ListFilesRequest{FiberId: id})
			return 0, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			read, err := tc.op(context.Background())
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("err = %v, want Unimplemented", err)
			}
			if read != tc.wantRead {
				t.Fatalf("the handler read %d messages, want %d", read, tc.wantRead)
			}
		})
	}
}

// TestStreamAdmission checks that every message a file call receives is
// refused when it carries a field the protocol does not define, the
// first and any later one.
func TestStreamAdmission(t *testing.T) {
	store := &memFiles{}
	h := newHarness(t, core.TierCheckpoint, withFiles(store))
	r, err := h.client.Clone(context.Background(), &grantv1.CloneRequest{
		GrantJwt: jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme", DiskBudgetBytes: 1 << 20}),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetFiberId()
	store.files = map[string]map[string][]byte{id: {"a.txt": []byte("abcd")}}

	upload := func(msgs ...*grantv1.UploadRequest) func(context.Context) error {
		return func(ctx context.Context) error {
			s, err := h.client.Upload(ctx)
			if err != nil {
				return err
			}
			for _, m := range msgs {
				// A server that already answered makes Send fail with
				// io.EOF, and CloseAndRecv then reports its status.
				if err := s.Send(m); errors.Is(err, io.EOF) {
					break
				}
			}
			_, err = s.CloseAndRecv()
			return err
		}
	}
	download := func(req *grantv1.DownloadRequest) func(context.Context) error {
		return func(ctx context.Context) error {
			s, err := h.client.Download(ctx, req)
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		}
	}
	list := func(req *grantv1.ListFilesRequest) func(context.Context) error {
		return func(ctx context.Context) error {
			_, err := h.client.ListFiles(ctx, req)
			return err
		}
	}
	dirtyHeader := &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{
		Header: smuggle(&grantv1.UploadHeader{FiberId: id, Path: "a.txt", Size: proto.Uint64(4)})}}
	cases := []struct {
		name string
		op   func(context.Context) error
		want codes.Code
	}{
		{name: "a clean upload reaches the handler", op: upload(header(id, "a.txt", 4), chunk(2), chunk(2)), want: codes.OK},
		{name: "an unknown field on the first upload message is InvalidArgument",
			op: upload(smuggle(header(id, "a.txt", 4)), chunk(2), chunk(2)), want: codes.InvalidArgument},
		{name: "an unknown field inside the upload header is InvalidArgument",
			op: upload(dirtyHeader, chunk(2), chunk(2)), want: codes.InvalidArgument},
		{name: "an unknown field on a later data chunk is InvalidArgument",
			op: upload(header(id, "a.txt", 4), chunk(2), smuggle(chunk(2))), want: codes.InvalidArgument},
		{name: "a clean download reaches the handler", op: download(&grantv1.DownloadRequest{FiberId: id, Path: "a.txt"}), want: codes.OK},
		{name: "a download with an unknown field is InvalidArgument",
			op: download(smuggle(&grantv1.DownloadRequest{FiberId: id, Path: "a.txt"})), want: codes.InvalidArgument},
		{name: "a clean listing reaches the handler", op: list(&grantv1.ListFilesRequest{FiberId: id}), want: codes.OK},
		{name: "a listing with an unknown field is InvalidArgument", op: list(smuggle(&grantv1.ListFilesRequest{FiberId: id})), want: codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tc.op(ctx); status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
