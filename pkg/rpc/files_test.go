package rpc_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/tlsconf"
)

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

// downloadStream is a Download handler's stream. It keeps nothing.
type downloadStream struct {
	grpc.ServerStream // only Context and Send are used
	ctx               context.Context
}

func (s *downloadStream) Context() context.Context      { return s.ctx }
func (s *downloadStream) Send(*grantv1.FileChunk) error { return nil }

func header(fiberID, path string, size uint64) *grantv1.UploadRequest {
	return &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{Header: &grantv1.UploadHeader{FiberId: fiberID, Path: path, Size: &size}}}
}

func chunk(n int) *grantv1.UploadRequest {
	return &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Data{Data: make([]byte, n)}}
}

// TestFileCalls checks how Upload, Download and ListFiles authorize and
// validate. Each is authorized like Park, so another caller's fiber and an
// unknown one both answer NotFound. A grant with no disk budget answers
// FailedPrecondition with a NoWorkspace detail. A call that passes every
// check answers Unimplemented until the file layer serves it.
func TestFileCalls(t *testing.T) {
	const budget = 4 << 20
	owner := tlsconf.Caller{Thumbprint: "owner-x5t"}
	other := tlsconf.Caller{Thumbprint: "other-x5t"}
	h := newHarness(t, core.TierCheckpoint, func(a *core.Core) { a.Verify = boundVerifier{thumbprint: owner.Thumbprint} })
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

	// upload runs an Upload over msgs and reports how many it read.
	upload := func(msgs ...*grantv1.UploadRequest) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			s := &uploadStream{ctx: ctx, msgs: msgs}
			err := h.server.Upload(s)
			return s.read, err
		}
	}
	download := func(req *grantv1.DownloadRequest) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			return 0, h.server.Download(req, &downloadStream{ctx: ctx})
		}
	}
	list := func(req *grantv1.ListFilesRequest) func(context.Context) (int, error) {
		return func(ctx context.Context) (int, error) {
			_, err := h.server.ListFiles(ctx, req)
			return 0, err
		}
	}
	cases := []struct {
		name            string
		caller          *tlsconf.Caller // nil is plaintext with no caller identity
		op              func(context.Context) (int, error)
		want            codes.Code
		wantNoWorkspace bool
		wantRead        int // for an upload, how many messages the handler read
	}{
		{name: "the owner's upload passes every check", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.Unimplemented, wantRead: 2},
		{name: "plaintext has no caller to check", op: upload(header(withWS, "a.txt", 3), chunk(3)), want: codes.Unimplemented, wantRead: 2},
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
		{name: "an empty file declares size zero", caller: &owner, op: upload(header(withWS, "a.txt", 0)), want: codes.Unimplemented, wantRead: 1},
		{name: "a file of the whole budget passes", caller: &owner,
			op:   upload(header(withWS, "a.txt", budget), chunk(rpc.MaxChunk), chunk(rpc.MaxChunk), chunk(rpc.MaxChunk), chunk(rpc.MaxChunk)),
			want: codes.Unimplemented, wantRead: 5},
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
		{name: "less data than declared is InvalidArgument", caller: &owner,
			op: upload(header(withWS, "a.txt", 3), chunk(2)), want: codes.InvalidArgument, wantRead: 2},
		{name: "the owner's download passes every check", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "a.txt"}), want: codes.Unimplemented},
		{name: "another caller's download is NotFound", caller: &other,
			op: download(&grantv1.DownloadRequest{FiberId: withWS, Path: "a.txt"}), want: codes.NotFound},
		{name: "a download from an unknown fiber is NotFound", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: "gw/1/99", Path: "a.txt"}), want: codes.NotFound},
		{name: "a download under a grant without a workspace is NoWorkspace", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: noWS, Path: "a.txt"}), want: codes.FailedPrecondition, wantNoWorkspace: true},
		{name: "a download without a path is InvalidArgument", caller: &owner,
			op: download(&grantv1.DownloadRequest{FiberId: withWS}), want: codes.InvalidArgument},
		{name: "the owner lists the workspace itself", caller: &owner,
			op: list(&grantv1.ListFilesRequest{FiberId: withWS}), want: codes.Unimplemented},
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
			read, err := tc.op(ctx)
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
		})
	}
}

// TestStreamAdmission checks that every message a file call receives is
// refused when it carries a field the protocol does not define, the
// first and any later one.
func TestStreamAdmission(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	r, err := h.client.Clone(context.Background(), &grantv1.CloneRequest{
		GrantJwt: jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme", DiskBudgetBytes: 1 << 20}),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := r.GetFiberId()

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
		{name: "a clean upload reaches the handler", op: upload(header(id, "a.txt", 4), chunk(2), chunk(2)), want: codes.Unimplemented},
		{name: "an unknown field on the first upload message is InvalidArgument",
			op: upload(smuggle(header(id, "a.txt", 4)), chunk(2), chunk(2)), want: codes.InvalidArgument},
		{name: "an unknown field inside the upload header is InvalidArgument",
			op: upload(dirtyHeader, chunk(2), chunk(2)), want: codes.InvalidArgument},
		{name: "an unknown field on a later data chunk is InvalidArgument",
			op: upload(header(id, "a.txt", 4), chunk(2), smuggle(chunk(2))), want: codes.InvalidArgument},
		{name: "a clean download reaches the handler", op: download(&grantv1.DownloadRequest{FiberId: id, Path: "a.txt"}), want: codes.Unimplemented},
		{name: "a download with an unknown field is InvalidArgument",
			op: download(smuggle(&grantv1.DownloadRequest{FiberId: id, Path: "a.txt"})), want: codes.InvalidArgument},
		{name: "a clean listing reaches the handler", op: list(&grantv1.ListFilesRequest{FiberId: id}), want: codes.Unimplemented},
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
