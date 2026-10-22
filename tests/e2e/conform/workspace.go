//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
)

// upload streams body to path in the fiber's workspace, in chunks of at
// most max bytes, and returns the reply.
func (c *client) upload(ctx context.Context, fiberID, path string, body []byte, max int) (*grantv1.FileInfo, error) {
	s, err := c.api.Upload(ctx)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	hdr := &grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{Header: &grantv1.UploadHeader{FiberId: fiberID, Path: path, Size: proto.Uint64(uint64(len(body))), Sha256: sum[:]}}}
	if err := s.Send(hdr); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for off := 0; off < len(body); off += max {
		end := min(off+max, len(body))
		if err := s.Send(&grantv1.UploadRequest{Part: &grantv1.UploadRequest_Data{Data: body[off:end]}}); err != nil {
			// The server already answered, and CloseAndRecv reports it.
			break
		}
	}
	return s.CloseAndRecv()
}

// download reads path from the fiber's workspace whole, with the info
// the first chunk carried.
func (c *client) download(ctx context.Context, fiberID, path string) (*grantv1.FileInfo, []byte, error) {
	s, err := c.api.Download(ctx, &grantv1.DownloadRequest{FiberId: fiberID, Path: path})
	if err != nil {
		return nil, nil, err
	}
	var info *grantv1.FileInfo
	var body []byte
	for {
		ch, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return info, body, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if info == nil {
			info = ch.GetInfo()
		}
		body = append(body, ch.GetData()...)
	}
}

// C12: a grant with a disk budget gives each fiber a workspace. A file
// uploaded into a session's fiber is listed and downloaded with the
// same bytes, survives a park and a resume of the session, and a file
// over the budget is refused before any byte lands, with no Miss. A
// grant without a disk budget has no workspace, and its fibers answer
// FailedPrecondition with the NoWorkspace detail.
func (c *client) c12(t *testing.T) {
	if !c.d.Workspaces {
		t.Skip("no -workspaces; the target's runtime gives fibers no workspace")
	}
	ctx, cancel := c.ctx(t, 3)
	defer cancel()
	const budget = 1 << 20
	_, tok := c.grant(t, "c12", func(g *core.Grant) { g.DiskBudgetBytes = budget })
	session := uid("S")
	r1, err := c.clone(ctx, tok, session, nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	id := r1.GetFiberId()
	released := id
	defer func() { c.release(ctx, released) }()

	body := bytes.Repeat([]byte("conform workspace bytes\n"), 4096) // 96 KiB, several chunks at 64 KiB
	info, err := c.upload(ctx, id, "in/data.txt", body, 64<<10)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	sum := sha256.Sum256(body)
	if info.GetPath() != "in/data.txt" || info.GetSize() != uint64(len(body)) || !bytes.Equal(info.GetSha256(), sum[:]) {
		t.Fatalf("upload reply = %+v, want in/data.txt, %d bytes, sha256 %x", info, len(body), sum)
	}
	list, err := c.api.ListFiles(ctx, &grantv1.ListFilesRequest{FiberId: id, Dir: "in"})
	if err != nil || len(list.GetFiles()) != 1 || list.GetFiles()[0].GetPath() != "in/data.txt" || list.GetFiles()[0].GetSize() != uint64(len(body)) {
		t.Fatalf("ListFiles(in) = %+v, %v", list, err)
	}
	if _, got, err := c.download(ctx, id, "in/data.txt"); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("download before the park: %d bytes, %v, want the %d uploaded", len(got), err, len(body))
	}
	if _, err := c.upload(ctx, id, "too-big", make([]byte, budget+1), 64<<10); status.Code(err) != codes.ResourceExhausted || rpc.IsMiss(err) {
		t.Fatalf("an upload over the budget = %v, want ResourceExhausted with no Miss", err)
	}
	if _, err := c.upload(ctx, id, "../escape", []byte("x"), 64<<10); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an upload that climbs out = %v, want InvalidArgument", err)
	}
	if _, _, err := c.download(ctx, id, "nope"); status.Code(err) != codes.NotFound {
		t.Fatalf("a download of a missing file = %v, want NotFound", err)
	}

	if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: id, Sync: true}); err != nil {
		t.Fatalf("park: %v", err)
	}
	if _, _, err := c.download(ctx, id, "in/data.txt"); status.Code(err) != codes.NotFound {
		t.Fatalf("a download from the parked fiber = %v, want NotFound (resume first)", err)
	}
	r2, err := c.clone(ctx, tok, session, nil)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	released = r2.GetFiberId()
	if r2.GetKind() != grantv1.CloneKind_RESUME {
		t.Fatalf("clone after the park kind = %v, want RESUME", r2.GetKind())
	}
	if _, got, err := c.download(ctx, r2.GetFiberId(), "in/data.txt"); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("download after the resume: %d bytes, %v, want the %d uploaded", len(got), err, len(body))
	}
	list, err = c.api.ListFiles(ctx, &grantv1.ListFilesRequest{FiberId: r2.GetFiberId()})
	if err != nil || len(list.GetFiles()) != 1 || list.GetFiles()[0].GetPath() != "in" || !list.GetFiles()[0].GetDirectory() {
		t.Fatalf("ListFiles after the resume = %+v, %v, want the in directory alone", list, err)
	}

	// No disk budget, no workspace.
	_, tokNone := c.grant(t, "c12n", nil)
	rn, err := c.clone(ctx, tokNone, "", nil)
	if err != nil {
		t.Fatalf("clone without a disk budget: %v", err)
	}
	defer c.release(ctx, rn.GetFiberId())
	_, err = c.upload(ctx, rn.GetFiberId(), "a.txt", []byte("x"), 64<<10)
	if status.Code(err) != codes.FailedPrecondition || !rpc.IsNoWorkspace(err) {
		t.Fatalf("an upload under a grant without a disk budget = %v, want FailedPrecondition with the NoWorkspace detail", err)
	}
}
