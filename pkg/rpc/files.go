package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// MaxChunk is the most data one Upload or Download message carries, well
// under gRPC's 4 MiB message limit.
const MaxChunk = 1 << 20

var (
	errNoHeader      = errors.New("rpc: an upload starts with its header")
	errTwoHeaders    = errors.New("rpc: an upload has one header")
	errNoPart        = errors.New("rpc: an upload message carries neither a header nor data")
	errNoPath        = errors.New("rpc: the file call names no path")
	errNoSize        = errors.New("rpc: the upload header declares no size")
	errChunkTooLarge = fmt.Errorf("rpc: a data chunk is larger than %d bytes", MaxChunk)
	errOverSize      = errors.New("rpc: the upload sent more bytes than its header declared")
	errShort         = errors.New("rpc: the upload ended before the size its header declared")
	errOverBudget    = errors.New("rpc: the file is larger than the grant's disk budget")
	// errNotServed answers a file call that passed every check, until
	// the workspace file layer and the backends serve it.
	errNotServed = errors.New("rpc: file transfer is not served by this home yet")
)

// fileGrant authorizes a file call the way Park is authorized. An unknown
// fiber and another caller's fiber both answer NotFound, so a fiber ID
// reveals nothing about who holds it. A fiber whose grant has no disk
// budget answers NoWorkspace. Otherwise it returns the fiber's grant.
func (s *Server) fileGrant(ctx context.Context, fiberID string) (core.Grant, error) {
	fence, ok := s.Core.Ledger.Fiber(fiberID)
	if !ok || !s.owns(ctx, fence.GrantUID) {
		return core.Grant{}, s.ToError(core.NotFound, core.ErrFiberUnknown)
	}
	g, ok := s.Core.Ledger.Grant(fence.GrantUID)
	if !ok {
		return core.Grant{}, s.ToError(core.NotFound, core.ErrFiberUnknown)
	}
	if g.DiskBudgetBytes == 0 {
		return core.Grant{}, s.ToError(core.NoWorkspace, fmt.Errorf("%w: fiber %s", core.ErrNoWorkspace, fiberID))
	}
	return g, nil
}

// Upload writes one file into a fiber's workspace. The first message is
// the header, which declares the size, so an oversize file is refused
// before any data is read. Every later message is a chunk of at most
// MaxChunk bytes, and the chunks add up to the declared size.
func (s *Server) Upload(stream grantv1.Fibers_UploadServer) error {
	first, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return s.ToError(core.Invalid, errNoHeader)
	}
	if err != nil {
		return err
	}
	h := first.GetHeader()
	switch {
	case h == nil:
		return s.ToError(core.Invalid, errNoHeader)
	case h.GetPath() == "":
		return s.ToError(core.Invalid, errNoPath)
	case h.Size == nil:
		return s.ToError(core.Invalid, errNoSize)
	}
	g, err := s.fileGrant(stream.Context(), h.GetFiberId())
	if err != nil {
		return err
	}
	if h.GetSize() > g.DiskBudgetBytes {
		return s.ToError(core.OverBudget, fmt.Errorf("%w: %d > %d bytes", errOverBudget, h.GetSize(), g.DiskBudgetBytes))
	}
	if err := s.recvChunks(stream, h.GetSize()); err != nil {
		return err
	}
	return status.Error(codes.Unimplemented, errNotServed.Error())
}

// recvChunks reads an upload's data to its end and checks each chunk
// against MaxChunk and the declared size.
func (s *Server) recvChunks(stream grantv1.Fibers_UploadServer, size uint64) error {
	var got uint64
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if got != size {
				return s.ToError(core.Invalid, fmt.Errorf("%w: %d of %d bytes", errShort, got, size))
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch m.GetPart().(type) {
		case *grantv1.UploadRequest_Header:
			return s.ToError(core.Invalid, errTwoHeaders)
		case nil:
			return s.ToError(core.Invalid, errNoPart)
		}
		n := uint64(len(m.GetData()))
		if n > MaxChunk {
			return s.ToError(core.Invalid, errChunkTooLarge)
		}
		if got += n; got > size {
			return s.ToError(core.Invalid, fmt.Errorf("%w: %d bytes declared", errOverSize, size))
		}
	}
}

// Download reads one regular file from a fiber's workspace.
func (s *Server) Download(req *grantv1.DownloadRequest, stream grantv1.Fibers_DownloadServer) error {
	if req.GetPath() == "" {
		return s.ToError(core.Invalid, errNoPath)
	}
	if _, err := s.fileGrant(stream.Context(), req.GetFiberId()); err != nil {
		return err
	}
	return status.Error(codes.Unimplemented, errNotServed.Error())
}

// ListFiles lists one directory of a fiber's workspace. An empty dir is
// the workspace itself.
func (s *Server) ListFiles(ctx context.Context, req *grantv1.ListFilesRequest) (*grantv1.ListFilesResponse, error) {
	if _, err := s.fileGrant(ctx, req.GetFiberId()); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, errNotServed.Error())
}
