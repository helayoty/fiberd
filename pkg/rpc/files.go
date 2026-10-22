package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host/wsfs"
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
	// errNotServed answers a file call on a runtime that holds no files
	// (the stub).
	errNotServed = errors.New("rpc: this home's runtime moves no files")
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

// files is the runtime's file store, or nil on a runtime without one.
func (s *Server) files() core.FileStore {
	fsr, _ := s.Core.Runtime.(core.FileStore)
	return fsr
}

// fileError maps what the file store answered to a status. The store
// wraps the file layer's sentinels, and each names one outcome.
func (s *Server) fileError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrNoWorkspace):
		return s.ToError(core.NoWorkspace, err)
	case errors.Is(err, core.ErrFiberUnknown), errors.Is(err, fs.ErrNotExist):
		return s.ToError(core.NotFound, err)
	case errors.Is(err, wsfs.ErrBudget), errors.Is(err, wsfs.ErrEntries):
		return s.ToError(core.OverBudget, err)
	case errors.Is(err, wsfs.ErrPath), errors.Is(err, wsfs.ErrNotRegular), errors.Is(err, wsfs.ErrSize), errors.Is(err, wsfs.ErrChecksum):
		return s.ToError(core.Invalid, err)
	case errors.Is(err, wsfs.ErrUnsupported):
		return status.Error(codes.Unimplemented, err.Error())
	default:
		return s.ToError(core.Internal, err)
	}
}

// Upload writes one file into a fiber's workspace. The first message is
// the header, which declares the size, so an oversize file is refused
// before any data is read. Every later message is a chunk of at most
// MaxChunk bytes, and the chunks add up to the declared size. The file
// appears only once every byte and the optional sha256 checked out.
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
	files := s.files()
	if files == nil {
		return status.Error(codes.Unimplemented, errNotServed.Error())
	}
	mode := fs.FileMode(h.GetMode()) & fs.ModePerm
	if mode == 0 {
		mode = 0o644
	}
	// The store reads the chunks as it writes, and a chunk that breaks
	// the rules ends the read with its error, which wins over the
	// store's short-size complaint.
	body := &chunkReader{stream: stream, size: h.GetSize()}
	info, err := files.Upload(stream.Context(), h.GetFiberId(), h.GetPath(), int64(h.GetSize()), mode, h.GetSha256(), body)
	if body.err != nil {
		return body.err
	}
	if err != nil {
		return s.fileError(err)
	}
	// The stream's end, after the last byte, which the store never asks
	// for.
	if err := body.drain(); err != nil {
		return err
	}
	return stream.SendAndClose(&grantv1.FileInfo{Path: info.Path, Size: uint64(info.Size), Mode: uint32(info.Mode.Perm()), Sha256: info.SHA256})
}

// chunkReader reads an upload's data off its stream as an io.Reader,
// checking every chunk against MaxChunk and the declared size. The
// first rule it breaks is kept in err, as a status.
type chunkReader struct {
	stream grantv1.Fibers_UploadServer
	size   uint64
	got    uint64
	buf    []byte
	err    error
	eof    bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.eof {
			return 0, io.EOF
		}
		data, err := c.next()
		if err != nil {
			c.err = err
			return 0, err
		}
		if data == nil {
			c.eof = true
			if c.got != c.size {
				c.err = status.Error(codes.InvalidArgument, fmt.Sprintf("%v: %d of %d bytes", errShort, c.got, c.size))
				return 0, c.err
			}
			return 0, io.EOF
		}
		c.buf = data
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// next reads one data message, nil at the stream's end.
func (c *chunkReader) next() ([]byte, error) {
	m, err := c.stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch m.GetPart().(type) {
	case *grantv1.UploadRequest_Header:
		return nil, status.Error(codes.InvalidArgument, errTwoHeaders.Error())
	case nil:
		return nil, status.Error(codes.InvalidArgument, errNoPart.Error())
	}
	data := m.GetData()
	n := uint64(len(data))
	if n > MaxChunk {
		return nil, status.Error(codes.InvalidArgument, errChunkTooLarge.Error())
	}
	if c.got += n; c.got > c.size {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("%v: %d bytes declared", errOverSize, c.size))
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// drain reads the stream to its end once the store took every declared
// byte, so a client that sends more than it declared is refused rather
// than cut off with its file in place.
func (c *chunkReader) drain() error {
	for !c.eof && c.err == nil {
		data, err := c.next()
		if err != nil {
			c.err = err
			break
		}
		if data == nil {
			c.eof = true
		}
	}
	return c.err
}

// Download reads one regular file from a fiber's workspace. The first
// chunk carries the file's info, and every chunk at most MaxChunk bytes.
func (s *Server) Download(req *grantv1.DownloadRequest, stream grantv1.Fibers_DownloadServer) error {
	if req.GetPath() == "" {
		return s.ToError(core.Invalid, errNoPath)
	}
	if _, err := s.fileGrant(stream.Context(), req.GetFiberId()); err != nil {
		return err
	}
	files := s.files()
	if files == nil {
		return status.Error(codes.Unimplemented, errNotServed.Error())
	}
	f, err := files.Download(stream.Context(), req.GetFiberId(), req.GetPath(), int64(req.GetOffset()))
	if err != nil {
		return s.fileError(err)
	}
	defer func() { _ = f.Close() }()
	info := f.Info()
	first := &grantv1.FileInfo{Path: info.Path, Size: uint64(info.Size), Mode: uint32(info.Mode.Perm())}
	buf := make([]byte, MaxChunk)
	for {
		n, rerr := f.Read(buf)
		if n > 0 || first != nil {
			if err := stream.Send(&grantv1.FileChunk{Info: first, Data: buf[:n]}); err != nil {
				return err
			}
			first = nil
		}
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			return s.fileError(rerr)
		}
	}
}

// ListFiles lists one directory of a fiber's workspace. An empty dir is
// the workspace itself.
func (s *Server) ListFiles(ctx context.Context, req *grantv1.ListFilesRequest) (*grantv1.ListFilesResponse, error) {
	if _, err := s.fileGrant(ctx, req.GetFiberId()); err != nil {
		return nil, err
	}
	files := s.files()
	if files == nil {
		return nil, status.Error(codes.Unimplemented, errNotServed.Error())
	}
	infos, err := files.ListFiles(ctx, req.GetFiberId(), req.GetDir())
	if err != nil {
		return nil, s.fileError(err)
	}
	resp := &grantv1.ListFilesResponse{Files: make([]*grantv1.FileInfo, len(infos))}
	for i, info := range infos {
		resp.Files[i] = &grantv1.FileInfo{Path: info.Path, Size: uint64(info.Size), Mode: uint32(info.Mode.Perm()), Directory: info.Mode.IsDir()}
	}
	return resp, nil
}
