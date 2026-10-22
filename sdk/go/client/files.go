package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync/atomic"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/rpc"
)

// FileInfo describes one entry of a fiber's workspace.
type FileInfo struct {
	// Path is relative to the fiber's /workspace.
	Path string
	Size uint64
	// Mode holds the permission bits only. Directory tells a directory
	// apart.
	Mode      fs.FileMode
	Directory bool
	// SHA256 is the content's digest. Only Upload's reply sets it.
	SHA256 []byte
}

func fileInfo(i *grantv1.FileInfo) FileInfo {
	return FileInfo{
		Path:      i.GetPath(),
		Size:      i.GetSize(),
		Mode:      fs.FileMode(i.GetMode()) & fs.ModePerm,
		Directory: i.GetDirectory(),
		SHA256:    i.GetSha256(),
	}
}

// UploadOption sets an optional field of an upload's header.
type UploadOption func(*uploadOptions)

type uploadOptions struct {
	mode   fs.FileMode
	sha256 []byte
}

// WithMode sets the file's permission bits. Without it the file is 0644.
func WithMode(mode fs.FileMode) UploadOption {
	return func(o *uploadOptions) { o.mode = mode }
}

// WithSHA256 has fiberd check the content against sum before the file
// appears.
func WithSHA256(sum []byte) UploadOption {
	return func(o *uploadOptions) { o.sha256 = sum }
}

// Upload writes one file of size bytes into a running fiber's workspace.
// path is relative to the fiber's /workspace. r must hold exactly size
// bytes, and Upload reads it to its end to check that. A nil r is empty.
// A reader that is short or long fails with ErrSize, and fiberd never
// places the file. The data goes in chunks of at most 1 MiB, and the file
// appears only once every byte arrived.
//
// Errors are *NoWorkspace, *QuotaExceeded, ErrSize, r's own error, or the
// raw gRPC error for anything else. NotFound reports an unknown fiber.
func (c *Client) Upload(ctx context.Context, fiberID, path string, size int64, r io.Reader, opts ...UploadOption) (FileInfo, error) {
	if size < 0 {
		return FileInfo{}, fmt.Errorf("%w: size %d is negative", ErrSize, size)
	}
	if r == nil {
		r = bytes.NewReader(nil)
	}
	var o uploadOptions
	for _, opt := range opts {
		opt(&o)
	}
	// A long reader fails before fiberd stages anything, so for an
	// empty file no stream opens until r is known to be empty.
	if size == 0 {
		if err := uploadEnded(r, 0); err != nil {
			return FileInfo{}, err
		}
	}
	// Returning without CloseAndRecv cancels the stream, so fiberd drops
	// a file that did not arrive whole.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.api.Upload(ctx)
	if err != nil {
		return FileInfo{}, classify(err)
	}
	declared := uint64(size)
	header := &grantv1.UploadHeader{FiberId: fiberID, Path: path, Size: &declared, Mode: uint32(o.mode.Perm()), Sha256: o.sha256}
	if err := stream.Send(&grantv1.UploadRequest{Part: &grantv1.UploadRequest_Header{Header: header}}); err != nil {
		return FileInfo{}, uploadSendError(stream, err)
	}
	buf := make([]byte, min(size, rpc.MaxChunk))
	for sent := int64(0); sent < size; {
		n := min(size-sent, rpc.MaxChunk)
		got, err := io.ReadFull(r, buf[:n])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return FileInfo{}, fmt.Errorf("%w: the reader ended after %d of %d bytes", ErrSize, sent+int64(got), size)
		}
		if err != nil {
			return FileInfo{}, fmt.Errorf("client: read upload: %w", err)
		}
		sent += n
		// The last chunk waits until r is known to end there, so fiberd
		// never stages every byte of a reader that is long.
		if sent == size {
			if err := uploadEnded(r, size); err != nil {
				return FileInfo{}, err
			}
		}
		// gRPC encodes the message before Send returns, so buf is free to
		// reuse.
		if err := stream.Send(&grantv1.UploadRequest{Part: &grantv1.UploadRequest_Data{Data: buf[:n]}}); err != nil {
			return FileInfo{}, uploadSendError(stream, err)
		}
	}
	info, err := stream.CloseAndRecv()
	if err != nil {
		return FileInfo{}, classify(err)
	}
	return fileInfo(info), nil
}

// uploadEnded reads one more byte from r, which must find its end. A
// byte there means r holds more than size.
func uploadEnded(r io.Reader, size int64) error {
	var probe [1]byte
	extra, err := io.ReadFull(r, probe[:])
	if extra > 0 {
		return fmt.Errorf("%w: the reader holds more than %d bytes", ErrSize, size)
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("client: read upload: %w", err)
	}
	return nil
}

// uploadSendError turns a failed Send into the stream's real error. On
// a client stream Send answers io.EOF once fiberd ended the call, and the
// status itself comes from CloseAndRecv.
func uploadSendError(stream grantv1.Fibers_UploadClient, err error) error {
	if !errors.Is(err, io.EOF) {
		return classify(err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		return classify(err)
	}
	return errEndedEarly
}

// Download opens one regular file of a running fiber's workspace for
// reading from offset. It waits for the first chunk, so a refusal comes
// from Download itself. The caller must Close the reader.
//
// Errors are *NoWorkspace, or the raw gRPC error for anything else.
// NotFound reports an unknown fiber or a missing file.
func (c *Client) Download(ctx context.Context, fiberID, path string, offset uint64) (*FileReader, error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := c.api.Download(ctx, &grantv1.DownloadRequest{FiberId: fiberID, Path: path, Offset: offset})
	if err != nil {
		cancel()
		return nil, classify(err)
	}
	first, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		cancel()
		return nil, fmt.Errorf("client: download of %s ended before its file info: %w", path, io.ErrUnexpectedEOF)
	}
	if err != nil {
		cancel()
		return nil, classify(err)
	}
	if first.GetInfo() == nil {
		cancel()
		return nil, fmt.Errorf("client: download of %s: the first chunk carries no file info", path)
	}
	return &FileReader{info: fileInfo(first.GetInfo()), stream: stream, cancel: cancel, buf: first.GetData()}, nil
}

// FileReader reads a file Download opened. Read returns io.EOF at the
// file's end. Close ends the stream and may run while a Read waits.
type FileReader struct {
	info   FileInfo
	stream grantv1.Fibers_DownloadClient
	cancel context.CancelFunc
	buf    []byte
	err    error // the stream's end, io.EOF or the call's error
	closed atomic.Bool
}

// Info describes the file, as the first chunk carried it.
func (f *FileReader) Info() FileInfo { return f.info }

// Read serves the chunks' data in order. After Close it returns
// fs.ErrClosed.
func (f *FileReader) Read(p []byte) (int, error) {
	if f.closed.Load() {
		return 0, fs.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	for len(f.buf) == 0 {
		if f.err != nil {
			return 0, f.err
		}
		chunk, err := f.stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			f.err = io.EOF
			f.cancel()
		case err != nil:
			if f.closed.Load() {
				return 0, fs.ErrClosed
			}
			f.err = classify(err)
			f.cancel()
		default:
			f.buf = chunk.GetData()
		}
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

// Close ends the download. Calling it again does nothing.
func (f *FileReader) Close() error {
	f.closed.Store(true)
	f.cancel()
	return nil
}

// ListFiles lists one directory of a running fiber's workspace, not
// recursively. An empty dir is the workspace itself. Errors are those of
// Download, and NotFound also reports a missing directory.
func (c *Client) ListFiles(ctx context.Context, fiberID, dir string) ([]FileInfo, error) {
	resp, err := c.api.ListFiles(ctx, &grantv1.ListFilesRequest{FiberId: fiberID, Dir: dir})
	if err != nil {
		return nil, classify(err)
	}
	files := make([]FileInfo, len(resp.GetFiles()))
	for i, f := range resp.GetFiles() {
		files[i] = fileInfo(f)
	}
	return files, nil
}
