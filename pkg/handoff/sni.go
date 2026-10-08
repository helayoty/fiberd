// Package handoff is the agent side of connection handoff. It accepts a
// caller's TLS connection, reads the routing key from the ClientHello's
// server name without consuming or decrypting anything, and passes the
// socket to the fiber the key belongs to. It also derives the TLS
// identity a grant's fibers serve with.
package handoff

import (
	"encoding/binary"
	"fmt"
)

// MaxHello is the most the agent reads of a ClientHello. That is one TLS
// record, its header plus the largest plaintext a record may carry.
const MaxHello = 5 + 16384

// ServerName returns the host name in the server name extension of the
// TLS ClientHello at the start of b. It reads only the record header,
// the handshake header and the extensions. ErrShort means b ends before
// the ClientHello does. The ClientHello must fit in its first record.
func ServerName(b []byte) (string, error) {
	if len(b) < 5 {
		if len(b) > 0 && b[0] != 0x16 {
			return "", ErrNotTLS
		}
		return "", ErrShort
	}
	// The record header holds content type handshake, a 3.x version and a
	// length.
	if b[0] != 0x16 || b[1] != 3 {
		return "", ErrNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen > MaxHello-5 {
		return "", fmt.Errorf("%w: record of %d bytes", ErrMalformed, recLen)
	}
	if len(b) < 5+recLen {
		return "", ErrShort
	}
	rec := b[5 : 5+recLen]
	// The handshake header holds type client_hello and a 24-bit length
	// within the record.
	if len(rec) < 4 || rec[0] != 0x01 {
		return "", ErrNotTLS
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if hsLen > len(rec)-4 {
		return "", fmt.Errorf("%w: ClientHello of %d bytes spans records", ErrMalformed, hsLen)
	}
	p := parser(rec[4 : 4+hsLen])
	if !p.skip(2+32) || // client_version, random
		!p.skipVec(1) || // session_id
		!p.skipVec(2) || // cipher_suites
		!p.skipVec(1) { // compression_methods
		return "", ErrMalformed
	}
	if len(p) == 0 {
		return "", ErrNoServerName // no extensions at all
	}
	exts, ok := p.vec(2)
	if !ok {
		return "", ErrMalformed
	}
	for len(exts) > 0 {
		typ, ok := exts.u16()
		if !ok {
			return "", ErrMalformed
		}
		data, ok := exts.vec(2)
		if !ok {
			return "", ErrMalformed
		}
		if typ != 0 { // server_name
			continue
		}
		list, ok := data.vec(2)
		if !ok {
			return "", ErrMalformed
		}
		for len(list) > 0 {
			nameType := list[0]
			list = list[1:]
			name, ok := list.vec(2)
			if !ok {
				return "", ErrMalformed
			}
			if nameType == 0 { // host_name
				if len(name) == 0 {
					return "", ErrMalformed
				}
				return string(name), nil
			}
		}
		return "", ErrNoServerName
	}
	return "", ErrNoServerName
}

// parser reads big-endian fields off the front of a byte slice.
type parser []byte

func (p *parser) skip(n int) bool {
	if len(*p) < n {
		return false
	}
	*p = (*p)[n:]
	return true
}

func (p *parser) u16() (uint16, bool) {
	if len(*p) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(*p)
	*p = (*p)[2:]
	return v, true
}

// vec reads a vector whose length prefix is lenBytes (1 or 2) long.
func (p *parser) vec(lenBytes int) (parser, bool) {
	if len(*p) < lenBytes {
		return nil, false
	}
	n := int((*p)[0])
	if lenBytes == 2 {
		n = int(binary.BigEndian.Uint16(*p))
	}
	*p = (*p)[lenBytes:]
	if len(*p) < n {
		return nil, false
	}
	v := (*p)[:n]
	*p = (*p)[n:]
	return v, true
}

func (p *parser) skipVec(lenBytes int) bool {
	_, ok := p.vec(lenBytes)
	return ok
}
