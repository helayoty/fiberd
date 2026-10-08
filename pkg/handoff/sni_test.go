package handoff

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

// clientHello is the first TLS record a Go client sends for serverName.
func clientHello(t testing.TB, serverName string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake() //nolint:gosec // only the ClientHello is used
		_ = cli.Close()
	}()
	head := make([]byte, 5)
	if _, err := io.ReadFull(srv, head); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(head[3:5]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatal(err)
	}
	return append(head, body...)
}

// crafted wraps a ClientHello body in its handshake and record headers.
func crafted(body []byte) []byte {
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// withExts is a ClientHello body whose extensions block holds exts as
// given, with a correct length prefix.
func withExts(exts ...byte) []byte {
	b := make([]byte, 2+32)                            // client_version, random
	b = append(b, 0)                                   // session_id
	b = append(b, 0, 2, 0x13, 0x01)                    // cipher_suites
	b = append(b, 1, 0)                                // compression_methods
	b = append(b, byte(len(exts)>>8), byte(len(exts))) // extensions length
	return append(b, exts...)
}

// sniExt is a server_name extension holding list as its name list.
func sniExt(list ...byte) []byte {
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return append([]byte{0, 0, byte(len(data) >> 8), byte(len(data))}, data...)
}

func TestServerName(t *testing.T) {
	hello := clientHello(t, "abc.fiberd")
	noSNI := clientHello(t, "") // a Go client sends none without a name
	spans := append([]byte(nil), hello...)
	spans[6], spans[7], spans[8] = 0xff, 0xff, 0xff // handshake longer than its record

	cases := []struct {
		name    string
		in      []byte
		want    string
		wantErr error
	}{
		{name: "go client", in: hello, want: "abc.fiberd"},
		{name: "upper case kept", in: clientHello(t, "ABC.fiberd"), want: "ABC.fiberd"},
		{name: "empty", in: nil, wantErr: ErrShort},
		{name: "record header only", in: hello[:5], wantErr: ErrShort},
		{name: "cut in the extensions", in: hello[:len(hello)-1], wantErr: ErrShort},
		{name: "no server name", in: noSNI, wantErr: ErrNoServerName},
		{name: "plaintext http", in: []byte("GET / HTTP/1.1\r\n\r\n"), wantErr: ErrNotTLS},
		{name: "one byte of http", in: []byte("G"), wantErr: ErrNotTLS},
		{name: "alert record", in: []byte{0x15, 3, 3, 0, 2, 2, 40}, wantErr: ErrNotTLS},
		{name: "record too long", in: []byte{0x16, 3, 1, 0x40, 0x01}, wantErr: ErrMalformed},
		{name: "handshake spans records", in: spans, wantErr: ErrMalformed},
		{name: "server hello", in: []byte{0x16, 3, 3, 0, 4, 0x02, 0, 0, 0}, wantErr: ErrNotTLS},
		{name: "truncated body", in: []byte{0x16, 3, 3, 0, 6, 0x01, 0, 0, 2, 3, 3}, wantErr: ErrMalformed},
		{name: "a record too short for a handshake header", in: []byte{0x16, 3, 3, 0, 2, 0x01, 0}, wantErr: ErrNotTLS},
		{name: "a body cut inside the random", in: crafted(make([]byte, 10)), wantErr: ErrMalformed},
		{name: "a body without an extensions block", in: crafted(withExts()[:2+32+1+4+2]), wantErr: ErrNoServerName},
		{name: "an empty extensions block", in: crafted(withExts()), wantErr: ErrNoServerName},
		{name: "an extensions length past the end", in: crafted(append(withExts()[:2+32+1+4+2], 0, 9)), wantErr: ErrMalformed},
		{name: "an extension cut inside its type", in: crafted(withExts(0)), wantErr: ErrMalformed},
		{name: "an extension whose data runs past the end", in: crafted(withExts(0, 5, 0, 9)), wantErr: ErrMalformed},
		{name: "a server_name extension too short for its list length", in: crafted(withExts(0, 0, 0, 1, 0)), wantErr: ErrMalformed},
		{name: "a name entry cut inside its length", in: crafted(withExts(sniExt(0, 0)...)), wantErr: ErrMalformed},
		{name: "an empty host name", in: crafted(withExts(sniExt(0, 0, 0)...)), wantErr: ErrMalformed},
		{name: "only a name of another type", in: crafted(withExts(sniExt(1, 0, 1, 'x')...)), wantErr: ErrNoServerName},
		{name: "a name of another type before the host name", in: crafted(withExts(sniExt(1, 0, 1, 'x', 0, 0, 3, 'a', 'b', 'c')...)), want: "abc"},
		{name: "other extensions before server_name", in: crafted(withExts(append([]byte{0, 0x10, 0, 1, 7}, sniExt(0, 0, 1, 'k')...)...)), want: "k"},
		{name: "other extensions only", in: crafted(withExts(0, 0x10, 0, 0)), wantErr: ErrNoServerName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ServerName(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("name = %q, want %q", got, tc.want)
			}
		})
	}
}

// FuzzServerName checks that no input panics or hangs the parser, and
// that it returns a name exactly when it returns no error.
func FuzzServerName(f *testing.F) {
	hello := clientHello(f, "abc.fiberd")
	f.Add(hello)
	f.Add(clientHello(f, ""))
	f.Add(hello[:40])
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		name, err := ServerName(b)
		if (err == nil) == (name == "") {
			t.Fatalf("name %q with err %v", name, err)
		}
		if len(name) > len(b) {
			t.Fatalf("name of %d bytes from %d bytes of input", len(name), len(b))
		}
	})
}
