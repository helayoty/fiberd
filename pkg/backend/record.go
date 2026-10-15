package backend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A channel record is one packet. Its kind byte comes first, then every
// field ended by NUL. The one record every backend sends a fiber at
// birth is the incarnation record, 'i'. A gVisor sandbox also claims
// its restore with 't' and acks its endpoint with 'a'.
//
//	i generation kind fence endpoint payload-hex|- session-hex|- key-PEM|- cert-PEM|- caller|- caller-PEM|- seed-hex
//	t token
//	a fence
//
// The payload and the session are hex so they may hold any byte, and
// "-" when empty. The key, certificate, caller thumbprint and caller
// certificate are a handoff fiber's TLS identity and "-" on every other
// fiber. The seed is 32 bytes of fresh entropy, hex, on every record.
const (
	RecordIncarnation = 'i'
	RecordClaim       = 't'
	RecordAck         = 'a'
	// IncarnationFields is how many fields an 'i' record carries.
	IncarnationFields = 11
	// SeedBytes is the size of the seed every incarnation record carries.
	SeedBytes = 32
	// RecordMax bounds one channel record. A payload rides in it as hex,
	// and libfiberzygote reads it into a buffer of this size.
	RecordMax = 64 << 10
	// FenceMax is the longest fence libfiberzygote holds, with its NUL.
	FenceMax = 128
)

// Identity is a handoff fiber's TLS identity, which rides on its
// record. KeyPEM and CertPEM are the grant's key and certificate,
// Caller the thumbprint of the one client certificate the fiber accepts
// and CallerPEM that certificate.
type Identity struct {
	KeyPEM    string
	CertPEM   string
	Caller    string
	CallerPEM string
}

// Incarnation is what a fiber learns at birth, as the 'i' record
// carries it. Kind is "fork" on proc and runc, "clone" for a gVisor
// sandbox restored from the template image and "resume" for one
// restored from a park. Generation is the host's count of the lineage,
// 1 or more. Identity is nil on every fiber but a handoff fiber.
type Incarnation struct {
	Generation int
	Kind       string
	Fence      string
	Endpoint   string
	Payload    []byte
	Session    string
	Identity   *Identity
	Seed       []byte
}

// Record frames inc as the 'i' record libfiberzygote parses. It refuses
// what the library would refuse, so a bad record is an error here and
// never a fiber that dies at birth.
func (inc Incarnation) Record() ([]byte, error) {
	if inc.Generation < 1 {
		return nil, fmt.Errorf("backend: record of %s: generation %d is not an incarnation", inc.Fence, inc.Generation)
	}
	if inc.Fence == "" || len(inc.Fence) >= FenceMax {
		return nil, fmt.Errorf("backend: record of %q: the fence is empty or longer than %d", inc.Fence, FenceMax-1)
	}
	if inc.Kind == "" || inc.Endpoint == "" {
		return nil, fmt.Errorf("backend: record of %s: kind %q or endpoint %q is empty", inc.Fence, inc.Kind, inc.Endpoint)
	}
	identity := []string{"-", "-", "-", "-"}
	if id := inc.Identity; id != nil {
		identity = []string{id.KeyPEM, id.CertPEM, id.Caller, id.CallerPEM}
		for i, v := range identity {
			if v == "" {
				return nil, fmt.Errorf("backend: record of %s: a handoff identity needs its key, certificate, caller and caller certificate together", inc.Fence)
			}
			if strings.ContainsRune(v, 0) {
				return nil, fmt.Errorf("backend: record of %s: the %s holds a NUL", inc.Fence, []string{"key", "certificate", "caller", "caller certificate"}[i])
			}
		}
	}
	for _, f := range []struct{ name, v string }{{"kind", inc.Kind}, {"fence", inc.Fence}, {"endpoint", inc.Endpoint}, {"session", inc.Session}} {
		if strings.ContainsRune(f.v, 0) {
			return nil, fmt.Errorf("backend: record of %s: the %s holds a NUL", inc.Fence, f.name)
		}
	}
	if len(inc.Seed) != SeedBytes {
		return nil, fmt.Errorf("backend: record of %s: seed is %d bytes, want %d", inc.Fence, len(inc.Seed), SeedBytes)
	}
	fields := []string{strconv.Itoa(inc.Generation), inc.Kind, inc.Fence, inc.Endpoint, hexOrDash(inc.Payload), hexOrDash([]byte(inc.Session))}
	fields = append(fields, identity...)
	fields = append(fields, hex.EncodeToString(inc.Seed))
	rec := Record(RecordIncarnation, fields...)
	if len(rec) > RecordMax {
		return nil, fmt.Errorf("backend: record of %s is %d bytes, over %d", inc.Fence, len(rec), RecordMax)
	}
	return rec, nil
}

func hexOrDash(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

// ErrRecord is the error every malformed record parses to.
var ErrRecord = errors.New("backend: malformed channel record")

// ParseIncarnation takes an 'i' record apart, as libfiberzygote does.
// Any record the library would refuse is ErrRecord with the reason.
func ParseIncarnation(data []byte) (Incarnation, error) {
	kind, fields, ok := ParseRecord(data)
	if !ok || kind != RecordIncarnation {
		return Incarnation{}, fmt.Errorf("%w: not an incarnation record", ErrRecord)
	}
	if len(fields) != IncarnationFields {
		return Incarnation{}, fmt.Errorf("%w: %d fields, want %d", ErrRecord, len(fields), IncarnationFields)
	}
	for i, f := range fields {
		if f == "" {
			return Incarnation{}, fmt.Errorf("%w: field %d is empty", ErrRecord, i)
		}
	}
	gen, err := parseGeneration(fields[0])
	if err != nil {
		return Incarnation{}, fmt.Errorf("%w: %w", ErrRecord, err)
	}
	inc := Incarnation{Generation: gen, Kind: fields[1], Fence: fields[2], Endpoint: fields[3]}
	if len(inc.Fence) >= FenceMax {
		return Incarnation{}, fmt.Errorf("%w: fence longer than %d", ErrRecord, FenceMax-1)
	}
	if inc.Payload, err = unhexField(fields[4]); err != nil {
		return Incarnation{}, fmt.Errorf("%w: payload: %w", ErrRecord, err)
	}
	session, err := unhexField(fields[5])
	if err != nil {
		return Incarnation{}, fmt.Errorf("%w: session: %w", ErrRecord, err)
	}
	if bytes.IndexByte(session, 0) >= 0 {
		return Incarnation{}, fmt.Errorf("%w: session holds a NUL", ErrRecord)
	}
	inc.Session = string(session)
	var id Identity
	set := 0
	for i, p := range []*string{&id.KeyPEM, &id.CertPEM, &id.Caller, &id.CallerPEM} {
		if f := fields[6+i]; f != "-" {
			*p = f
			set++
		}
	}
	if set != 0 && set != 4 {
		return Incarnation{}, fmt.Errorf("%w: a handoff identity needs all four of its fields", ErrRecord)
	}
	if set == 4 {
		inc.Identity = &id
	}
	if inc.Seed, err = hex.DecodeString(fields[10]); err != nil || len(inc.Seed) != SeedBytes {
		return Incarnation{}, fmt.Errorf("%w: seed is not %d hex bytes", ErrRecord, SeedBytes)
	}
	return inc, nil
}

// parseGeneration reads a generation as the record carries it, decimal
// digits with no leading zero, 1 or more.
func parseGeneration(s string) (int, error) {
	if s == "" || s[0] == '0' {
		return 0, fmt.Errorf("generation %q is not 1 or more", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("generation %q is not decimal", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("generation %q is out of range", s)
	}
	return n, nil
}

// unhexField decodes a hex field, "-" for none.
func unhexField(s string) ([]byte, error) {
	if s == "-" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// Record builds one channel record.
func Record(kind byte, fields ...string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(kind)
	for _, f := range fields {
		buf.WriteString(f)
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// ParseRecord takes one record apart. It is refused when it is empty or
// a field is not NUL-ended.
func ParseRecord(data []byte) (kind byte, fields []string, ok bool) {
	if len(data) < 2 || data[len(data)-1] != 0 {
		return 0, nil, false
	}
	parts := bytes.Split(data[1:len(data)-1], []byte{0})
	fields = make([]string, len(parts))
	for i, p := range parts {
		fields[i] = string(p)
	}
	return data[0], fields, true
}
