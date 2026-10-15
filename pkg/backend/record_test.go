package backend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var testSeed = bytes.Repeat([]byte{0xab}, SeedBytes)

// TestIncarnationRecord checks the one record every fiber reads at
// birth, both ways. A record frames as eleven NUL-ended fields behind
// 'i', with "-" for an empty payload, session or identity field, and
// parses back to what was framed. What libfiberzygote would refuse is
// refused here first, so no fiber dies at birth over a bad record.
func TestIncarnationRecord(t *testing.T) {
	id := Identity{KeyPEM: "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n", CertPEM: "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n",
		Caller: "x5t", CallerPEM: "-----BEGIN CERTIFICATE-----\nq\n-----END CERTIFICATE-----\n"}
	full := Incarnation{Generation: 3, Kind: "resume", Fence: "g/1/2", Endpoint: "/run/g/1-2.sock", Payload: []byte(`{"task":1}`), Session: "conv 42",
		Identity: &id, Seed: testSeed}
	plain := Incarnation{Generation: 1, Kind: "fork", Fence: "g/1/1", Endpoint: "handoff", Seed: testSeed}
	cases := []struct {
		name string
		inc  Incarnation
		// fields is what the record must carry, in order. nil means
		// framing must fail with wantErr in the error.
		fields  []string
		wantErr string
	}{
		{name: "every field set", inc: full, fields: []string{"3", "resume", "g/1/2", "/run/g/1-2.sock", hex.EncodeToString([]byte(`{"task":1}`)), hex.EncodeToString([]byte("conv 42")),
			id.KeyPEM, id.CertPEM, "x5t", id.CallerPEM, hex.EncodeToString(testSeed)}},
		{name: "no payload, no session, no identity", inc: plain, fields: []string{"1", "fork", "g/1/1", "handoff", "-", "-", "-", "-", "-", "-", hex.EncodeToString(testSeed)}},
		{name: "generation 0", inc: with(plain, func(i *Incarnation) { i.Generation = 0 }), wantErr: "not an incarnation"},
		{name: "no fence", inc: with(plain, func(i *Incarnation) { i.Fence = "" }), wantErr: "fence is empty"},
		{name: "fence too long", inc: with(plain, func(i *Incarnation) { i.Fence = strings.Repeat("f", FenceMax) }), wantErr: "longer than 127"},
		{name: "no kind", inc: with(plain, func(i *Incarnation) { i.Kind = "" }), wantErr: "is empty"},
		{name: "no endpoint", inc: with(plain, func(i *Incarnation) { i.Endpoint = "" }), wantErr: "is empty"},
		{name: "NUL in the endpoint", inc: with(plain, func(i *Incarnation) { i.Endpoint = "a\x00b" }), wantErr: "endpoint holds a NUL"},
		{name: "NUL in the session", inc: with(plain, func(i *Incarnation) { i.Session = "a\x00b" }), wantErr: "session holds a NUL"},
		{name: "NUL in the key", inc: with(full, func(i *Incarnation) {
			i.Identity = &Identity{KeyPEM: "k\x00", CertPEM: "c", Caller: "x", CallerPEM: "p"}
		}), wantErr: "key holds a NUL"},
		{name: "half an identity", inc: with(full, func(i *Incarnation) { i.Identity = &Identity{KeyPEM: id.KeyPEM, CertPEM: id.CertPEM, Caller: "x5t"} }), wantErr: "together"},
		{name: "a caller alone", inc: with(plain, func(i *Incarnation) { i.Identity = &Identity{Caller: "x5t"} }), wantErr: "together"},
		{name: "short seed", inc: with(plain, func(i *Incarnation) { i.Seed = testSeed[:31] }), wantErr: "seed is 31 bytes"},
		{name: "no seed", inc: with(plain, func(i *Incarnation) { i.Seed = nil }), wantErr: "seed is 0 bytes"},
		{name: "payload over the record bound", inc: with(plain, func(i *Incarnation) { i.Payload = bytes.Repeat([]byte{1}, RecordMax/2) }), wantErr: "over 65536"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := tc.inc.Record()
			if tc.fields == nil {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Record = %q, %v, want an error mentioning %q", rec, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			kind, fields, ok := ParseRecord(rec)
			if !ok || kind != RecordIncarnation {
				t.Fatalf("record %q: kind %q ok %v", rec, kind, ok)
			}
			if len(fields) != IncarnationFields {
				t.Fatalf("%d fields %q, want %d", len(fields), fields, IncarnationFields)
			}
			for i := range fields {
				if fields[i] != tc.fields[i] {
					t.Fatalf("field %d = %q, want %q", i, fields[i], tc.fields[i])
				}
			}
			got, err := ParseIncarnation(rec)
			if err != nil {
				t.Fatal(err)
			}
			if !same(got, tc.inc) {
				t.Fatalf("parsed back %+v, want %+v", got, tc.inc)
			}
		})
	}
}

// TestParseIncarnationRefuses checks that a malformed record is
// ErrRecord with the reason, never a partial incarnation.
func TestParseIncarnationRefuses(t *testing.T) {
	good := []string{"2", "clone", "g/1/1", "/host/1-1.sock", "-", "-", "-", "-", "-", "-", hex.EncodeToString(testSeed)}
	key := "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n"
	cases := []struct {
		name string
		rec  []byte
		want string
	}{
		{name: "empty", rec: nil, want: "not an incarnation"},
		{name: "tag alone", rec: []byte{'i'}, want: "not an incarnation"},
		{name: "no NUL at the end", rec: []byte("i2\x00clone"), want: "not an incarnation"},
		{name: "a claim", rec: Record(RecordClaim, "tok"), want: "not an incarnation"},
		{name: "ten fields", rec: Record(RecordIncarnation, good[:10]...), want: "10 fields"},
		{name: "twelve fields", rec: Record(RecordIncarnation, append(append([]string{}, good...), "x")...), want: "12 fields"},
		{name: "empty kind", rec: Record(RecordIncarnation, replace(good, 1, "")...), want: "field 1 is empty"},
		{name: "generation 0", rec: Record(RecordIncarnation, replace(good, 0, "0")...), want: "not 1 or more"},
		{name: "generation with a leading zero", rec: Record(RecordIncarnation, replace(good, 0, "02")...), want: "not 1 or more"},
		{name: "generation not a number", rec: Record(RecordIncarnation, replace(good, 0, "2x")...), want: "not decimal"},
		{name: "generation out of range", rec: Record(RecordIncarnation, replace(good, 0, "99999999999999999999999")...), want: "out of range"},
		{name: "fence too long", rec: Record(RecordIncarnation, replace(good, 2, strings.Repeat("f", FenceMax))...), want: "fence longer"},
		{name: "payload not hex", rec: Record(RecordIncarnation, replace(good, 4, "zz")...), want: "payload"},
		{name: "session not hex", rec: Record(RecordIncarnation, replace(good, 5, "abc")...), want: "session"},
		{name: "session with a NUL", rec: Record(RecordIncarnation, replace(good, 5, "6100")...), want: "session holds a NUL"},
		{name: "key without the rest of the identity", rec: Record(RecordIncarnation, replace(good, 6, key)...), want: "all four"},
		{name: "seed too short", rec: Record(RecordIncarnation, replace(good, 10, "abab")...), want: "seed is not 32"},
		{name: "seed not hex", rec: Record(RecordIncarnation, replace(good, 10, strings.Repeat("zz", SeedBytes))...), want: "seed is not 32"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inc, err := ParseIncarnation(tc.rec)
			if !errors.Is(err, ErrRecord) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseIncarnation = %+v, %v, want ErrRecord mentioning %q", inc, err, tc.want)
			}
			if inc.Fence != "" || inc.Seed != nil {
				t.Fatalf("a refused record left %+v behind", inc)
			}
		})
	}
}

// TestParseRecord checks the framing every record shares.
func TestParseRecord(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		kind   byte
		fields []string
		ok     bool
	}{
		{name: "one field", data: []byte("ttoken\x00"), kind: 't', fields: []string{"token"}, ok: true},
		{name: "an empty field", data: []byte("a\x00"), kind: 'a', fields: []string{""}, ok: true},
		{name: "two fields", data: Record('i', "1", "x"), kind: 'i', fields: []string{"1", "x"}, ok: true},
		{name: "empty", data: nil},
		{name: "a kind alone", data: []byte("a")},
		{name: "not NUL-ended", data: []byte("afence")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, fields, ok := ParseRecord(tc.data)
			if ok != tc.ok || kind != tc.kind || strings.Join(fields, "|") != strings.Join(tc.fields, "|") {
				t.Fatalf("ParseRecord(%q) = %q %q %v, want %q %q %v", tc.data, kind, fields, ok, tc.kind, tc.fields, tc.ok)
			}
		})
	}
}

func with(inc Incarnation, f func(*Incarnation)) Incarnation {
	f(&inc)
	return inc
}

func replace(fields []string, i int, v string) []string {
	out := append([]string{}, fields...)
	out[i] = v
	return out
}

func same(a, b Incarnation) bool {
	if (a.Identity == nil) != (b.Identity == nil) || (a.Identity != nil && *a.Identity != *b.Identity) {
		return false
	}
	return a.Generation == b.Generation && a.Kind == b.Kind && a.Fence == b.Fence && a.Endpoint == b.Endpoint &&
		bytes.Equal(a.Payload, b.Payload) && a.Session == b.Session && bytes.Equal(a.Seed, b.Seed)
}
