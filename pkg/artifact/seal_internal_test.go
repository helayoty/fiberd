package artifact

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"
)

// TestKeySeparation: every kind of key derives from the master under its
// own HKDF info, so no two of them coincide, even for a delta whose
// domain is spelled like a parent's label.
func TestKeySeparation(t *testing.T) {
	master := &SealKey{ID: "k", Key: bytes.Repeat([]byte{9}, 32)}
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wrapSeed, err := hkdf.Key(sha256.New, master.Key, nil, infoWrap, 32)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		a, b func() ([]byte, error)
	}{
		{name: "parent and delta of the same label", a: func() ([]byte, error) { return parentKey(master, sha) },
			b: func() ([]byte, error) { return deltaKey(master, "parent:"+sha) }},
		{name: "parent and the wrap seed", a: func() ([]byte, error) { return parentKey(master, sha) },
			b: func() ([]byte, error) { return wrapSeed, nil }},
		{name: "delta and the wrap seed", a: func() ([]byte, error) { return deltaKey(master, "fiberd-template-wrap-v1") },
			b: func() ([]byte, error) { return wrapSeed, nil }},
		{name: "two parents", a: func() ([]byte, error) { return parentKey(master, sha) },
			b: func() ([]byte, error) { return parentKey(master, sha[:63]+"b") }},
		{name: "a parent and the master", a: func() ([]byte, error) { return parentKey(master, sha) },
			b: func() ([]byte, error) { return master.Key, nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := c.a()
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.b()
			if err != nil {
				t.Fatal(err)
			}
			if len(a) != 32 || len(b) != 32 {
				t.Fatalf("keys of %d and %d bytes, want 32", len(a), len(b))
			}
			if bytes.Equal(a, b) {
				t.Fatal("the two keys are the same")
			}
		})
	}
}

// TestParentKeyDeterministic: the parent key is a function of the master
// and the sha alone, so any home with the master opens any home's parent.
func TestParentKeyDeterministic(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name   string
		master []byte
		same   bool
	}{
		{name: "the same master", master: bytes.Repeat([]byte{9}, 32), same: true},
		{name: "another master", master: bytes.Repeat([]byte{8}, 32)},
	}
	ref, err := parentKey(&SealKey{ID: "k", Key: bytes.Repeat([]byte{9}, 32)}, sha)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parentKey(&SealKey{ID: "other-id", Key: c.master}, sha)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, ref) != c.same {
				t.Fatalf("same key = %v, want %v", !c.same, c.same)
			}
		})
	}
}
