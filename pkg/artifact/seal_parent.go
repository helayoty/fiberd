package artifact

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Sealed parent checkpoints. A home-made parent is the zygote's memory
// after READY, so it leaves the home only sealed. Its key derives from
// the master and the parent's own content hash, the sha256 every delta
// names as parent_sha256. The sealed files carry the label parent:<sha>
// and no expiry. A parent copied to another sha's tag fails the label
// check, and a parent pushed in the clear fails the magic check, both
// before any pagemap is parsed.
//
// What the sha covers is decided by the delta codec (criu.LoadParent
// hashes the pages files in pagemap order), not here. So OpenParentDir
// does not hash the plaintext. The caller must load the opened directory
// with the codec and compare its SHA256 to the sha it asked for, which is
// what pullParent and ImportDelta do today. One definition of the hash,
// in the code that makes it, is safer than a second one here that could
// drift from it.

// parentDomain is the seal label of a parent checkpoint.
const parentDomain = "parent:"

// ParentContext is the context a parent checkpoint is sealed for. The
// zero Expires means never.
func ParentContext(sha string) SealContext {
	return SealContext{Domain: parentDomain + sha}
}

// checkSHA256Hex refuses anything but 64 lowercase hex digits, so a seal
// label and its HKDF info are made of exactly what a delta or a config
// names.
func checkSHA256Hex(what, sha string) error {
	if len(sha) != 64 {
		return fmt.Errorf("artifact: %s %q is not a sha256", what, sha)
	}
	for _, c := range sha {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("artifact: %s %q is not a sha256", what, sha)
		}
	}
	return nil
}

// parentKey is the key every file of a parent checkpoint is sealed under.
// Its info prefix differs from a delta's, so the two never coincide even
// for a delta whose domain is literally parent:<sha>.
func parentKey(k *SealKey, sha string) ([]byte, error) {
	return hkdf.Key(sha256.New, k.Key, nil, infoParent+parentDomain+sha, 32)
}

// SealParentDir writes every file PushDir would push from src, sealed as
// the parent checkpoint sha, into dst under the same names. src must be
// the store entry whose codec hash is sha.
func SealParentDir(src, dst string, k *SealKey, sha string) error {
	if k == nil {
		return errors.New("artifact: no seal key")
	}
	if err := checkSHA256Hex("parent hash", sha); err != nil {
		return err
	}
	dk, err := parentKey(k, sha)
	if err != nil {
		return err
	}
	return sealDirWith(src, dst, dk, sealHeader{Key: k.ID, Context: ParentContext(sha)})
}

// OpenParentDir replaces every sealed file in dir by its plaintext. It
// refuses any file not sealed with k as the parent sha, or sealed as a
// delta or as author images, or changed since. On error, dir holds a
// mix of sealed and plain files, and the caller must remove it. On
// success the caller still loads dir with the delta codec and checks
// that it hashes to sha.
func OpenParentDir(dir string, k *SealKey, sha string) error {
	if k == nil {
		return errors.New("artifact: no seal key")
	}
	if err := checkSHA256Hex("parent hash", sha); err != nil {
		return err
	}
	want := ParentContext(sha)
	keyFor := func(h sealHeader) ([]byte, error) {
		switch {
		case h.Key != k.ID:
			return nil, fmt.Errorf("%w: sealed with key %q, this home has %q", ErrSealed, h.Key, k.ID)
		case h.Wrap != nil:
			return nil, fmt.Errorf("%w: sealed as author images, not a parent", ErrSealed)
		case !sameSealContext(h.Context, want):
			return nil, fmt.Errorf("%w: sealed as %q, not parent %s", ErrSealed, h.Context.Domain, sha[:12])
		}
		return parentKey(k, sha)
	}
	_, err := openDirWith(dir, keyFor)
	return err
}
