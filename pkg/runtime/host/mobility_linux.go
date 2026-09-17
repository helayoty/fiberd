//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// Session mobility through the registry.
//
//	<DeltaRegistry>/<domain>:s-<hash(session)>  the parked delta
//	<DeltaRegistry>/<domain>:p-<parent sha>      a zygote checkpoint a
//	                                             delta depends on
//
// The domain is the grant's session domain (session_class, else the
// template digest): two homes hold different grants, but a session's
// state is a delta over one template's pages, so that is what they
// share.
//
// A home publishes after every park of a named session and records the
// digest it pushed beside the delta. Another home finds the session by
// reading the manifest, decides on w_bytes, pulls it by digest, fetches
// the parent if it lacks it, and deletes the tag: from then on only the
// claiming home holds the session. The publishing home notices on its
// next Clone(S) that its recorded digest is no longer at the tag and
// forgets its stale copy.

func (r *Runtime) domainRepo(g core.Grant) string { return domainRepoFor(r.cfg.DeltaRegistry, g) }

// PublishDelta implements core.DeltaPublisher.
func (r *Runtime) PublishDelta(ctx context.Context, deltaRef string, g core.Grant, session string) (string, error) {
	if r.cfg.DeltaRegistry == "" {
		return "", errors.New("host: no delta registry configured")
	}
	var m manifest
	if err := readJSON(filepath.Join(deltaRef, "manifest.json"), &m); err != nil {
		return "", err
	}
	grantUID := g.UID
	repo := r.domainRepo(g)
	if m.Delta && m.Parent != "" {
		if err := r.publishParent(ctx, repo, m.Parent); err != nil {
			return "", fmt.Errorf("host: publish parent: %w", err)
		}
	}
	ref := repo + ":" + sessionTag(session)
	ann := map[string]string{
		artifact.AnnotationWBytes:  strconv.FormatUint(m.WBytes, 10),
		artifact.AnnotationParent:  m.Parent,
		artifact.AnnotationHome:    r.cfg.HomeID,
		artifact.AnnotationFence:   m.Fence,
		artifact.AnnotationGrant:   grantUID,
		artifact.AnnotationSession: session,
	}
	r.host.Annotate(ann) // what a claiming home must be able to restore
	digest, err := artifact.PushDir(ctx, deltaRef, ref, artifact.ArtifactTypeDelta, ann, r.cfg.RegistryPlainHTTP)
	if err != nil {
		return "", err
	}
	if err := writeJSON(filepath.Join(deltaRef, remoteFile), remoteRecord{Ref: ref, Digest: digest}); err != nil {
		return "", err
	}
	log.Printf("host: published %s/%s as %s@%s (%d bytes)", grantUID, session, ref, digest[:19], m.WBytes)
	return ref + "@" + digest, nil
}

// publishParent pushes a zygote checkpoint once, so a claiming home that
// was not warmed from the same artifact can still merge the delta.
func (r *Runtime) publishParent(ctx context.Context, repo, sha string) error {
	ref := repo + ":" + parentTag(sha)
	if _, found, err := artifact.Resolve(ctx, ref, r.cfg.RegistryPlainHTTP); err != nil {
		return err
	} else if found {
		return nil
	}
	dir := filepath.Join(r.parentsDir(), sha)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("parent %s not in the store: %w", sha[:12], err)
	}
	ann := map[string]string{artifact.AnnotationParent: sha, artifact.AnnotationHome: r.cfg.HomeID}
	r.host.Annotate(ann)
	_, err := artifact.PushDir(ctx, dir, ref, artifact.ArtifactTypeParent, ann, r.cfg.RegistryPlainHTTP)
	if err == nil {
		log.Printf("host: published parent checkpoint %s", sha[:12])
	}
	return err
}

// FindDelta implements core.DeltaFinder: the manifest only.
func (r *Runtime) FindDelta(ctx context.Context, g core.Grant, session string) (core.RemoteDelta, bool, error) {
	if r.cfg.DeltaRegistry == "" {
		return core.RemoteDelta{}, false, nil
	}
	ref := r.domainRepo(g) + ":" + sessionTag(session)
	loc, found, err := artifact.Resolve(ctx, ref, r.cfg.RegistryPlainHTTP)
	if err != nil || !found {
		return core.RemoteDelta{}, false, err
	}
	if loc.ArtifactType != artifact.ArtifactTypeDelta {
		return core.RemoteDelta{}, false, fmt.Errorf("host: %s is %q, not a delta", ref, loc.ArtifactType)
	}
	w, _ := strconv.ParseUint(loc.Annotations[artifact.AnnotationWBytes], 10, 64)
	rd := core.RemoteDelta{WBytes: w, Home: loc.Annotations[artifact.AnnotationHome], Handle: loc.Digest}
	// The parity gate for a session made elsewhere: found, but not ours
	// to take unless its pages can restore here.
	if made, ok := artifact.PlatformFromAnnotations(loc.Annotations); ok {
		if err := r.cfg.Parity.Check(r.host, made); err != nil {
			return rd, true, &core.RemoteMiss{
				Err:           fmt.Errorf("%w: %s/%s parked on %s (%s): %w", core.ErrIncompatible, g.UID, session, rd.Home, made, err),
				PreferredHome: rd.Home,
			}
		}
	}
	return rd, true, nil
}

// ClaimDelta implements core.DeltaFinder: pull by the digest that was
// found, fetch the parent if this home lacks it, then delete the tag so
// no other home can claim the same state.
func (r *Runtime) ClaimDelta(ctx context.Context, g core.Grant, session string, rd core.RemoteDelta) (string, error) {
	grantUID := g.UID
	repo := r.domainRepo(g)
	ref := repo + ":" + sessionTag(session)
	dst := filepath.Join(r.cfg.DeltaDir, grantUID, fmt.Sprintf("claimed-%s-%d", sessionTag(session), time.Now().UnixNano()))
	if _, err := artifact.PullDir(ctx, repo+"@"+rd.Handle, dst, r.cfg.RegistryPlainHTTP); err != nil {
		_ = os.RemoveAll(dst)
		return "", err
	}
	_ = os.Remove(filepath.Join(dst, remoteFile)) // the publisher's record, not ours
	if codec := r.codec(); codec != nil && codec.HasDelta(dst) {
		info, err := codec.ReadDeltaInfo(dst)
		if err != nil {
			_ = os.RemoveAll(dst)
			return "", err
		}
		if _, err := r.parent(info.ParentSHA256); err != nil {
			if err := r.pullParent(ctx, repo, info.ParentSHA256); err != nil {
				_ = os.RemoveAll(dst)
				return "", fmt.Errorf("host: delta needs parent %s: %w", info.ParentSHA256[:12], err)
			}
		}
	}
	// The claim: the tag must still point at what we pulled.
	loc, found, err := artifact.Resolve(ctx, ref, r.cfg.RegistryPlainHTTP)
	if err != nil {
		_ = os.RemoveAll(dst)
		return "", err
	}
	if !found || loc.Digest != rd.Handle {
		_ = os.RemoveAll(dst)
		return "", errors.New("host: session was claimed or re-parked elsewhere meanwhile")
	}
	if err := artifact.Delete(ctx, ref, r.cfg.RegistryPlainHTTP); err != nil {
		_ = os.RemoveAll(dst)
		return "", fmt.Errorf("host: claim %s: %w", ref, err)
	}
	log.Printf("host: claimed %s/%s from %s (%d bytes) -> %s", grantUID, session, rd.Home, rd.WBytes, dst)
	return dst, nil
}

// pullParent fetches a zygote checkpoint into the store and verifies it
// hashes to what the delta expects.
func (r *Runtime) pullParent(ctx context.Context, repo, sha string) error {
	dst := filepath.Join(r.parentsDir(), sha)
	tmp := dst + ".pull"
	_ = os.RemoveAll(tmp)
	if _, err := artifact.PullDir(ctx, repo+":"+parentTag(sha), tmp, r.cfg.RegistryPlainHTTP); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	codec := r.codec()
	if codec == nil {
		_ = os.RemoveAll(tmp)
		return errors.New("host: backend has no delta codec")
	}
	p, err := codec.LoadParent(tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	got := p.SHA256()
	p.Close()
	if got != sha {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("pulled parent hashes to %s, want %s", got[:12], sha[:12])
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	log.Printf("host: pulled parent checkpoint %s", sha[:12])
	return nil
}

// Owned implements core.DeltaFinder: a published delta is still ours
// while the tag holds the digest we pushed. Never published: ours.
func (r *Runtime) Owned(ctx context.Context, deltaRef string) bool {
	var rec remoteRecord
	if err := readJSON(filepath.Join(deltaRef, remoteFile), &rec); err != nil {
		return true
	}
	loc, found, err := artifact.Resolve(ctx, rec.Ref, r.cfg.RegistryPlainHTTP)
	if err != nil {
		return true // cannot tell; keep serving what we have
	}
	return found && loc.Digest == rec.Digest
}
