package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
)

// Where a session lives in the delta registry (see mobility_linux.go for
// the publish/find/claim protocol the runtime runs over it).

var repoUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// domainRepoFor is the repository a grant's sessions are published under:
// one per session domain, named after it, disambiguated by a hash.
func domainRepoFor(registry string, g core.Grant) string {
	domain := g.SessionDomain()
	sum := sha256.Sum256([]byte(domain))
	name := repoUnsafe.ReplaceAllString(strings.ToLower(strings.TrimPrefix(domain, "sha256:")), "-")
	name = strings.Trim(name, "-._")
	if name == "" {
		name = "g"
	}
	if len(name) > 40 {
		name = name[:40]
	}
	return strings.TrimSuffix(registry, "/") + "/" + name + "-" + hex.EncodeToString(sum[:4])
}

func sessionTag(session string) string {
	sum := sha256.Sum256([]byte(session))
	return "s-" + hex.EncodeToString(sum[:12])
}

func parentTag(sha string) string {
	if len(sha) > 24 {
		sha = sha[:24]
	}
	return "p-" + sha
}

// pushDelta seals the delta in src for its domain and session under
// cfg's seal key and pushes the sealed copy to ref, signed. The plaintext
// never leaves this home.
func pushDelta(ctx context.Context, cfg Config, src, ref string, ann map[string]string, c artifact.SealContext) (string, error) {
	tmp, err := os.MkdirTemp(filepath.Dir(src), ".seal-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := artifact.SealDir(src, tmp, cfg.DeltaKeys.Seal, c); err != nil {
		return "", err
	}
	ann = maps.Clone(ann)
	ann[artifact.AnnotationDomain] = c.Domain
	ann[artifact.AnnotationSession] = c.Session
	ann[artifact.AnnotationExpires] = c.Expires.UTC().Format(time.RFC3339)
	ann[artifact.AnnotationSealKey] = cfg.DeltaKeys.Seal.ID
	return artifact.PushDir(ctx, tmp, ref, artifact.ArtifactTypeDelta, ann, cfg.DeltaKeys.Signer, cfg.RegistryPlainHTTP)
}

// sealContext is what a delta for session of g pushed now is sealed for.
func (c Config) sealContext(g core.Grant, session, fence string, now time.Time) artifact.SealContext {
	return artifact.SealContext{Domain: g.SessionDomain(), Session: session, Fence: fence,
		Expires: now.Add(deltaTTL).UTC().Truncate(time.Second)}
}

// checkSigned refuses a signed delta whose annotations name another
// domain or session than the one asked for (a manifest copied onto
// another tag), or whose expiry has passed. Call it after the signature
// is verified: before that, nothing in the annotations is believed.
func checkSigned(ann map[string]string, domain, session string, now time.Time) error {
	if ann[artifact.AnnotationDomain] != domain || ann[artifact.AnnotationSession] != session {
		return fmt.Errorf("%w: signed for %s/%s, not %s/%s", artifact.ErrUntrusted,
			ann[artifact.AnnotationDomain], ann[artifact.AnnotationSession], domain, session)
	}
	exp, err := time.Parse(time.RFC3339, ann[artifact.AnnotationExpires])
	if err != nil {
		return fmt.Errorf("%w: no expiry", artifact.ErrUntrusted)
	}
	if !now.Before(exp) {
		return fmt.Errorf("%w: at %s", artifact.ErrExpired, exp.Format(time.RFC3339))
	}
	return nil
}

type remoteRecord struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

const remoteFile = "remote.json"

// Export and import: a parked session as portable files.
//
// A home publishes every park of a named session to its delta registry
// and claims sessions from it; that is how state moves between homes
// that share a registry. An environment that moves state itself (a
// control plane with its own snapshot store) needs the session as a
// handful of files it can ship and hand back: ExportDelta takes the
// session out of the registry into a directory, ImportDelta puts a
// directory back under a session name, so the next Clone of that name
// on the importing home claims and resumes it. Both work on any registry
// the home is configured with, a file:// one included.

const (
	// ExportDeltaFile holds the delta's files (the parked images and their
	// manifest), ExportParentFile the template checkpoint the delta is
	// relative to (absent when the park was a full checkpoint), and
	// ExportInfoFile describes both.
	ExportDeltaFile  = "fiberd-delta.tar"
	ExportParentFile = "fiberd-parent.tar"
	ExportInfoFile   = "fiberd-delta.json"
)

// ExportInfo is what ExportDelta writes beside the archives. Domain
// records where the session came from for whoever ships the files;
// ImportDelta never believes it (the destination grant's domain decides
// what the delta must open for). Annotations and ParentAnnotations are
// the signed manifests of the delta and of its parent checkpoint: the
// signatures they carry are what ImportDelta checks the archives
// against, so an export made before parents were signed has no
// ParentAnnotations and its parent is refused.
type ExportInfo struct {
	Session           string            `json:"session"`
	Domain            string            `json:"domain"`
	Digest            string            `json:"digest"`
	Annotations       map[string]string `json:"annotations"`
	Parent            string            `json:"parent_sha256,omitempty"`
	ParentAnnotations map[string]string `json:"parent_annotations,omitempty"`
}

// platformAnnotations are the facts about the platform a checkpoint was
// made on that a parent pushed by an import carries along.
var platformAnnotations = []string{artifact.AnnotationArch, artifact.AnnotationKernel, artifact.AnnotationLibc, artifact.AnnotationBackend}

// resolveParent finds the parent checkpoint sha under repo and checks
// that a trusted home signed it as that checkpoint. Nothing in its
// manifest is believed before the signature is, and a signed parent
// copied onto another checkpoint's tag is not that checkpoint.
func resolveParent(ctx context.Context, cfg Config, repo, sha string) (artifact.Located, error) {
	loc, found, err := artifact.Resolve(ctx, repo+":"+parentTag(sha), cfg.RegistryPlainHTTP)
	if err != nil {
		return artifact.Located{}, err
	}
	if !found {
		return artifact.Located{}, fmt.Errorf("parent %s is not published", sha[:12])
	}
	if loc.ArtifactType != artifact.ArtifactTypeParent {
		return artifact.Located{}, fmt.Errorf("parent %s is %q, not a parent checkpoint", sha[:12], loc.ArtifactType)
	}
	if err := cfg.DeltaKeys.Verify(loc); err != nil {
		return artifact.Located{}, fmt.Errorf("parent %s: %w", sha[:12], err)
	}
	if err := checkParentSigned(loc.Annotations, sha); err != nil {
		return artifact.Located{}, err
	}
	return loc, nil
}

// checkParentSigned refuses a verified parent manifest that names
// another checkpoint than the one it stands for.
func checkParentSigned(ann map[string]string, sha string) error {
	if ann[artifact.AnnotationParent] != sha {
		return fmt.Errorf("%w: parent %s is signed as checkpoint %q", artifact.ErrUntrusted, sha[:12], ann[artifact.AnnotationParent])
	}
	return nil
}

// ExportDelta moves the published delta of session under grant g from
// the registry into dir and returns the names of the files it wrote. The
// session's tag is deleted from the registry afterwards: the home that
// exported it forgets its copy on its next Clone of the name, and only
// what dir holds can bring the session back.
func ExportDelta(ctx context.Context, cfg Config, g core.Grant, session, dir string) ([]string, error) {
	if err := cfg.checkDeltaRegistry(); err != nil {
		return nil, err
	}
	repo := domainRepoFor(cfg.DeltaRegistry, g)
	ref := repo + ":" + sessionTag(session)
	loc, found, err := artifact.Resolve(ctx, ref, cfg.RegistryPlainHTTP)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("host: session %s/%s is not published", g.UID, session)
	}
	if loc.ArtifactType != artifact.ArtifactTypeDelta {
		return nil, fmt.Errorf("host: %s is %q, not a delta", ref, loc.ArtifactType)
	}
	if err := cfg.DeltaKeys.Verify(loc); err != nil {
		return nil, fmt.Errorf("host: refusing to export %s/%s: %w", g.UID, session, err)
	}
	if err := checkSigned(loc.Annotations, g.SessionDomain(), session, time.Now()); err != nil {
		return nil, fmt.Errorf("host: refusing to export %s/%s: %w", g.UID, session, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(dir, ".export-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if _, err := artifact.PullDir(ctx, repo+"@"+loc.Digest, filepath.Join(tmp, "delta"), cfg.RegistryPlainHTTP); err != nil {
		return nil, err
	}
	if err := artifact.TarDir(filepath.Join(tmp, "delta"), filepath.Join(dir, ExportDeltaFile)); err != nil {
		return nil, err
	}
	files := []string{ExportDeltaFile, ExportInfoFile}
	info := ExportInfo{Session: session, Domain: g.SessionDomain(), Digest: loc.Digest, Annotations: loc.Annotations,
		Parent: loc.Annotations[artifact.AnnotationParent]}
	if info.Parent != "" {
		// The parent travels with the delta, and so does its signed
		// manifest: the importing home checks the files against it rather
		// than taking whatever the archive holds on this home's word.
		ploc, err := resolveParent(ctx, cfg, repo, info.Parent)
		if err != nil {
			return nil, fmt.Errorf("host: refusing to export %s/%s: delta needs %w", g.UID, session, err)
		}
		if _, err := artifact.PullDir(ctx, repo+"@"+ploc.Digest, filepath.Join(tmp, "parent"), cfg.RegistryPlainHTTP); err != nil {
			return nil, fmt.Errorf("host: delta needs parent %s: %w", info.Parent[:12], err)
		}
		info.ParentAnnotations = ploc.Annotations
		if err := artifact.TarDir(filepath.Join(tmp, "parent"), filepath.Join(dir, ExportParentFile)); err != nil {
			return nil, err
		}
		files = append(files, ExportParentFile)
	}
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ExportInfoFile), b, 0o644); err != nil {
		return nil, err
	}
	if err := artifact.Delete(ctx, ref, cfg.RegistryPlainHTTP); err != nil {
		return nil, fmt.Errorf("host: retire %s after export: %w", ref, err)
	}
	return files, nil
}

// ImportDelta publishes the files ExportDelta wrote in dir as session
// under grant g, so that Clone(session) on this home finds, claims and
// resumes it. The session name may differ from the exported one: a
// template's golden state imported under many names is many sessions.
func ImportDelta(ctx context.Context, cfg Config, g core.Grant, session, dir string) error {
	if err := cfg.checkDeltaRegistry(); err != nil {
		return err
	}
	var info ExportInfo
	b, err := os.ReadFile(filepath.Join(dir, ExportInfoFile))
	if err != nil {
		return fmt.Errorf("host: import: %w", err)
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return fmt.Errorf("host: import %s: %w", ExportInfoFile, err)
	}
	repo := domainRepoFor(cfg.DeltaRegistry, g)
	// The delta is opened in the clear below, so the working directory
	// goes under DeltaDir, which fibers never see, and not the system temp
	// dir, which they share. A caller without a DeltaDir (one that is not
	// a home, like a control plane shipping snapshots) works beside the
	// export files, as ExportDelta does, where it already keeps them.
	base := cfg.DeltaDir
	if base == "" {
		base = dir
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return fmt.Errorf("host: import: %w", err)
	}
	tmp, err := os.MkdirTemp(base, ".import-")
	if err != nil {
		return fmt.Errorf("host: import: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	// The delta must carry a trusted home's signature over these very
	// files, and open with this home's seal key for the session it was
	// exported as, before this home seals and signs it as its own. The
	// parent is template state, not tenant memory, so it is not sealed,
	// but it must carry a trusted home's signature too: a claim checks
	// only that its pages hash to what the delta names, and this home
	// signs what it pushes, so an unverified parent would become a
	// trusted one here.
	//
	// The domain is g's, never the export's: the seal key is derived per
	// domain from a master every home holds, so a delta of any domain
	// would open here, and taking the domain from the (unsigned) info file
	// would let an import carry one tenant's session into another's
	// grant. The session name is the export's: a golden snapshot imported
	// under many names in its own domain is many sessions.
	if err := artifact.Untar(filepath.Join(dir, ExportDeltaFile), filepath.Join(tmp, "delta")); err != nil {
		return fmt.Errorf("host: import delta: %w", err)
	}
	if err := cfg.DeltaKeys.VerifyDir(filepath.Join(tmp, "delta"), artifact.ArtifactTypeDelta, info.Annotations); err != nil {
		return fmt.Errorf("host: import %s/%s: %w", g.UID, session, err)
	}
	now := time.Now()
	domain := g.SessionDomain()
	if err := checkSigned(info.Annotations, domain, info.Session, now); err != nil {
		return fmt.Errorf("host: import %s/%s: %w", g.UID, session, err)
	}
	sealed, err := artifact.OpenDir(filepath.Join(tmp, "delta"), cfg.DeltaKeys.Seal, domain, info.Session, now)
	if err != nil {
		return fmt.Errorf("host: import %s/%s: %w", g.UID, session, err)
	}
	if info.Parent != "" && info.Parent != info.Annotations[artifact.AnnotationParent] {
		return fmt.Errorf("host: import %s/%s: %s names parent %s, the signed delta %s", g.UID, session, ExportInfoFile,
			info.Parent, info.Annotations[artifact.AnnotationParent])
	}
	if info.Parent != "" {
		pref := repo + ":" + parentTag(info.Parent)
		if _, found, err := artifact.Resolve(ctx, pref, cfg.RegistryPlainHTTP); err != nil {
			return err
		} else if !found {
			if err := artifact.Untar(filepath.Join(dir, ExportParentFile), filepath.Join(tmp, "parent")); err != nil {
				return fmt.Errorf("host: import parent: %w", err)
			}
			if err := cfg.DeltaKeys.VerifyDir(filepath.Join(tmp, "parent"), artifact.ArtifactTypeParent, info.ParentAnnotations); err != nil {
				return fmt.Errorf("host: import %s/%s: parent %s: %w", g.UID, session, info.Parent[:12], err)
			}
			if err := checkParentSigned(info.ParentAnnotations, info.Parent); err != nil {
				return fmt.Errorf("host: import %s/%s: %w", g.UID, session, err)
			}
			// The parent carries the platform facts it was made on, from its
			// own signed manifest where it has them, else from the delta's.
			ann := map[string]string{artifact.AnnotationParent: info.Parent, artifact.AnnotationHome: cfg.HomeID}
			for _, k := range platformAnnotations {
				if v, ok := info.ParentAnnotations[k]; ok {
					ann[k] = v
				} else if v, ok := info.Annotations[k]; ok {
					ann[k] = v
				}
			}
			if _, err := artifact.PushDir(ctx, filepath.Join(tmp, "parent"), pref, artifact.ArtifactTypeParent, ann, cfg.DeltaKeys.Signer, cfg.RegistryPlainHTTP); err != nil {
				return err
			}
		}
	}
	_ = os.Remove(filepath.Join(tmp, "delta", remoteFile))
	ann := make(map[string]string, len(info.Annotations)+3)
	for k, v := range info.Annotations {
		if k != artifact.AnnotationSignature && k != artifact.AnnotationSigner {
			ann[k] = v
		}
	}
	ann[artifact.AnnotationGrant] = g.UID
	ann[artifact.AnnotationHome] = cfg.HomeID
	ref := repo + ":" + sessionTag(session)
	_, err = pushDelta(ctx, cfg, filepath.Join(tmp, "delta"), ref, ann, cfg.sealContext(g, session, sealed.Fence, now))
	return err
}
