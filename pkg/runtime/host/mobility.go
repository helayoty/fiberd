package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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

// ExportInfo is what ExportDelta writes beside the archives.
type ExportInfo struct {
	Session     string            `json:"session"`
	Domain      string            `json:"domain"`
	Digest      string            `json:"digest"`
	Annotations map[string]string `json:"annotations"`
	Parent      string            `json:"parent_sha256,omitempty"`
}

// ExportDelta moves the published delta of session under grant g from
// the registry into dir and returns the names of the files it wrote. The
// session's tag is deleted from the registry afterwards: the home that
// exported it forgets its copy on its next Clone of the name, and only
// what dir holds can bring the session back.
func ExportDelta(ctx context.Context, cfg Config, g core.Grant, session, dir string) ([]string, error) {
	if cfg.DeltaRegistry == "" {
		return nil, errors.New("host: no delta registry configured")
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
		pref := repo + ":" + parentTag(info.Parent)
		if _, err := artifact.PullDir(ctx, pref, filepath.Join(tmp, "parent"), cfg.RegistryPlainHTTP); err != nil {
			return nil, fmt.Errorf("host: delta needs parent %s: %w", info.Parent[:12], err)
		}
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
	if cfg.DeltaRegistry == "" {
		return errors.New("host: no delta registry configured")
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
	tmp, err := os.MkdirTemp("", "fiberd-import-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if info.Parent != "" {
		pref := repo + ":" + parentTag(info.Parent)
		if _, found, err := artifact.Resolve(ctx, pref, cfg.RegistryPlainHTTP); err != nil {
			return err
		} else if !found {
			if err := artifact.Untar(filepath.Join(dir, ExportParentFile), filepath.Join(tmp, "parent")); err != nil {
				return fmt.Errorf("host: import parent: %w", err)
			}
			// The parent carries the platform facts the delta was made on.
			ann := map[string]string{artifact.AnnotationParent: info.Parent, artifact.AnnotationHome: cfg.HomeID}
			for _, k := range []string{artifact.AnnotationArch, artifact.AnnotationKernel, artifact.AnnotationLibc, artifact.AnnotationBackend} {
				if v, ok := info.Annotations[k]; ok {
					ann[k] = v
				}
			}
			if _, err := artifact.PushDir(ctx, filepath.Join(tmp, "parent"), pref, artifact.ArtifactTypeParent, ann, cfg.RegistryPlainHTTP); err != nil {
				return err
			}
		}
	}
	if err := artifact.Untar(filepath.Join(dir, ExportDeltaFile), filepath.Join(tmp, "delta")); err != nil {
		return fmt.Errorf("host: import delta: %w", err)
	}
	_ = os.Remove(filepath.Join(tmp, "delta", remoteFile))
	ann := make(map[string]string, len(info.Annotations)+3)
	for k, v := range info.Annotations {
		ann[k] = v
	}
	ann[artifact.AnnotationSession] = session
	ann[artifact.AnnotationGrant] = g.UID
	ann[artifact.AnnotationHome] = cfg.HomeID
	ref := repo + ":" + sessionTag(session)
	if _, err := artifact.PushDir(ctx, filepath.Join(tmp, "delta"), ref, artifact.ArtifactTypeDelta, ann, cfg.RegistryPlainHTTP); err != nil {
		return err
	}
	return nil
}
