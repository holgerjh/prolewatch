package brief

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/holgerjh/prolewatch/internal/safe"
	"github.com/klauspost/compress/zstd"
)

// PrivilegedSurface is one root-execution channel a built package carries.
type PrivilegedSurface struct {
	// Member is the archive member name, normalised: no leading "./".
	Member string
	Kind   SurfaceKind
	// Activation says whether this surface must be answered for or only shown.
	// See SurfaceActivation.
	Activation SurfaceActivation
	// LinkTarget is set when the member is a symlink. A link is shown rather
	// than summarised because where it points is the whole content of the file.
	LinkTarget string
	// When describes the moment the code runs, for the gate's display. The
	// distinction that matters to a user is this-transaction versus every
	// future one.
	When string
	// Body is the file's contents when it is small enough to read, already
	// rendered safe for a terminal. A user asked to approve code must be shown
	// the code.
	Body string
	// Truncated reports that Body is not the whole file. A gate that silently
	// shows part of a scriptlet is worse than one that admits it.
	Truncated bool
	Size      int64
}

// maxSurfaceBody bounds how much of a surface file is read for display. The
// bytes are attacker-authored; a scriptlet worth reading is far smaller.
const maxSurfaceBody = 64 * 1024

// pacmanMetadataMembers are archive members pacman owns. They are never
// privileged surfaces and are never stripped.
var pacmanMetadataMembers = map[string]bool{
	".PKGINFO": true, ".BUILDINFO": true, ".MTREE": true, ".INSTALL": true, ".CHANGELOG": true,
}

// EnumerateSurfaces lists every privileged-integration surface in a built
// package, reading small ones so the gate can show the user the code.
//
// The archive is attacker-produced. Go's own tar and zstd readers are used
// rather than handing the bytes to bsdtar, and the caller is expected to run
// this inside containment - see docs/architecture.md control 3.
func EnumerateSurfaces(packagePath string) ([]PrivilegedSurface, error) {
	file, err := os.Open(packagePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder, err := zstd.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("open package: %w", err)
	}
	defer decoder.Close()

	var surfaces []PrivilegedSurface
	reader := tar.NewReader(decoder)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read package: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		class, ok := ClassifySurface(header.Name)
		if !ok {
			continue
		}
		surface := PrivilegedSurface{
			Member:     NormalizeMember(header.Name),
			Kind:       class.Kind,
			Activation: class.Activation,
			When:       class.When,
			Size:       header.Size,
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			// A link's meaning is not in its path. One occupying a unit name can
			// alias, replace or mask an existing unit, and classification that
			// reads only the path cannot tell which - so a link that would
			// otherwise have been listed is asked about instead.
			surface.LinkTarget = safe.Inline(header.Linkname, 4096)
			if !surface.Activation.RequiresDecision() {
				surface.Activation = ActivationAutomatic
				surface.When = "a link occupying " + surface.Member + "; where it points decides what it does"
			}
		}
		if header.Typeflag == tar.TypeReg {
			body, truncated, err := readBounded(reader, maxSurfaceBody)
			if err != nil {
				return nil, err
			}
			surface.Body = safe.Text(body, maxSurfaceBody)
			surface.Truncated = truncated
		}
		surfaces = append(surfaces, surface)
	}
	sort.Slice(surfaces, func(i, j int) bool { return surfaces[i].Member < surfaces[j].Member })
	return surfaces, nil
}

// SurfacesRequiringDecision returns the surfaces that run as root, or grant
// privilege, with no further step by anyone.
//
// This is the set worth stopping an install for. The rest - a unit nobody has
// enabled, a user-session unit, a module file nothing references - is
// inventory: real, worth showing, and not a question, because a question asked
// on every service package is answered by reflex.
func SurfacesRequiringDecision(surfaces []PrivilegedSurface) []PrivilegedSurface {
	var decide []PrivilegedSurface
	for _, surface := range surfaces {
		if surface.Activation.RequiresDecision() {
			decide = append(decide, surface)
		}
	}
	return decide
}

func readBounded(reader io.Reader, limit int64) (string, bool, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(raw)) > limit {
		return string(raw[:limit]), true, nil
	}
	return string(raw), false, nil
}
