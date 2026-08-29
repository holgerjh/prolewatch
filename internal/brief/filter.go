package brief

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/holgerjh/prolewatch/internal/safe"
	"github.com/klauspost/compress/zstd"
)

// FilterResult describes what a rewrite removed and what it produced.
type FilterResult struct {
	Stripped []string
	Pruned   []string
	// SHA256 of the rewritten archive. Any approval was bound to the archive
	// the build produced, so a rewrite hands pacman different bytes and the
	// transaction must be re-bound to these.
	SHA256 string
}

// dropSet computes, exactly once, the set of member names a rewrite removes:
// the requested strip set plus every directory left with nothing beneath it.
//
// This function exists because the strip set and the .MTREE filter set must be
// computed identically. If they diverge, pacman -Qp may parse an archive whose
// .MTREE still names a stripped member; pacman -Qkk then reports an altered
// installed package. One computation feeds both consumers.
func dropSet(members []*tar.Header, strip []string) (drop map[string]bool, pruned []string) {
	stripSet := map[string]bool{}
	for _, name := range strip {
		stripSet[NormalizeMember(name)] = true
	}
	directories := map[string]bool{}
	survivingFiles := map[string]bool{}
	for _, header := range members {
		name := NormalizeMember(header.Name)
		if header.Typeflag == tar.TypeDir {
			directories[name] = true
			continue
		}
		if !stripSet[name] {
			survivingFiles[name] = true
		}
	}
	drop = map[string]bool{}
	for name := range stripSet {
		drop[name] = true
	}
	for directory := range directories {
		occupied := false
		for file := range survivingFiles {
			if strings.HasPrefix(file, directory+"/") {
				occupied = true
				break
			}
		}
		if !occupied {
			drop[directory] = true
			pruned = append(pruned, directory)
		}
	}
	sort.Strings(pruned)
	return drop, pruned
}

// FilterArchive rewrites a built package with the named members removed.
//
// It filters the stream: entries are copied with their headers intact, dropped
// members are skipped, and .MTREE is rewritten by removing the corresponding
// lines from the original text. Nothing else changes by a single byte.
//
// Extracting and repacking as the ordinary user loses archive ownership, while
// regenerating under fakeroot also requires reproducing makepkg's exact bsdtar
// options and .MTREE fields across versions. Streaming preserves headers and
// needs neither fakeroot nor an option string.
//
// One cosmetic consequence, owned here rather than left for pacman -Qi to
// surface unexplained: .PKGINFO's installed-size becomes stale. pacman uses it
// for reporting, not verification.
func FilterArchive(sourcePath, targetPath string, strip []string) (FilterResult, error) {
	headers, err := archiveHeaders(sourcePath)
	if err != nil {
		return FilterResult{}, err
	}
	present := map[string]bool{}
	for _, header := range headers {
		present[NormalizeMember(header.Name)] = true
	}
	for _, name := range strip {
		normalized := NormalizeMember(name)
		if !present[normalized] {
			return FilterResult{}, fmt.Errorf("cannot strip %q: not present in the package", normalized)
		}
		if pacmanMetadataMembers[normalized] && normalized != ".INSTALL" {
			// .MTREE, .PKGINFO and .BUILDINFO are pacman's own metadata.
			// Removing one produces a package that does not install, which is a
			// worse outcome than declining to strip.
			return FilterResult{}, fmt.Errorf("refusing to strip pacman metadata member %q", normalized)
		}
	}
	drop, pruned := dropSet(headers, strip)

	source, err := os.Open(sourcePath)
	if err != nil {
		return FilterResult{}, err
	}
	defer source.Close()
	decoder, err := zstd.NewReader(source)
	if err != nil {
		return FilterResult{}, err
	}
	defer decoder.Close()

	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return FilterResult{}, err
	}
	defer target.Close()
	encoder, err := zstd.NewWriter(target)
	if err != nil {
		return FilterResult{}, err
	}

	reader := tar.NewReader(decoder)
	writer := tar.NewWriter(encoder)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return FilterResult{}, fmt.Errorf("read package: %w", err)
		}
		name := NormalizeMember(header.Name)
		if drop[name] {
			continue
		}
		if name == ".MTREE" {
			if err := writeFilteredMTree(writer, header, reader, drop); err != nil {
				return FilterResult{}, err
			}
			continue
		}
		if err := writer.WriteHeader(header); err != nil {
			return FilterResult{}, err
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := io.Copy(writer, reader); err != nil {
				return FilterResult{}, err
			}
		}
	}
	if err := writer.Close(); err != nil {
		return FilterResult{}, err
	}
	if err := encoder.Close(); err != nil {
		return FilterResult{}, err
	}
	if err := target.Close(); err != nil {
		return FilterResult{}, err
	}

	digest, err := safe.HashFileNoFollow(targetPath)
	if err != nil {
		return FilterResult{}, err
	}
	stripped := make([]string, 0, len(strip))
	for _, name := range strip {
		stripped = append(stripped, NormalizeMember(name))
	}
	sort.Strings(stripped)
	return FilterResult{Stripped: stripped, Pruned: pruned, SHA256: digest}, nil
}

// writeFilteredMTree rewrites .MTREE by removing the lines naming dropped
// members. The original gzipped text is filtered rather than regenerated, so
// every surviving line - including ownership, modes and digests - is byte
// identical to what makepkg emitted.
func writeFilteredMTree(writer *tar.Writer, header *tar.Header, reader io.Reader, drop map[string]bool) error {
	compressed, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	decompressor, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf(".MTREE is not gzip: %w", err)
	}
	text, err := io.ReadAll(decompressor)
	if err != nil {
		return err
	}
	var kept strings.Builder
	for _, line := range strings.SplitAfter(string(text), "\n") {
		trimmed := strings.TrimSuffix(line, "\n")
		// Comments and /set /unset directives carry no member name and must
		// survive: /set establishes the defaults every following line inherits.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/set") || strings.HasPrefix(trimmed, "/unset") {
			kept.WriteString(line)
			continue
		}
		// The pathname token is escaped; the drop set holds decoded archive
		// member names. Comparing the raw token removed the member from the
		// archive and left its metadata record behind for any name libarchive
		// escapes - a space is written \040.
		name, _, _ := strings.Cut(trimmed, " ")
		if drop[NormalizeMember(DecodeMTreePath(name))] {
			continue
		}
		kept.WriteString(line)
	}
	var blob bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&blob, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := compressor.Write([]byte(kept.String())); err != nil {
		return err
	}
	if err := compressor.Close(); err != nil {
		return err
	}
	rewritten := *header
	rewritten.Size = int64(blob.Len())
	if err := writer.WriteHeader(&rewritten); err != nil {
		return err
	}
	_, err = writer.Write(blob.Bytes())
	return err
}

func archiveHeaders(path string) ([]*tar.Header, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder, err := zstd.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	var headers []*tar.Header
	reader := tar.NewReader(decoder)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return headers, nil
		}
		if err != nil {
			return nil, err
		}
		copied := *header
		headers = append(headers, &copied)
	}
}
