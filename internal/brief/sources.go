package brief

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/safe"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	SourceKindArchive   = "archive"
	SourceKindFile      = "file"
	SourceKindSignature = "signature"
	SourceKindVCS       = "vcs"
)

type SourceProvenance struct {
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	URL               string `json:"url"`
	Transport         string `json:"transport"`
	Binding           string `json:"binding"`
	DeclaredAlgorithm string `json:"declared_algorithm,omitempty"`
	DeclaredDigest    string `json:"declared_digest,omitempty"`
	ObservedSHA256    string `json:"observed_sha256,omitempty"`
	ScanDepth         int    `json:"scan_depth"`
	ContentInspected  bool   `json:"content_inspected"`
}

type SourceVerification struct {
	Checksums string `json:"checksums"`
	PGP       string `json:"pgp"`
}

func (s SourceProvenance) Validate() error {
	validKinds := map[string]bool{SourceKindArchive: true, SourceKindFile: true, SourceKindSignature: true, SourceKindVCS: true}
	validBindings := map[string]bool{"fixed-digest": true, "vcs-commit": true, "mutable-vcs": true, "signature-companion": true, "unbound": true}
	if s.Name == "" || len(s.Name) > 4096 || path.Base(s.Name) != s.Name || len(s.URL) > 8192 || s.Transport == "" || len(s.Transport) > 64 || !validKinds[s.Kind] || !validBindings[s.Binding] || s.ScanDepth < 0 || s.ScanDepth > 64 {
		return fmt.Errorf("invalid source provenance for %q", s.Name)
	}
	if s.ObservedSHA256 != "" && !safe.ValidHexDigest(s.ObservedSHA256) {
		return fmt.Errorf("invalid observed source digest for %q", s.Name)
	}
	if (s.DeclaredAlgorithm == "") != (s.DeclaredDigest == "") || len(s.DeclaredAlgorithm) > 32 || len(s.DeclaredDigest) > 256 {
		return fmt.Errorf("invalid declared source binding for %q", s.Name)
	}
	return nil
}

func (s SourceVerification) Validate() error {
	if !map[string]bool{"": true, "unknown": true, "passed": true}[s.Checksums] || !map[string]bool{"": true, "unknown": true, "pending": true, "verified": true, "skipped": true, "not-applicable": true}[s.PGP] {
		return fmt.Errorf("invalid source verification receipt")
	}
	return nil
}

type sourceLane struct {
	sources []string
	sums    map[string][]string
}

var fullCommitRE = regexp.MustCompile(`(?i)^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)

func ParseSourceProvenance(raw []byte, scanDepth int) []SourceProvenance {
	// SRCINFO suffixes (for example source_x86_64 and sha256sums_x86_64) form
	// parallel lanes. Digest entries are matched by position within the same lane,
	// mirroring makepkg metadata without executing PKGBUILD shell.
	lanes := map[string]*sourceLane{}
	lane := func(suffix string) *sourceLane {
		if lanes[suffix] == nil {
			lanes[suffix] = &sourceLane{sums: map[string][]string{}}
		}
		return lanes[suffix]
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " = ")
		if !ok {
			continue
		}
		if key == "source" || strings.HasPrefix(key, "source_") {
			lane(strings.TrimPrefix(key, "source")).sources = append(lane(strings.TrimPrefix(key, "source")).sources, value)
			continue
		}
		for _, algorithm := range []string{"b2", "sha512", "sha384", "sha256", "sha224", "sha1", "md5"} {
			prefix := algorithm + "sums"
			if key == prefix || strings.HasPrefix(key, prefix+"_") {
				suffix := strings.TrimPrefix(key, prefix)
				lane(suffix).sums[algorithm] = append(lane(suffix).sums[algorithm], value)
				break
			}
		}
	}
	var result []SourceProvenance
	for _, current := range lanes {
		for index, declared := range current.sources {
			sourceURL := declared
			if _, value, ok := strings.Cut(declared, "::"); ok {
				sourceURL = value
			}
			if !remoteSourceRE.MatchString(sourceURL) {
				continue
			}
			entry := SourceProvenance{Name: makepkgSourceName(declared), URL: sourceURL, Transport: sourceTransport(sourceURL), ScanDepth: scanDepth}
			entry.Kind = remoteSourceKind(sourceURL, entry.Name)
			entry.Binding = "unbound"
			// Prefer the strongest declared non-SKIP checksum in deterministic order.
			for _, algorithm := range []string{"b2", "sha512", "sha384", "sha256", "sha224", "sha1", "md5"} {
				values := current.sums[algorithm]
				if index < len(values) && values[index] != "" && !strings.EqualFold(values[index], "SKIP") {
					entry.Binding, entry.DeclaredAlgorithm, entry.DeclaredDigest = "fixed-digest", algorithm, values[index]
					break
				}
			}
			if entry.Kind == SourceKindVCS {
				// Forty and 64 hex characters cover full Git SHA-1/SHA-256-style
				// commit IDs. Branches/tags remain explicitly mutable provenance.
				if commit := sourceFragmentValue(sourceURL, "commit"); fullCommitRE.MatchString(commit) {
					entry.Binding, entry.DeclaredAlgorithm, entry.DeclaredDigest = "vcs-commit", "commit", strings.ToLower(commit)
				} else if entry.Binding != "fixed-digest" {
					entry.Binding = "mutable-vcs"
				}
			} else if entry.Kind == SourceKindSignature && entry.Binding == "unbound" {
				entry.Binding = "signature-companion"
			}
			if entry.Name != "" && path.Base(entry.Name) == entry.Name {
				result = append(result, entry)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name || result[i].Name == result[j].Name && result[i].URL < result[j].URL
	})
	return result
}

// SupportedSourceTransport reports whether Prolewatch can carry a declared
// source, and says why not when it cannot.
//
// The first release fetches over HTTP(S) only, and the broker permits only
// ports 80 and 443, so a `git://` (9418) or `git+ssh://` source cannot work
// however it is classified. Saying so during the pre briefing is the whole
// point: the package would otherwise fail deep inside acquisition, after the
// user has already read a briefing and agreed to continue, with an error about
// a scheme they never chose.
//
// SSH is not an oversight to fix later without thought. It means credentials,
// and a build that holds the user's keys is the thing containment exists to
// prevent; carrying it would need a brokered agent, not a wider port list.
func SupportedSourceTransport(url string) (bool, string) {
	lower := strings.ToLower(url)
	for _, prefix := range []string{"bzr+", "fossil+", "git+", "hg+", "svn+"} {
		lower = strings.TrimPrefix(lower, prefix)
	}
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return true, ""
	case !strings.Contains(lower, "://"):
		// A bare name is a file already in the checkout, which needs no
		// transport at all.
		return true, ""
	}
	scheme := lower[:strings.Index(lower, "://")]
	return false, scheme
}

func sourceTransport(value string) string {
	if index := strings.Index(value, "://"); index > 0 {
		return strings.ToLower(value[:index])
	}
	if index := strings.IndexByte(value, '+'); index > 0 {
		return strings.ToLower(value[:index])
	}
	return "remote"
}

func remoteSourceKind(value, name string) string {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"bzr+", "fossil+", "git+", "hg+", "svn+"} {
		if strings.HasPrefix(lower, prefix) {
			return SourceKindVCS
		}
	}
	remoteName := value
	if index := strings.IndexAny(remoteName, "?#"); index >= 0 {
		remoteName = remoteName[:index]
	}
	ext := strings.ToLower(path.Ext(name))
	remoteExt := strings.ToLower(path.Ext(remoteName))
	if ext == ".sig" || ext == ".asc" || remoteExt == ".sig" || remoteExt == ".asc" {
		return SourceKindSignature
	}
	if archiveFormatFromName(name) != "" || archiveFormatFromName(remoteName) != "" {
		return SourceKindArchive
	}
	return SourceKindFile
}

func sourceFragmentValue(value, key string) string {
	fragment := ""
	if index := strings.IndexByte(value, '#'); index >= 0 {
		fragment = value[index+1:]
	}
	for _, item := range strings.Split(fragment, "&") {
		if name, result, ok := strings.Cut(item, "="); ok && name == key {
			return result
		}
	}
	return ""
}

func archiveFormatFromName(name string) string {
	lower := strings.ToLower(name)
	for suffix, format := range map[string]string{
		".tar": "tar", ".tar.gz": "gzip", ".tgz": "gzip", ".tar.bz2": "bzip2", ".tbz2": "bzip2",
		".tar.xz": "xz", ".txz": "xz", ".tar.zst": "zstd", ".zip": "zip",
	} {
		if strings.HasSuffix(lower, suffix) {
			return format
		}
	}
	return ""
}

// unsupportedTransportFindings reports declared sources this build cannot
// fetch, before the build starts rather than after.
//
// Not a hard block: it is a compatibility boundary, not a security failure, and
// the honest outcome is that the user learns immediately why this package will
// not build under Prolewatch instead of watching acquisition fail later.
func unsupportedTransportFindings(sources []SourceProvenance) []Finding {
	var findings []Finding
	for _, source := range sources {
		if ok, scheme := SupportedSourceTransport(source.URL); !ok {
			findings = append(findings, Finding{Severity: "medium", Category: "coverage", File: ".SRCINFO",
				Evidence:  source.Name + ": " + scheme,
				Rationale: "this release fetches declared sources over HTTP(S) only, so the build cannot retrieve this source; install the package without Prolewatch or ask upstream for an HTTP(S) source",
				RuleID:    "source-transport-unsupported"})
		}
	}
	return findings
}

func sourceProvenanceFindings(sources []SourceProvenance) []Finding {
	var findings []Finding
	for _, source := range sources {
		if source.Binding != "unbound" && source.Binding != "mutable-vcs" {
			continue
		}
		findings = append(findings, Finding{Severity: "medium", Category: "integrity", File: ".SRCINFO", Evidence: source.Name + ": " + source.Binding, Rationale: "vendor source provenance is mutable or lacks a fixed content binding; local policy accepts it with a warning", RuleID: "vendor-provenance-weak"})
	}
	return findings
}

func bindObservedSources(inv *Inventory) {
	// Bind a file source by its file digest and a VCS/directory source by canonical
	// metadata for every descendant. Archive-member pseudo-records are omitted
	// because their bytes are already committed by the containing file.
	if inv == nil || len(inv.Sources) == 0 {
		return
	}
	for index := range inv.Sources {
		source := &inv.Sources[index]
		var records []map[string]any
		for _, record := range inv.Files {
			if record.Kind == "archive-member" {
				continue
			}
			if record.Path == source.Name {
				source.ObservedSHA256 = record.SHA256
				records = nil
				break
			}
			if strings.HasPrefix(record.Path, source.Name+"/") {
				records = append(records, bindingValue(record))
			}
		}
		if source.ObservedSHA256 == "" && len(records) > 0 {
			sort.Slice(records, func(i, j int) bool { return fmt.Sprint(records[i]["path"]) < fmt.Sprint(records[j]["path"]) })
			if raw, err := safe.CanonicalJSON(records); err == nil {
				source.ObservedSHA256 = safe.SHA256Bytes(raw)
			}
		}
		source.ContentInspected = source.ObservedSHA256 != "" && inv.Phase == "post" && source.ScanDepth > 0
	}
}

func bindingValue(record FileRecord) map[string]any {
	return map[string]any{
		"path": record.Path, "path_b64": record.PathB64, "kind": record.Kind,
		"mode": record.Mode, "size": record.Size, "sha256": record.SHA256,
		"executable": record.Executable, "link_target": record.LinkTarget,
	}
}

func BindingHashFiles(files []FileRecord) (string, error) {
	values := make([]map[string]any, 0, len(files))
	for _, record := range files {
		if record.Kind != "archive-member" {
			values = append(values, bindingValue(record))
		}
	}
	sort.Slice(values, func(i, j int) bool { return fmt.Sprint(values[i]["path_b64"]) < fmt.Sprint(values[j]["path_b64"]) })
	raw, err := safe.CanonicalJSON(values)
	if err != nil {
		return "", err
	}
	return safe.SHA256Bytes(raw), nil
}

func BindingHashManifest(manifest []map[string]any) (string, error) {
	files := make([]FileRecord, 0, len(manifest))
	for _, value := range manifest {
		record, err := ValidateManifestRecord(value)
		if err != nil {
			return "", err
		}
		files = append(files, record)
	}
	return BindingHashFiles(files)
}

// SourceSummary states how firmly a package's material is pinned, and what
// verification said about it.
//
// "3 sources, 2 pinned to exact bytes, 1 mutable" is the difference between a
// package whose content cannot change under the recipe and one whose git tag
// can be moved after review. It belongs beside the findings, because a finding
// in mutable material is a finding about something that may not be what
// arrives next time.
func SourceSummary(sources []SourceProvenance, verification SourceVerification) string {
	if len(sources) == 0 {
		return ""
	}
	depth := sources[0].ScanDepth
	fixed, weak := 0, 0
	for _, source := range sources {
		if source.Binding == "fixed-digest" || source.Binding == "vcs-commit" || source.Binding == "signature-companion" {
			fixed++
		} else {
			weak++
		}
	}
	policy := "content accepted uninspected"
	if depth > 0 {
		policy = fmt.Sprintf("content inspected to depth %d", depth)
	}
	result := fmt.Sprintf("%d pinned to exact bytes", fixed)
	if weak > 0 {
		result += fmt.Sprintf(", %d mutable", weak)
	}
	result += " · " + policy
	if verification.Checksums != "" && verification.Checksums != "unknown" {
		result += " · checksums " + verification.Checksums
	}
	if verification.PGP != "" && verification.PGP != "unknown" && verification.PGP != "not-applicable" {
		result += " · PGP " + verification.PGP
	}
	return result
}

var manifestKeys = map[string]bool{
	"path": true, "path_b64": true, "kind": true, "mode": true, "size": true,
	"sha256": true, "executable": true, "text": true, "link_target": true,
	"archive_entries": true, "archive_format": true, "extractable": true,
	"selected_reason": true, "binary_metadata": true,
}

func ValidateManifestRecord(record map[string]any) (FileRecord, error) {
	// Round-trip through the typed record only after enforcing the exact key set.
	// This avoids accepting JSON-compatible maps with silently ignored metadata.
	if len(record) != len(manifestKeys) {
		return FileRecord{}, errors.New("manifest record has missing or extra fields")
	}
	for key := range record {
		if !manifestKeys[key] {
			return FileRecord{}, fmt.Errorf("manifest record contains unknown field %q", key)
		}
	}
	raw, err := safe.CanonicalJSON(record)
	if err != nil {
		return FileRecord{}, err
	}
	var decoded FileRecord
	if err := safe.DecodeJSON(raw, &decoded); err != nil {
		return FileRecord{}, fmt.Errorf("invalid manifest record: %w", err)
	}
	validKinds := map[string]bool{"file": true, "archive-member": true, "symlink": true, "fifo": true, "char-device": true, "block-device": true, "socket": true, "special": true}
	validReasons := map[string]bool{"": true, "mandatory": true, "archive-member": true, "binary-metadata": true, "executable": true}
	if decoded.Path == "" || len(decoded.Path) > 4096 || len(decoded.PathB64) > 8192 || !validKinds[decoded.Kind] || decoded.Mode > 0o7777 || decoded.Size < 0 || decoded.ArchiveEntries < 0 || len(decoded.LinkTarget) > 4096 || !validReasons[decoded.SelectedReason] || decoded.BinaryMetadata == nil {
		return FileRecord{}, errors.New("manifest record violates value limits")
	}
	if _, err := base64.URLEncoding.DecodeString(decoded.PathB64); err != nil {
		return FileRecord{}, errors.New("manifest path_b64 is invalid")
	}
	if decoded.Kind == "file" || decoded.Kind == "archive-member" {
		if !safe.ValidHexDigest(decoded.SHA256) {
			return FileRecord{}, errors.New("manifest file digest is invalid")
		}
	} else if decoded.SHA256 != "" {
		return FileRecord{}, errors.New("non-file manifest record has a digest")
	}
	return decoded, nil
}
