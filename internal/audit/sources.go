package audit

import (
	"bufio"
	"fmt"
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
	if s.ObservedSHA256 != "" && !validHexDigest(s.ObservedSHA256) {
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

func parseSourceProvenance(raw []byte, scanDepth int) []SourceProvenance {
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
			for _, algorithm := range []string{"b2", "sha512", "sha384", "sha256", "sha224", "sha1", "md5"} {
				values := current.sums[algorithm]
				if index < len(values) && values[index] != "" && !strings.EqualFold(values[index], "SKIP") {
					entry.Binding, entry.DeclaredAlgorithm, entry.DeclaredDigest = "fixed-digest", algorithm, values[index]
					break
				}
			}
			if entry.Kind == SourceKindVCS {
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
			if raw, err := CanonicalJSON(records); err == nil {
				source.ObservedSHA256 = SHA256Bytes(raw)
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

func bindingHashFiles(files []FileRecord) (string, error) {
	values := make([]map[string]any, 0, len(files))
	for _, record := range files {
		if record.Kind != "archive-member" {
			values = append(values, bindingValue(record))
		}
	}
	sort.Slice(values, func(i, j int) bool { return fmt.Sprint(values[i]["path_b64"]) < fmt.Sprint(values[j]["path_b64"]) })
	raw, err := CanonicalJSON(values)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(raw), nil
}

func bindingHashManifest(manifest []map[string]any) (string, error) {
	files := make([]FileRecord, 0, len(manifest))
	for _, value := range manifest {
		record, err := validateManifestRecord(value)
		if err != nil {
			return "", err
		}
		files = append(files, record)
	}
	return bindingHashFiles(files)
}

func sourceSummary(sources []SourceProvenance, verification SourceVerification) string {
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
	policy := "accepted uninspected"
	if depth > 0 {
		policy = fmt.Sprintf("inspected to depth %d", depth)
	}
	result := fmt.Sprintf("%d vendor source(s) · %s · %d bound", len(sources), policy, fixed)
	if weak > 0 {
		result += fmt.Sprintf(" · %d weak", weak)
	}
	if verification.Checksums != "" && verification.Checksums != "unknown" {
		result += " · checksums " + verification.Checksums
	}
	if verification.PGP != "" && verification.PGP != "unknown" && verification.PGP != "not-applicable" {
		result += " · PGP " + verification.PGP
	}
	return result
}
