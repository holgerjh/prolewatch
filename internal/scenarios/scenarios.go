package scenarios

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/holgerjh/prolewatch/internal/audit"
)

const (
	manifestName     = "scenario.json"
	packageDirectory = "package"
	maxManifestBytes = 64 * 1024
	maxFixtureBytes  = 4 * 1024 * 1024
	maxFixtureFiles  = 128
)

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,127}$`)
	webURLPattern = regexp.MustCompile(`https?://[^\s'"<>]+`)
)

type Manifest struct {
	SchemaVersion  int             `json:"schema_version"`
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Incident       string          `json:"incident"`
	Reference      string          `json:"reference"`
	Claim          string          `json:"claim"`
	Phase          string          `json:"phase"`
	Expected       Expected        `json:"expected"`
	GeneratedFiles []GeneratedFile `json:"generated_files"`
}

type Expected struct {
	Decision         string            `json:"decision"`
	ApprovalEligible *bool             `json:"approval_eligible"`
	CoverageComplete *bool             `json:"coverage_complete"`
	ExactRuleIDs     bool              `json:"exact_rule_ids"`
	RequiredFindings []ExpectedFinding `json:"required_findings"`
}

type ExpectedFinding struct {
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	HardBlock bool   `json:"hard_block"`
}

type GeneratedFile struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
}

type Result struct {
	Manifest         Manifest
	Decision         string
	ApprovalEligible bool
	CoverageComplete bool
	Findings         []audit.Finding
	Problems         []string
}

func (r Result) Passed() bool { return len(r.Problems) == 0 }

func Run(root, only string) ([]Result, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read scenario root: %w", err)
	}
	var results []Result
	found := false
	for _, entry := range entries {
		if !entry.IsDir() {
			return nil, fmt.Errorf("unexpected non-directory in scenario root: %s", entry.Name())
		}
		if only != "" && entry.Name() != only {
			continue
		}
		found = true
		scenarioRoot := filepath.Join(root, entry.Name())
		manifest, err := loadManifest(scenarioRoot, entry.Name())
		if err != nil {
			return nil, err
		}
		packageRoot, cleanup, err := materializePackage(scenarioRoot, manifest.GeneratedFiles)
		if err != nil {
			return nil, fmt.Errorf("scenario %s: %w", manifest.ID, err)
		}
		result, runErr := runOne(manifest, packageRoot)
		cleanup()
		if runErr != nil {
			return nil, fmt.Errorf("scenario %s: %w", manifest.ID, runErr)
		}
		results = append(results, result)
	}
	if only != "" && !found {
		return nil, fmt.Errorf("unknown scenario %q", only)
	}
	if len(results) == 0 {
		return nil, errors.New("no security scenarios found")
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Manifest.ID < results[j].Manifest.ID })
	return results, nil
}

func runOne(manifest Manifest, packageRoot string) (Result, error) {
	cfg := audit.DefaultConfig()
	cfg.Review.Mode = audit.ReviewModeDeterministicOnly
	inventory, err := audit.NewScanner(cfg).ScanDirectory(packageRoot, manifest.Phase)
	if err != nil {
		return Result{}, err
	}
	assessment := audit.AssessDeterministic(inventory)
	result := Result{
		Manifest: manifest, Decision: assessment.Decision,
		ApprovalEligible: assessment.ApprovalEligible,
		CoverageComplete: inventory.Coverage.Complete,
		Findings:         append([]audit.Finding(nil), inventory.Findings...),
	}
	if result.Decision != manifest.Expected.Decision {
		result.Problems = append(result.Problems, fmt.Sprintf("decision=%s, want %s", result.Decision, manifest.Expected.Decision))
	}
	if result.ApprovalEligible != *manifest.Expected.ApprovalEligible {
		result.Problems = append(result.Problems, fmt.Sprintf("approval_eligible=%t, want %t", result.ApprovalEligible, *manifest.Expected.ApprovalEligible))
	}
	if result.CoverageComplete != *manifest.Expected.CoverageComplete {
		result.Problems = append(result.Problems, fmt.Sprintf("coverage_complete=%t, want %t", result.CoverageComplete, *manifest.Expected.CoverageComplete))
	}
	for _, expected := range manifest.Expected.RequiredFindings {
		if !hasFinding(result.Findings, expected) {
			result.Problems = append(result.Problems, fmt.Sprintf("missing finding %s/%s/hard=%t", expected.RuleID, expected.Severity, expected.HardBlock))
		}
	}
	if manifest.Expected.ExactRuleIDs {
		actual := make(map[string]bool)
		wanted := make(map[string]bool)
		for _, finding := range result.Findings {
			actual[finding.RuleID] = true
		}
		for _, finding := range manifest.Expected.RequiredFindings {
			wanted[finding.RuleID] = true
		}
		if !sameSet(actual, wanted) {
			result.Problems = append(result.Problems, fmt.Sprintf("rule_ids=%v, want exactly %v", sortedKeys(actual), sortedKeys(wanted)))
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].RuleID == result.Findings[j].RuleID {
			return result.Findings[i].File < result.Findings[j].File
		}
		return result.Findings[i].RuleID < result.Findings[j].RuleID
	})
	return result, nil
}

func loadManifest(root, directoryName string) (Manifest, error) {
	path := filepath.Join(root, manifestName)
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("scenario %s: stat manifest: %w", directoryName, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return Manifest{}, fmt.Errorf("scenario %s: manifest is not a bounded regular file", directoryName)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("scenario %s: read manifest: %w", directoryName, err)
	}
	var manifest Manifest
	if err := audit.DecodeStrict(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("scenario %s: decode manifest: %w", directoryName, err)
	}
	if err := manifest.validate(directoryName); err != nil {
		return Manifest{}, fmt.Errorf("scenario %s: %w", directoryName, err)
	}
	return manifest, nil
}

func (manifest Manifest) validate(directoryName string) error {
	if manifest.SchemaVersion != 1 {
		return errors.New("unsupported manifest schema")
	}
	if !idPattern.MatchString(manifest.ID) || manifest.ID != directoryName {
		return errors.New("id must be a lowercase slug matching its directory")
	}
	if strings.TrimSpace(manifest.Title) == "" || len(manifest.Title) > 160 {
		return errors.New("title is empty or too long")
	}
	if strings.TrimSpace(manifest.Incident) == "" || len(manifest.Incident) > 160 {
		return errors.New("incident mapping is empty or too long")
	}
	if !strings.HasPrefix(manifest.Reference, "docs/") || !strings.Contains(manifest.Reference, ".md#") || strings.Contains(manifest.Reference, "..") {
		return errors.New("reference must be an anchored repository documentation path")
	}
	if manifest.Claim != "control" && manifest.Claim != "mitigated" && manifest.Claim != "partially-mitigated" {
		return errors.New("claim must be control, mitigated, or partially-mitigated")
	}
	if manifest.Phase != "pre" && manifest.Phase != "post" {
		return errors.New("phase must be pre or post")
	}
	if manifest.Expected.Decision != "allow" && manifest.Expected.Decision != "block" {
		return errors.New("expected decision must be allow or block")
	}
	if manifest.Expected.ApprovalEligible == nil || manifest.Expected.CoverageComplete == nil {
		return errors.New("approval_eligible and coverage_complete expectations are required")
	}
	if manifest.Expected.RequiredFindings == nil || manifest.GeneratedFiles == nil {
		return errors.New("required_findings and generated_files must be explicit arrays")
	}
	if manifest.Expected.Decision == "allow" && *manifest.Expected.ApprovalEligible {
		return errors.New("an allowed scenario cannot be approval-eligible")
	}
	seenFindings := make(map[string]bool)
	for _, finding := range manifest.Expected.RequiredFindings {
		if !ruleIDPattern.MatchString(finding.RuleID) || !validSeverity(finding.Severity) || seenFindings[finding.RuleID] {
			return fmt.Errorf("invalid or duplicate expected finding %q", finding.RuleID)
		}
		seenFindings[finding.RuleID] = true
	}
	if len(manifest.GeneratedFiles) > 16 {
		return errors.New("too many generated fixtures")
	}
	seenGenerated := make(map[string]bool)
	for _, generated := range manifest.GeneratedFiles {
		if err := validateRelativePath(generated.Path); err != nil || seenGenerated[generated.Path] {
			return fmt.Errorf("invalid or duplicate generated path %q", generated.Path)
		}
		seenGenerated[generated.Path] = true
		switch generated.Kind {
		case "minimal-elf", "traversal-tar":
			if generated.Target != "" {
				return fmt.Errorf("generated file %q has an unexpected target", generated.Path)
			}
		case "escaping-symlink":
			if generated.Target != "../outside" {
				return fmt.Errorf("escaping symlink %q must use the inert ../outside target", generated.Path)
			}
		default:
			return fmt.Errorf("unsupported generated fixture kind %q", generated.Kind)
		}
	}
	return nil
}

func materializePackage(scenarioRoot string, generated []GeneratedFile) (string, func(), error) {
	source := filepath.Join(scenarioRoot, packageDirectory)
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() {
		return "", func() {}, errors.New("package directory is missing")
	}
	temporary, err := os.MkdirTemp("", "prolewatch-scenario-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(temporary) }
	packageRoot := filepath.Join(temporary, packageDirectory)
	if err := os.Mkdir(packageRoot, 0o700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := copyFixtureTree(source, packageRoot); err != nil {
		cleanup()
		return "", func() {}, err
	}
	for _, fixture := range generated {
		if err := generateFixture(packageRoot, fixture); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return packageRoot, cleanup, nil
}

func copyFixtureTree(source, destination string) error {
	files := 0
	var total int64
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		if err := validateRelativePath(relative); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			return fmt.Errorf("fixture must be a non-executable regular file: %s", relative)
		}
		files++
		total += info.Size()
		if files > maxFixtureFiles || total > maxFixtureBytes {
			return errors.New("fixture corpus exceeds safety limits")
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(io.LimitReader(input, maxFixtureBytes+1))
		closeErr := input.Close()
		if readErr != nil || closeErr != nil || len(content) > maxFixtureBytes {
			return errors.New("fixture file exceeds safety limit")
		}
		if err := validateFixtureURLs(relative, content); err != nil {
			return err
		}
		return os.WriteFile(target, content, info.Mode().Perm())
	})
}

func generateFixture(root string, fixture GeneratedFile) error {
	target := filepath.Join(root, filepath.FromSlash(fixture.Path))
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("generated fixture collides with package file: %s", fixture.Path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	switch fixture.Kind {
	case "minimal-elf":
		content := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 24)...)
		return os.WriteFile(target, content, 0o600)
	case "traversal-tar":
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		payload := []byte("harmless traversal fixture\n")
		if err := writer.WriteHeader(&tar.Header{Name: "../outside", Mode: 0o600, Size: int64(len(payload))}); err != nil {
			return err
		}
		if _, err := writer.Write(payload); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
		return os.WriteFile(target, output.Bytes(), 0o600)
	case "escaping-symlink":
		return os.Symlink(fixture.Target, target)
	default:
		return fmt.Errorf("unsupported generated fixture kind: %s", fixture.Kind)
	}
}

func validateFixtureURLs(path string, content []byte) error {
	for _, match := range webURLPattern.FindAllString(string(content), -1) {
		parsed, err := url.Parse(strings.TrimRight(match, ").,;"))
		if err != nil {
			return fmt.Errorf("fixture %s contains an invalid URL", path)
		}
		host := strings.ToLower(parsed.Hostname())
		if host != "invalid" && !strings.HasSuffix(host, ".invalid") {
			return fmt.Errorf("fixture %s contains non-reserved network target %q", path, host)
		}
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return errors.New("path must remain inside the scenario package")
	}
	return nil
}

func hasFinding(findings []audit.Finding, expected ExpectedFinding) bool {
	for _, finding := range findings {
		if finding.RuleID == expected.RuleID && finding.Severity == expected.Severity && finding.HardBlock == expected.HardBlock {
			return true
		}
	}
	return false
}

func validSeverity(value string) bool {
	switch value {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func sameSet(first, second map[string]bool) bool {
	if len(first) != len(second) {
		return false
	}
	for key := range first {
		if !second[key] {
			return false
		}
	}
	return true
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
