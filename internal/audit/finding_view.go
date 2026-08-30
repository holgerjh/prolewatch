package audit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"golang.org/x/sys/unix"
)

const (
	findingPreviewMaxFiles = findingGuidanceLimit
	findingPreviewMaxBytes = 8 << 20
	findingPreviewRadius   = 2
)

type findingPreviewTarget struct {
	finding brief.Finding
	record  *brief.FileRecord
	carried bool
}

// findingPreviewTargets returns only findings at the configured decision
// threshold that name a line in a local, manifest-bound text file. Archive members require a separate
// extraction boundary and are deliberately not guessed into a host path.
func findingPreviewTargets(report *Report, root, minimumSeverity string) []findingPreviewTarget {
	if report == nil || root == "" || report.Phase == "artifact" {
		return nil
	}
	records := make(map[string]brief.FileRecord, len(report.Manifest))
	for _, value := range report.Manifest {
		record, err := brief.ValidateManifestRecord(value)
		if err == nil && record.Kind == "file" && record.Text {
			records[record.Path] = record
		}
	}
	pending := make([]findingPreviewTarget, 0, len(report.Findings))
	carriedTargets := make([]findingPreviewTarget, 0, len(report.Findings))
	carriedIDs := carriedFindingIDSet(report.CarriedDecision)
	seen := map[string]bool{}
	for _, finding := range report.Findings {
		if !severityAtLeast(finding.Severity, minimumSeverity) || finding.Line == nil || *finding.Line < 1 {
			continue
		}
		record, ok := records[finding.File]
		key := findingGuidanceID(finding)
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		recordCopy := record
		target := findingPreviewTarget{finding: finding, record: &recordCopy, carried: carriedIDs[key]}
		if target.carried {
			carriedTargets = append(carriedTargets, target)
		} else {
			pending = append(pending, target)
		}
	}
	return append(pending, carriedTargets...)
}

// allFindingPreviewTargets includes every stored finding. A manifest-bound
// local text record is optional: line-less and archive findings still have
// useful metadata and persisted AI guidance even though no source excerpt can
// safely be opened for them.
func allFindingPreviewTargets(report *Report) []findingPreviewTarget {
	if report == nil {
		return nil
	}
	records := make(map[string]brief.FileRecord, len(report.Manifest))
	for _, value := range report.Manifest {
		record, err := brief.ValidateManifestRecord(value)
		if err == nil && record.Kind == "file" && record.Text {
			records[record.Path] = record
		}
	}
	carriedIDs := carriedFindingIDSet(report.CarriedDecision)
	pending := make([]findingPreviewTarget, 0, len(report.Findings))
	carriedTargets := make([]findingPreviewTarget, 0, len(report.Findings))
	for _, finding := range report.Findings {
		target := findingPreviewTarget{finding: finding, carried: carriedIDs[findingGuidanceID(finding)]}
		if finding.Line != nil && *finding.Line > 0 {
			if record, ok := records[finding.File]; ok {
				recordCopy := record
				target.record = &recordCopy
			}
		}
		if target.carried {
			carriedTargets = append(carriedTargets, target)
		} else {
			pending = append(pending, target)
		}
	}
	return append(pending, carriedTargets...)
}

// metadataFindingPreviewTargets filters the metadata-capable all-findings view
// by severity. The artifact gate uses it for [i]: archive members cannot be
// reopened beneath a checkout root, but their stored path, evidence and
// guidance remain inspectable without pretending an excerpt is available.
func metadataFindingPreviewTargets(report *Report, minimumSeverity string) []findingPreviewTarget {
	all := allFindingPreviewTargets(report)
	filtered := make([]findingPreviewTarget, 0, len(all))
	for _, target := range all {
		if severityAtLeast(target.finding.Severity, minimumSeverity) {
			// This view is deliberately metadata-only. In particular, never let
			// an archive member whose display path happens to match a checkout
			// record cross into the local-file excerpt path.
			target.record = nil
			filtered = append(filtered, target)
		}
	}
	return filtered
}

// renderFindingPreview shows bounded source context and clearly separated AI
// advice without invoking a pager, editor, shell, or plugin host. Every source
// byte comes from a descriptor opened beneath the scanned root and is compared
// with the report manifest before it is rendered through terminalInline.
func renderFindingPreview(report *Report, root, minimumSeverity string, renderer terminalRenderer) string {
	return renderFindingPreviewTargets(report, root, findingPreviewTargets(report, root, minimumSeverity), renderer, findingPreviewMaxFiles, "decision findings")
}

func renderMetadataFindingPreview(report *Report, minimumSeverity string, renderer terminalRenderer, limit int) string {
	return renderFindingPreviewTargets(report, "", metadataFindingPreviewTargets(report, minimumSeverity), renderer, limit, "decision findings")
}

// renderAllFindingPreview is used by the explicit inspect command and the
// optional [a] action on prompts that already exist. A zero limit is unbounded
// because the command is an explicit request; prompt actions pass the bounded
// findingPreviewMaxFiles value and hand omitted entries off to that command.
func renderAllFindingPreview(report *Report, root string, renderer terminalRenderer, limit int) string {
	return renderFindingPreviewTargets(report, root, allFindingPreviewTargets(report), renderer, limit, "all findings")
}

func renderFindingPreviewTargets(report *Report, root string, targets []findingPreviewTarget, renderer terminalRenderer, limit int, scope string) string {
	if len(targets) == 0 {
		return ""
	}
	omitted := 0
	if limit > 0 && len(targets) > limit {
		omitted = len(targets) - limit
		targets = targets[:limit]
	}
	type cachedFile struct {
		raw       []byte
		localPath string
		err       error
	}
	cache := map[string]cachedFile{}
	type previewSection struct {
		heading   string
		metadata  string
		evidence  string
		localPath string
		context   []string
		advisory  []string
		carried   bool
	}
	sections := make([]previewSection, 0, len(targets))
	for _, target := range targets {
		source := target.finding.Source
		if source == "" {
			source = "deterministic"
		}
		section := previewSection{
			heading: strings.ToUpper(target.finding.Severity) + " (" + terminalInline(source, 32) + ") · " + terminalInline(target.finding.Rationale, 1000),
			carried: target.carried,
		}
		if target.carried {
			section.heading = strings.ToUpper(target.finding.Severity) + " (" + terminalInline(source, 32) + " · approved at recipe gate) · " + terminalInline(target.finding.Rationale, 1000)
		}
		location := terminalInline(target.finding.File, 4096)
		if target.finding.Line == nil {
			section.metadata = location + " · " + terminalInline(target.finding.Category, 100) + " · rule " + terminalInline(target.finding.RuleID, 200) + " · no source line recorded"
			if evidence := terminalInline(target.finding.Evidence, 1000); evidence != "" {
				section.evidence = "Evidence · " + evidence
			}
		} else {
			location += fmt.Sprintf(":%d", *target.finding.Line)
			switch {
			case target.record == nil:
				section.metadata = location + " · " + terminalInline(target.finding.Category, 100) + " · source context unavailable · no manifest-bound local text file"
			case root == "":
				section.metadata = location + " · " + terminalInline(target.finding.Category, 100) + " · source context unavailable · checkout changed or removed"
			default:
				cached, ok := cache[target.record.PathB64]
				if !ok {
					cached.raw, cached.localPath, cached.err = readManifestBoundFindingFile(root, *target.record)
					cache[target.record.PathB64] = cached
				}
				if cached.err != nil {
					section.metadata = location + " · " + terminalInline(target.finding.Category, 100) + " · source context unavailable · checkout changed, removed, or no longer matches this report"
				} else {
					context, err := findingContextLines(cached.raw, *target.finding.Line, findingPreviewRadius)
					if err != nil {
						section.metadata = location + " · " + terminalInline(target.finding.Category, 100) + " · source context unavailable · recorded line is outside the bound file"
					} else {
						section.metadata = location + " · " + terminalInline(target.finding.Category, 100) + " · SHA-256 verified"
						if target.carried {
							section.metadata += " · exact bytes unchanged"
						}
						section.localPath = "Local file (untrusted) · " + terminalInline(cached.localPath, 4096) + fmt.Sprintf(":%d", *target.finding.Line)
						for _, current := range context {
							marker := " "
							if current.Line == *target.finding.Line {
								marker = ">"
							}
							section.context = append(section.context, fmt.Sprintf("%s %6d │ %s", marker, current.Line, current.Text))
						}
					}
				}
			}
			if len(section.context) == 0 {
				if evidence := terminalInline(target.finding.Evidence, 1000); evidence != "" {
					section.evidence = "Evidence · " + evidence
				}
			}
		}
		if !target.carried {
			section.advisory = findingAdvisoryLines(report, target.finding)
		}
		sections = append(sections, section)
	}

	if !renderer.enabled() {
		plain := []string{"Prolewatch: read-only inspection of " + scope}
		carriedHeadingShown := false
		for _, section := range sections {
			if section.carried && !carriedHeadingShown {
				plain = append(plain, "Previously approved finding context (exact bytes unchanged)")
				carriedHeadingShown = true
			}
			plain = append(plain, section.heading, section.metadata)
			if section.evidence != "" {
				plain = append(plain, section.evidence)
			}
			if section.localPath != "" {
				plain = append(plain, section.localPath)
			}
			plain = append(plain, section.context...)
			plain = append(plain, section.advisory...)
			if len(section.advisory) > 0 {
				plain = append(plain, "")
			}
		}
		if omitted > 0 {
			plain = append(plain, omittedFindingPreviewLine(report, omitted))
		}
		plain = append(plain, "Opening a local file in an external tool leaves this verified read-only view.")
		return strings.Join(plain, "\n")
	}
	framed := []string{renderer.paint("blue", renderer.anchor()) + " " + renderer.paint("bold", "PROLEWATCH") + renderer.paint("muted", renderer.divider()+"READ-ONLY FINDING INSPECTION")}
	carriedHeadingShown := false
	for _, section := range sections {
		if section.carried && !carriedHeadingShown {
			framed = append(framed, renderer.paint("blue", renderer.pipe()))
			framed = append(framed, renderer.paint("blue", renderer.pipe())+"  "+renderer.paint("blue", "Previously approved finding context · exact bytes unchanged"))
			carriedHeadingShown = true
		}
		headingRole := severityRoleFromText(section.heading)
		if section.carried {
			headingRole = "blue"
		}
		framed = append(framed, renderer.paint("blue", renderer.fork())+" "+renderer.paint(headingRole, section.heading))
		framed = append(framed, renderer.paint("blue", renderer.pipe())+"  "+renderer.paint("muted", section.metadata))
		if section.evidence != "" {
			framed = append(framed, renderer.paint("blue", renderer.pipe())+"  "+renderer.paint("muted", section.evidence))
		}
		if section.localPath != "" {
			framed = append(framed, renderer.paint("blue", renderer.pipe())+"  "+renderer.paint("muted", section.localPath))
		}
		for _, line := range section.context {
			framed = append(framed, renderer.paint("blue", renderer.pipe())+" "+line)
		}
		if len(section.advisory) > 0 {
			framed = append(framed, renderer.paint("blue", renderer.pipe()))
			framed = append(framed, renderer.paint("blue", renderer.pipe())+"  "+renderer.paint("amber", section.advisory[0]))
			for _, line := range section.advisory[1:] {
				framed = append(framed, renderer.paint("blue", renderer.pipe())+"    "+line)
			}
			framed = append(framed, renderer.paint("blue", renderer.pipe()))
		}
	}
	if omitted > 0 {
		framed = append(framed, renderer.paint("blue", renderer.pipe())+"  "+renderer.paint("muted", omittedFindingPreviewLine(report, omitted)))
	}
	framed = append(framed, renderer.paint("blue", renderer.pipe())+" "+renderer.paint("muted", "Opening a local file in an external tool leaves this verified read-only view."))
	framed = append(framed, renderer.paint("blue", renderer.anchor())+" "+renderer.paint("bold", "PROLEWATCH")+renderer.paint("muted", renderer.divider()+"INSPECTION ENDED"))
	return strings.Join(framed, "\n")
}

func omittedFindingPreviewLine(report *Report, omitted int) string {
	id := "--latest"
	if report != nil && report.ReportID != "" {
		id = terminalInline(report.ReportID, 4096)
	}
	label := "findings"
	if omitted == 1 {
		label = "finding"
	}
	return fmt.Sprintf("… %d more %s · prolewatch inspect %s", omitted, label, id)
}

func severityRoleFromText(heading string) string {
	if strings.HasPrefix(heading, "HIGH ") || strings.HasPrefix(heading, "CRITICAL ") {
		return "red"
	}
	return "amber"
}

func findingAdvisoryLines(report *Report, finding brief.Finding) []string {
	if finding.Source == "ai" {
		lines := []string{"AI-GENERATED FINDING"}
		if evidence := terminalInline(finding.Evidence, 1000); evidence != "" {
			lines = append(lines, "evidence · "+evidence)
		}
		return lines
	}
	guidance, ok := reportFindingGuidance(report, finding)
	if !ok {
		status := "NOT PRODUCED FOR THIS REPORT"
		if report == nil || report.Reviewer.Mode != ReviewModeAI {
			status = "NOT ENABLED"
		} else if report.Reviewer.Error != "" {
			status = "UNAVAILABLE"
		}
		return []string{"AI GUIDANCE · " + status}
	}
	identity := terminalInline(report.Reviewer.Provider, 100)
	if model := terminalInline(report.Reviewer.Model, 256); model != "" {
		if identity != "" {
			identity += "/"
		}
		identity += model
	}
	label := "AI GUIDANCE"
	if identity != "" {
		label += " · " + identity
	}
	return []string{label, strings.ReplaceAll(guidance.Assessment, "-", " ") + " · " + terminalInline(guidance.Comment, 1000)}
}

func reportFindingGuidance(report *Report, finding brief.Finding) (FindingGuidance, bool) {
	if report == nil || finding.Source == "ai" {
		return FindingGuidance{}, false
	}
	wanted := findingGuidanceID(finding)
	// Multiple content batches may independently comment on the same finding.
	// Display the most cautious assessment, never the most permissive one.
	rank := map[string]int{"likely-benign": 0, "unclear": 1, "concerning": 2}
	bestRank := -1
	var best FindingGuidance
	for _, verdict := range report.Reviewer.Verdicts {
		for _, guidance := range verdict.Guidance {
			currentRank, valid := rank[guidance.Assessment]
			if guidance.FindingID == wanted && valid && currentRank > bestRank {
				best, bestRank = guidance, currentRank
			}
		}
	}
	return best, bestRank >= 0
}

func findingContextLines(raw []byte, line, radius int) ([]GuidanceContextLine, error) {
	if line < 1 || radius < 0 {
		return nil, errors.New("invalid context line")
	}
	text := safe.ValidUTF8OrReplacement(raw)
	all := strings.Split(text, "\n")
	if len(all) > 0 && all[len(all)-1] == "" {
		all = all[:len(all)-1]
	}
	if line > len(all) {
		return nil, errors.New("line outside file")
	}
	start := max(1, line-radius)
	end := min(len(all), line+radius)
	result := make([]GuidanceContextLine, 0, end-start+1)
	for number := start; number <= end; number++ {
		result = append(result, GuidanceContextLine{Line: number, Text: terminalInline(all[number-1], 320)})
	}
	return result, nil
}

func readManifestBoundFindingFile(root string, record brief.FileRecord) ([]byte, string, error) {
	roots := []string{root}
	if sourceRoot := ExistingTransactionSourceDir(root); sourceRoot != "" && sourceRoot != root {
		roots = append(roots, sourceRoot)
	}
	var lastErr error
	for _, candidate := range roots {
		raw, localPath, err := readManifestBoundFindingFileAt(candidate, record)
		if err == nil {
			return raw, localPath, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

func readManifestBoundFindingFileAt(root string, record brief.FileRecord) ([]byte, string, error) {
	if record.Kind != "file" || !record.Text || record.Size < 0 || record.Size > findingPreviewMaxBytes {
		return nil, "", errors.New("file is not previewable")
	}
	rawPath, err := base64.URLEncoding.DecodeString(record.PathB64)
	if err != nil || len(rawPath) == 0 || rawPath[0] == '/' || strings.IndexByte(string(rawPath), 0) >= 0 {
		return nil, "", errors.New("invalid manifest path")
	}
	components := strings.Split(string(rawPath), "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, "", errors.New("manifest path escapes root")
		}
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, "", err
	}
	rootFD, err := unix.Open(resolved, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(rootFD)

	currentFD := rootFD
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if currentFD != rootFD {
			unix.Close(currentFD)
		}
		if openErr != nil {
			return nil, "", openErr
		}
		currentFD = next
	}
	if currentFD != rootFD {
		defer unix.Close(currentFD)
	}
	fd, err := unix.Openat(currentFD, components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "finding-context")
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != record.Size {
		return nil, "", errors.New("manifest file metadata changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, findingPreviewMaxBytes+1))
	if err != nil || int64(len(raw)) != record.Size {
		return nil, "", errors.New("manifest file size changed")
	}
	if err := unix.Fstat(fd, &after); err != nil || !safe.SameStat(before, after) {
		return nil, "", errors.New("manifest file changed while reading")
	}
	if safe.SHA256Bytes(raw) != record.SHA256 {
		return nil, "", errors.New("manifest file digest changed")
	}
	return raw, filepath.Join(append([]string{resolved}, components...)...), nil
}
