package brief

import (
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type rule struct {
	id, expression, severity, category, rationale string
	hardBlock                                     bool
	pattern                                       *regexp.Regexp
}

// newRule builds one deterministic pattern rule.
//
// The hard parameter is retained but no pattern rule sets it any more, and that
// is the briefing model rather than an oversight. A regular expression over
// attacker-authored text is recognition: it can be obfuscated around, and it
// misfires on legitimate code. Hard blocks are reserved for properties that are
// enforced rather than recognised - path traversal, escaping symlinks, member
// type violations - which no rewriting of the text can change.
//
// Recognised behavior is contained rather than treated as structural proof.
// For example, `curl | bash` in build() runs with no network unless the user
// brokers it; the finding's job is to tell the user it is there.
func newRule(id, expression, severity, category, rationale string, hard bool) rule {
	return rule{id: id, expression: expression, severity: severity, category: category, rationale: rationale, hardBlock: hard,
		pattern: regexp.MustCompile(`(?im)` + expression)}
}

var rules = []rule{
	// Regex rules provide bounded, explainable signatures and run alongside the
	// shell AST/structured-manifest checks. They are detection evidence, not a
	// general proof of program behavior.
	newRule("remote-pipe-shell", `(?:curl|wget)\b[^\n|]{0,500}\|\s*(?:sudo\s+)?(?:(?:ba|z|k)?sh|python(?:3)?|perl|ruby)\b`, "critical", "remote_execution", "remote content is piped directly to a shell", false),
	newRule("remote-source", `(?:source|\.)\s+(?:<\(\s*)?(?:/dev/fd/\d+|https?://|\$\(\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b)`, "critical", "remote_execution", "remote content is sourced through process substitution", false),
	newRule("decode-execute", `(?:base64\s+(?:-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d|(?:gzip|bzip2|xz)\s+-d|python(?:3)?\s+-c[^\n]{0,200}(?:b64decode|decompress)|(?:printf|echo)\s+[^\n]{0,300}\\x[0-9a-f]{2})[^\n]{0,500}(?:\||;|&&|\)\s*\|)\s*(?:eval|exec|(?:ba|z|k)?sh|python(?:3)?)\b`, "critical", "decode_execute", "decoded or decompressed data is immediately executed", false),
	newRule("credential-path", `(?:\$HOME|~|/home/[^/\s]+)/(?:\.ssh|\.gnupg|\.aws|\.config/gcloud|\.kube|\.docker|\.local/share/keyrings|\.mozilla|\.config/(?:chromium|google-chrome))\b|(?:id_rsa|id_ed25519|wallet\.dat|credentials\.json)\b`, "critical", "credential_access", "package content accesses user credentials or sensitive profiles", false),
	newRule("reverse-shell", `/dev/tcp/|\b(?:nc|ncat|netcat|socat)\b[^\n]{0,300}(?:-e\b|EXEC:)|\b(?:bash|sh)\s+-i\b`, "critical", "remote_execution", "reverse-shell primitives are present", false),
	newRule("process-injection", `\b(?:LD_PRELOAD|ptrace)\b|/proc/(?:self|[0-9*]+)/mem\b`, "critical", "process_injection", "process injection or memory modification primitive is present", false),
	newRule("host-persistence", `(?:/etc/(?:sudoers|pam\.d|cron\.|profile)|\.config/autostart|\.bashrc|\.zshrc)\b|\bcrontab\s+-`, "critical", "persistence", "direct modification of a persistence or authentication surface is present", false),
	newRule("dynamic-execution", `\b(?-i:eval|exec)\b|\b(?-i:(?:ba|z|k)?sh)\s+-c\b|\b(?-i:python(?:3)?)\s+-c\b`, "high", "obfuscation", "indirect command execution requires review", false),
	newRule("build-phase-download", `(?:prepare|pkgver|build|check|package)\s*\(\s*\)\s*\{`, "high", "network", "a PKGBUILD build function performs network or package-manager activity", false),
	newRule("unexpected-network-client", `\b(?-i:curl|wget|ftp|scp|ssh|nc|ncat|netcat|socat)\b`, "medium", "network", "network client use requires provenance and phase review", false),
	newRule("integrity-disabled", `(?:sha(?:256|512|1)sums|b2sums|md5sums)\s*=\s*\([^)]*['"]?SKIP|\b--skip(?:checksums|integ|pgpcheck)\b`, "medium", "integrity", "source integrity verification is disabled or bypassed", false),
	newRule("plain-http-source", `http://[^\s'")]+`, "low", "integrity", "unencrypted source URL is present", false),
	newRule("privileged-mode", `\b(?:chmod\s+(?:[ugo+]*s|[0-7]*[46][0-7]{2})|setcap\b|chown\s+root)\b`, "high", "privilege_escalation", "privileged ownership, capability, or set-id mode is requested", false),
	newRule("package-manager-hook", `(?:usr/lib/systemd/system|usr/lib/udev/rules\.d|usr/share/libalpm/hooks|usr/lib/tmpfiles\.d|usr/lib/sysusers\.d|etc/pam\.d|etc/sudoers\.d)`, "medium", "persistence", "package installs a privileged integration or activation hook", false),
	newRule("language-build-hook", `\b(?:preinstall|postinstall|prepare)\s*['"]?\s*:|\bbuild\.rs\b|add_custom_(?:command|target)\s*\(|meson\.add_install_script|setup\.py\b`, "medium", "build_hook", "language or build-system lifecycle hook can execute code", false),
	newRule("prompt-injection", `(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|system\s+prompt|you\s+are\s+(?:chatgpt|codex|claude)`, "high", "prompt_injection", "content attempts to influence the reviewing model", false),
}

type RuleEngine struct {
	MaxFindings int
	Threats     *ThreatBundle
	ThreatError error
}

func (engine RuleEngine) ScanSemantic(path, text string, executable, mandatory bool) []Finding {
	if engine.ThreatError != nil {
		return []Finding{{Severity: "critical", Category: "coverage", File: path, Evidence: truncate(engine.ThreatError.Error(), 320), Rationale: "embedded threat intelligence could not be validated", RuleID: "threat-bundle-invalid", HardBlock: true}}
	}
	return SemanticTextFindings(path, text, executable, mandatory, engine.Threats)
}

var buildDownloadRE = regexp.MustCompile(`(?i)\b(?:curl|wget|git\s+clone|npm\s+(?:install|ci)|pip\s+install|go\s+get|cargo\s+install)\b`)

func (engine RuleEngine) findingLimit() int {
	if engine.MaxFindings > 0 {
		return engine.MaxFindings
	}
	return defaultMaxFindings
}

func (engine RuleEngine) ScanText(path, text string, lineOffset int) []Finding {
	behaviorText := text
	if diffBehavior, ok := unifiedDiffBehaviorText(path, text); ok {
		behaviorText = diffBehavior
	} else if shellCommentLinePath(path) {
		masker := shellCommentMasker{linePrefix: true}
		behaviorText = masker.Mask(text)
	}
	return engine.scanPreparedText(path, text, behaviorText, lineOffset)
}

// scanPreparedText applies executable-behavior signatures to behaviorText and
// content-safety signatures to the original text. The two strings must retain
// identical byte and newline positions so findings still point at the source.
func (engine RuleEngine) scanPreparedText(path, text, behaviorText string, lineOffset int) []Finding {
	return representativeFindings(engine.scanPreparedFindings(path, text, behaviorText, lineOffset))
}

func (engine RuleEngine) scanPreparedFindings(path, text, behaviorText string, lineOffset int) []Finding {
	// Ask regexps for at most limit+1 matches so an overfull scan is observable
	// without accumulating attacker-controlled result volume.
	findings := make([]Finding, 0)
	limit := engine.findingLimit()
	for _, current := range rules {
		remaining := limit + 1 - len(findings)
		if remaining <= 0 {
			break
		}
		ruleText := behaviorText
		if current.id == "prompt-injection" {
			// Comments are still sent to the reviewing model, so instructions in
			// them remain relevant even though they are not executable shell.
			ruleText = text
		}
		if current.id == "build-phase-download" {
			// Look at no more than 12 KiB after a makepkg function header. This
			// catches nearby download behavior without one header consuming an
			// unbounded remainder of a generated file.
			line, previousOffset := lineOffset+1, 0
			for _, header := range current.pattern.FindAllStringIndex(ruleText, remaining) {
				end := min(len(ruleText), header[1]+12000)
				download := buildDownloadRE.FindStringIndex(ruleText[header[1]:end])
				if download == nil {
					continue
				}
				loc := []int{header[0], header[1] + download[1]}
				line += strings.Count(ruleText[previousOffset:loc[0]], "\n")
				previousOffset = loc[0]
				evidence := strings.Join(strings.Fields(ruleText[loc[0]:loc[1]]), " ")
				if len(evidence) > 320 {
					evidence = evidence[:320]
				}
				lineCopy := line
				findings = append(findings, Finding{Severity: current.severity, Category: current.category, File: path, Line: &lineCopy, Evidence: evidence, Rationale: current.rationale, RuleID: current.id, HardBlock: current.hardBlock})
			}
			continue
		}
		if current.id == "plain-http-source" && !mandatoryControlPath(path) {
			continue
		}
		if (current.id == "dynamic-execution" || current.id == "unexpected-network-client" || current.id == "language-build-hook") && !mandatoryControlPath(path) {
			continue
		}
		line, previousOffset := lineOffset+1, 0
		for _, loc := range current.pattern.FindAllStringIndex(ruleText, remaining) {
			if current.id == "plain-http-source" && loc[0] > 0 && (ruleText[loc[0]-1] == 's' || ruleText[loc[0]-1] == 'S') {
				continue
			}
			line += strings.Count(ruleText[previousOffset:loc[0]], "\n")
			previousOffset = loc[0]
			evidence := strings.Join(strings.Fields(ruleText[loc[0]:loc[1]]), " ")
			if len(evidence) > 320 {
				evidence = evidence[:320]
			}
			lineCopy := line
			findings = append(findings, Finding{Severity: current.severity, Category: current.category, File: path,
				Line: &lineCopy, Evidence: evidence, Rationale: current.rationale, RuleID: current.id, HardBlock: current.hardBlock})
		}
	}
	remaining := limit + 1 - len(findings)
	if remaining > 0 && unicodeObfuscationRelevant(path) {
		findings = append(findings, unicodeFindings(path, text, lineOffset, remaining)...)
	}
	return findings
}

func shellCommentLinePath(name string) bool {
	base := strings.ToLower(path.Base(name))
	if base == "pkgbuild" {
		return true
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".install", ".sh", ".bash", ".zsh", ".ksh":
		return true
	default:
		return false
	}
}

// shellCommentMasker replaces pure shell comment lines with spaces while
// preserving byte offsets and newlines. It intentionally does not erase inline
// comments: deciding where an inline # becomes syntax requires full shell
// context. A line whose first non-whitespace byte is # has no executable
// behavior on its face, including in the generated shell snippets commonly
// embedded in PKGBUILDs. State is retained across reader chunks so a long
// comment cannot become executable-looking text at a chunk boundary.
type shellCommentMasker struct {
	linePrefix bool
	comment    bool
}

func (masker *shellCommentMasker) Mask(text string) string {
	masked := []byte(text)
	for index, current := range masked {
		if masker.comment {
			if current == '\n' {
				masker.comment = false
				masker.linePrefix = true
			} else {
				masked[index] = ' '
			}
			continue
		}
		switch {
		case current == '\n':
			masker.linePrefix = true
		case masker.linePrefix && (current == ' ' || current == '\t' || current == '\r'):
			// Still before the first non-whitespace byte on this line.
		case masker.linePrefix && current == '#':
			masked[index] = ' '
			masker.comment = true
		default:
			masker.linePrefix = false
		}
	}
	return string(masked)
}

func (engine RuleEngine) ScanReader(path string, reader io.Reader, sampleLimit int64) ([]Finding, []byte, int64, error) {
	// Scan in 1 MiB chunks but retain a 16 KiB overlap so bounded multi-token
	// signatures spanning a read boundary are still visible. Duplicate evidence
	// from the overlap is removed by rule/line/evidence identity.
	buffer := make([]byte, 1024*1024)
	var sample []byte
	previousText, previousBehavior := "", ""
	maskComments := shellCommentLinePath(path)
	commentMasker := shellCommentMasker{linePrefix: true}
	lineOffset := 0
	var total int64
	findings := make([]Finding, 0)
	seen := make(map[string]bool)
	diffCandidate := unifiedDiffPath(path)
	rawOverLimit := false
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			raw := buffer[:n]
			total += int64(n)
			if int64(len(sample)) < sampleLimit {
				remaining := int(sampleLimit - int64(len(sample)))
				if remaining > n {
					remaining = n
				}
				sample = append(sample, raw[:remaining]...)
			}
			decoded := string(raw)
			behaviorDecoded := decoded
			if maskComments {
				behaviorDecoded = commentMasker.Mask(decoded)
			}
			combinedText := previousText + decoded
			combinedBehavior := previousBehavior + behaviorDecoded
			base := lineOffset - strings.Count(previousText, "\n")
			if base < 0 {
				base = 0
			}
			for _, finding := range engine.scanPreparedText(path, combinedText, combinedBehavior, base) {
				if rawOverLimit {
					break
				}
				line := 0
				if finding.Line != nil {
					line = *finding.Line
				}
				key := fmt.Sprintf("%s\x00%d\x00%s", finding.RuleID, line, finding.Evidence)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, finding)
					if len(findings) > engine.findingLimit() {
						if !diffCandidate {
							return nil, nil, total, errors.New("deterministic finding limit exceeded")
						}
						rawOverLimit = true
					}
				}
			}
			if rawOverLimit && total > sampleLimit {
				return nil, nil, total, errors.New("deterministic finding limit exceeded")
			}
			lineOffset += strings.Count(decoded, "\n")
			if len(combinedText) > 16384 {
				previousText = combinedText[len(combinedText)-16384:]
				previousBehavior = combinedBehavior[len(combinedBehavior)-16384:]
			} else {
				previousText = combinedText
				previousBehavior = combinedBehavior
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, total, err
		}
	}
	if diffCandidate && total == int64(len(sample)) {
		text := string(sample)
		if behaviorText, ok := unifiedDiffBehaviorText(path, text); ok {
			findings = engine.scanPreparedFindings(path, text, behaviorText, 0)
			if len(findings) > engine.findingLimit() {
				return nil, nil, total, errors.New("deterministic finding limit exceeded")
			}
			return representativeFindings(findings), sample, total, nil
		}
	}
	if rawOverLimit {
		return nil, nil, total, errors.New("deterministic finding limit exceeded")
	}
	return representativeFindings(findings), sample, total, nil
}

func representativeFindings(findings []Finding) []Finding {
	// Preserve every hard block; cap contextual repetitions at three per rule so
	// reports show representative locations without attacker-amplified noise.
	const maxContextMatchesPerRule = 3
	result := make([]Finding, 0, len(findings))
	counts := make(map[string]int)
	for _, finding := range findings {
		if finding.HardBlock || counts[finding.RuleID] < maxContextMatchesPerRule {
			result = append(result, finding)
			if !finding.HardBlock {
				counts[finding.RuleID]++
			}
		}
	}
	return result
}

func unicodeObfuscationRelevant(name string) bool {
	// Debug packages install inert source copies below /usr/src/debug. They are
	// useful to a debugger but are not evaluated during installation or normal
	// package operation. Treating ordinary source typography there as executable
	// concealment creates a high-severity feedback loop: each false finding also
	// selects that member for AI review.
	if strings.Contains(strings.ToLower(name), "!/usr/src/debug/") {
		return false
	}
	base := strings.ToLower(path.Base(name))
	if base == "copying" || base == "notice" || strings.HasPrefix(base, "license") {
		return false
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".po", ".pot", ".mo", ".html", ".htm", ".md", ".rst", ".adoc":
		return false
	default:
		return true
	}
}

var confusables = func() map[rune]bool {
	m := map[rune]bool{}
	for _, r := range "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧαβγδεζηικνопрстухАВЕКМНОРСТХаеорсухіј" {
		m[r] = true
	}
	return m
}()

func unicodeFindings(path, text string, lineOffset, limit int) []Finding {
	var result []Finding
	for index, line := range strings.Split(text, "\n") {
		if len(result) >= limit {
			break
		}
		lineNumber := lineOffset + index + 1
		var controls []rune
		for byteOffset, r := range line {
			leadingBOM := r == '\uFEFF' && lineNumber == 1 && byteOffset == 0
			// Form feed is source whitespace/page separation in the languages
			// Prolewatch encounters. Like tab and carriage return, it does not by
			// itself conceal executable behavior.
			if (unicode.IsControl(r) || unicode.In(r, unicode.Cf)) && r != '\t' && r != '\r' && r != '\f' && !leadingBOM {
				controls = append(controls, r)
			}
		}
		confusing := mixedIdentifierConfusables(line)
		if len(controls) > 0 {
			pieces := make([]string, 0, min(8, len(controls)))
			for _, r := range controls[:min(8, len(controls))] {
				pieces = append(pieces, fmt.Sprintf("U+%04X", r))
			}
			ln := lineNumber
			result = append(result, Finding{Source: "deterministic", Severity: "high", Category: "obfuscation", File: path, Line: &ln, Evidence: "hidden control characters: " + strings.Join(pieces, ", "), Rationale: "invisible control characters can conceal behavior", RuleID: "unicode-control"})
		}
		if len(result) >= limit {
			break
		}
		if utf8.RuneCountInString(line) > 20000 {
			// Twenty thousand runes is intentionally far beyond ordinary source
			// formatting but bounds a common generated/encoded concealment pattern.
			ln := lineNumber
			result = append(result, Finding{Source: "deterministic", Severity: "medium", Category: "obfuscation", File: path, Line: &ln, Evidence: fmt.Sprintf("line length %d", utf8.RuneCountInString(line)), Rationale: "extremely long lines can conceal generated or encoded payloads", RuleID: "long-line"})
		}
		if len(result) >= limit {
			break
		}
		if len(confusing) > 0 {
			pieces := make([]string, 0, min(8, len(confusing)))
			for _, r := range confusing[:min(8, len(confusing))] {
				pieces = append(pieces, fmt.Sprintf("%c=U+%04X", r, r))
			}
			ln := lineNumber
			result = append(result, Finding{Source: "deterministic", Severity: "high", Category: "obfuscation", File: path, Line: &ln, Evidence: "mixed-script confusables: " + strings.Join(pieces, ", "), Rationale: "mixed Latin and confusable Unicode characters can conceal identifiers", RuleID: "unicode-confusable"})
		}
	}
	return result
}

// mixedIdentifierConfusables returns confusable runes only when they share one
// identifier-like token with an ASCII letter. Merely placing ordinary Latin
// source text and a standalone Cyrillic/Greek codepoint on the same line is not
// mixed-script identifier concealment (lookup tables routinely do exactly
// that).
func mixedIdentifierConfusables(line string) []rune {
	var result, tokenConfusables []rune
	hasASCIIAlpha := false
	flush := func() {
		if hasASCIIAlpha && len(tokenConfusables) > 0 {
			result = append(result, tokenConfusables...)
		}
		tokenConfusables = tokenConfusables[:0]
		hasASCIIAlpha = false
	}
	for _, r := range line {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || r == '_' {
			if r <= unicode.MaxASCII && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				hasASCIIAlpha = true
			}
			if confusables[r] {
				tokenConfusables = append(tokenConfusables, r)
			}
			continue
		}
		flush()
	}
	flush()
	return result
}
