package audit

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

func newRule(id, expression, severity, category, rationale string, hard bool) rule {
	return rule{id: id, expression: expression, severity: severity, category: category, rationale: rationale, hardBlock: hard,
		pattern: regexp.MustCompile(`(?im)` + expression)}
}

var rules = []rule{
	newRule("remote-pipe-shell", `(?:curl|wget)\b[^\n|]{0,500}\|\s*(?:sudo\s+)?(?:(?:ba|z|k)?sh|python(?:3)?|perl|ruby)\b`, "critical", "remote_execution", "remote content is piped directly to a shell", true),
	newRule("remote-source", `(?:source|\.)\s+(?:<\(\s*)?(?:/dev/fd/\d+|https?://|\$\(\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b)`, "critical", "remote_execution", "remote content is sourced through process substitution", true),
	newRule("decode-execute", `(?:base64\s+(?:-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d|(?:gzip|bzip2|xz)\s+-d|python(?:3)?\s+-c[^\n]{0,200}(?:b64decode|decompress)|(?:printf|echo)\s+[^\n]{0,300}\\x[0-9a-f]{2})[^\n]{0,500}(?:\||;|&&|\)\s*\|)\s*(?:eval|exec|(?:ba|z|k)?sh|python(?:3)?)\b`, "critical", "decode_execute", "decoded or decompressed data is immediately executed", true),
	newRule("credential-path", `(?:\$HOME|~|/home/[^/\s]+)/(?:\.ssh|\.gnupg|\.aws|\.config/gcloud|\.kube|\.docker|\.local/share/keyrings|\.mozilla|\.config/(?:chromium|google-chrome))\b|(?:id_rsa|id_ed25519|wallet\.dat|credentials\.json)\b`, "critical", "credential_access", "package content accesses user credentials or sensitive profiles", true),
	newRule("reverse-shell", `/dev/tcp/|\b(?:nc|ncat|netcat|socat)\b[^\n]{0,300}(?:-e\b|EXEC:)|\b(?:bash|sh)\s+-i\b`, "critical", "remote_execution", "reverse-shell primitives are present", true),
	newRule("process-injection", `\b(?:LD_PRELOAD|ptrace)\b|/proc/(?:self|[0-9*]+)/mem\b`, "critical", "process_injection", "process injection or memory modification primitive is present", true),
	newRule("host-persistence", `(?:/etc/(?:sudoers|pam\.d|cron\.|profile)|\.config/autostart|\.bashrc|\.zshrc)\b|\bcrontab\s+-`, "critical", "persistence", "direct modification of a persistence or authentication surface is present", true),
	newRule("dynamic-execution", `\b(?-i:eval|exec)\b|\b(?-i:(?:ba|z|k)?sh)\s+-c\b|\b(?-i:python(?:3)?)\s+-c\b`, "high", "obfuscation", "dynamic command execution requires review", false),
	newRule("build-phase-download", `(?:prepare|pkgver|build|check|package)\s*\(\s*\)\s*\{`, "high", "network", "a PKGBUILD build function performs network or package-manager activity", false),
	newRule("unexpected-network-client", `\b(?-i:curl|wget|ftp|scp|ssh|nc|ncat|netcat|socat)\b`, "medium", "network", "network client use requires provenance and phase review", false),
	newRule("integrity-disabled", `(?:sha(?:256|512|1)sums|b2sums|md5sums)\s*=\s*\([^)]*['"]?SKIP|\b--skip(?:checksums|integ|pgpcheck)\b`, "medium", "integrity", "source integrity verification is disabled or bypassed", false),
	newRule("plain-http-source", `http://[^\s'")]+`, "low", "integrity", "unencrypted source URL is present", false),
	newRule("privileged-mode", `\b(?:chmod\s+(?:[ugo+]*s|[0-7]*[46][0-7]{2})|setcap\b|chown\s+root)\b`, "high", "privilege_escalation", "privileged ownership, capability, or set-id mode is requested", false),
	newRule("package-manager-hook", `(?:usr/lib/systemd/system|usr/lib/udev/rules\.d|usr/share/libalpm/hooks|usr/lib/tmpfiles\.d|usr/lib/sysusers\.d|etc/pam\.d|etc/sudoers\.d)`, "medium", "persistence", "package installs a privileged integration or activation hook", false),
	newRule("language-build-hook", `\b(?:preinstall|postinstall|prepare)\s*['"]?\s*:|\bbuild\.rs\b|add_custom_(?:command|target)\s*\(|meson\.add_install_script|setup\.py\b`, "medium", "build_hook", "language or build-system lifecycle hook can execute code", false),
	newRule("prompt-injection", `(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|system\s+prompt|you\s+are\s+(?:chatgpt|codex|claude)`, "high", "prompt_injection", "content attempts to influence the reviewing model", true),
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
	return semanticTextFindings(path, text, executable, mandatory, engine.Threats)
}

var buildDownloadRE = regexp.MustCompile(`(?i)\b(?:curl|wget|git\s+clone|npm\s+(?:install|ci)|pip\s+install|go\s+get|cargo\s+install)\b`)

func (engine RuleEngine) findingLimit() int {
	if engine.MaxFindings > 0 {
		return engine.MaxFindings
	}
	return DefaultConfig().Limits.MaxFindings
}

func (engine RuleEngine) ScanText(path, text string, lineOffset int) []Finding {
	findings := make([]Finding, 0)
	limit := engine.findingLimit()
	for _, current := range rules {
		remaining := limit + 1 - len(findings)
		if remaining <= 0 {
			break
		}
		if current.id == "build-phase-download" {
			line, previousOffset := lineOffset+1, 0
			for _, header := range current.pattern.FindAllStringIndex(text, remaining) {
				end := min(len(text), header[1]+12000)
				download := buildDownloadRE.FindStringIndex(text[header[1]:end])
				if download == nil {
					continue
				}
				loc := []int{header[0], header[1] + download[1]}
				line += strings.Count(text[previousOffset:loc[0]], "\n")
				previousOffset = loc[0]
				evidence := strings.Join(strings.Fields(text[loc[0]:loc[1]]), " ")
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
		if (current.id == "dynamic-execution" || current.id == "unexpected-network-client") && !mandatoryControlPath(path) {
			continue
		}
		line, previousOffset := lineOffset+1, 0
		for _, loc := range current.pattern.FindAllStringIndex(text, remaining) {
			if current.id == "plain-http-source" && loc[0] > 0 && (text[loc[0]-1] == 's' || text[loc[0]-1] == 'S') {
				continue
			}
			line += strings.Count(text[previousOffset:loc[0]], "\n")
			previousOffset = loc[0]
			evidence := strings.Join(strings.Fields(text[loc[0]:loc[1]]), " ")
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
	return representativeFindings(findings)
}

func (engine RuleEngine) ScanReader(path string, reader io.Reader, sampleLimit int64) ([]Finding, []byte, int64, error) {
	buffer := make([]byte, 1024*1024)
	var sample []byte
	previous := ""
	lineOffset := 0
	var total int64
	findings := make([]Finding, 0)
	seen := make(map[string]bool)
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
			combined := previous + decoded
			base := lineOffset - strings.Count(previous, "\n")
			if base < 0 {
				base = 0
			}
			for _, finding := range engine.ScanText(path, combined, base) {
				line := 0
				if finding.Line != nil {
					line = *finding.Line
				}
				key := fmt.Sprintf("%s\x00%d\x00%s", finding.RuleID, line, finding.Evidence)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, finding)
					if len(findings) > engine.findingLimit() {
						return nil, nil, total, errors.New("deterministic finding limit exceeded")
					}
				}
			}
			lineOffset += strings.Count(decoded, "\n")
			if len(combined) > 16384 {
				previous = combined[len(combined)-16384:]
			} else {
				previous = combined
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, total, err
		}
	}
	return representativeFindings(findings), sample, total, nil
}

func representativeFindings(findings []Finding) []Finding {
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
		var controls, confusing []rune
		hasASCIIAlpha := false
		for byteOffset, r := range line {
			if r <= 127 && ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				hasASCIIAlpha = true
			}
			leadingBOM := r == '\uFEFF' && lineNumber == 1 && byteOffset == 0
			if (unicode.IsControl(r) || unicode.In(r, unicode.Cf)) && r != '\t' && r != '\r' && !leadingBOM {
				controls = append(controls, r)
			}
			if confusables[r] {
				confusing = append(confusing, r)
			}
		}
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
			ln := lineNumber
			result = append(result, Finding{Source: "deterministic", Severity: "medium", Category: "obfuscation", File: path, Line: &ln, Evidence: fmt.Sprintf("line length %d", utf8.RuneCountInString(line)), Rationale: "extremely long lines can conceal generated or encoded payloads", RuleID: "long-line"})
		}
		if len(result) >= limit {
			break
		}
		if hasASCIIAlpha && len(confusing) > 0 {
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
