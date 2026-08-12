package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var (
	privilegeCommands   = map[string]bool{"sudo": true, "doas": true, "su": true, "pkexec": true}
	hostPackageCommands = map[string]bool{"pacman": true, "makepkg": true, "yay": true, "paru": true}
	sensitiveCommands   = map[string]bool{
		"sudo": true, "doas": true, "su": true, "pkexec": true, "pacman": true, "makepkg": true,
		"yay": true, "paru": true, "curl": true, "wget": true, "git": true, "gpg": true,
	}
	downloadCommands    = map[string]bool{"curl": true, "wget": true, "fetch": true}
	interpreterCommands = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "python": true, "python3": true, "perl": true, "ruby": true}
	dynamicArrayRE      = regexp.MustCompile(`(?m)^\s*(?:source(?:_[A-Za-z0-9_]+)?|(?:b2|md5|sha1|sha224|sha256|sha384|sha512)sums(?:_[A-Za-z0-9_]+)?)\s*=\s*\([^\n)]*(?:\$\(|\x60|<\()`)
)

func semanticTextFindings(file, text string, executable, mandatory bool, bundle *ThreatBundle) []Finding {
	findings := structuredManifestFindings(file, text, bundle)
	if !shellSemanticCandidate(file, text, executable) {
		return findings
	}
	parsed, err := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true)).Parse(strings.NewReader(text), file)
	if err != nil {
		if mandatory || executable {
			findings = append(findings, Finding{
				Severity: "critical", Category: "coverage", File: file, Evidence: truncate(err.Error(), 320),
				Rationale: "mandatory shell content could not be parsed as Bash", RuleID: "shell-parse-incomplete", HardBlock: true,
			})
		}
		return findings
	}

	seen := make(map[string]bool)
	callProfiles := make(map[*syntax.CallExpr]string)
	syntax.Walk(parsed, func(node syntax.Node) bool {
		declaration, ok := node.(*syntax.FuncDecl)
		if !ok || declaration.Name == nil {
			return true
		}
		profile := makepkgProfileForFunction(declaration.Name.Value)
		if profile == "" {
			return true
		}
		syntax.Walk(declaration.Body, func(child syntax.Node) bool {
			if call, ok := child.(*syntax.CallExpr); ok {
				callProfiles[call] = profile
			}
			return true
		})
		return true
	})
	add := func(f Finding) {
		line := 0
		if f.Line != nil {
			line = *f.Line
		}
		key := fmt.Sprintf("%s\x00%d\x00%s", f.RuleID, line, f.Evidence)
		if !seen[key] {
			seen[key] = true
			findings = append(findings, f)
		}
	}

	syntax.Walk(parsed, func(node syntax.Node) bool {
		switch current := node.(type) {
		case *syntax.CallExpr:
			words := staticCallWords(current)
			if len(words) == 0 {
				return true
			}
			command, args := unwrapCommand(words)
			line := int(current.Pos().Line())
			evidence := renderShellNode(current)
			switch {
			case privilegeCommands[command]:
				add(semanticFinding(file, line, "critical", "privilege_escalation", "shell-privilege-command", evidence,
					"package-controlled code invokes a host privilege-escalation command", true))
			case hostPackageCommands[command]:
				add(semanticFinding(file, line, "critical", "privilege_escalation", "shell-host-package-manager", evidence,
					"package-controlled code invokes a host package manager or recursively invokes makepkg", true))
			}
			if command == "alias" {
				for _, arg := range args {
					name, _, _ := strings.Cut(arg, "=")
					if sensitiveCommands[path.Base(name)] {
						add(semanticFinding(file, line, "critical", "obfuscation", "shell-tool-shadow", evidence,
							"package-controlled code shadows a security-sensitive command", true))
					}
				}
			}
			if ecosystem, packages, ok := ecosystemInstall(command, args); ok {
				installTime := strings.HasSuffix(strings.ToLower(file), ".install")
				for _, packageName := range packages {
					if entry, matched := bundle.ecosystemPackage(ecosystem, packageName); matched {
						add(threatFinding(file, line, entry, evidence))
					}
				}
				severity, hard, rationale := "high", false, "build phase invokes an ecosystem package installer and requires review"
				if installTime {
					severity, hard, rationale = "critical", true, "package installation script invokes an ecosystem package installer"
				}
				add(semanticFinding(file, line, severity, "build_hook", "shell-ecosystem-install", evidence, rationale, hard))
			}
			if step, ok := knownBuildNetworkStep(command, args); ok {
				ruleID := "shell-known-network-step"
				if profile := callProfiles[current]; profile != "" {
					ruleID += "-" + profile
				}
				add(semanticFinding(file, line, "medium", "network", ruleID, step,
					"build recipe invokes a recognized dependency or source fetch step", false))
			}
			if (command == "source" || command == ".") && callContainsProcessDownloader(current) {
				add(semanticFinding(file, line, "critical", "remote_execution", "shell-remote-source", evidence,
					"remote content is sourced through command or process substitution", true))
			}
		case *syntax.BinaryCmd:
			if current.Op != syntax.Pipe && current.Op != syntax.PipeAll {
				return true
			}
			left, right := firstCommand(current.X), firstCommand(current.Y)
			if downloadCommands[left] && interpreterCommands[right] {
				add(semanticFinding(file, int(current.Pos().Line()), "critical", "remote_execution", "shell-remote-pipeline",
					renderShellNode(current), "remote content is piped directly to an interpreter", true))
			}
		case *syntax.FuncDecl:
			if current.Name != nil && sensitiveCommands[path.Base(current.Name.Value)] {
				add(semanticFinding(file, int(current.Pos().Line()), "critical", "obfuscation", "shell-tool-shadow",
					renderShellNode(current), "package-controlled code defines a function that shadows a security-sensitive command", true))
			}
		}
		return true
	})

	if loc := dynamicArrayRE.FindStringIndex(text); loc != nil {
		line := 1 + strings.Count(text[:loc[0]], "\n")
		add(semanticFinding(file, line, "high", "integrity", "shell-dynamic-source-array", strings.Join(strings.Fields(text[loc[0]:loc[1]]), " "),
			"source or checksum arrays contain dynamic command evaluation", false))
	}
	return findings
}

func makepkgProfileForFunction(name string) string {
	switch strings.ToLower(name) {
	case "prepare":
		return "prepare"
	case "build", "check", "package":
		return "build"
	default:
		return ""
	}
}

func shellSemanticCandidate(file, text string, executable bool) bool {
	base := strings.ToLower(path.Base(file))
	ext := strings.ToLower(path.Ext(file))
	if base == "pkgbuild" || ext == ".install" || ext == ".sh" || ext == ".bash" {
		return true
	}
	if !executable || !strings.HasPrefix(text, "#!") {
		return false
	}
	shebang := strings.ToLower(strings.SplitN(text, "\n", 2)[0])
	fields := strings.Fields(strings.TrimPrefix(shebang, "#!"))
	if len(fields) == 0 {
		return false
	}
	interpreter := path.Base(fields[0])
	if interpreter == "env" && len(fields) > 1 {
		interpreter = path.Base(fields[1])
	}
	return interpreter == "sh" || interpreter == "bash" || interpreter == "dash" || interpreter == "zsh" || interpreter == "ksh"
}

func semanticFinding(file string, line int, severity, category, ruleID, evidence, rationale string, hard bool) Finding {
	lineCopy := line
	return Finding{Severity: severity, Category: category, File: file, Line: &lineCopy, Evidence: truncate(strings.Join(strings.Fields(evidence), " "), 320), Rationale: rationale, RuleID: ruleID, HardBlock: hard}
}

func staticCallWords(call *syntax.CallExpr) []string {
	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		value, ok := staticShellWord(word)
		if !ok {
			words = append(words, "")
			continue
		}
		words = append(words, value)
	}
	return words
}

func staticShellWord(word *syntax.Word) (string, bool) {
	var result strings.Builder
	var appendParts func([]syntax.WordPart) bool
	appendParts = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch value := part.(type) {
			case *syntax.Lit:
				result.WriteString(value.Value)
			case *syntax.SglQuoted:
				result.WriteString(value.Value)
			case *syntax.DblQuoted:
				if !appendParts(value.Parts) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	if !appendParts(word.Parts) {
		return "", false
	}
	return result.String(), true
}

func unwrapCommand(words []string) (string, []string) {
	for len(words) > 0 {
		command := path.Base(words[0])
		switch command {
		case "command", "builtin", "nohup":
			words = words[1:]
			continue
		case "env":
			words = words[1:]
			for len(words) > 0 && (strings.HasPrefix(words[0], "-") || strings.Contains(words[0], "=")) {
				words = words[1:]
			}
			continue
		}
		return command, words[1:]
	}
	return "", nil
}

func ecosystemInstall(command string, args []string) (string, []string, bool) {
	command = strings.ToLower(command)
	if len(args) == 0 {
		return "", nil, false
	}
	verb := strings.ToLower(args[0])
	valid := false
	switch command {
	case "npm":
		valid = verb == "install" || verb == "i" || verb == "add" || verb == "ci"
	case "bun":
		valid = verb == "install" || verb == "add"
	case "pip", "pip3", "pipx":
		valid = verb == "install"
	case "cargo", "gem", "composer":
		valid = verb == "install"
	}
	if !valid {
		return "", nil, false
	}
	packages := make([]string, 0, len(args)-1)
	for _, arg := range args[1:] {
		if arg != "" && !strings.HasPrefix(arg, "-") {
			packages = append(packages, packageIdentity(arg))
		}
	}
	ecosystem := command
	if command == "bun" {
		ecosystem = "npm"
	}
	return ecosystem, packages, true
}

// knownBuildNetworkStep deliberately recognizes command shapes rather than
// merely executable names. It is used to explain and optionally enable the
// bounded build-network broker; arbitrary curl/wget and generic shell commands
// must never inherit that automatic policy.
func knownBuildNetworkStep(command string, args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	command = strings.ToLower(command)
	step := strings.ToLower(args[0])
	switch command {
	case "cargo":
		if step == "fetch" {
			for _, arg := range args[1:] {
				if arg == "--locked" {
					return "cargo fetch --locked", true
				}
			}
		}
	}
	return "", false
}

func firstCommand(stmt *syntax.Stmt) string {
	if stmt == nil || stmt.Cmd == nil {
		return ""
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		words := staticCallWords(command)
		name, _ := unwrapCommand(words)
		return name
	case *syntax.BinaryCmd:
		return firstCommand(command.X)
	}
	return ""
}

func callContainsProcessDownloader(call *syntax.CallExpr) bool {
	found := false
	syntax.Walk(call, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch value := node.(type) {
		case *syntax.ProcSubst:
			for _, stmt := range value.Stmts {
				if downloadCommands[firstCommand(stmt)] {
					found = true
					return false
				}
			}
		case *syntax.CmdSubst:
			for _, stmt := range value.Stmts {
				if downloadCommands[firstCommand(stmt)] {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func renderShellNode(node syntax.Node) string {
	var output bytes.Buffer
	if err := syntax.NewPrinter(syntax.Minify(true)).Print(&output, node); err != nil {
		return fmt.Sprintf("shell node at line %d", node.Pos().Line())
	}
	return truncate(output.String(), 320)
}

func structuredManifestFindings(file, text string, bundle *ThreatBundle) []Finding {
	base := strings.ToLower(path.Base(file))
	switch base {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json":
		return jsonManifestFindings(file, text, bundle)
	case ".npmrc":
		return configLineFindings(file, text, regexp.MustCompile(`(?i)^\s*(?:registry|@[^:]+:registry)\s*=`), "npm registry override requires review")
	case "go.mod":
		return configLineFindings(file, text, regexp.MustCompile(`(?i)^\s*replace\s+`), "Go module replacement changes source provenance")
	case "config", "config.toml":
		if strings.Contains(strings.ToLower(file), ".cargo/") {
			return configLineFindings(file, text, regexp.MustCompile(`(?i)^\s*(?:replace-with|registry)\s*=`), "Cargo source replacement or custom registry requires review")
		}
	case "pip.conf", "pyproject.toml":
		return configLineFindings(file, text, regexp.MustCompile(`(?i)^\s*(?:index-url|extra-index-url|index_url|extra_index_url)\s*=`), "Python package index override requires review")
	}
	return nil
}

func jsonManifestFindings(file, text string, bundle *ThreatBundle) []Finding {
	var document map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(text))
	if err := decoder.Decode(&document); err != nil {
		return []Finding{semanticFinding(file, 1, "critical", "coverage", "manifest-json-invalid", err.Error(), "mandatory package manifest is not valid JSON", true)}
	}
	var findings []Finding
	if raw, ok := document["scripts"]; ok {
		var scripts map[string]string
		if json.Unmarshal(raw, &scripts) == nil {
			keys := make([]string, 0, len(scripts))
			for key := range scripts {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if key == "preinstall" || key == "install" || key == "postinstall" || key == "prepare" {
					findings = append(findings, semanticFinding(file, 1, "high", "build_hook", "manifest-lifecycle-script", key+": "+scripts[key], "package manifest defines an executable lifecycle script", false))
				}
			}
		}
	}
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var dependencies map[string]json.RawMessage
		if raw, ok := document[field]; ok && json.Unmarshal(raw, &dependencies) == nil {
			for name := range dependencies {
				if entry, matched := bundle.ecosystemPackage("npm", name); matched {
					findings = append(findings, threatFinding(file, 1, entry, field+": "+name))
				}
			}
		}
	}
	if raw, ok := document["packages"]; ok {
		var packages map[string]json.RawMessage
		if json.Unmarshal(raw, &packages) == nil {
			for packagePath := range packages {
				name := strings.TrimPrefix(packagePath, "node_modules/")
				if entry, matched := bundle.ecosystemPackage("npm", name); matched {
					findings = append(findings, threatFinding(file, 1, entry, packagePath))
				}
			}
		}
	}
	for _, field := range []string{"registry", "publishConfig"} {
		if raw, ok := document[field]; ok && len(raw) > 0 {
			findings = append(findings, semanticFinding(file, 1, "high", "network", "manifest-registry-override", field+": "+string(raw), "package manifest overrides registry or publication provenance", false))
		}
	}
	return findings
}

func configLineFindings(file, text string, pattern *regexp.Regexp, rationale string) []Finding {
	var findings []Finding
	for index, line := range strings.Split(text, "\n") {
		if pattern.MatchString(line) {
			findings = append(findings, semanticFinding(file, index+1, "high", "network", "manifest-source-override", line, rationale, false))
		}
	}
	return findings
}
