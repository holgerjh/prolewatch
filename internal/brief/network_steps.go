package brief

import (
	"sort"
	"strings"
)

// KnownNetworkSteps recognises the small allowlisted set of dependency-prefetch
// commands a package declares, so the egress prompt can aggregate them instead
// of interrogating per host.
//
// Recognition is never inferred from arbitrary shell text. The rule engine
// emits named findings for a closed set of shapes, and only those findings
// count; anything else falls through to the ordinary per-destination prompt.
// Recognition enriches a prompt - it never authorises access.
//
// It takes findings and sources rather than a report because that is all it
// reads. The narrower signature is what lets it live in the inspection layer,
// where the findings it interprets are produced, instead of above it.
func KnownNetworkSteps(findings []Finding, sources []SourceProvenance, profile string) []string {
	ruleID := "shell-known-network-step-" + profile
	seen := map[string]bool{}
	for _, finding := range findings {
		knownProfile := strings.TrimPrefix(finding.RuleID, "shell-known-network-step-")
		if knownProfile == finding.RuleID || (profile != "" && finding.RuleID != ruleID) ||
			finding.Evidence == "" || findingBelongsToVendorSource(finding.File, sources) {
			continue
		}
		seen[finding.Evidence] = true
	}
	steps := make([]string, 0, len(seen))
	for step := range seen {
		steps = append(steps, step)
	}
	sort.Strings(steps)
	return steps
}

// Vendored trees are attacker-supplied dependency copies. A prefetch command
// found inside one is not the package's own declared build step.
func findingBelongsToVendorSource(file string, sources []SourceProvenance) bool {
	for _, source := range sources {
		if file == source.Name || strings.HasPrefix(file, source.Name+"!/") {
			return true
		}
	}
	return false
}

// UsesPersistentGoCache and UsesPersistentCargoHome report whether the
// corresponding locked prefetch step was recognised. Persistent caches are
// mounted only then; ordinary package code receives ephemeral state.
func UsesPersistentGoCache(findings []Finding, sources []SourceProvenance) bool {
	return containsStep(findings, sources, "go mod download")
}

func UsesPersistentCargoHome(findings []Finding, sources []SourceProvenance) bool {
	return containsStep(findings, sources, "cargo fetch --locked")
}

func containsStep(findings []Finding, sources []SourceProvenance, wanted string) bool {
	for _, step := range KnownNetworkSteps(findings, sources, "") {
		if step == wanted {
			return true
		}
	}
	return false
}
