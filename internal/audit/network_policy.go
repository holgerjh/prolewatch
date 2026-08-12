package audit

import (
	"sort"
	"strings"
)

func knownNetworkSteps(report *Report, profile string) []string {
	if report == nil {
		return nil
	}
	ruleID := "shell-known-network-step-" + profile
	seen := map[string]bool{}
	for _, finding := range report.Findings {
		knownProfile := strings.TrimPrefix(finding.RuleID, "shell-known-network-step-")
		if knownProfile == finding.RuleID || (profile != "" && finding.RuleID != ruleID) ||
			finding.Evidence == "" || findingBelongsToVendorSource(finding.File, report.Sources) {
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

func findingBelongsToVendorSource(file string, sources []SourceProvenance) bool {
	for _, source := range sources {
		if file == source.Name || strings.HasPrefix(file, source.Name+"!/") {
			return true
		}
	}
	return false
}

func automaticKnownToolNetwork(cfg Config, profile string, report *Report) ([]string, bool) {
	if !cfg.Network.AutoEnableKnownTools || (profile != "prepare" && profile != "build") {
		return nil, false
	}
	steps := knownNetworkSteps(report, profile)
	return steps, len(steps) > 0
}

func usesPersistentCargoHome(report *Report) bool {
	for _, step := range knownNetworkSteps(report, "") {
		if step == "cargo fetch --locked" {
			return true
		}
	}
	return false
}
