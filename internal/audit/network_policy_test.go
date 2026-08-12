package audit

import "testing"

func TestAutomaticKnownToolNetworkPolicy(t *testing.T) {
	report := &Report{Findings: []Finding{
		{RuleID: "shell-known-network-step-prepare", Evidence: "cargo fetch --locked"},
		{RuleID: "shell-known-network-step-prepare", Evidence: "cargo fetch --locked"},
		{RuleID: "shell-known-network-step-prepare", File: "vendor.sh", Evidence: "npm ci"},
		{RuleID: "unexpected-network-client", Evidence: "curl"},
	}, Sources: []SourceProvenance{{Name: "vendor.sh"}}}
	cfg := DefaultConfig()
	steps, enabled := automaticKnownToolNetwork(cfg, "prepare", report)
	if !enabled || len(steps) != 1 || steps[0] != "cargo fetch --locked" {
		t.Fatalf("known network decision = %v, %#v", enabled, steps)
	}
	if _, enabled := automaticKnownToolNetwork(cfg, "verify", report); enabled {
		t.Fatal("known-tool policy unexpectedly changed source verification")
	}
	if _, enabled := automaticKnownToolNetwork(cfg, "build", report); enabled {
		t.Fatal("prepare-only fetch enabled the later build invocation")
	}
	if !usesPersistentCargoHome(report) {
		t.Fatal("locked Cargo fetch did not request its transaction-local cache")
	}
	cfg.Network.AutoEnableKnownTools = false
	if _, enabled := automaticKnownToolNetwork(cfg, "build", report); enabled {
		t.Fatal("disabled known-tool policy still enabled network")
	}
}
