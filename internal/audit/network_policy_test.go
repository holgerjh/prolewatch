package audit

import (
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/egress"
)

// Network-enablement policy: whether an invocation may have a network at all.
// This reads a Report, so it stays in audit while the step recognition it
// consults lives in internal/brief.

func TestInvocationNetworkRequiresSafePhaseBoundReport(t *testing.T) {
	pre := &Report{Phase: "pre", Decision: "allow"}
	post := &Report{Phase: "post", Decision: "allow", NetworkEligible: true}
	if !invocationNetworkEnabled("verify", pre) || invocationNetworkEnabled("build", pre) ||
		!invocationNetworkEnabled("prepare", post) || !invocationNetworkEnabled("build", post) {
		t.Fatal("safe reports did not receive their phase-scoped network broker")
	}
	for _, report := range []*Report{
		nil,
		{Phase: "post", Decision: "block", NetworkEligible: true},
		{Phase: "post", Decision: "allow", NetworkEligible: false},
		{Phase: "post", Decision: "block", NetworkEligible: false},
	} {
		if invocationNetworkEnabled("build", report) || invocationNetworkEnabled("verify", report) {
			t.Fatalf("a report without a positive phase-bound decision received a network broker: %+v", report)
		}
	}
}

func TestPromptSourcesPreferTheFrozenVCSPlan(t *testing.T) {
	report := &Report{Sources: []brief.SourceProvenance{
		{
			URL: "git+https://stale.example/gtk.git#tag=old", Kind: brief.SourceKindVCS,
			Transport: "git+https", Binding: "mutable-vcs",
		},
		{URL: "https://stale.example/release.tar.zst", Kind: brief.SourceKindArchive},
	}}
	committed := promptSourcesFromReport(report)
	if len(committed) != 1 || committed[0].Host != "stale.example" {
		t.Fatalf("report prompt sources=%+v; trusted-side archive acquisition must not be presented as a makepkg checkout", committed)
	}
	frozen := promptSourcesFromFrozen([]egress.DeclaredSource{{
		Raw: "gtk::git+https://gitlab.gnome.org/GNOME/gtk.git#commit=0123456789abcdef0123456789abcdef01234567",
		URL: "https://gitlab.gnome.org/GNOME/gtk.git", Kind: egress.SourceVCS,
	}})
	if len(frozen) != 1 || frozen[0].Host != "gitlab.gnome.org" || frozen[0].Kind != brief.SourceKindVCS ||
		frozen[0].URL != "git+https://gitlab.gnome.org/GNOME/gtk.git#commit=0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("frozen prompt sources=%+v", frozen)
	}
}

func TestKnownToolNetworkContextNeverAuthorizes(t *testing.T) {
	report := &Report{Findings: []brief.Finding{
		{RuleID: "shell-known-network-step-prepare", Evidence: "cargo fetch --locked"},
		{RuleID: "shell-known-network-step-prepare", Evidence: "cargo fetch --locked"},
		{RuleID: "shell-known-network-step-prepare", File: "vendor.sh", Evidence: "npm ci"},
		{RuleID: "unexpected-network-client", Evidence: "curl"},
	}, Sources: []brief.SourceProvenance{{Name: "vendor.sh"}}}
	steps := brief.KnownNetworkSteps(report.Findings, report.Sources, "prepare")
	if len(steps) != 1 || steps[0] != "cargo fetch --locked" {
		t.Fatalf("known network context = %#v", steps)
	}
	if steps := brief.KnownNetworkSteps(report.Findings, report.Sources, "verify"); len(steps) != 0 {
		t.Fatal("prepare-only context leaked into source verification")
	}
	if steps := brief.KnownNetworkSteps(report.Findings, report.Sources, "build"); len(steps) != 0 {
		t.Fatal("prepare-only context leaked into the later build invocation")
	}
	if !brief.UsesPersistentCargoHome(report.Findings, report.Sources) {
		t.Fatal("locked Cargo fetch did not request its transaction-local cache")
	}
}
