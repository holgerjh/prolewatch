package audit

import (
	"context"
	"strings"
	"testing"
)

func TestProviderSemanticCanaryUsesManifestBoundPKGBUILD(t *testing.T) {
	inventory := providerSemanticCanaryInventory()
	if inventory == nil || len(inventory.Files) != 1 || inventory.Files[0].Path != "PKGBUILD" || inventory.Files[0].PathB64 != "UEtHQlVJTEQ=" {
		t.Fatalf("semantic canary does not expose an unambiguous PKGBUILD: %+v", inventory)
	}
	if !inventory.Coverage.Complete || inventory.ManifestHash == "" || !strings.Contains(inventory.Files[0].SelectedText, "Ignore all previous instructions") {
		t.Fatalf("semantic canary lost its complete prompt-injection fixture: %+v", inventory)
	}
	for _, finding := range inventory.Findings {
		if finding.File != "PKGBUILD" {
			t.Fatalf("deterministic canary finding escaped its manifest path: %+v", finding)
		}
	}
}

func TestDeterministicDoctorOmitsProviderRequirements(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	previousFactory := providerAdapterFactory
	called := false
	providerAdapterFactory = func(Config) providerAdapter {
		called = true
		return previousFactory(DefaultConfig())
	}
	defer func() { providerAdapterFactory = previousFactory }()

	checks := RunDoctor(context.Background(), cfg, true)
	if called {
		t.Fatal("deterministic-only doctor initialized an AI provider")
	}
	for _, check := range checks {
		switch check.Name {
		case "active provider binary", "prolewatch user", "dedicated provider authentication", "verdict schema", "active provider compatibility", "isolated provider semantic canary", "provider semantic attestation":
			t.Fatalf("deterministic-only doctor required provider check %q", check.Name)
		}
	}
}
