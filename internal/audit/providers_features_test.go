package audit

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCodexFeatureListAcceptsDottedNamespaces(t *testing.T) {
	output := "zeta stable true\n" +
		"guardianv2.thread_context                under development  false\n" +
		"alpha stable false\n" +
		"legacy deprecated false\n" +
		"gone removed true\n"
	features, err := parseCodexFeatureList(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "guardianv2.thread_context", "zeta"}
	if !reflect.DeepEqual(features, want) {
		t.Fatalf("features = %q, want %q", features, want)
	}
}

func TestParseCodexFeatureListRejectsMalformedKeys(t *testing.T) {
	for _, key := range []string{
		".thread_context", "guardianv2.", "guardianv2..thread_context",
		"guardianv2.2thread_context", "guardianv2-thread_context", "guardianv2/thread_context",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := parseCodexFeatureList(key + " stable false\n")
			if err == nil || !strings.Contains(err.Error(), "cannot parse Codex feature entry") {
				t.Fatalf("malformed feature key %q was accepted: %v", key, err)
			}
		})
	}
}
