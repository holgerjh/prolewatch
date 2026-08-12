package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityScenariosCommandDispatch(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "security-scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"security-scenarios", "--root", root, "--scenario", "baseline-safe"}, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("security-scenarios status=%d stderr=%q", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS baseline-safe") {
		t.Fatalf("missing scenario result: %s", stdout.String())
	}
}
