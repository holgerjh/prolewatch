package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerdictSchemaMatchesStructuredOutputSubset(t *testing.T) {
	repositoryShare, err := filepath.Abs(filepath.Join("..", "..", "share"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repositoryShare, "verdict.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateVerdictSchema(raw); err != nil {
		t.Fatalf("verdict schema is not accepted by the Structured Outputs preflight: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	schemaVersion := properties["schema_version"].(map[string]any)
	delete(schemaVersion, "type")
	broken, _ := json.Marshal(schema)
	if err := validateVerdictSchema(broken); err == nil || !strings.Contains(err.Error(), "schema_version must have a type key") {
		t.Fatalf("missing property type was not rejected precisely: %v", err)
	}

	schemaVersion["type"] = "integer"
	schema["additionalProperties"] = true
	broken, _ = json.Marshal(schema)
	if err := validateVerdictSchema(broken); err == nil || !strings.Contains(err.Error(), "additionalProperties") {
		t.Fatalf("open root object was not rejected: %v", err)
	}

	schema["additionalProperties"] = false
	required := schema["required"].([]any)
	schema["required"] = required[1:]
	broken, _ = json.Marshal(schema)
	if err := validateVerdictSchema(broken); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("optional Structured Outputs property was not rejected: %v", err)
	}
}
