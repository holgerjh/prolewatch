package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const verdictSchemaDraft = "http://json-schema.org/draft-07/schema#"

// validateVerdictSchema checks the structural requirements imposed by
// OpenAI Structured Outputs before a provider request consumes quota. It is
// intentionally narrower than a general JSON Schema validator.
func validateVerdictSchema(raw []byte) error {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("decode verdict schema: %w", err)
	}
	if root["$schema"] != verdictSchemaDraft {
		return fmt.Errorf("verdict schema must declare %q", verdictSchemaDraft)
	}
	rootTypes, err := structuredOutputTypes(root, "$")
	if err != nil {
		return err
	}
	if !rootTypes["object"] {
		return errors.New("verdict schema root must have type object")
	}
	return validateStructuredOutputNode(root, "$")
}

func validateStructuredOutputNode(node map[string]any, path string) error {
	types, err := structuredOutputTypes(node, path)
	if err != nil {
		return err
	}
	if types["object"] {
		properties, ok := node["properties"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s object must define properties", path)
		}
		if additional, ok := node["additionalProperties"].(bool); !ok || additional {
			return fmt.Errorf("%s object must set additionalProperties to false", path)
		}
		requiredRaw, ok := node["required"].([]any)
		if !ok {
			return fmt.Errorf("%s object must require every property", path)
		}
		required := make(map[string]bool, len(requiredRaw))
		for _, value := range requiredRaw {
			name, ok := value.(string)
			if !ok || required[name] {
				return fmt.Errorf("%s required list is invalid", path)
			}
			required[name] = true
		}
		var missing []string
		for name, childRaw := range properties {
			if !required[name] {
				missing = append(missing, name)
			}
			child, ok := childRaw.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.properties.%s is not a schema object", path, name)
			}
			if err := validateStructuredOutputNode(child, path+".properties."+name); err != nil {
				return err
			}
		}
		for name := range required {
			if _, ok := properties[name]; !ok {
				return fmt.Errorf("%s requires unknown property %q", path, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("%s does not require properties: %s", path, strings.Join(missing, ", "))
		}
	}
	if types["array"] {
		items, ok := node["items"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s array must define schema items", path)
		}
		if err := validateStructuredOutputNode(items, path+".items"); err != nil {
			return err
		}
	}
	if alternatives, ok := node["anyOf"].([]any); ok {
		for index, alternativeRaw := range alternatives {
			alternative, ok := alternativeRaw.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.anyOf[%d] is not a schema object", path, index)
			}
			if err := validateStructuredOutputNode(alternative, fmt.Sprintf("%s.anyOf[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	if definitions, ok := node["$defs"].(map[string]any); ok {
		for name, definitionRaw := range definitions {
			definition, ok := definitionRaw.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.$defs.%s is not a schema object", path, name)
			}
			if err := validateStructuredOutputNode(definition, path+".$defs."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func structuredOutputTypes(node map[string]any, path string) (map[string]bool, error) {
	if _, ref := node["$ref"].(string); ref {
		return map[string]bool{}, nil
	}
	raw, present := node["type"]
	if !present {
		if _, anyOf := node["anyOf"]; anyOf {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("%s must have a type key", path)
	}
	values := []any{raw}
	if list, ok := raw.([]any); ok {
		values = list
	}
	allowed := map[string]bool{"string": true, "number": true, "boolean": true, "integer": true, "object": true, "array": true, "null": true}
	types := make(map[string]bool, len(values))
	for _, value := range values {
		name, ok := value.(string)
		if !ok || !allowed[name] || types[name] {
			return nil, fmt.Errorf("%s has invalid type declaration", path)
		}
		types[name] = true
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("%s has empty type declaration", path)
	}
	return types, nil
}
