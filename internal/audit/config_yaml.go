package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxConfigYAMLDepth = 32

var configDecimalRE = regexp.MustCompile(`^(?:0|-?[1-9][0-9]*)$`)
var configKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// decodeConfigYAML first constrains YAML to the scalar/map/list subset needed
// for policy, then uses the existing JSON tags and unknown-field rejection.
// This avoids a second, potentially divergent set of field names on every
// nested configuration struct.
func decodeConfigYAML(raw []byte) (Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("configuration is empty")
		}
		return Config{}, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, errors.New("configuration contains multiple YAML documents")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return Config{}, errors.New("configuration must be one YAML mapping")
	}
	value, err := configYAMLValue(document.Content[0], 0)
	if err != nil {
		return Config{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return Config{}, err
	}
	strict := json.NewDecoder(bytes.NewReader(canonical))
	strict.DisallowUnknownFields()
	var cfg Config
	if err := strict.Decode(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func configYAMLValue(node *yaml.Node, depth int) (any, error) {
	if depth > maxConfigYAMLDepth {
		return nil, errors.New("configuration YAML nesting limit exceeded")
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return nil, errors.New("configuration YAML anchors and aliases are forbidden")
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, errors.New("configuration YAML mapping is invalid")
		}
		mapping := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
				return nil, errors.New("configuration YAML keys must be plain strings")
			}
			if !configKeyRE.MatchString(key.Value) {
				return nil, fmt.Errorf("invalid configuration key %q: use lowercase snake_case", key.Value)
			}
			if _, exists := mapping[key.Value]; exists {
				return nil, fmt.Errorf("duplicate configuration key %q", key.Value)
			}
			item, err := configYAMLValue(node.Content[index+1], depth+1)
			if err != nil {
				return nil, err
			}
			mapping[key.Value] = item
		}
		return mapping, nil
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, errors.New("configuration YAML sequence is invalid")
		}
		items := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			item, err := configYAMLValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			return node.Value, nil
		case "!!int":
			if !configDecimalRE.MatchString(node.Value) {
				return nil, errors.New("configuration numbers must be plain decimal integers")
			}
			return json.Number(node.Value), nil
		case "!!bool":
			if strings.EqualFold(node.Value, "true") {
				return true, nil
			}
			if strings.EqualFold(node.Value, "false") {
				return false, nil
			}
		case "!!null":
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unsupported configuration YAML node or tag %q", node.Tag)
}
