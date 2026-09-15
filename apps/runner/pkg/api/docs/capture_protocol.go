// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docs

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CaptureProtocol returns the canonical capture surface from the generated
// Runner API contract, including every transitively referenced definition.
// Deployment-specific host/version metadata and unrelated API routes do not
// change this interface. The generated contract remains the sole schema owner.
func CaptureProtocol() ([]byte, error) {
	return captureProtocol([]byte(SwaggerInfo.ReadDoc()))
}

func captureProtocol(document []byte) ([]byte, error) {
	var source struct {
		Paths               map[string]json.RawMessage `json:"paths"`
		Definitions         map[string]json.RawMessage `json:"definitions"`
		SecurityDefinitions json.RawMessage            `json:"securityDefinitions"`
	}
	if err := json.Unmarshal(document, &source); err != nil {
		return nil, fmt.Errorf("decode capture API contract: %w", err)
	}
	paths := map[string]json.RawMessage{}
	definitions := map[string]json.RawMessage{}
	var collect func(json.RawMessage) error
	collect = func(raw json.RawMessage) error {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		var walk func(any) error
		walk = func(value any) error {
			switch value := value.(type) {
			case []any:
				for _, entry := range value {
					if err := walk(entry); err != nil {
						return err
					}
				}
			case map[string]any:
				if ref, ok := value["$ref"].(string); ok {
					const prefix = "#/definitions/"
					if !strings.HasPrefix(ref, prefix) {
						return fmt.Errorf("capture API contract has unsupported reference %q", ref)
					}
					name := strings.TrimPrefix(ref, prefix)
					if _, found := definitions[name]; !found {
						definition, exists := source.Definitions[name]
						if !exists {
							return fmt.Errorf("capture API contract lacks definition %q", name)
						}
						definitions[name] = definition
						if err := collect(definition); err != nil {
							return err
						}
					}
				}
				for _, entry := range value {
					if err := walk(entry); err != nil {
						return err
					}
				}
			}
			return nil
		}
		return walk(value)
	}
	const prefix = "/sandboxes/{sandboxId}/working-copy-captures"
	for path, operation := range source.Paths {
		if path != prefix && !strings.HasPrefix(path, prefix+"/") {
			continue
		}
		paths[path] = operation
		if err := collect(operation); err != nil {
			return nil, err
		}
	}
	if len(paths) == 0 || len(definitions) == 0 {
		return nil, fmt.Errorf("capture API contract has no complete capture surface")
	}
	// Decode once before encoding so RawMessage formatting cannot alter identity.
	raw, err := json.Marshal(map[string]any{
		"swagger": "2.0", "info": map[string]string{"title": "Working-copy capture", "version": "2"},
		"paths": paths, "definitions": definitions, "securityDefinitions": source.SecurityDefinitions,
	})
	if err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}
