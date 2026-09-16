package docs

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCaptureProtocolUsesExactGeneratedSurface(t *testing.T) {
	actual, err := CaptureProtocol()
	if err != nil {
		t.Fatal(err)
	}
	var protocol map[string]any
	if err := json.Unmarshal(actual, &protocol); err != nil {
		t.Fatal(err)
	}
	paths := protocol["paths"].(map[string]any)
	if _, exists := paths["/sandboxes/{sandboxId}/working-copy-captures/capabilities"]; !exists {
		t.Fatal("capture discovery is missing")
	}
	for _, suffix := range []string{"", "/observe", "/read", "/delete"} {
		if _, exists := paths["/sandboxes/{sandboxId}/working-copy-captures/sandbox-files"+suffix]; !exists {
			t.Fatalf("native sandbox capture operation %q is missing", suffix)
		}
	}
	if _, exists := paths["/info"]; exists {
		t.Fatal("unrelated Runner API changed capture identity")
	}
	definitions := protocol["definitions"].(map[string]any)
	for _, name := range []string{"workingcopy.CaptureAuthority", "workingcopy.CaptureBinding", "workingcopy.WorkingTreeInventoryReceipt", "generationstop.ExpectedGeneration", "workingcopy.SandboxFileReceipt", "workingcopy.CaptureComponent"} {
		if _, exists := definitions[name]; !exists {
			t.Fatalf("missing transitive definition %s", name)
		}
	}
	var source map[string]any
	if err := json.Unmarshal([]byte(SwaggerInfo.ReadDoc()), &source); err != nil {
		t.Fatal(err)
	}
	source["host"] = "unrelated-deployment.invalid"
	source["info"] = map[string]any{"version": "different-build"}
	source["paths"].(map[string]any)["/unrelated"] = map[string]any{"description": "outside capture"}
	formatted, _ := json.MarshalIndent(source, "", "  ")
	unchanged, err := captureProtocol(formatted)
	if err != nil || !bytes.Equal(unchanged, actual) {
		t.Fatalf("unrelated metadata or formatting changed interface: %v", err)
	}
	source["definitions"].(map[string]any)["workingcopy.CaptureAuthority"].(map[string]any)["description"] = "Changed source contract"
	changedBytes, _ := json.Marshal(source)
	changed, err := captureProtocol(changedBytes)
	if err != nil || bytes.Equal(changed, actual) {
		t.Fatalf("contract change did not change interface: %v", err)
	}
	delete(source["definitions"].(map[string]any), "workingcopy.CaptureAuthority")
	missing, _ := json.Marshal(source)
	if _, err := captureProtocol(missing); err == nil {
		t.Fatal("missing referenced schema was admitted")
	}
}

func TestCaptureProtocolRefusesMissingSurface(t *testing.T) {
	for _, document := range []string{"invalid", `{}`, `{"paths":{"/elsewhere":{}}}`} {
		if _, err := captureProtocol([]byte(document)); err == nil {
			t.Fatal("incomplete contract was admitted")
		}
	}
}
