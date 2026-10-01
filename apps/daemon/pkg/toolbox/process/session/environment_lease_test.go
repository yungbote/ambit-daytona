//go:build linux

package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	native "github.com/daytonaio/daemon/pkg/session"
	"github.com/google/uuid"
	sloggin "github.com/samber/slog-gin"
)

func TestEnvironmentLeaseHTTPAcceptanceIsRecoverableWithoutValues(t *testing.T) {
	configDir := t.TempDir()
	engine, _ := newSessionEngine(t, configDir, nil)
	const sessionID = "credential-process"
	if status, _ := call(t, engine, http.MethodPost, "/process/session", CreateSessionRequest{SessionId: sessionID}); status != http.StatusCreated {
		t.Fatal("native session creation failed")
	}
	t.Cleanup(func() { call(t, engine, http.MethodDelete, "/process/session/"+sessionID, nil) })
	status, body := call(t, engine, http.MethodGet, "/process/session/"+sessionID, nil)
	var before SessionDTO
	if status != http.StatusOK || json.Unmarshal(body, &before) != nil || before.EnvironmentLeaseVersion != 1 {
		t.Fatal("native HTTP reader did not advertise the environment protocol")
	}
	// nosecret: generated synthetic material, never an external credential.
	value := "synthetic-" + uuid.NewString()
	lease := &native.EnvironmentLease{Version: 1, ID: uuid.NewString(), ExpiresAt: time.Now().Add(5 * time.Second), Values: map[string]string{"api_key": value, "empty_value": ""}}
	status, body = call(t, engine, http.MethodPost, "/process/session/"+sessionID+"/exec", SessionExecuteRequest{
		Command: `test -z "$empty_value" && printf '%s' "$api_key" | sha256sum`, EnvironmentLease: lease, SuppressInputEcho: true,
	})
	var executed SessionExecuteResponse
	if status != http.StatusOK || json.Unmarshal(body, &executed) != nil || executed.ExitCode == nil || *executed.ExitCode != 0 || executed.Output == nil {
		t.Fatal("native HTTP environment invocation failed")
	}
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
	if !bytes.Contains([]byte(*executed.Output), []byte(expected)) || bytes.Contains(body, []byte(value)) {
		t.Fatal("native HTTP recipient or response violated the transient environment contract")
	}
	// Discard the response, as a caller with a lost reply would. Native metadata
	// still identifies exactly the accepted lease; no new dispatch is needed.
	status, body = call(t, engine, http.MethodGet, "/process/session/"+sessionID, nil)
	var recovered SessionDTO
	if status != http.StatusOK || json.Unmarshal(body, &recovered) != nil || recovered.EnvironmentLeaseID != lease.ID || recovered.EnvironmentLeaseExpiresAt == nil || !recovered.EnvironmentLeaseExpiresAt.Equal(lease.ExpiresAt) || !recovered.InputClosed || len(recovered.Commands) != 1 {
		t.Fatal("lost-reply observation did not retain exact native acceptance")
	}
	if bytes.Contains(body, []byte(value)) {
		t.Fatal("native command observation serialized environment values")
	}
	if status, _ := call(t, engine, http.MethodPost, "/process/session/"+sessionID+"/exec", SessionExecuteRequest{Command: "true", EnvironmentLease: lease}); status != http.StatusGone {
		t.Fatal("a finite credential session accepted a second invocation")
	}
	if err := filepath.WalkDir(configDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(value)) {
			t.Error("native HTTP dispatch persisted environment material")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentLeaseHTTPValidationDoesNotEchoRequestMaterial(t *testing.T) {
	var logged bytes.Buffer
	engine, _ := newSessionEngine(t, t.TempDir(), nil, sloggin.New(slog.New(slog.NewTextHandler(&logged, nil))))
	// nosecret: malformed synthetic request material deliberately occupies a
	// typed metadata field. A parser's raw error must not become public output.
	value := "synthetic-" + uuid.NewString()
	status, body := call(t, engine, http.MethodPost, "/process/session/absent/exec", map[string]any{
		"command": "true", "environmentLease": map[string]any{"version": 1, "id": uuid.NewString(), "expiresAt": value, "values": map[string]string{"api_key": value}},
	})
	if status != http.StatusBadRequest || bytes.Contains(body, []byte(value)) || bytes.Contains(logged.Bytes(), []byte(value)) {
		t.Fatal("native HTTP request validation exposed transient request material")
	}
}

func TestEnvironmentLeaseOpenAPIKeepsValuesInDispatchOnly(t *testing.T) {
	encoded, err := os.ReadFile("../../docs/swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Definitions map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Session", "SessionExecuteResponse"} {
		definition := document.Definitions[name]
		for _, field := range []string{"environmentLeaseVersion", "environmentLeaseId", "environmentLeaseExpiresAt"} {
			if _, exists := definition.Properties[field]; !exists {
				t.Fatal("OpenAPI omits native lease custody metadata")
			}
			for _, required := range definition.Required {
				if required == field {
					t.Fatal("OpenAPI makes the optional native reader a legacy requirement")
				}
			}
		}
		if _, exists := definition.Properties["values"]; exists {
			t.Fatal("OpenAPI exposes dispatch values in native custody")
		}
	}
	if _, exists := document.Definitions["SessionExecuteRequest"].Properties["environmentLease"]; !exists {
		t.Fatal("OpenAPI omits finite environment dispatch")
	}
	if _, exists := document.Definitions["session.EnvironmentLease"].Properties["values"]; !exists {
		t.Fatal("OpenAPI omits the transient environment input")
	}
}
