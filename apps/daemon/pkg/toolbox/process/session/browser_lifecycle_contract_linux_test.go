//go:build linux

package session

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Native4a ControlRequest::parse and sign_in::restarted are the producer
// shapes; Product BrowserControlCommand and readBrowserControlResult are the
// consumers. Exercise the actual Go decoder, serializer and reply projector
// together so the HTTP/channel seam cannot silently omit a lifecycle variant.
func TestBrowserLifecycleControlWireContract(t *testing.T) {
	for op, fields := range map[string]string{
		"inspect":      "",
		"downloads":    "",
		"acquire":      `,"controllerId":"` + browserFixtureController + `","expiresAt":123`,
		"renew":        `,"controllerId":"` + browserFixtureController + `","expiresAt":123`,
		"release":      `,"controllerId":"` + browserFixtureController + `"`,
		"restart":      `,"controllerId":"` + browserFixtureController + `"`,
		"copy":         `,"controllerId":"` + browserFixtureController + `"`,
		"files":        `,"controllerId":"` + browserFixtureController + `"`,
		"input":        `,"controllerId":"` + browserFixtureController + `","sequence":1,"events":[{"type":"sign_in","idleTimeoutMs":600000}]`,
		"drop":         `,"controllerId":"` + browserFixtureController + `","sequence":1,"expectedSurfaceGeneration":"bbbbcccc-dddd-4eee-8fff-000011112222","x":0,"y":10`,
		"setfiles":     `,"controllerId":"` + browserFixtureController + `","sequence":1,"destinationId":"bbbbcccc-dddd-4eee-8fff-000011112222","files":["/workspace/file"]`,
		"dismissfiles": `,"controllerId":"` + browserFixtureController + `","destinationId":"bbbbcccc-dddd-4eee-8fff-000011112222"`,
	} {
		t.Run(op, func(t *testing.T) {
			body := `{"op":"` + op + `"` + fields + `}`
			request, err := decodeBrowserControlRequest(strings.NewReader(body))
			if err != nil {
				t.Fatalf("Product command refused before native dispatch: %s: %v", body, err)
			}
			wire, refused := browserControlCommand(request)
			if refused != nil {
				t.Fatalf("command failed serialization: %+v", refused)
			}
			want := `{"action":"ambit_browser_control",` + strings.TrimPrefix(body, "{") + "\n"
			if string(wire) != want {
				t.Fatalf("native command = %s, want %s", wire, want)
			}
		})
	}
	request := browserControlRequest{Op: "restart", ControllerID: browserFixtureController}
	surface := `{"kind":"browser-window","coordinateSpace":"display-pixels","generation":"bbbbcccc-dddd-4eee-8fff-000011112222","width":1280,"height":720,"originX":0,"originY":0,"deviceScaleFactor":2,"cursorIncluded":false}`
	for _, shape := range []string{"null", surface} {
		producer := shape
		if shape != "null" {
			producer = strings.TrimSuffix(shape, "}") + `,"nativeWindow":42,"privatePath":"/private/profile"}`
		}
		raw := `{"status":"restarted","surface":` + producer + `,"controllerId":"private","expiresAt":99,"lastSequence":4,"secret":"` + browserFixtureSecret + `"}`
		line := []byte(`{"id":"private","success":true,"data":` + raw + `}`)
		outcome, succeeded, intact := projectBrowserControlReply(line, request)
		body, err := json.Marshal(outcome.body)
		want := `{"status":"restarted","surface":` + shape + `}`
		if err != nil || !succeeded || !intact || outcome.status != http.StatusOK || string(body) != want {
			t.Fatalf("native restart projection = %d %s (success=%v intact=%v), want %s", outcome.status, body, succeeded, intact, want)
		}
	}
	for _, invalid := range []string{
		`{}`, `{"status":"restarted"}`, `{"status":"restarted","surface":{}}`,
		`{"status":"controlled","controllerId":"` + browserFixtureController + `","expiresAt":123,"lastSequence":0}`,
		`{"status":"restarted","surface":false}`, `{"status":"restarted","surface":[]}`,
		`{"status":"restarted","surface":` + strings.Replace(surface, `"width":1280`, `"width":0`, 1) + `}`,
	} {
		outcome := projectBrowserControlSuccess(json.RawMessage(invalid), request)
		body, _ := json.Marshal(outcome.body)
		if outcome.status != http.StatusBadGateway || string(body) != `{"code":"browser_control_outcome_unknown"}` {
			t.Fatalf("invalid restart became an acknowledgment: %s: %d %s", invalid, outcome.status, body)
		}
	}
	for _, code := range []string{"browser_control_invalid", "browser_control_conflict", "browser_control_unavailable", "browser_control_outcome_unknown"} {
		outcome, succeeded, intact := projectBrowserControlReply([]byte(fmt.Sprintf(`{"success":false,"code":%q,"reason":"exited","error":%q}`, code, browserFixtureSecret)), request)
		body, _ := json.Marshal(outcome.body)
		if succeeded || !intact || outcome.status != http.StatusConflict || string(body) != fmt.Sprintf(`{"code":%q}`, code) {
			t.Fatalf("native refusal changed or leaked private data: %s: %d %s", code, outcome.status, body)
		}
	}
	for _, malformed := range [][]byte{nil, []byte(`{"success":true`)} {
		outcome, succeeded, intact := projectBrowserControlReply(malformed, request)
		if succeeded || intact || outcome.status != http.StatusBadGateway {
			t.Fatalf("lost/malformed reply was restated as an intact restart: %+v", outcome)
		}
	}
	if _, err := readBrowserControlReply(bufio.NewReader(bytes.NewReader(nil)), browserControlLimit); err == nil {
		t.Fatal("closed command transport produced a restart acknowledgment")
	}
}

func TestBrowserRestartRejectsLeaseAndInputFields(t *testing.T) {
	valid := `{"op":"restart","controllerId":"` + browserFixtureController + `"`
	for _, extra := range []string{
		`,"expiresAt":123`, `,"sequence":1`, `,"events":[{"type":"input_mouse"}]`,
		`,"expectedSurfaceGeneration":"bbbbcccc-dddd-4eee-8fff-000011112222"`,
		`,"destinationId":"bbbbcccc-dddd-4eee-8fff-000011112222"`, `,"files":["/private/file"]`,
		`,"x":0`, `,"y":0`, `,"unknown":true`,
	} {
		if _, err := decodeBrowserControlRequest(strings.NewReader(valid + extra + `}`)); err == nil {
			t.Fatalf("restart admitted unrelated fields: %s", extra)
		}
	}
	for _, id := range []string{"", "../other", "00000000-0000-0000-0000-000000000000", strings.ToUpper(browserFixtureController)} {
		if _, err := decodeBrowserControlRequest(strings.NewReader(fmt.Sprintf(`{"op":"restart","controllerId":%q}`, id))); err == nil {
			t.Fatalf("restart admitted invalid controller identity: %q", id)
		}
	}
}
