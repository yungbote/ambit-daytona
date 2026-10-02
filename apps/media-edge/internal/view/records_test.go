// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Ported from the toolbox's browser_views_linux_test.go,
// browser_cursor_test.go and browser_activity_test.go.

func TestVisualStreamRejectsCommandsAndNonvisualData(t *testing.T) {
	for _, value := range []string{
		`{"type":"command","command":"secret task input"}`,
		`{"type":"result","data":{"token":"secret"}}`,
		`{"type":"console","text":"secret task input"}`,
		`{"type":"frame","seq":0}`,
		`{"type":"frame","seq":-1}`,
		`{"type":"frame","seq":"3"}`,
		`{"type":"unavailable","reason":"a driver's own words"}`,
		`not json`,
	} {
		if _, _, kind := projectRecord([]byte(value)); kind != recordDropped {
			t.Fatalf("forwarded nonvisual or malformed message: %s", value)
		}
	}
	// A driver failure is a fact the viewer is owed; its text is not.
	if body, _, kind := projectRecord([]byte(`{"type":"error","message":"secret task input"}`)); kind != recordFailed || body != nil {
		t.Fatalf("driver failure was relayed as %v with body %s", kind, body)
	}
	if body, ack, kind := projectRecord([]byte(`{"type":"finished","private":"secret task input"}`)); kind != recordFinished || body != nil || ack != 0 {
		t.Fatalf("explicit stream completion retained driver data: kind=%v body=%s ack=%d", kind, body, ack)
	}
	// The toolbox's own failure record is the failure it reports.
	if _, _, kind := projectRecord(append(unavailableRecord, '\n')); kind != recordFailed {
		t.Fatal("the toolbox's failure record was not read as a failure")
	}
	frame := []byte(`{"type":"frame","seq":17,"data":"AA==","metadata":{"deviceWidth":1280,"deviceHeight":720}}`)
	if body, ack, kind := projectRecord(frame); kind != recordVisual || ack != 17 || string(body) != string(frame) {
		t.Fatal("visual frame lost its acknowledgment identity")
	}
	for _, value := range []string{`{"type":"status","connected":false}`, `{"type":"url","url":"https://example.com"}`} {
		if _, ack, kind := projectRecord([]byte(value)); kind != recordVisual || ack != 0 {
			t.Fatalf("visual state was rejected or treated as a frame: %s", value)
		}
	}
}

func TestViewProjectsOnlyTheCurrentTabLocation(t *testing.T) {
	value := []byte(`{"type":"tabs","tabs":[{"active":false,"url":"https://private.test/","title":"private"},{"active":true,"url":"https://example.test/","title":"Current","targetId":"private"}],"token":"private"}`)
	body, sequence, kind := projectRecord(value)
	if kind != recordVisual || sequence != 0 || string(body) != `{"type":"url","url":"https://example.test/","title":"Current"}` {
		t.Fatalf("unexpected location projection: %s %d %v", body, sequence, kind)
	}
	for _, invalid := range []string{
		`{"type":"tabs"}`, `{"type":"tabs","tabs":[]}`,
		`{"type":"tabs","tabs":[{"active":false,"url":"https://private.test/"}]}`,
		`{"type":"tabs","tabs":[{"active":true,"url":""}]}`,
		`{"type":"tabs","tabs":[{"active":"true","url":"https://example.test/"}]}`,
		`{"type":"tabs","tabs":[{"active":true,"url":"https://one.test/"},{"active":true,"url":"https://two.test/"}]}`,
	} {
		if _, _, kind := projectRecord([]byte(invalid)); kind != recordDropped {
			t.Fatalf("ambiguous tab snapshot was forwarded: %s", invalid)
		}
	}
	observed := []byte(`{"type":"tabs","tabs":[{"active":true,"url":"https://example.test/","canGoBack":true,"canGoForward":false,"history":["private"]}]}`)
	body, _, kind = projectRecord(observed)
	if kind != recordVisual || !bytes.Contains(body, []byte(`"canGoBack":true`)) || !bytes.Contains(body, []byte(`"canGoForward":false`)) || bytes.Contains(body, []byte("private")) {
		t.Fatalf("history availability projection: %s", body)
	}
}

func TestCursorRecordsProjectTheKeywordOrTheImage(t *testing.T) {
	image := `{"hash":"9f8579ba9c44aa01","width":48,"height":48,"hotX":24,"hotY":24,"scale":2,"png":"` + cursorPNG(48, 48) + `","private":"secret"}`
	for _, input := range []string{
		`{"type":"cursor","ts":912345678,"serial":17,"css":"text","private":"secret"}`,
		`{"type":"cursor","ts":912345678,"serial":18,"image":` + image + `}`,
		`{"type":"cursor","ts":912345678,"serial":20,"css":null,"image":` + image + `}`,
		`{"type":"cursor","ts":912345678,"serial":19,"image":{"hash":"9f8579ba9c44aa01","width":48,"height":48,"hotX":24,"hotY":24,"scale":2}}`,
	} {
		projected, sequence, kind := projectRecord([]byte(input))
		if kind != recordVisual || sequence != 0 || strings.Contains(string(projected), "secret") {
			t.Fatalf("cursor was not projected: %s -> %s", input, projected)
		}
		var value map[string]any
		if json.Unmarshal(projected, &value) != nil || value["type"] != "cursor" || value["ts"] != float64(912345678) || value["serial"] == nil {
			t.Fatalf("cursor identity lost: %s", projected)
		}
		css, stated := value["css"]
		if _, image := value["image"]; !stated || (css == nil) != image || (css != nil && css != "text") {
			t.Fatalf("cursor identity misstated: %s", projected)
		}
	}
	for _, keyword := range cursorKeywords {
		input := `{"type":"cursor","ts":1,"serial":1,"css":"` + keyword + `"}`
		if _, _, kind := projectRecord([]byte(input)); kind != recordVisual {
			t.Fatalf("keyword %s refused", keyword)
		}
	}
}

func TestCursorRecordsRefuseAnythingButOneBoundedIdentity(t *testing.T) {
	image := func(fields string) string {
		return `{"type":"cursor","ts":1,"serial":1,"image":{` + fields + `}}`
	}
	valid := `"hash":"9f8579ba9c44aa01","width":48,"height":48,"hotX":24,"hotY":24,"scale":2`
	for _, input := range []string{
		`{"type":"cursor","ts":1,"serial":1}`,
		`{"type":"cursor","ts":1,"serial":1,"css":"auto"}`,
		`{"type":"cursor","ts":1,"serial":1,"css":"url(x)"}`,
		`{"type":"cursor","ts":1,"serial":1,"css":"TEXT"}`,
		`{"type":"cursor","serial":1,"css":"text"}`,
		`{"type":"cursor","ts":9007199254740992,"serial":1,"css":"text"}`,
		`{"type":"cursor","ts":1,"css":"text"}`,
		`{"type":"cursor","ts":1,"serial":4294967296,"css":"text"}`,
		`{"type":"cursor","ts":1,"serial":1,"css":"text","image":{` + valid + `}}`,
		`{"type":"cursor","ts":1,"serial":1,"css":null}`,
		`{"type":"cursor","ts":1,"serial":1,"css":""}`,
		`{"type":"cursor","ts":1,"serial":1,"css":"","image":{` + valid + `}}`,
		image(strings.Replace(valid, `"hash":"9f8579ba9c44aa01"`, `"hash":"xyz"`, 1)),
		image(strings.Replace(valid, `"hash":"9f8579ba9c44aa01"`, `"hash":"9f85"`, 1)),
		image(strings.Replace(valid, `"width":48`, `"width":0`, 1)),
		image(strings.Replace(valid, `"width":48`, `"width":257`, 1)),
		image(strings.Replace(valid, `"hotX":24`, `"hotX":48`, 1)),
		image(strings.Replace(valid, `"hotY":24`, `"hotY":-1`, 1)),
		image(strings.Replace(valid, `"scale":2`, `"scale":3`, 1)),
		image(valid + `,"png":"not base64!"`),
		image(valid + `,"png":"` + base64.StdEncoding.EncodeToString([]byte("GIF89a")) + `"`),
		image(valid + `,"png":"` + cursorPNG(47, 48) + `"`),
		`{"type":"cursor","ts":1,"serial":1,"css":"text","padding":"` + strings.Repeat("x", cursorRecordLimit) + `"}`,
	} {
		if projected, _, kind := projectRecord([]byte(input)); kind != recordDropped || projected != nil {
			t.Fatalf("invalid cursor admitted: %.200s", input)
		}
	}
}

func TestActivityProjectsOnlyVisualInput(t *testing.T) {
	for _, input := range []string{
		`{"type":"activity","pageGeneration":"page-2","source":"agent","kind":"scrolling","timestamp":13,"x":999,"text":"private-input"}`,
		`{"type":"pointer","pageGeneration":"page-2","source":"agent","eventType":"press","x":20,"y":30,"buttons":1,"modifiers":0,"timestamp":12,"text":"private-input"}`,
		`{"type":"activity","pageGeneration":"page-2","source":"human","kind":"typing","timestamp":13,"key":"private-input","code":"private-input","text":"private-input"}`,
		`{"type":"pointer","pageGeneration":"page-3","eventType":"reset","timestamp":14,"source":"private-input"}`,
	} {
		body, valid := activityRecord([]byte(input))
		if !valid || strings.Contains(string(body), "private-input") {
			t.Fatalf("invalid public activity projection: %s", body)
		}
		var value map[string]any
		if json.Unmarshal(body, &value) != nil || value["pageGeneration"] == nil || value["timestamp"] == nil {
			t.Fatalf("lost activity identity: %s", body)
		}
	}
}

func TestActivityRefusesUnidentifiedOrMalformedInput(t *testing.T) {
	for _, input := range []string{
		`{"type":"activity","source":"agent","kind":"typing","timestamp":1}`,
		`{"type":"activity","pageGeneration":"p","source":"website","kind":"typing","timestamp":1}`,
		`{"type":"activity","pageGeneration":"p","source":"agent","kind":"text","timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"click","x":1,"y":2,"buttons":1,"modifiers":0,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"press","x":-1,"y":2,"buttons":1,"modifiers":0,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"press","x":1,"y":2,"buttons":1.5,"modifiers":0,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"press","x":1,"y":2,"buttons":1,"modifiers":16,"timestamp":1}`,
		`{"type":"pointer","pageGeneration":"p","eventType":"reset","timestamp":-1}`,
	} {
		if _, valid := activityRecord([]byte(input)); valid {
			t.Fatalf("invalid activity was accepted: %s", input)
		}
	}
}

func TestActivityCarriesTheCaptureClock(t *testing.T) {
	for _, input := range []string{
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"move","x":20,"y":30,"buttons":0,"modifiers":0,"timestamp":12,"ts":912345678}`,
		`{"type":"activity","pageGeneration":"p","source":"agent","kind":"typing","timestamp":13,"ts":912345679}`,
	} {
		body, valid := activityRecord([]byte(input))
		var value map[string]any
		if !valid || json.Unmarshal(body, &value) != nil || value["ts"] == nil {
			t.Fatalf("capture clock was dropped: %s", body)
		}
	}
	for _, input := range []string{
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"move","x":20,"y":30,"buttons":0,"modifiers":0,"timestamp":12,"ts":-1}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"move","x":20,"y":30,"buttons":0,"modifiers":0,"timestamp":12,"ts":9007199254740992}`,
		`{"type":"activity","pageGeneration":"p","source":"agent","kind":"typing","timestamp":13,"ts":"soon"}`,
	} {
		if _, valid := activityRecord([]byte(input)); valid {
			t.Fatalf("unbounded clock admitted: %s", input)
		}
	}
}

// Every record the projection emits projects to itself, so the toolbox's
// already-projected stream passes the edge byte for byte, and a driver's raw
// stream comes out exactly as the toolbox would have shaped it.
func TestRecordProjectionIsIdempotent(t *testing.T) {
	image := `{"hash":"9f8579ba9c44aa01","width":48,"height":48,"hotX":24,"hotY":24,"scale":2,"png":"` + cursorPNG(48, 48) + `"}`
	for _, input := range []string{
		`{"type":"status","connected":true,"screencasting":true,"viewportWidth":640,"viewportHeight":480,"engine":"chromium","recording":false,"private":"x"}`,
		`{"type":"url","url":"https://example.test/a?b=1&c=<d>","title":"Café   \"q\"","timestamp":123,"canGoBack":true,"canGoForward":false}`,
		`{"type":"tabs","tabs":[{"active":true,"url":"https://example.test/&x","title":"T","canGoBack":false}]}`,
		`{"type":"presentation","role":"primary","requested":{"width":400,"height":300},"applied":{"kind":"browser-window","coordinateSpace":"display-pixels","generation":"11111111-1111-4111-8111-111111111111","width":800,"height":600,"originX":0,"originY":0,"deviceScaleFactor":2,"cursorIncluded":false},"private":"x"}`,
		`{"type":"presentation","role":"secondary","requested":{"width":400,"height":300},"error":"viewport_unavailable"}`,
		`{"type":"pointer","pageGeneration":"p","source":"agent","eventType":"move","x":20.5,"y":30.25,"buttons":0,"modifiers":0,"timestamp":1727600000123.5,"ts":912345678,"coordinateSpace":"display-pixels","surfaceGeneration":"11111111-1111-4111-8111-111111111111"}`,
		`{"type":"pointer","pageGeneration":"p","eventType":"reset","timestamp":14}`,
		`{"type":"activity","pageGeneration":"p","source":"human","kind":"typing","timestamp":1e21}`,
		`{"type":"cursor","ts":912345678,"serial":17,"css":"text"}`,
		`{"type":"cursor","ts":912345678,"serial":18,"image":` + image + `}`,
		`{"type":"files","ts":1234567,"path":"x"}`,
	} {
		projected, _, kind := projectRecord([]byte(input))
		if kind != recordVisual {
			t.Fatalf("refused %s", input)
		}
		again, _, kind := projectRecord(projected)
		if kind != recordVisual || !bytes.Equal(again, projected) {
			t.Fatalf("not idempotent:\n%s\n%s", projected, again)
		}
	}
	for _, terminal := range [][]byte{finishedRecord, unavailableRecord} {
		c := NewChannel(Declaration{Width: 320, Height: 240, FrameWindow: 1})
		d, end := c.Upstream(true, terminal)
		if d == nil || end == nil || !bytes.Equal(d.Text, terminal) {
			t.Fatalf("terminal %s projected to %v %v", terminal, d, end)
		}
	}
}
