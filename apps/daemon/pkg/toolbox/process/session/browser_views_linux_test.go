//go:build linux

package session

import "testing"

func TestVisualStreamRejectsCommandsAndNonvisualData(t *testing.T) {
	for _, value := range []string{
		`{"type":"command","command":"secret task input"}`,
		`{"type":"result","data":{"token":"secret"}}`,
		`{"type":"error","message":"secret task input"}`,
		`{"type":"console","text":"secret task input"}`,
		`{"type":"frame","seq":0}`,
		`{"type":"frame","seq":-1}`,
		`{"type":"frame","seq":"3"}`,
		`not json`,
	} {
		if _, _, ok := browserViewMessage([]byte(value)); ok {
			t.Fatalf("forwarded nonvisual or malformed message: %s", value)
		}
	}
	frame := []byte(`{"type":"frame","seq":17,"data":"AA==","metadata":{"deviceWidth":1280,"deviceHeight":720}}`)
	if body, ack, ok := browserViewMessage(frame); !ok || ack != 17 || string(body) != string(frame) {
		t.Fatal("visual frame lost its acknowledgment identity")
	}
	for _, value := range []string{`{"type":"status","connected":false}`, `{"type":"url","url":"https://example.com"}`} {
		if _, ack, ok := browserViewMessage([]byte(value)); !ok || ack != 0 {
			t.Fatalf("visual state was rejected or treated as a frame: %s", value)
		}
	}
}
