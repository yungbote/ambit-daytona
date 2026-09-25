// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"strings"
	"testing"
)

func browserCursorPNG(width, height int) string {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewNRGBA(image.Rect(0, 0, width, height))); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(encoded.Bytes())
}

// The remote pointer's state reaches the viewer as a CSS keyword, or as the
// exact image and hotspot of a page's own cursor, with the capture clock.
func TestBrowserCursorRecordsProjectTheKeywordOrTheImage(t *testing.T) {
	image := `{"hash":"9f8579ba9c44aa01","width":48,"height":48,"hotX":24,"hotY":24,"scale":2,"png":"` + browserCursorPNG(48, 48) + `","private":"secret"}`
	for _, input := range []string{
		`{"type":"cursor","ts":912345678,"serial":17,"css":"text","private":"secret"}`,
		`{"type":"cursor","ts":912345678,"serial":18,"image":` + image + `}`,
		// A viewer that already holds this hash needs only the reference.
		`{"type":"cursor","ts":912345678,"serial":19,"image":{"hash":"9f8579ba9c44aa01","width":48,"height":48,"hotX":24,"hotY":24,"scale":2}}`,
	} {
		projected, sequence, kind := browserViewMessage([]byte(input), false)
		if kind != browserRecordVisual || sequence != 0 || strings.Contains(string(projected), "secret") {
			t.Fatalf("cursor was not projected: %s -> %s", input, projected)
		}
		var value map[string]any
		if json.Unmarshal(projected, &value) != nil || value["type"] != "cursor" || value["ts"] != float64(912345678) || value["serial"] == nil {
			t.Fatalf("cursor identity lost: %s", projected)
		}
	}
	for _, keyword := range browserCursorKeywords {
		input := `{"type":"cursor","ts":1,"serial":1,"css":"` + keyword + `"}`
		if _, _, kind := browserViewMessage([]byte(input), false); kind != browserRecordVisual {
			t.Fatalf("keyword %s refused", keyword)
		}
	}
}

func TestBrowserCursorRecordsRefuseAnythingButOneBoundedIdentity(t *testing.T) {
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
		image(strings.Replace(valid, `"hash":"9f8579ba9c44aa01"`, `"hash":"xyz"`, 1)),
		image(strings.Replace(valid, `"hash":"9f8579ba9c44aa01"`, `"hash":"9f85"`, 1)),
		image(strings.Replace(valid, `"width":48`, `"width":0`, 1)),
		image(strings.Replace(valid, `"width":48`, `"width":257`, 1)),
		image(strings.Replace(valid, `"hotX":24`, `"hotX":48`, 1)),
		image(strings.Replace(valid, `"hotY":24`, `"hotY":-1`, 1)),
		image(strings.Replace(valid, `"scale":2`, `"scale":3`, 1)),
		image(valid + `,"png":"not base64!"`),
		image(valid + `,"png":"` + base64.StdEncoding.EncodeToString([]byte("GIF89a")) + `"`),
		image(valid + `,"png":"` + browserCursorPNG(47, 48) + `"`),
		`{"type":"cursor","ts":1,"serial":1,"css":"text","padding":"` + strings.Repeat("x", browserCursorRecordLimit) + `"}`,
	} {
		if projected, _, kind := browserViewMessage([]byte(input), false); kind != browserRecordDropped || projected != nil {
			t.Fatalf("invalid cursor admitted: %.200s", input)
		}
	}
}
