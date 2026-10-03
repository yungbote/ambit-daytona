// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// The page's messages, as the backend relay reads them
// (browser-view-channel.spec.ts) and the toolbox then does
// (browser_frames_linux_test.go, browser_video_linux_test.go,
// browser_audio_linux_test.go).

func TestViewerMessagesHaveClosedSchemas(t *testing.T) {
	const stream = "fe6a33c7-cc88-4b79-a1a3-e665da233873"
	// Each valid message leaves in the one canonical text both hops write.
	for input, canonical := range map[string]string{
		`{"type":"ack","seq":10}`:                                            `{"type":"ack","seq":10}`,
		`{"seq":10,"type":"ack"}`:                                            `{"type":"ack","seq":10}`,
		`{"type":"presentation","width":1,"height":2048}`:                    `{"type":"presentation","width":1,"height":2048}`,
		`{"type":"audio","enabled":true,"generation":1}`:                     `{"type":"audio","enabled":true,"generation":1}`,
		`{"type":"audio","enabled":false,"generation":2}`:                    `{"type":"audio","enabled":false,"generation":2}`,
		`{"type":"video","enabled":true,"generation":1}`:                     `{"type":"video","enabled":true,"generation":1}`,
		`{"type":"video","keyframe":true,"generation":2}`:                    `{"type":"video","keyframe":true,"generation":2}`,
		`{"type":"ack","track":"video","streamId":"` + stream + `","seq":9}`: `{"type":"ack","track":"video","streamId":"` + stream + `","seq":9}`,
		// JavaScript reads these numbers as the integers they denote.
		`{"type":"ack","seq":1.0}`:                       `{"type":"ack","seq":1}`,
		`{"type":"ack","seq":1e3}`:                       `{"type":"ack","seq":1000}`,
		`{"type":"ack","seq":9007199254740991}`:          `{"type":"ack","seq":9007199254740991}`,
		"\xef\xbb\xbf{\"type\":\"ack\",\"seq\":5}":       `{"type":"ack","seq":5}`,
		`{"type":"ack","seq":5,"seq":6}`:                 `{"type":"ack","seq":6}`,
		` {"type":"presentation","width":7,"height":8} `: `{"type":"presentation","width":7,"height":8}`,
	} {
		m, valid := parseViewerMessage([]byte(input))
		if !valid || string(m.encode()) != canonical {
			t.Fatalf("%s: valid=%v encoded %s, want %s", input, valid, m.encode(), canonical)
		}
	}
	for _, input := range []string{
		`null`, `[]`, `{`, `"ack"`, `{"type":"ack","seq":0}`, `{"type":"ack","seq":1.5}`, `{"type":"ack","seq":-1}`, `{"type":"ack","seq":-0}`,
		`{"type":"ack","seq":"1"}`, `{"type":"ack","seq":9007199254740992}`, `{"type":"ack","seq":1e400}`, `{"type":"ack","seq":10,"width":null}`,
		`{"type":"presentation","width":0,"height":1}`, `{"type":"presentation","width":2049,"height":1}`,
		`{"type":"presentation","width":1,"height":1,"viewerId":"changed"}`, `{"type":"presentation","width":1,"height":1,"seq":10}`,
		`{"type":"input","events":[]}`, `{"type":"cdp","method":"Runtime.evaluate"}`, `{"type":"ack","seq":1}{}`,
		strings.Repeat(" ", MaxViewerMessageBytes+1), "\xff",
		`{"type":"audio"}`, `{"type":"audio","enabled":"true"}`, `{"type":"audio","enabled":true,"controllerId":"foreign"}`,
		`{"type":"audio","enabled":true,"generation":0}`,
		`{"type":"video"}`, `{"type":"video","enabled":true}`, `{"type":"video","enabled":"true","generation":1}`, `{"type":"video","enabled":true,"generation":0}`,
		`{"type":"video","keyframe":false,"generation":1}`, `{"type":"video","keyframe":true,"enabled":true,"generation":1}`,
		`{"type":"video","enabled":true,"generation":1,"controllerId":"foreign"}`, `{"type":"video","enabled":true,"generation":1,"seq":2}`,
		`{"type":"ack","track":"audio","streamId":"` + stream + `","seq":1}`, `{"type":"ack","track":"video","streamId":"other/session","seq":1}`,
		`{"type":"ack","track":"video","streamId":"` + stream + `","seq":0}`, `{"type":"ack","track":"video","seq":1}`,
		`{"type":"ack","track":"video","streamId":"` + stream + `","seq":1,"generation":1}`,
		`{"type":"ack","track":"video","streamId":"00000000-0000-0000-0000-000000000000","seq":1}`,
		`{"type":"ack","track":"video","streamId":"` + strings.ToUpper(stream) + `","seq":1}`,
		`{"type":"grant","token":"x"}`,
	} {
		if _, valid := parseViewerMessage([]byte(input)); valid {
			t.Fatalf("invalid message admitted: %.80s", input)
		}
	}
}

func TestDeclarationsAsTheBackendUpgradeReadsThem(t *testing.T) {
	parse := func(query string) (Declaration, error) {
		values, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		return ParseDeclaration(values)
	}
	base := "frames=binary&patches=1"
	for query, want := range map[string]Declaration{
		base: {FrameWindow: 1},
		base + "&video=av1-444&videoCapacity=coded": {FrameWindow: 1, Video: []string{"av1-444"}, VideoCapacity: true},
		base + "&frameWindow=8&width=734&height=910&cursor=viewer&visible=crop&audio=opus&video=av1-444,av1,vp9": {
			Width: 734, Height: 910, FrameWindow: 8, Cursor: true, Crop: true, Audio: "opus", Video: []string{"av1-444", "av1", "vp9"}},
		base + "&width=2048&height=1":             {Width: 2048, Height: 1, FrameWindow: 1},
		base + "&audio=pcm-s16le":                 {FrameWindow: 1, Audio: "pcm-s16le"},
		base + "&video=vp9-444,av1-444,vp9,av1":   {FrameWindow: 1, Video: []string{"vp9-444", "av1-444", "vp9", "av1"}},
		base + "&frames=other&patches=0":          {FrameWindow: 1},
		base + "&width=320&width=9999&height=240": {Width: 320, Height: 240, FrameWindow: 1},
		base + "&cursor=viewer&cursor=other":      {FrameWindow: 1, Cursor: true},
		base + "&tenantId=t&viewerId=v&unknown=1": {FrameWindow: 1},
	} {
		got, err := parse(query)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v %v, want %+v", query, got, err, want)
		}
	}
	for _, query := range []string{
		"", "patches=1", "frames=binary", "frames=other&patches=1", "frames=binary&patches=0",
		base + "&frameWindow=0", base + "&frameWindow=9", base + "&frameWindow=08", base + "&frameWindow=",
		base + "&width=320", base + "&height=240", base + "&width=0&height=240", base + "&width=2049&height=100",
		base + "&width=0320&height=240", base + "&width=320&height=", base + "&width=1e3&height=5", base + "&width=99999999999999999999&height=5",
		base + "&cursor=hidden", base + "&cursor=", base + "&visible=scale", base + "&visible=",
		base + "&audio=", base + "&audio=OPUS", base + "&audio=pcm", base + "&audio=opus&audio=opus",
		base + "&video=", base + "&video=h264", base + "&video=av1,av1", base + "&video=AV1", base + "&video=av1,",
		base + "&video=av1%20,vp9", base + "&video=av1&video=vp9", base + "&video=" + strings.Repeat("av1,", 16) + "vp9",
		base + "&videoCapacity=coded", base + "&video=av1&videoCapacity=", base + "&video=av1&videoCapacity=other", base + "&video=av1&videoCapacity=coded&videoCapacity=coded",
	} {
		if _, err := parse(query); err == nil {
			t.Fatalf("accepted %q", query)
		}
	}
}

// The view route receives the declaration exactly as the backend's provider
// writes it (URLSearchParams.set in the provider's order).
func TestDeclarationQueryIsTheBackendDial(t *testing.T) {
	for want, d := range map[string]Declaration{
		"frameWindow=1&frames=binary&patches=1":                                   {FrameWindow: 1},
		"frameWindow=1&frames=binary&patches=1&video=av1-444&videoCapacity=coded": {FrameWindow: 1, Video: []string{"av1-444"}, VideoCapacity: true},
		"frameWindow=8&frames=binary&patches=1&width=734&height=910&cursor=viewer&visible=crop&audio=pcm-s16le&video=av1-444%2Cav1": {
			Width: 734, Height: 910, FrameWindow: 8, Cursor: true, Crop: true, Audio: "pcm-s16le", Video: []string{"av1-444", "av1"}},
		"frameWindow=3&frames=binary&patches=1&cursor=viewer": {FrameWindow: 3, Cursor: true},
	} {
		if got := d.Query(); got != want {
			t.Fatalf("query %s, want %s", got, want)
		}
		values, _ := url.ParseQuery(d.Query())
		if again, err := ParseDeclaration(values); err != nil || !reflect.DeepEqual(again, d) {
			t.Fatalf("the dial does not read back: %+v %v", again, err)
		}
	}
}
