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

// The toolbox's channel journeys (browser_view_channel_linux_test.go and the
// video and audio channel tests), played against the protocol directly: the
// driver's messages go in through Upstream, the page's through Viewer.

type script struct {
	t *testing.T
	c *Channel
}

func newScript(t *testing.T, d Declaration) script { return script{t, NewChannel(d)} }

func presenting() Declaration { return Declaration{Width: 320, Height: 240, FrameWindow: 1} }

func (s script) deliver(text bool, message []byte) map[string]any {
	s.t.Helper()
	d, end := s.c.Upstream(text, message)
	if d == nil || end != nil {
		s.t.Fatalf("not delivered: %v %v: %.120s", d, end, message)
	}
	if bytes.Contains(wire(d), []byte(fixtureSecret)) {
		s.t.Fatal("private metadata reached the viewer")
	}
	if d.Kind != Record {
		return nil
	}
	var value map[string]any
	if json.Unmarshal(d.Text, &value) != nil {
		s.t.Fatalf("record is not JSON: %s", d.Text)
	}
	return value
}

func (s script) record(fields map[string]any) map[string]any {
	s.t.Helper()
	return s.deliver(true, jsonOf(fields))
}

func (s script) drop(text bool, message []byte) {
	s.t.Helper()
	if d, end := s.c.Upstream(text, message); d != nil || end != nil {
		s.t.Fatalf("delivered what must be dropped: %v %v", d, end)
	}
}

func (s script) end(text bool, message []byte, code int, reason string) *Delivery {
	s.t.Helper()
	d, end := s.c.Upstream(text, message)
	if end == nil || end.Code != code || end.Reason != reason {
		s.t.Fatalf("close %v, want %d %s", end, code, reason)
	}
	return d
}

func (s script) forward(message string, slot Slot) {
	s.t.Helper()
	f, end := s.c.Viewer(true, []byte(message))
	if f == nil || end != nil || f.Slot != slot {
		s.t.Fatalf("%s not forwarded: %v %v", message, f, end)
	}
}

func (s script) ignore(message string) {
	s.t.Helper()
	if f, end := s.c.Viewer(true, []byte(message)); f != nil || end != nil {
		s.t.Fatalf("%s: %v %v", message, f, end)
	}
}

func (s script) refuse(text bool, message string) {
	s.t.Helper()
	if _, end := s.c.Viewer(text, []byte(message)); end == nil || end.Code != 1008 || end.Reason != "browser_view_invalid_message" {
		s.t.Fatalf("%.60s was not refused: %v", message, end)
	}
}

func TestChannelWaitsForPaintAndFinishes(t *testing.T) {
	s := newScript(t, presenting())
	if status := s.record(map[string]any{"type": "status", "connected": true, "screencasting": true, "private": fixtureSecret}); len(status) != 3 {
		t.Fatalf("status %v", status)
	}
	s.drop(true, jsonOf(map[string]any{"type": "console", "text": fixtureSecret}))
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"presentation","width":400,"height":300}`, SlotPresentation)
	presentation := s.record(map[string]any{"type": "presentation", "role": "primary", "requested": map[string]any{"width": 400, "height": 300}, "applied": fixtureSurface(), "private": fixtureSecret})
	if presentation["requested"].(map[string]any)["width"] != float64(400) {
		t.Fatalf("presentation: %v", presentation)
	}
	// The window holds one frame until it is painted.
	s.end(false, frameAt(12, 10), 1011, "browser_view_invalid_frame")
	s = newScript(t, presenting())
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
	s.deliver(false, frameAt(12, 10))
	s.forward(`{"type":"ack","seq":12}`, SlotFrameAck)
	finished := s.end(true, jsonOf(map[string]any{"type": "finished", "private": fixtureSecret}), 4410, "browser_view_ended")
	if finished == nil || string(finished.Text) != `{"type":"finished"}` {
		t.Fatalf("terminal projection: %v", finished)
	}
}

func TestChannelObserverHasNoPresentationAuthority(t *testing.T) {
	s := newScript(t, Declaration{FrameWindow: 8})
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
	s.deliver(false, frameAt(12, 10))
	s.refuse(true, `{"type":"presentation","width":400,"height":300}`)
}

func TestChannelRelaysDoorbellsAndCursors(t *testing.T) {
	s := newScript(t, Declaration{Width: 320, Height: 240, FrameWindow: 1, Cursor: true})
	if doorbell := s.record(map[string]any{"type": "files", "ts": 1234567, "path": fixtureSecret}); len(doorbell) != 2 || doorbell["ts"] != float64(1234567) {
		t.Fatalf("files doorbell: %v", doorbell)
	}
	s.drop(true, jsonOf(map[string]any{"type": "files"}))
	if cursor := s.record(map[string]any{"type": "cursor", "ts": 1234568, "serial": 17, "css": "text", "private": fixtureSecret}); len(cursor) != 4 || cursor["css"] != "text" {
		t.Fatalf("cursor record: %v", cursor)
	}
	s.deliver(false, frameAt(10, 0))
}

func TestChannelFallsBackOnlyForValidInitialOldFrames(t *testing.T) {
	textFrame := func(surface, jpeg bool) []byte {
		header, payload := fixtureFrame(false)
		delete(header, "byteLength")
		header["data"] = base64.StdEncoding.EncodeToString(payload)
		if !surface {
			delete(header, "surface")
		}
		if !jpeg {
			header["data"] = "not-a-jpeg"
		}
		return jsonOf(header)
	}
	legacyBinary := func(seq int, valid bool) []byte {
		header, payload := fixtureFrame(false)
		header["seq"] = seq
		delete(header, "surface")
		header["metadata"] = map[string]any{"deviceWidth": 640, "deviceHeight": 480}
		if !valid {
			payload[len(payload)-1] = 0
		}
		return pack(header, payload)
	}
	newScript(t, presenting()).end(true, textFrame(false, true), 1003, "browser_view_channel_unsupported")
	newScript(t, presenting()).end(true, textFrame(true, true), 1003, "browser_view_channel_unsupported")
	newScript(t, presenting()).end(true, textFrame(true, false), 1011, "browser_view_invalid_frame")
	newScript(t, presenting()).end(false, legacyBinary(10, true), 1003, "browser_view_channel_unsupported")
	newScript(t, presenting()).end(false, legacyBinary(10, false), 1011, "browser_view_invalid_frame")
	// After a native frame, an old frame is not a capability to fall back to.
	for _, old := range [][]byte{legacyBinary(12, true), textFrame(true, true)} {
		s := newScript(t, presenting())
		s.deliver(false, frameAt(10, 0))
		s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
		s.end(!bytes.HasPrefix(old, []byte{0}), old, 1011, "browser_view_invalid_frame")
	}
}

func TestChannelRejectsClientControlAndBadAcknowledgements(t *testing.T) {
	for _, message := range []string{`{`, `{"type":"ack","seq":9}`, `{"type":"ack","seq":11}`, `{"type":"input","events":[]}`, `{"type":"cdp","method":"Runtime.evaluate"}`,
		`{"type":"presentation","width":400,"height":300,"viewer":"changed"}`, `{"type":"presentation","width":2049,"height":300}`, strings.Repeat(" ", MaxViewerMessageBytes+1),
		`{"type":"audio","enabled":true,"generation":1}`, `{"type":"video","enabled":true,"generation":1}`, `{"type":"video","keyframe":true,"generation":1}`,
		`{"type":"ack","track":"video","streamId":"` + videoEpoch + `","seq":1}`} {
		s := newScript(t, presenting())
		s.deliver(false, frameAt(10, 0))
		s.refuse(true, message)
	}
	s := newScript(t, presenting())
	s.deliver(false, frameAt(10, 0))
	s.refuse(false, `{"type":"ack","seq":10}`)
	s = newScript(t, presenting())
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
	s.deliver(false, frameAt(12, 10))
	s.ignore(`{"type":"ack","seq":10}`)
	s.forward(`{"type":"presentation","width":400,"height":300}`, SlotPresentation)
}

func TestChannelClosesOnInvalidFramesAndReportsDriverFailures(t *testing.T) {
	header, payload := fixtureFrame(false)
	header["byteLength"] = len(payload) + 1
	newScript(t, presenting()).end(false, pack(header, payload), 1011, "browser_view_invalid_frame")
	s := newScript(t, presenting())
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
	s.end(false, frameAt(12, 9), 1011, "browser_view_invalid_frame")
	failure := newScript(t, presenting()).end(true, jsonOf(map[string]any{"type": "error", "message": fixtureSecret}), 1011, "screencast_failed")
	if failure == nil || string(failure.Text) != `{"type":"unavailable","reason":"screencast_failed"}` {
		t.Fatalf("failure: %v", failure)
	}
	// A frame record that is not a frame, and text that is not JSON, end it.
	newScript(t, presenting()).end(true, []byte(`{"type":"frame","seq":0}`), 1011, "browser_view_invalid_frame")
	newScript(t, presenting()).end(true, []byte("not json"), 1011, "browser_view_invalid_frame")
	newScript(t, presenting()).end(true, []byte("{\"type\":\"status\",\"engine\":\"\xff\"}"), 1011, "browser_view_invalid_frame")
	// Media nobody negotiated is not a frame either.
	newScript(t, presenting()).end(false, videoUnit(videoEpoch, 1, true), 1011, "browser_view_invalid_frame")
	newScript(t, presenting()).end(true, jsonOf(map[string]any{"type": "video", "state": "available", "codec": "av1"}), 1011, "browser_view_invalid_video")
	newScript(t, presenting()).end(true, jsonOf(map[string]any{"type": "audio", "state": "available", "codec": "opus"}), 1011, "browser_view_invalid_audio")
}

// The backend relay bounds what reaches the page as metadata.
func TestChannelBoundsRecordsAsThePageDoes(t *testing.T) {
	url := "https://example.test/" + strings.Repeat("a", MaxRecordBytes-60)
	s := newScript(t, presenting())
	if location := s.record(map[string]any{"type": "url", "url": url}); location["url"] != url {
		t.Fatal("a record within the bound was not delivered")
	}
	// HTML-significant characters grow sixfold when projected.
	s.end(true, jsonOf(map[string]any{"type": "url", "url": strings.Repeat("&", MaxRecordBytes/6+1)}), 1011, "browser_view_unavailable")
}

func TestChannelUsesTheBoundedWindowAndCumulativePaintACK(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		s := newScript(t, Declaration{Width: 320, Height: 240, FrameWindow: 8})
		s.deliver(false, frameAt(10, 0))
		for seq := 12; seq <= 24; seq += 2 {
			s.deliver(false, frameAt(seq, seq-2))
		}
		if overflow {
			s.end(false, frameAt(26, 24), 1011, "browser_view_invalid_frame")
			continue
		}
		// One acknowledgement releases the first five; the next delta keeps its exact base.
		s.forward(`{"type":"ack","seq":18}`, SlotFrameAck)
		s.deliver(false, frameAt(26, 24))
		s.forward(`{"type":"ack","seq":26}`, SlotFrameAck)
		s.end(true, []byte(`{"type":"finished"}`), 4410, "browser_view_ended")
	}
}

func (s script) offerVideo() {
	s.t.Helper()
	if offer := s.record(map[string]any{"type": "video", "state": "available", "codec": "av1", "private": fixtureSecret}); len(offer) != 3 || offer["codec"] != "av1" {
		s.t.Fatalf("bad offer %v", offer)
	}
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
	s.forward(`{"type":"video","enabled":true,"generation":1}`, SlotVideo)
	started := s.record(map[string]any{"type": "video", "state": "started", "generation": 1, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoEpoch, "private": fixtureSecret})
	if started["streamId"] != videoEpoch || started["codecString"] != "av01.0.12M.08" {
		s.t.Fatalf("bad start %v", started)
	}
	s.deliver(false, videoUnit(videoEpoch, 1, true))
}

func videoDeclaration() Declaration {
	return Declaration{Width: 320, Height: 240, FrameWindow: 1, Video: []string{"av1-444", "av1"}}
}

func TestChannelVideoReplacesFramesAndReturnsToThem(t *testing.T) {
	s := newScript(t, videoDeclaration())
	s.offerVideo()
	s.deliver(false, videoUnit(videoEpoch, 2, false))
	// A retired stream's and a duplicate acknowledgement are dropped; the
	// driver receives exactly the painted prefix.
	s.ignore(`{"type":"ack","track":"video","streamId":"` + videoNextEpoch + `","seq":1}`)
	s.forward(`{"type":"ack","track":"video","streamId":"`+videoEpoch+`","seq":2}`, SlotVideoAck)
	s.ignore(`{"type":"ack","track":"video","streamId":"` + videoEpoch + `","seq":1}`)
	s.forward(`{"type":"video","keyframe":true,"generation":1}`, SlotKeyframe)
	s.deliver(false, videoUnit(videoEpoch, 3, true))
	s.forward(`{"type":"video","enabled":false,"generation":2}`, SlotVideo)
	if stopped := s.record(map[string]any{"type": "video", "state": "stopped", "generation": 2, "codec": "av1"}); stopped["state"] != "stopped" {
		t.Fatalf("not stopped: %v", stopped)
	}
	// A keyframe request for a fallen-back subscription repairs nothing.
	s.ignore(`{"type":"video","keyframe":true,"generation":2}`)
	s.deliver(false, frameAt(12, 0))
}

func TestChannelVideoResubscriptionDiscardsTheRetiredStream(t *testing.T) {
	s := newScript(t, videoDeclaration())
	s.offerVideo()
	s.deliver(false, videoUnit(videoEpoch, 2, false))
	s.forward(`{"type":"ack","track":"video","streamId":"`+videoEpoch+`","seq":2}`, SlotVideoAck)
	s.forward(`{"type":"video","enabled":false,"generation":2}`, SlotVideo)
	s.forward(`{"type":"video","enabled":true,"generation":3}`, SlotVideo)
	s.ignore(`{"type":"video","enabled":true,"generation":3}`)
	// What the old subscription still had in flight never reaches the viewer.
	s.drop(false, videoUnit(videoEpoch, 3, false))
	s.drop(true, jsonOf(map[string]any{"type": "video", "state": "stopped", "codec": "av1", "generation": 2}))
	started := s.record(map[string]any{"type": "video", "state": "started", "codec": "av1", "codecString": "av01.0.12M.08", "generation": 3, "streamId": videoNextEpoch})
	if started["streamId"] != videoNextEpoch {
		t.Fatalf("retired record leaked: %v", started)
	}
	s.deliver(false, videoUnit(videoNextEpoch, 1, true))
	// A start for a generation the viewer retired while it was queued is dropped.
	s.forward(`{"type":"video","enabled":false,"generation":4}`, SlotVideo)
	s.drop(true, jsonOf(map[string]any{"type": "video", "state": "started", "codec": "av1", "codecString": "av01.0.12M.08", "generation": 3, "streamId": videoEpoch}))
}

func TestChannelVideoNeverSkipsAPicture(t *testing.T) {
	for name, next := range map[string][]byte{
		"a gap":                  videoUnit(videoEpoch, 3, false),
		"a repeat":               videoUnit(videoEpoch, 1, true),
		"a clock that runs back": func() []byte { h := videoHeaderFixture(2, false, 64); h["ts"] = 1; return pack(h, make([]byte, 64)) }(),
		"a coded size without a key picture": func() []byte {
			h := videoHeaderFixture(2, false, 64)
			h["coded"] = map[string]any{"width": 1024, "height": 2048}
			h["visible"] = map[string]any{"x": 0, "y": 0, "width": 1000, "height": 1888}
			return pack(h, make([]byte, 64))
		}(),
		"another codec": func() []byte {
			h := videoHeaderFixture(2, false, 64)
			h["codec"] = "av1-444"
			return pack(h, make([]byte, 64))
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			s := newScript(t, videoDeclaration())
			s.offerVideo()
			s.end(false, next, 1011, "browser_view_invalid_video")
		})
	}
	// The first picture of a stream needs no other.
	s := newScript(t, videoDeclaration())
	s.record(map[string]any{"type": "video", "state": "available", "codec": "av1"})
	s.forward(`{"type":"video","enabled":true,"generation":1}`, SlotVideo)
	s.record(map[string]any{"type": "video", "state": "started", "generation": 1, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoEpoch})
	s.end(false, videoUnit(videoEpoch, 1, false), 1011, "browser_view_invalid_video")
	// The offer may not change codec, nor name one the viewer did not declare.
	s = newScript(t, videoDeclaration())
	s.record(map[string]any{"type": "video", "state": "available", "codec": "av1"})
	s.end(true, jsonOf(map[string]any{"type": "video", "state": "available", "codec": "av1-444"}), 1011, "browser_view_invalid_video")
	newScript(t, videoDeclaration()).end(true, jsonOf(map[string]any{"type": "video", "state": "available", "codec": "vp9"}), 1011, "browser_view_invalid_video")
	// A start before any offer is invalid.
	s = newScript(t, videoDeclaration())
	s.end(true, jsonOf(map[string]any{"type": "video", "state": "started", "generation": 0, "codec": "av1", "codecString": "av01.0.12M.08", "streamId": videoEpoch}), 1011, "browser_view_invalid_video")
}

func TestChannelVideoRefusesAnUnofferedSubscriptionAndAFutureAcknowledgement(t *testing.T) {
	s := newScript(t, presenting())
	s.deliver(false, frameAt(10, 0))
	s.refuse(true, `{"type":"video","enabled":true,"generation":1}`)
	s = newScript(t, videoDeclaration())
	s.offerVideo()
	s.deliver(false, videoUnit(videoEpoch, 2, false))
	s.refuse(true, `{"type":"ack","track":"video","streamId":"`+videoEpoch+`","seq":9}`)
}

func (s script) offerAudio() {
	s.t.Helper()
	if offer := s.record(map[string]any{"type": "audio", "state": "available", "codec": "pcm-s16le", "private": fixtureSecret}); len(offer) != 3 {
		s.t.Fatalf("bad offer %v", offer)
	}
	s.deliver(false, frameAt(10, 0))
	s.forward(`{"type":"audio","enabled":true,"generation":1}`, SlotAudio)
	started := s.record(map[string]any{"type": "audio", "state": "started", "generation": 1, "codec": "pcm-s16le", "streamId": audioEpoch, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0, "private": fixtureSecret})
	if started["state"] != "started" {
		s.t.Fatalf("bad start %v", started)
	}
	s.deliver(false, audioPacket(audioEpoch, 1))
	// Sound never consumes the frames' paint credit.
	s.forward(`{"type":"ack","seq":10}`, SlotFrameAck)
}

func TestChannelAudioUsesTheSameChannelWithoutConsumingFrameCredit(t *testing.T) {
	s := newScript(t, Declaration{Width: 320, Height: 240, FrameWindow: 1, Audio: "pcm-s16le"})
	s.offerAudio()
	s.forward(`{"type":"audio","enabled":false,"generation":2}`, SlotAudio)
	// Never queue sound after a mute.
	s.drop(false, audioPacket(audioEpoch, 2))
	if stopped := s.record(map[string]any{"type": "audio", "state": "stopped", "generation": 2, "codec": "pcm-s16le"}); stopped["state"] != "stopped" {
		t.Fatalf("not stopped: %v", stopped)
	}
	s.deliver(false, frameAt(12, 10))
}

func TestChannelAudioMuteUnmuteDiscardsTheOldEpochWithoutClosingPixels(t *testing.T) {
	s := newScript(t, Declaration{Width: 320, Height: 240, FrameWindow: 1, Audio: "pcm-s16le"})
	s.offerAudio()
	s.forward(`{"type":"audio","enabled":false,"generation":2}`, SlotAudio)
	s.forward(`{"type":"audio","enabled":true,"generation":3}`, SlotAudio)
	s.drop(false, audioPacket(audioEpoch, 2))
	s.drop(true, jsonOf(map[string]any{"type": "audio", "state": "stopped", "codec": "pcm-s16le", "generation": 2}))
	started := s.record(map[string]any{"type": "audio", "state": "started", "codec": "pcm-s16le", "generation": 3, "streamId": audioNextEpoch, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0})
	if started["generation"] != float64(3) {
		t.Fatalf("retired metadata leaked %v", started)
	}
	s.deliver(false, audioPacket(audioNextEpoch, 1))
	s.end(false, audioPacket(audioNextEpoch, 3), 1011, "browser_view_invalid_audio")
	s = newScript(t, Declaration{Width: 320, Height: 240, FrameWindow: 1, Audio: "pcm-s16le"})
	s.offerAudio()
	s.deliver(false, frameAt(12, 10))
	// A start before any offer, and another codec, are invalid.
	s = newScript(t, Declaration{FrameWindow: 1, Audio: "opus"})
	s.end(true, jsonOf(map[string]any{"type": "audio", "state": "started", "generation": 0, "codec": "opus", "streamId": audioEpoch, "sampleRate": 48000, "channels": 2, "frameSamples": 480, "primingSamples": 0}), 1011, "browser_view_invalid_audio")
	newScript(t, Declaration{FrameWindow: 1, Audio: "opus"}).end(true, jsonOf(map[string]any{"type": "audio", "state": "available", "codec": "pcm-s16le"}), 1011, "browser_view_invalid_audio")
	// The producer's single unavailable answer at generation 0 reaches the viewer.
	newScript(t, Declaration{FrameWindow: 1, Audio: "opus"}).record(map[string]any{"type": "audio", "state": "unavailable", "codec": "opus", "generation": 0})
}

func TestPendingKeepsTheNewestOfEachSlotInSubscriptionOrder(t *testing.T) {
	p := NewPending()
	if _, ok := p.Next(); ok {
		t.Fatal("an empty mailbox yields nothing")
	}
	put := func(slot Slot, message string) bool { return p.Put(Forward{Slot: slot, Message: []byte(message)}) }
	put(SlotFrameAck, `a1`)
	if !put(SlotFrameAck, `a2`) {
		t.Fatal("a superseded message is reported")
	}
	put(SlotPresentation, `p1`)
	put(SlotPresentation, `p2`)
	put(SlotVideoAck, `v1`)
	put(SlotKeyframe, `k1`)
	put(SlotAudio, `s1`)
	select {
	case <-p.Ready():
	default:
		t.Fatal("a put signals the writer")
	}
	var order []string
	for message, ok := p.Next(); ok; message, ok = p.Next() {
		order = append(order, string(message))
	}
	if strings.Join(order, ",") != "s1,k1,p2,v1,a2" {
		t.Fatalf("order %v", order)
	}
	// A new subscription retires what named the old one.
	put(SlotKeyframe, `k2`)
	put(SlotVideoAck, `v2`)
	put(SlotVideo, `sub`)
	order = nil
	for message, ok := p.Next(); ok; message, ok = p.Next() {
		order = append(order, string(message))
	}
	if strings.Join(order, ",") != "sub" {
		t.Fatalf("after a subscription %v", order)
	}
}
