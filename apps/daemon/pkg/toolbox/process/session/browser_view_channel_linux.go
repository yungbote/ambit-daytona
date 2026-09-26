// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/daytonaio/daemon/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const browserViewerMessageLimit = 4096
const browserMaximumFrameWindow = 8

// ViewBrowserChannel carries only visual output, painted-frame acknowledgements
// and presentation sizes. The upgrade binds the viewer identity for its
// lifetime, and declares what this viewer draws itself: with cursor=viewer the
// pointer, from pointer samples and cursor records, so the driver may leave it
// out of the frames; with visible=crop frames 1:1 from the top-left cropped to
// their visible window, so the driver may keep the display at a size class
// through a resize. Each holds once every connected viewer says so.
func (s *SessionController) ViewBrowserChannel(c *gin.Context) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		c.Status(http.StatusUpgradeRequired)
		return
	}
	presentation, valid := parseBrowserChannelPresentation(c.Request)
	formats := c.Request.URL.Query()["frames"]
	pointer := c.Request.URL.Query()["cursor"]
	crop := c.Request.URL.Query()["visible"]
	window, windowValid := parseBrowserFrameWindow(c.Request)
	audioCodec, audioValid := parseBrowserAudioDeclaration(c.Request)
	if !valid || !windowValid || !audioValid || len(formats) > 1 || (len(formats) == 1 && formats[0] != "binary") || len(pointer) > 1 || (len(pointer) == 1 && pointer[0] != "viewer") ||
		len(crop) > 1 || (len(crop) == 1 && crop[0] != "crop") {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_view_invalid"})
		return
	}
	selected, ok := s.selectBrowserView(c)
	if !ok {
		return
	}
	binaryFrames := len(formats) == 1
	maxFps := 10
	var headers http.Header
	if presentation != nil {
		maxFps = 60
		headers = http.Header{"X-Ambit-Browser-Viewer": []string{presentation.Viewer}}
	}
	address := fmt.Sprintf("ws://127.0.0.1:%d/?pacing=ack&maxFps=%d&patches=1&frameWindow=%d", selected.port, maxFps, window)
	if presentation != nil {
		address += fmt.Sprintf("&width=%d&height=%d", presentation.Width, presentation.Height)
	}
	if binaryFrames {
		address += "&frames=binary"
	}
	if len(pointer) == 1 {
		address += "&cursor=viewer"
	}
	if len(crop) == 1 {
		address += "&visible=crop"
	}
	if audioCodec != "" {
		address += "&audio=" + audioCodec
	}
	upstream, _, err := (&websocket.Dialer{HandshakeTimeout: browserDriverWriteTimeout}).DialContext(c.Request.Context(), address, headers)
	if err != nil {
		c.Status(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if ended, err := s.browserViewCurrent(*selected); ended || err != nil {
		if ended {
			c.Status(http.StatusNotFound)
		} else {
			browserObservationError(c, err)
		}
		return
	}
	socket, err := util.UpgradeToWebSocket(c.Writer, c.Request)
	if err != nil {
		return
	}
	channel := &browserViewChannel{controller: s, view: *selected, socket: socket, upstream: upstream, binary: binaryFrames, presentation: presentation != nil, pending: browserFrameWindow{limit: window}, audioCodec: audioCodec}
	channel.run(c.Request.Context())
}

func parseBrowserChannelPresentation(request *http.Request) (*browserPresentation, bool) {
	if !validBrowserUUID(request.Header.Get("X-Ambit-Browser-Viewer")) {
		return nil, false
	}
	query := request.URL.Query()
	if !query.Has("width") && !query.Has("height") {
		return nil, true
	}
	return parseBrowserPresentation(request)
}

func parseBrowserFrameWindow(request *http.Request) (int, bool) {
	values := request.URL.Query()["frameWindow"]
	if len(values) == 0 {
		return 1, true
	}
	if len(values) != 1 {
		return 0, false
	}
	window, err := strconv.Atoi(values[0])
	return window, err == nil && window >= 1 && window <= browserMaximumFrameWindow
}

// Reuse the process and listener identities that define the selected view;
// a replacement listener in the same live process cannot inherit this channel.
func (s *SessionController) browserViewCurrent(view browserView) (ended bool, err error) {
	observed, err := s.sessionService.ObserveOwnedProcess(view.SessionID, view.pid)
	if err != nil || observed.StartTime != view.born {
		if browserViewEnded(observed, view.born, err) {
			return true, nil
		}
		return false, err
	}
	held, err := processHoldsSocket(view.pid, view.listener)
	if browserCustodyEnded(err) {
		return true, nil
	}
	return !held && err == nil, err
}

type browserViewChannel struct {
	controller      *SessionController
	view            browserView
	socket          *websocket.Conn
	upstream        *websocket.Conn
	binary          bool
	presentation    bool
	audioCodec      string
	audioOffered    atomic.Bool
	audioEnabled    atomic.Bool
	audioGeneration atomic.Uint64
	// Epoch is owned only by the upstream reader, independently of JPEG state.
	audioEpoch browserAudioEpoch
	delivery   sync.Mutex
	pending    browserFrameWindow
	unanswered atomic.Int32
	closeOnce  sync.Once
	// Only the upstream reader owns the prior frame's geometry and sequence.
	previous browserFrameHeader
}

func (ch *browserViewChannel) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		_ = ch.socket.Close()
		_ = ch.upstream.Close()
		workers.Wait()
	}()
	stop := context.AfterFunc(ctx, func() {
		_ = ch.socket.Close()
		_ = ch.upstream.Close()
	})
	defer stop()
	ch.upstream.SetReadLimit(browserBinaryFrameLimit)
	ch.socket.SetPongHandler(func(string) error { ch.unanswered.Store(0); return nil })
	workers.Add(2)
	go func() { defer workers.Done(); defer cancel(); ch.readViewer() }()
	go func() { defer workers.Done(); ch.watch(ctx) }()
	for {
		kind, message, err := ch.upstream.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				if ended, _ := ch.controller.browserViewCurrent(ch.view); ended {
					ch.close(browserChannelViewEnded, "browser_view_ended")
				} else {
					ch.close(websocket.CloseInternalServerErr, "screencast_failed")
				}
			}
			return
		}
		if kind == websocket.BinaryMessage {
			if ch.audioCodec != "" && browserBinaryMedia(message) {
				if err := ch.deliverAudioPacket(message); err != nil {
					ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_audio")
					return
				}
				continue
			}
			frame, err := parseBrowserBinaryFrame(message)
			if ch.binary && err != nil && ch.previous.Seq == 0 && browserLegacyBinaryFrame(message) {
				ch.close(websocket.CloseUnsupportedData, "browser_view_channel_unsupported")
				return
			}
			if !ch.binary || err != nil {
				ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
				return
			}
			accepted, err := ch.deliverFrame(frame.header.browserFrameHeader, frame.wireSize(), func() error {
				_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
				writer, err := ch.socket.NextWriter(websocket.BinaryMessage)
				if err != nil {
					return err
				}
				writeErr := frame.writeTo(writer)
				closeErr := writer.Close()
				if writeErr != nil {
					return writeErr
				}
				return closeErr
			})
			if !accepted {
				ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
			}
			if !accepted || err != nil {
				return
			}
			continue
		}
		var envelope struct {
			Type    string          `json:"type"`
			Surface json.RawMessage `json:"surface"`
		}
		if kind != websocket.TextMessage || !utf8.Valid(message) || json.Unmarshal(message, &envelope) != nil {
			ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
			return
		}
		if envelope.Type == "audio" {
			if err := ch.deliverAudioMetadata(message); err != nil {
				ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_audio")
				return
			}
			continue
		}
		projected, sequence, record := browserViewMessage(message, true)
		switch record {
		case browserRecordDropped:
			if envelope.Type == "frame" {
				ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
				return
			}
			continue
		case browserRecordFinished:
			_ = ch.writeText(bytes.TrimSpace(browserFinishedRecord))
			ch.close(browserChannelViewEnded, "browser_view_ended")
			return
		case browserRecordFailed:
			_ = ch.writeText(bytes.TrimSpace(browserUnavailableRecord))
			ch.close(websocket.CloseInternalServerErr, "screencast_failed")
			return
		}
		if sequence != 0 {
			var frame browserFrameHeader
			if ch.previous.Seq == 0 && (ch.binary || envelope.Surface == nil) && browserTextFrameHasJPEG(projected) {
				ch.close(websocket.CloseUnsupportedData, "browser_view_channel_unsupported")
				return
			}
			if ch.binary || json.Unmarshal(projected, &frame) != nil {
				ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
				return
			}
			accepted, err := ch.deliverFrame(frame, len(projected), func() error { return ch.writeText(projected) })
			if !accepted {
				ch.close(websocket.CloseInternalServerErr, "browser_view_invalid_frame")
			}
			if !accepted || err != nil {
				return
			}
			continue
		}
		if ch.writeText(projected) != nil {
			return
		}
	}
}

// ACK credit cannot be consumed until the frame's WebSocket write completes.
// Waiting for completion also avoids rejecting a legitimate fast peer's ACK.
func (ch *browserViewChannel) deliverFrame(frame browserFrameHeader, size int, write func() error) (bool, error) {
	ch.delivery.Lock()
	defer ch.delivery.Unlock()
	if !ch.acceptFrame(frame, size) {
		return false, nil
	}
	err := write()
	if err != nil {
		// A failed write cannot release usable credit for an undelivered frame.
		// Close the upstream before allowing a waiting ACK to proceed.
		ch.close(websocket.CloseInternalServerErr, "screencast_failed")
	}
	return true, err
}

func (ch *browserViewChannel) acknowledgeFrame(sequence uint64) (forward, valid bool) {
	ch.delivery.Lock()
	defer ch.delivery.Unlock()
	return ch.pending.acknowledge(sequence)
}

func (ch *browserViewChannel) acceptFrame(frame browserFrameHeader, bytes int) bool {
	if !frame.Surface.valid() || frame.Seq <= ch.previous.Seq || (frame.BaseSeq != 0 &&
		(frame.BaseSeq != ch.previous.Seq || frame.Surface.Generation != ch.previous.Surface.Generation ||
			frame.Surface.Width != ch.previous.Surface.Width || frame.Surface.Height != ch.previous.Surface.Height)) {
		return false
	}
	if !ch.pending.reserve(frame.Seq, bytes) {
		return false
	}
	ch.previous = frame
	return true
}

// Only sequence and byte counts are retained after a write, never JPEG payloads.
// The small negotiated window hides network RTT without an unbounded frame queue.
type browserFrameWindow struct {
	mu           sync.Mutex
	limit        int
	bytes        int
	acknowledged uint64
	frames       []browserSentFrame
}

type browserSentFrame struct {
	sequence uint64
	bytes    int
}

func (w *browserFrameWindow) reserve(sequence uint64, bytes int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.frames) >= w.limit || bytes <= 0 || bytes > browserBinaryFrameLimit-w.bytes {
		return false
	}
	w.frames = append(w.frames, browserSentFrame{sequence, bytes})
	w.bytes += bytes
	return true
}

// A painted sequence cumulatively acknowledges only a prefix ending at an
// actually sent frame. A stale duplicate is harmless and is not sent upstream.
func (w *browserFrameWindow) acknowledge(sequence uint64) (forward, valid bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if sequence <= w.acknowledged {
		return false, true
	}
	for index, frame := range w.frames {
		if frame.sequence != sequence {
			continue
		}
		for _, acknowledged := range w.frames[:index+1] {
			w.bytes -= acknowledged.bytes
		}
		w.frames = w.frames[:copy(w.frames, w.frames[index+1:])]
		w.acknowledged = sequence
		return true, true
	}
	return false, false
}

func (ch *browserViewChannel) writeText(message []byte) error {
	_ = ch.socket.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
	return ch.socket.WriteMessage(websocket.TextMessage, message)
}

// The two accepted messages have separate closed schemas. In particular a
// presentation update cannot include a viewer identity, input or a CDP command.
func browserViewerMessage(message []byte) (projected []byte, ack uint64, valid bool) {
	if len(message) > browserViewerMessageLimit || !utf8.Valid(message) {
		return nil, 0, false
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(message, &envelope) != nil {
		return nil, 0, false
	}
	decode := func(value any) bool {
		decoder := json.NewDecoder(bytes.NewReader(message))
		decoder.DisallowUnknownFields()
		return decoder.Decode(value) == nil && decoder.Decode(new(any)) == io.EOF
	}
	switch envelope.Type {
	case "audio":
		var value struct {
			Type       string `json:"type"`
			Enabled    *bool  `json:"enabled"`
			Generation uint64 `json:"generation"`
		}
		if !decode(&value) || value.Enabled == nil || value.Generation == 0 || value.Generation > browserSafeInteger {
			return nil, 0, false
		}
		projected, _ = json.Marshal(value)
		return projected, 0, true
	case "ack":
		var value struct {
			Type string `json:"type"`
			Seq  uint64 `json:"seq"`
		}
		if !decode(&value) || value.Seq == 0 {
			return nil, 0, false
		}
		projected, _ = json.Marshal(value)
		return projected, value.Seq, true
	case "presentation":
		var value struct {
			Type   string `json:"type"`
			Width  uint32 `json:"width"`
			Height uint32 `json:"height"`
		}
		if !decode(&value) || value.Width == 0 || value.Width > 2048 || value.Height == 0 || value.Height > 2048 {
			return nil, 0, false
		}
		projected, _ = json.Marshal(value)
		return projected, 0, true
	}
	return nil, 0, false
}

func (ch *browserViewChannel) readViewer() {
	for {
		kind, reader, err := ch.socket.NextReader()
		if err != nil {
			return
		}
		if kind != websocket.TextMessage {
			ch.close(websocket.ClosePolicyViolation, "frame_not_text")
			return
		}
		message, err := io.ReadAll(io.LimitReader(reader, browserViewerMessageLimit+1))
		if err != nil {
			return
		}
		projected, ack, valid := browserViewerMessage(message)
		var output struct {
			Type       string `json:"type"`
			Enabled    bool   `json:"enabled"`
			Generation uint64 `json:"generation"`
		}
		if valid {
			_ = json.Unmarshal(projected, &output)
		}
		isAudio := output.Type == "audio"
		if !valid || (isAudio && !ch.audioOffered.Load()) || (!isAudio && ack == 0 && !ch.presentation) {
			ch.close(websocket.ClosePolicyViolation, "browser_view_invalid_message")
			return
		}
		if isAudio {
			if output.Generation <= ch.audioGeneration.Load() {
				continue
			}
			ch.audioGeneration.Store(output.Generation)
			ch.audioEnabled.Store(output.Enabled)
		}
		if ack != 0 {
			forward, valid := ch.acknowledgeFrame(ack)
			if !valid {
				ch.close(websocket.ClosePolicyViolation, "browser_view_invalid_message")
				return
			}
			if !forward {
				continue
			}
		}
		_ = ch.upstream.SetWriteDeadline(time.Now().Add(browserDriverWriteTimeout))
		if ch.upstream.WriteMessage(websocket.TextMessage, projected) != nil {
			ch.close(websocket.CloseInternalServerErr, "screencast_failed")
			return
		}
	}
}

func (ch *browserViewChannel) watch(ctx context.Context) {
	custody := time.NewTicker(browserCustodyInterval)
	defer custody.Stop()
	pings := time.NewTicker(ch.controller.browserPingInterval)
	defer pings.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-custody.C:
			ended, err := ch.controller.browserViewCurrent(ch.view)
			if ended {
				ch.close(browserChannelViewEnded, "browser_view_ended")
				return
			}
			if err != nil {
				ch.close(websocket.CloseInternalServerErr, "browser_view_unobservable")
				return
			}
		case <-pings.C:
			if int(ch.unanswered.Add(1)) > browserChannelUnansweredPings {
				_ = ch.socket.Close()
				return
			}
			if ch.socket.WriteControl(websocket.PingMessage, nil, time.Now().Add(browserChannelControlTimeout)) != nil {
				_ = ch.socket.Close()
				return
			}
		}
	}
}

func (ch *browserViewChannel) close(code int, reason string) {
	ch.closeOnce.Do(func() {
		_ = ch.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(browserChannelControlTimeout))
		_ = ch.socket.Close()
		_ = ch.upstream.Close()
	})
}
