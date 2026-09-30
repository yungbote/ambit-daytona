// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	wt "github.com/quic-go/webtransport-go"
)

// The compiled worker must recover after a retired reader was emitted with
// none, some or all of its ordinal prefix. The successor is the exact native
// large-picture archive, never a smaller synthetic substitute.
func TestNativeArchiveThroughBuiltWorkerAfterRetiredPart(t *testing.T) {
	script, worker, archivePath, bodyPath := os.Getenv("MEDIA_EDGE_BROWSER_CHUNKS_SCRIPT"), os.Getenv("MEDIA_EDGE_BROWSER_INTEROP_WORKER"), os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_PARTS_FILE"), os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_KEY_FILE")
	if script == "" || worker == "" || archivePath == "" || bodyPath == "" {
		t.Skip("built worker, browser script and immutable native archive/body required")
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	for _, prefixBytes := range []int{0, 8, 17} {
		t.Run(fmt.Sprintf("prefix%d", prefixBytes), func(t *testing.T) {
			var connections atomic.Int32
			_, _, _, address, trust := pairThrough(t, nil, 120*time.Second, func(c *carrier) {
				if connections.Add(1) == 1 {
					return // pair's Go handshake client; only Chrome reads media
				}
				declaration, err := view.ParseDeclaration(url.Values{"frames": {"binary"}, "patches": {"1"}, "video": {"av1-444"}, "videoCapacity": {"coded"}, "videoFraming": {"chunks"}, "audio": {"opus"}})
				if err != nil {
					t.Error(err)
					return
				}
				channel := view.NewChannel(declaration)
				sendRecord := func(text string) bool {
					d, closing := channel.Upstream(true, []byte(text))
					if closing != nil || d == nil {
						t.Errorf("canonical record: %v", closing)
						return false
					}
					return c.Send(d) == nil
				}
				wait := func(wanted func(*view.Forward) bool) bool {
					for {
						text, data, err := c.Receive()
						if err != nil {
							return false
						}
						forward, closing := channel.Viewer(text, data)
						if closing != nil {
							t.Errorf("canonical receipt: %v", closing)
							return false
						}
						if forward != nil && wanted(forward) {
							return true
						}
					}
				}
				if !sendRecord(`{"type":"video","state":"available","codec":"av1-444"}`) ||
					!wait(func(f *view.Forward) bool { return f.Slot == view.SlotVideo }) ||
					!sendRecord(`{"type":"audio","state":"available","codec":"opus"}`) ||
					!wait(func(f *view.Forward) bool { return f.Slot == view.SlotAudio }) {
					return
				}
				archive, err := os.Open(archivePath)
				if err != nil {
					t.Error(err)
					return
				}
				defer archive.Close()
				readPart := func() ([]byte, error) {
					var size [4]byte
					if _, err := io.ReadFull(archive, size[:]); err != nil {
						return nil, err
					}
					length := binary.BigEndian.Uint32(size[:])
					if length < 5 || length > view.MaxVideoPartBytes {
						return nil, fmt.Errorf("invalid archived part size%d", length)
					}
					part := make([]byte, length)
					_, err := io.ReadFull(archive, part)
					return part, err
				}
				first, err := readPart()
				if err != nil {
					t.Error(err)
					return
				}
				var descriptor map[string]any
				headerLength := binary.BigEndian.Uint32(first[:4])
				if err := json.Unmarshal(first[4:4+headerLength], &descriptor); err != nil {
					t.Error(err)
					return
				}
				newID := descriptor["streamId"].(string)
				const oldID = "11111111-1111-4111-8111-111111111111"
				started := func(id string) string {
					return `{"type":"video","state":"started","generation":1,"codec":"av1-444","codecString":"av01.1.16M.08","streamId":"` + id + `"}`
				}
				if !sendRecord(started(oldID)) {
					return
				}
				descriptor["streamId"] = oldID
				header, _ := json.Marshal(descriptor)
				partial := make([]byte, 4+len(header)+64)
				binary.BigEndian.PutUint32(partial, uint32(len(header)))
				copy(partial[4:], header)
				copy(partial[4+len(header):], first[4+headerLength:4+headerLength+64])
				delivery, closing := channel.Upstream(false, partial)
				if closing != nil || delivery == nil || c.Send(delivery) != nil ||
					!wait(func(f *view.Forward) bool { return f.Transfer.Offset == 64 }) {
					t.Error("first partial did not reach production receiver")
					return
				}
				stalled, err := c.session.OpenUniStreamSync(c.session.Context())
				if err != nil {
					t.Error(err)
					return
				}
				c.pictures++
				prefix := make([]byte, 17)
				prefix[0] = 1
				binary.BigEndian.PutUint64(prefix[1:9], c.controls.Load())
				binary.BigEndian.PutUint64(prefix[9:], c.pictures)
				c.mu.Lock()
				if c.parts == nil {
					c.parts = make(map[*wt.SendStream]*pendingPart)
				}
				c.parts[stalled] = &pendingPart{stream: stalled, streamID: oldID}
				c.mu.Unlock()
				if prefixBytes > 0 {
					if _, err := stalled.Write(prefix[:prefixBytes]); err != nil {
						t.Error(err)
						return
					}
				}
				if !sendRecord(started(newID)) ||
					!sendRecord(`{"type":"audio","state":"started","generation":1,"codec":"opus","streamId":"44444444-4444-4444-8444-444444444444","sampleRate":48000,"channels":2,"frameSamples":480,"primingSamples":0}`) ||
					!sendRecord(`{"type":"cursor","ts":123,"serial":1,"css":"text"}`) {
					return
				}
				audio, _ := channel.Upstream(false, packet([]byte(`{"type":"media","track":"audio","codec":"opus","streamId":"44444444-4444-4444-8444-444444444444","seq":1,"ts":123,"samples":480,"byteLength":3}`), []byte{1, 2, 3}))
				if audio == nil || c.Send(audio) != nil {
					t.Error("audio did not survive retired part")
					return
				}
				parts := 0
				for part := first; part != nil; {
					delivery, closing := channel.Upstream(false, part)
					if closing != nil || delivery == nil || c.Send(delivery) != nil {
						t.Errorf("native archive atpart%d: %v", parts, closing)
						return
					}
					end := delivery.Transfer.Offset
					if !wait(func(f *view.Forward) bool { return f.Transfer.Offset == end }) {
						return
					}
					parts++
					part, err = readPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Error(err)
						return
					}
				}
				if !wait(func(f *view.Forward) bool { return f.Paint.Sequence == 1 }) {
					t.Error("no complete successor paint ACK")
				}
				t.Logf("compiled worker retirement prefix%d +exact native archive%dparts/%dB bodySHA%x", prefixBytes, parts, len(body), hash)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "node", script, address, fmt.Sprintf("%x", hash), "webtransport", worker, trust)
			cmd.Env = append(os.Environ(), "MEDIA_EDGE_BROWSER_RETIREMENT=1")
			if prefix := os.Getenv("MEDIA_EDGE_BROWSER_SCREENSHOT_PREFIX"); prefix != "" {
				cmd.Env = append(cmd.Env, fmt.Sprintf("MEDIA_EDGE_BROWSER_SCREENSHOT_FILE=%s-prefix%d.png", prefix, prefixBytes))
			}
			output, err := cmd.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatalf("real compiled worker/archive retirement: %v", err)
			}
		})
	}
}

func packet(header, body []byte) []byte {
	encoded := make([]byte, 4+len(header)+len(body))
	binary.BigEndian.PutUint32(encoded, uint32(len(header)))
	copy(encoded[4:], header)
	copy(encoded[4+len(header):], body)
	return encoded
}
