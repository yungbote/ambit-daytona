// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	ws "github.com/gorilla/websocket"
)

// Uses the real canonical channel/carrier and production browser reader,
// decoder and stage. The immutable codec body is a recorded native artifact;
// this source fixture is not the live Rust/T1/Product publisher.
func TestCanonicalNativePartsThroughProductionBrowserWebSocket(t *testing.T) {
	script, path := os.Getenv("MEDIA_EDGE_BROWSER_CHUNKS_SCRIPT"), os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_KEY_FILE")
	if script == "" || path == "" {
		t.Skip("browser chunks script and recorded native key required")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.Open(filepath.Join(filepath.Dir(path), "native-q32-4096-wire-r1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	var prefix [4]byte
	if _, err := io.ReadFull(fixture, prefix[:]); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err := io.ReadFull(fixture, header); err != nil {
		t.Fatal(err)
	}
	var descriptor map[string]any
	if err := json.Unmarshal(header, &descriptor); err != nil {
		t.Fatal(err)
	}
	var archive *os.File
	var firstArchived []byte
	if archivePath := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_PARTS_FILE"); archivePath != "" {
		archive, err = os.Open(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		defer archive.Close()
		firstArchived, err = readArchivedPart(archive)
		if err != nil {
			t.Fatal(err)
		}
		headerSize := int(binary.BigEndian.Uint32(firstArchived))
		if headerSize+4 > len(firstArchived) {
			t.Fatal("invalid native archive first header")
		}
		if err := json.Unmarshal(firstArchived[4:4+headerSize], &descriptor); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		declaration, err := view.ParseDeclaration(r.URL.Query())
		if err != nil || !declaration.VideoChunks {
			t.Error("production reader did not negotiate chunks")
			return
		}
		conn, err := (&ws.Upgrader{WriteBufferSize: 64 << 10, CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := newCarrier(conn, time.Hour)
		defer c.Close(0, "")
		channel := view.NewChannel(declaration)
		flight := &chunkFlight{window: 2048}
		wake, started, painted := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
		failed := make(chan error, 1)
		go func() {
			for {
				text, message, err := c.Receive()
				if err != nil {
					failed <- err
					return
				}
				forward, closing := channel.Viewer(text, message)
				if closing != nil {
					failed <- fmt.Errorf("canonical receipt closed%d/%s", closing.Code, closing.Reason)
					return
				}
				if forward == nil {
					continue
				}
				if forward.Slot == view.SlotVideo {
					started <- struct{}{}
				}
				if forward.Transfer.Offset > 0 {
					if !flight.received(int(forward.Transfer.Offset)) {
						failed <- fmt.Errorf("unissued received prefix")
						return
					}
					select {
					case wake <- struct{}{}:
					default:
					}
				}
				if forward.Paint.Sequence > 0 {
					painted <- struct{}{}
				}
			}
		}()
		sendRecord := func(text string) bool {
			d, closing := channel.Upstream(true, []byte(text))
			if closing != nil || d == nil {
				t.Errorf("canonical record: %v", closing)
				return false
			}
			if err := c.Send(d); err != nil {
				return false
			}
			return true
		}
		if !sendRecord(`{"type":"video","state":"available","codec":"av1-444"}`) {
			return
		}
		select {
		case <-started:
		case <-failed:
			return
		case <-ctx.Done():
			return
		}
		id := descriptor["streamId"].(string)
		if !sendRecord(`{"type":"video","state":"started","generation":1,"codec":"av1-444","codecString":"av01.1.16M.08","streamId":"` + id + `"}`) {
			return
		}
		var archived []byte
		for offset := 0; offset < len(payload); {
			var header map[string]any
			if offset == 0 {
				header = make(map[string]any, len(descriptor)+1)
				for k, v := range descriptor {
					header[k] = v
				}
				header["offset"] = 0
			} else {
				header = map[string]any{"type": "media", "track": "video", "streamId": id, "seq": 1, "offset": offset}
			}
			encoded, _ := json.Marshal(header)
			count := min(len(payload)-offset, 1024-8-len(encoded))
			if archive != nil && archived == nil {
				if offset == 0 {
					archived = firstArchived
				} else {
					archived, err = readArchivedPart(archive)
					if err != nil {
						t.Error(err)
						return
					}
				}
			}
			if archive != nil {
				size := int(binary.BigEndian.Uint32(archived))
				encoded = archived[4 : 4+size]
				count = len(archived) - 4 - size
			}
			if count < 1 {
				t.Error("fixture descriptor exceeded bootstrap envelope")
				return
			}
			charge := 4 + len(encoded) + count
			if charge > 125 {
				charge += 4
			} else {
				charge += 2
			}
			if !flight.reserve(offset+count, charge) {
				select {
				case <-wake:
				case <-failed:
					return
				case <-ctx.Done():
					return
				}
				continue
			}
			packet := make([]byte, 4+len(encoded)+count)
			binary.BigEndian.PutUint32(packet, uint32(len(encoded)))
			copy(packet[4:], encoded)
			copy(packet[4+len(encoded):], payload[offset:offset+count])
			if archive != nil {
				packet = archived
				archived = nil
			}
			d, closing := channel.Upstream(false, packet)
			if closing != nil || d == nil {
				t.Errorf("canonical part at%d: %v", offset, closing)
				return
			}
			if c.PartBytes(d) != charge {
				t.Error("projected wire charge changed")
				return
			}
			if err := c.Send(d); err != nil {
				return
			}
			offset += count
		}
		select {
		case <-painted:
		case <-failed:
		case <-ctx.Done():
			t.Error("no complete paint ACK")
		}
	}))
	defer server.Close()
	hash := sha256.Sum256(payload)
	output, err := exec.CommandContext(ctx, "node", script, "ws"+server.URL[4:], fmt.Sprintf("%x", hash), "websocket").CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("real production browser reader: %v", err)
	}
}

// The archive length is a fixture boundary, never forwarded onto the wire.
func readArchivedPart(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size < 5 || size > view.MaxVideoPartBytes {
		return nil, fmt.Errorf("invalid archived envelope size%d", size)
	}
	part := make([]byte, size)
	_, err := io.ReadFull(reader, part)
	if err == nil {
		header := binary.BigEndian.Uint32(part)
		if header < 2 || header > 4096 || uint64(header)+4 >= uint64(len(part)) {
			return nil, fmt.Errorf("invalid archived part header%d", header)
		}
	}
	return part, err
}
