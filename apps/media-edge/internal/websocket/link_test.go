// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
	ws "github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// The task-only listener serializes actual TCP writes; no host qdisc or
// network interface changes. Small writes expose progress during a logical
// WebSocket message, without changing that message's application framing.
type pacedListener struct {
	net.Listener
	ctx      context.Context
	bytes    atomic.Int64
	progress chan struct{}
	once     sync.Once
	rate     atomic.Int64
	writeMu  sync.Mutex
	writes   []pacedWrite
	history  []pacedWrite
	dropped  uint64
	unpaced  bool
}

type pacedWrite struct {
	WireBytes            int
	BitsPerSecondAtStart int64
	StartedUnixMs        float64
	DurationMs           float64
	Track                string
	StreamID             string
	Sequence             uint64
	WrittenBytes         int
	WriteError           string
}

type pacedTrace struct {
	Largest []pacedWrite
	History []pacedWrite
	Dropped uint64
}

func (l *pacedListener) writeTrace() pacedTrace {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return pacedTrace{append([]pacedWrite(nil), l.writes...), append([]pacedWrite(nil), l.history...), l.dropped}
}

// The task serializer records bounded original-wire writes, never payloads.
func (l *pacedListener) recordWrite(data []byte, began time.Time, rate int64, written int, writeErr error) {
	row := pacedWrite{WireBytes: len(data), WrittenBytes: written, BitsPerSecondAtStart: rate, StartedUnixMs: float64(began.UnixNano()) / 1e6, DurationMs: float64(time.Since(began)) / float64(time.Millisecond)}
	if writeErr != nil {
		row.WriteError = writeErr.Error()
	}
	if len(data) >= 2 && data[0]&15 == 2 {
		prefix := 2
		if data[1]&127 == 126 {
			prefix = 4
		} else if data[1]&127 == 127 {
			prefix = 10
		}
		if len(data) >= prefix+4 {
			length := int(binary.BigEndian.Uint32(data[prefix:]))
			if length > 0 && length <= 4096 && len(data) >= prefix+4+length {
				var header struct {
					Track    string `json:"track"`
					StreamID string `json:"streamId"`
					Sequence uint64 `json:"seq"`
				}
				if json.Unmarshal(data[prefix+4:prefix+4+length], &header) == nil {
					row.Track, row.StreamID, row.Sequence = header.Track, header.StreamID, header.Sequence
				}
			}
		}
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if len(l.history) < 16384 {
		l.history = append(l.history, row)
	} else {
		l.dropped++
	}
	l.writes = append(l.writes, row)
	sort.Slice(l.writes, func(i, j int) bool { return l.writes[i].DurationMs > l.writes[j].DurationMs })
	if len(l.writes) > 10 {
		l.writes = l.writes[:10]
	}
}

type pacedConnection struct {
	net.Conn
	owner *pacedListener
}

func (l *pacedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &pacedConnection{Conn: c, owner: l}, nil
}

func (c *pacedConnection) Write(data []byte) (written int, writeErr error) {
	started, original, rate := time.Now(), data, c.owner.rate.Load()
	if c.owner.unpaced {
		written, writeErr = c.Conn.Write(data)
		c.owner.bytes.Add(int64(written))
		c.owner.recordWrite(original, started, 0, written, writeErr)
		return written, writeErr
	}
	if rate == 0 {
		rate = 500000
	}
	defer func() { c.owner.recordWrite(original, started, rate, written, writeErr) }()
	for len(data) > 0 {
		part := min(len(data), 4096)
		rate := c.owner.rate.Load()
		if rate == 0 {
			rate = 500000
		}
		timer := time.NewTimer(time.Duration(part*8) * time.Second / time.Duration(rate))
		select {
		case <-timer.C:
		case <-c.owner.ctx.Done():
			timer.Stop()
			return written, c.owner.ctx.Err()
		}
		n, err := c.Conn.Write(data[:part])
		written += n
		data = data[n:]
		if c.owner.bytes.Add(int64(n)) >= 64<<10 {
			c.owner.once.Do(func() { close(c.owner.progress) })
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func TestPacedTCPLinkSerializesAKnownByteTrain(t *testing.T) {
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	link := &pacedListener{ctx: ctx, progress: make(chan struct{})}
	conn := &pacedConnection{Conn: writer, owner: link}
	read := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, reader, 20000); read <- err }()
	started := time.Now()
	for n := 0; n < 20; n++ {
		if _, err := conn.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed < 320*time.Millisecond || elapsed > 800*time.Millisecond || link.bytes.Load() != 20000 {
		t.Fatalf("20KB at500kbit/s took%s, bytes%d; expected320ms floor", elapsed, link.bytes.Load())
	}
	t.Logf("actual known20x1000B TCP train: %s vs320ms serialization floor", elapsed)
}

func TestPacedTCPTraceBindsOriginalAudioEnvelopeAndRetainsBoundedWrites(t *testing.T) {
	header := []byte(`{"type":"media","track":"audio","codec":"opus","streamId":"11111111-1111-4111-8111-111111111111","seq":378}`)
	body := make([]byte, 4+len(header)+321)
	binary.BigEndian.PutUint32(body, uint32(len(header)))
	copy(body[4:], header)
	wire := append([]byte{0x82, 126, byte(len(body) >> 8), byte(len(body))}, body...)
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	link := &pacedListener{ctx: ctx, progress: make(chan struct{})}
	link.rate.Store(500000)
	conn := &pacedConnection{Conn: writer, owner: link}
	read := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, reader, int64(12*len(wire))); read <- err }()
	for n := 0; n < 12; n++ {
		if _, err := conn.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	observed := link.writeTrace()
	trace := observed.Largest
	if len(trace) != 10 {
		t.Fatalf("trace retained%d writes, expected10", len(trace))
	}
	for index, row := range trace {
		if row.Track != "audio" || row.Sequence != 378 || row.StreamID != "11111111-1111-4111-8111-111111111111" || row.WireBytes != len(wire) || row.WrittenBytes != len(wire) || row.WriteError != "" || row.BitsPerSecondAtStart != 500000 || row.DurationMs < float64(len(wire)*8)/500 {
			t.Fatalf("trace changed original audio/wire identity or serialization: %+v", row)
		}
		if index > 0 && trace[index-1].DurationMs < row.DurationMs {
			t.Fatal("trace is not ordered by observed duration")
		}
	}
	trace[0].Track = "altered"
	if link.writeTrace().Largest[0].Track != "audio" {
		t.Fatal("trace caller mutated retained measurement")
	}
	if len(observed.History) != 12 || observed.Dropped != 0 {
		t.Fatalf("complete original-write chronology changed: %+v", observed)
	}
	for index, row := range observed.History {
		if index > 0 && row.StartedUnixMs < observed.History[index-1].StartedUnixMs {
			t.Fatal("original-write chronology is not ordered")
		}
	}
}

func TestPacedWriteHistoryReportsTruncationInsteadOfClaimingCompleteChronology(t *testing.T) {
	link := &pacedListener{}
	for count := 0; count < 16389; count++ {
		link.recordWrite(nil, time.Now(), 500000, 0, nil)
	}
	trace := link.writeTrace()
	if len(trace.History) != 16384 || len(trace.Largest) != 10 || trace.Dropped != 5 {
		t.Fatalf("bounded trace failed to disclose omitted writes: %d/%d/%d", len(trace.History), len(trace.Largest), trace.Dropped)
	}
}

type observedWriteConnection struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c observedWriteConnection) Write(data []byte) (int, error) { return c.write(data) }

func TestUnpacedObserverDelegatesOneUnchangedWriteAndRecordsActualResult(t *testing.T) {
	failure := errors.New("known write failure")
	for _, outcome := range []struct {
		name string
		n    int
		err  error
	}{
		{"complete", 8197, nil},
		{"short", 317, nil},
		{"partial-error", 317, failure},
		{"zero-error", 0, failure},
		{"zero", 0, nil},
	} {
		t.Run(outcome.name, func(t *testing.T) {
			data := make([]byte, 8197)
			calls := 0
			link := &pacedListener{unpaced: true}
			// A nonzero rate must not turn passive observation into serialization.
			link.rate.Store(1)
			conn := &pacedConnection{owner: link, Conn: observedWriteConnection{write: func(actual []byte) (int, error) {
				calls++
				if len(actual) != len(data) || &actual[0] != &data[0] {
					t.Fatal("observer split or copied the original write")
				}
				return outcome.n, outcome.err
			}}}
			n, err := conn.Write(data)
			if calls != 1 || n != outcome.n || err != outcome.err {
				t.Fatalf("observer changed delegate result: calls%d n%d err%v", calls, n, err)
			}
			trace := link.writeTrace()
			if len(trace.History) != 1 || len(trace.Largest) != 1 || trace.Dropped != 0 || link.bytes.Load() != int64(n) {
				t.Fatalf("observer lost actual write result: %+v bytes%d", trace, link.bytes.Load())
			}
			row := trace.History[0]
			expectedError := ""
			if outcome.err != nil {
				expectedError = outcome.err.Error()
			}
			if row.WireBytes != len(data) || row.WrittenBytes != n || row.WriteError != expectedError || row.BitsPerSecondAtStart != 0 || row.StartedUnixMs <= 0 || row.DurationMs < 0 {
				t.Fatalf("observer claimed a different completion: %+v", row)
			}
		})
	}
}

func TestRecordedNativeKeyShowsWholeMessageWebSocketAudioHOL(t *testing.T) {
	path := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_KEY_FILE")
	if path == "" {
		t.Skip("recorded native key required")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan *carrier, 1)
	keyDone := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&ws.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := newCarrier(conn, time.Hour)
		defer c.Close(0, "")
		ready <- c
		keyDone <- c.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: payload})
		<-ctx.Done()
	}))
	link := &pacedListener{Listener: server.Listener, ctx: ctx, progress: make(chan struct{})}
	server.Listener = link
	server.Start()
	defer server.Close()
	client, _, err := ws.DefaultDialer.Dial("ws"+server.URL[4:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Drain real bytes without waiting for the browser's whole-message event.
	// Even this streaming consumer cannot pass the current logical unit.
	reading := make(chan struct{})
	go func() {
		_, reader, err := client.NextReader()
		if err == nil {
			_, _ = io.Copy(io.Discard, reader)
		}
		close(reading)
	}()
	c := <-ready
	select {
	case <-link.progress:
	case <-time.After(5 * time.Second):
		t.Fatal("no actual TCP picture progress")
	}
	audioDone := make(chan error, 1)
	started := time.Now()
	go func() {
		audioDone <- c.Send(&view.Delivery{Kind: view.Audio, Header: []byte(`{"track":"audio"}`), Payload: make([]byte, 160)})
	}()
	observation := time.NewTimer(200 * time.Millisecond)
	select {
	case <-audioDone:
		t.Fatal("whole-message apparatus did not expose audio serialization")
	case <-keyDone:
		t.Fatal("large key finished before the HOL observation")
	case <-observation.C:
	}
	bytes := link.bytes.Load()
	hash := sha256.Sum256(payload)
	t.Logf("actual WS native key SHA256=%x body%dB at500kbit/s: partial TCP progress%dB; audio write blocked%s before whole-picture completion; key serialization floor%s. This is protocol HOL characterization, not native input/glass acceptance", hash, len(payload), bytes, time.Since(started), time.Duration(len(payload)*8)*time.Second/500000)
	cancel()
	c.Close(0, "")
	_ = client.Close()
	select {
	case <-keyDone:
	case <-time.After(time.Second):
		t.Fatal("key writer did not cancel")
	}
	select {
	case <-audioDone:
	case <-time.After(time.Second):
		t.Fatal("queued audio writer did not cancel")
	}
	<-reading
}

// chunkFlight is the spike's byte-credit gate, independent of paint. A
// boundary is reserved before socket I/O; receipts may arrive before the
// writer returns. Only outstanding boundaries remain in memory.
type chunkFlight struct {
	mu                  sync.Mutex
	window, bytes, peak int
	acknowledged        int
	boundaries          []chunkBoundary
}

type chunkBoundary struct{ offset, wire int }

func (f *chunkFlight) reserve(offset, wire int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if wire <= 0 || (f.bytes != 0 && wire > f.window-f.bytes) {
		return false
	}
	f.boundaries = append(f.boundaries, chunkBoundary{offset, wire})
	f.bytes += wire
	f.peak = max(f.peak, f.bytes)
	return true
}

func (f *chunkFlight) received(offset int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if offset <= f.acknowledged {
		return offset == f.acknowledged
	}
	for index, boundary := range f.boundaries {
		if boundary.offset != offset {
			continue
		}
		for _, part := range f.boundaries[:index+1] {
			f.bytes -= part.wire
		}
		f.boundaries = f.boundaries[:copy(f.boundaries, f.boundaries[index+1:])]
		f.acknowledged = offset
		return true
	}
	return false
}

func TestChunkCreditReservationAcceptsEarlyReceiptAndPrunes(t *testing.T) {
	f := &chunkFlight{window: 1024}
	if f.received(1) || !f.reserve(16, 600) || f.reserve(32, 600) || f.received(17) || !f.received(16) {
		t.Fatal("unissued receipt or credit boundary accepted")
	}
	// A tiny window cannot hold the minimum nonempty envelope. Its full
	// debit is permitted only when empty, and then awaits received credit.
	f.window = 3
	if !f.reserve(17, 120) || f.reserve(18, 120) || !f.received(17) || len(f.boundaries) != 0 || f.bytes != 0 {
		t.Fatal("minimum-envelope debt or cumulative pruning failed")
	}
}

type chunkLinkResult struct {
	wire, parts, peak, socketPeak, controls int
	audioWire, controlWire                  int
	elapsed                                 time.Duration
	err                                     error
}

// The hard slice uses the actual carrier, TCP socket and immutable native
// body. It intentionally precedes native/T1/Product qualification: the
// sender is this bounded protocol spike, not the native publisher.
func TestRecordedNativeKeyWithChunkCreditAt500k(t *testing.T) {
	path := os.Getenv("MEDIA_EDGE_BROWSER_NATIVE_KEY_FILE")
	if path == "" {
		t.Skip("recorded native key required")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.Open(path[:len(path)-len("native-q32-noise-4096x4096.av1")] + "native-q32-4096-wire-r1.bin")
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
	if int(descriptor["byteLength"].(float64)) != len(payload) {
		t.Fatal("fixture/body mismatch")
	}
	// Compare window sizes on identical prefixes; spend one whole-key run
	// on the smallest window that can cover two scheduling opportunities.
	for _, quanta := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("window-%d-prefix", quanta), func(t *testing.T) {
			runChunkKeyLink(t, payload[:64<<10], descriptor, quanta*1024, false)
		})
	}
	t.Run("complete-window-2", func(t *testing.T) {
		runChunkKeyLink(t, payload, descriptor, 2*1024, true)
	})
}

func runChunkKeyLink(t *testing.T, payload []byte, descriptor map[string]any, window int, adversarial bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	result := make(chan chunkLinkResult, 1)
	link := &pacedListener{ctx: ctx, progress: make(chan struct{})}
	flight := &chunkFlight{window: window}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&ws.Upgrader{WriteBufferSize: 4096}).Upgrade(w, r, nil)
		if err != nil {
			result <- chunkLinkResult{err: err}
			return
		}
		c := newCarrier(conn, time.Hour)
		defer c.Close(0, "")
		wake := make(chan struct{}, 1)
		control := make(chan []byte, 1)
		readerError := make(chan error, 1)
		painted := make(chan struct{}, 1)
		go func() {
			for {
				text, data, err := c.Receive()
				if err != nil {
					readerError <- err
					return
				}
				var receipt struct {
					Type   string
					Offset int
				}
				if !text || json.Unmarshal(data, &receipt) != nil {
					readerError <- fmt.Errorf("invalid receipt")
					return
				}
				switch receipt.Type {
				case "received":
					if !flight.received(receipt.Offset) {
						readerError <- fmt.Errorf("unissued prefix%d", receipt.Offset)
						return
					}
					select {
					case wake <- struct{}{}:
					default:
					}
				case "input":
					select {
					case control <- data:
					case <-ctx.Done():
						return
					}
				case "ack":
					flight.mu.Lock()
					complete := flight.acknowledged == len(payload)
					flight.mu.Unlock()
					if !complete {
						readerError <- fmt.Errorf("paint before complete received prefix")
						return
					}
					painted <- struct{}{}
				}
			}
		}()
		started := time.Now()
		stats := chunkLinkResult{}
		finish := func(err error) {
			stats.err, stats.elapsed = err, time.Since(started)
			flight.mu.Lock()
			stats.peak = flight.peak
			flight.mu.Unlock()
			result <- stats
		}
		audio := time.NewTicker(100 * time.Millisecond)
		defer audio.Stop()
		sendAudio := func() error {
			body := make([]byte, 160)
			binary.BigEndian.PutUint64(body, uint64(time.Now().UnixNano()))
			delivery := &view.Delivery{Kind: view.Audio, Header: []byte(`{"type":"media","track":"audio"}`), Payload: body}
			stats.audioWire = delivery.Size() + 4
			return c.Send(delivery)
		}
		sendControl := func(data []byte) error {
			stats.controls++
			stats.controlWire = max(stats.controlWire, len(data)+2)
			return c.Send(&view.Delivery{Kind: view.Record, Text: data})
		}
		for offset := 0; offset < len(payload); {
			// Return to the existing priority order at every part boundary.
			select {
			case data := <-control:
				if err := sendControl(data); err != nil {
					finish(err)
					return
				}
			default:
			}
			select {
			case <-audio.C:
				if err := sendAudio(); err != nil {
					finish(err)
					return
				}
			default:
			}
			var partHeader []byte
			if offset == 0 {
				first := make(map[string]any, len(descriptor)+1)
				for key, value := range descriptor {
					first[key] = value
				}
				first["byteLength"], first["offset"] = len(payload), 0
				partHeader, _ = json.Marshal(first)
			} else {
				partHeader, _ = json.Marshal(struct {
					Type     string `json:"type"`
					Track    string `json:"track"`
					StreamID any    `json:"streamId"`
					Seq      any    `json:"seq"`
					Offset   int    `json:"offset"`
				}{"media", "video", descriptor["streamId"], descriptor["seq"], offset})
			}
			count := min(len(payload)-offset, max(1, 1024-8-len(partHeader)))
			wire := 8 + len(partHeader) + count //4B envelope prefix + actual4B WS header
			if !flight.reserve(offset+count, wire) {
				select {
				case <-wake:
				case data := <-control:
					if err := sendControl(data); err != nil {
						finish(err)
						return
					}
				case <-audio.C:
					if err := sendAudio(); err != nil {
						finish(err)
						return
					}
				case err := <-readerError:
					finish(err)
					return
				case <-ctx.Done():
					finish(ctx.Err())
					return
				}
				continue
			}
			if err := c.Send(&view.Delivery{Kind: view.Video, Header: partHeader, Payload: payload[offset : offset+count]}); err != nil {
				finish(err)
				return
			}
			offset += count
			stats.wire += wire
			stats.parts++
			if tcp, ok := conn.UnderlyingConn().(*pacedConnection); ok {
				if raw, err := tcp.Conn.(*net.TCPConn).SyscallConn(); err == nil {
					_ = raw.Control(func(fd uintptr) {
						queued, err := unix.IoctlGetInt(int(fd), unix.TIOCOUTQ)
						if err == nil {
							stats.socketPeak = max(stats.socketPeak, queued)
						}
					})
				}
			}
		}
		for {
			select {
			case <-painted:
				finish(nil)
				return
			case data := <-control:
				if err := sendControl(data); err != nil {
					finish(err)
					return
				}
			case <-audio.C:
				if err := sendAudio(); err != nil {
					finish(err)
					return
				}
			case err := <-readerError:
				finish(err)
				return
			case <-ctx.Done():
				finish(ctx.Err())
				return
			}
		}
	}))
	link.Listener = server.Listener
	server.Listener = link
	server.Start()
	defer server.Close()
	client, _, err := ws.DefaultDialer.Dial("ws"+server.URL[4:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var writing sync.Mutex
	write := func(value any) error { writing.Lock(); defer writing.Unlock(); return client.WriteJSON(value) }
	inputDone := make(chan struct{})
	defer func() { cancel(); <-inputDone }()
	go func() {
		defer close(inputDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if write(map[string]any{"type": "input", "at": time.Now().UnixNano()}) != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	assembled := make([]byte, len(payload))
	seen, audioCount, controls := 0, 0, 0
	var maxAudio, maxInput time.Duration
	var stallAt time.Time
	stallOffset, latestHeld := 0, 0
	receive := func(offset int) error {
		return write(map[string]any{"type": "received", "track": "video", "streamId": descriptor["streamId"], "seq": descriptor["seq"], "offset": offset})
	}
	for seen < len(payload) {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		kind, data, err := client.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if kind == ws.TextMessage {
			var echo struct {
				Type string
				At   int64
			}
			if json.Unmarshal(data, &echo) != nil || echo.Type != "input" {
				t.Fatalf("unexpected control%q", data)
			}
			controls++
			maxInput = max(maxInput, time.Since(time.Unix(0, echo.At)))
		} else {
			if len(data) < 4 {
				t.Fatal("short part")
			}
			headerBytes := int(binary.BigEndian.Uint32(data))
			if headerBytes < 2 || headerBytes+4 > len(data) {
				t.Fatal("bad part envelope")
			}
			var part struct {
				Track      string
				Offset     int
				ByteLength int
			}
			if err := json.Unmarshal(data[4:4+headerBytes], &part); err != nil {
				t.Fatal(err)
			}
			body := data[4+headerBytes:]
			if part.Track == "audio" {
				audioCount++
				maxAudio = max(maxAudio, time.Since(time.Unix(0, int64(binary.BigEndian.Uint64(body)))))
			} else {
				if part.Offset != seen || len(body) == 0 || len(data)+4 > 1024 || seen+len(body) > len(assembled) {
					t.Fatalf("invalid contiguous bounded part at%d: %+v body%d", seen, part, len(body))
				}
				copy(assembled[seen:], body)
				seen += len(body)
				if adversarial && stallAt.IsZero() && seen >= 32<<10 {
					stallAt, stallOffset = time.Now(), seen
					link.rate.Store(250000)
				}
				if !stallAt.IsZero() && time.Since(stallAt) < 200*time.Millisecond {
					latestHeld = seen
				} else if err := receive(seen); err != nil {
					t.Fatal(err)
				}
			}
		}
		if latestHeld > 0 && time.Since(stallAt) >= 200*time.Millisecond {
			if latestHeld-stallOffset > window {
				t.Fatalf("stalled receiver advanced%d payload bytes beyond%d-byte credit", latestHeld-stallOffset, window)
			}
			if err := receive(latestHeld); err != nil {
				t.Fatal(err)
			}
			latestHeld = 0
			link.rate.Store(500000)
		}
	}
	if sha256.Sum256(assembled) != sha256.Sum256(payload) {
		t.Fatal("reassembly changed the native key")
	}
	// No decode/paint credit is issued until the entire exact body exists.
	if err := write(map[string]any{"type": "ack", "track": "video", "streamId": descriptor["streamId"], "seq": descriptor["seq"]}); err != nil {
		t.Fatal(err)
	}
	stats := <-result
	if stats.err != nil {
		t.Fatal(stats.err)
	}
	// Video credit excludes the concurrent priority packet/echo. The kernel
	// can retain that one bounded audio envelope as well as the video window.
	if stats.peak > window || stats.socketPeak > window+stats.audioWire+stats.controlWire || audioCount == 0 || controls == 0 || maxAudio > 150*time.Millisecond || maxInput > 150*time.Millisecond {
		t.Fatalf("unbounded/blocked chunk path: %+v audio%d/%s control%d/%s", stats, audioCount, maxAudio, controls, maxInput)
	}
	t.Logf("actual bounded WS at500k: keySHA%x body%dB exact videoWire%dB parts%d window%dB peakCredit%dB kernelQueuedPeak%dB duration%s audio%d maxAge%s control%d maxRTT%s; first-key zero paint ACK until full assembly. Native/T1/Product input remains unverified", sha256.Sum256(payload), len(payload), stats.wire, stats.parts, window, stats.peak, stats.socketPeak, stats.elapsed, audioCount, maxAudio, controls, maxInput)
}
