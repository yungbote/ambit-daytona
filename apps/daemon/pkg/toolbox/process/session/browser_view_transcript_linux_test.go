// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A view transcript is what one viewer and one real driver said to each other
// on a view connection, in the order the viewer observed it: the driver's
// messages as they arrived and the viewer's as they left. It is recorded
// straight at the driver (browser_view_transcript_real_linux_test.go), so it
// holds the driver's own bytes, and it is replayed through this route to
// state what the route does to them.
//
// The file is gzip-compressed JSON lines. The first line is the header; then
// one line per message.
type browserViewTranscriptHeader struct {
	// The upgrade query a viewer's relay sends this route, as the host does.
	Declaration string `json:"declaration"`
	Viewer      string `json:"viewer"`
	Driver      string `json:"driver"`
}

type browserViewTranscriptLine struct {
	// "down": the driver's message; "up": the viewer's.
	Direction string `json:"dir"`
	Binary    bool   `json:"binary,omitempty"`
	Data      []byte `json:"data"`
}

type browserViewTranscript struct {
	header   browserViewTranscriptHeader
	messages []browserViewTranscriptLine
}

func readBrowserViewTranscript(path string) (browserViewTranscript, error) {
	var transcript browserViewTranscript
	file, err := os.Open(path)
	if err != nil {
		return transcript, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return transcript, err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	if !scanner.Scan() {
		return transcript, errors.New("an empty transcript")
	}
	if err := json.Unmarshal(scanner.Bytes(), &transcript.header); err != nil {
		return transcript, err
	}
	for scanner.Scan() {
		var line browserViewTranscriptLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			return transcript, err
		}
		transcript.messages = append(transcript.messages, line)
	}
	return transcript, scanner.Err()
}

// A step is the driver's messages up to the viewer's next reply, then that
// reply. Replaying step by step keeps every causal order of the recording:
// what the viewer sent after a message still follows it, and what the driver
// sent after the viewer's reply still follows the reply.
type browserViewTranscriptStep struct {
	down []browserViewTranscriptLine
	up   [][]byte
}

func (transcript browserViewTranscript) steps() []browserViewTranscriptStep {
	var steps []browserViewTranscriptStep
	var current browserViewTranscriptStep
	for _, message := range transcript.messages {
		if message.Direction == "down" && len(current.up) != 0 {
			steps = append(steps, current)
			current = browserViewTranscriptStep{}
		}
		if message.Direction == "down" {
			current.down = append(current.down, message)
		} else {
			current.up = append(current.up, message.Data)
		}
	}
	return append(steps, current)
}

// The replay's own two messages. The step marker is a location record, which
// every revision of the route projects to these same bytes; the barrier is a
// size no dock has, which every revision forwards to a presenter's driver.
var browserViewReplayBarrier = []byte(`{"type":"presentation","width":1,"height":1}`)

func browserViewReplayMarker(step int) []byte {
	return []byte(`{"type":"url","url":"https://replay.invalid/` + strconv.Itoa(step) + `"}`)
}

func browserViewReplayStep(message []byte) (int, bool) {
	const prefix, suffix = `{"type":"url","url":"https://replay.invalid/`, `"}`
	if !bytes.HasPrefix(message, []byte(prefix)) || !bytes.HasSuffix(message, []byte(suffix)) {
		return 0, false
	}
	step, err := strconv.Atoi(string(message[len(prefix) : len(message)-len(suffix)]))
	return step, err == nil
}

// serveBrowserViewReplay is the driver's side of a replay: each step's
// messages, then the step's marker, then whatever the route forwards until
// the viewer's barrier. After the last step the driver leaves.
func serveBrowserViewReplay(driver *browserViewFixtureDriver, path string) {
	transcript, err := readBrowserViewTranscript(path)
	if err != nil {
		return
	}
	for index, step := range transcript.steps() {
		for _, message := range step.down {
			kind := websocket.TextMessage
			if message.Binary {
				kind = websocket.BinaryMessage
			}
			if driver.connection.WriteMessage(kind, message.Data) != nil {
				return
			}
		}
		if driver.connection.WriteMessage(websocket.TextMessage, browserViewReplayMarker(index)) != nil {
			return
		}
		for {
			_, message, err := driver.read()
			if err != nil {
				return
			}
			if bytes.Equal(message, browserViewReplayBarrier) {
				break
			}
		}
	}
}

// browserViewReplayResult is what one revision of the route did with one
// transcript: what the viewer received, how the channel closed, what the
// driver received and the upgrade it was dialled with.
type browserViewReplayResult struct {
	Viewer  []browserViewTranscriptLine `json:"viewer"`
	Close   string                      `json:"close"`
	Driver  [][]byte                    `json:"driver"`
	Upgrade string                      `json:"upgrade"`
}

// TestBrowserViewTranscriptReplay replays a recorded transcript through this
// route and writes what it did to AMBIT_TEST_BROWSER_TRANSCRIPT_OUT. Given
// AMBIT_TEST_BROWSER_TRANSCRIPT_BASELINE, the result of another revision of
// the route on the same transcript, it states every difference by class and
// fails on any difference outside the classes the change owns. Skipped unless
// AMBIT_TEST_BROWSER_TRANSCRIPT names a transcript.
func TestBrowserViewTranscriptReplay(t *testing.T) {
	path, output := os.Getenv("AMBIT_TEST_BROWSER_TRANSCRIPT"), os.Getenv("AMBIT_TEST_BROWSER_TRANSCRIPT_OUT")
	if path == "" || output == "" {
		t.Skip("set AMBIT_TEST_BROWSER_TRANSCRIPT and AMBIT_TEST_BROWSER_TRANSCRIPT_OUT")
	}
	transcript, err := readBrowserViewTranscript(path)
	if err != nil {
		t.Fatal(err)
	}
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "replay-owner")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace.socketDir, "primary.transcript"), content, 0600); err != nil {
		t.Fatal(err)
	}
	workspace.runDriver(t, "replay-owner", "primary", "view-channel-replay")
	id, _ := workspace.only(t, "replay-owner", "primary")
	connection, response, err := websocket.DefaultDialer.Dial(browserViewerAddress(workspace.serve(t), "replay-owner", id)+"?"+transcript.header.Declaration,
		http.Header{"X-Ambit-Browser-Viewer": []string{transcript.header.Viewer}})
	if err != nil {
		t.Fatalf("replay dial: %v %v", err, response)
	}
	defer connection.Close()
	connection.SetReadLimit(64 << 20)
	steps := transcript.steps()
	var result browserViewReplayResult
	for {
		_ = connection.SetReadDeadline(time.Now().Add(20 * time.Second))
		kind, message, err := connection.ReadMessage()
		if err != nil {
			var closed *websocket.CloseError
			if !errors.As(err, &closed) {
				t.Fatalf("the replay ended without a close: %v", err)
			}
			result.Close = fmt.Sprintf("%d %s", closed.Code, closed.Text)
			break
		}
		if step, marker := browserViewReplayStep(message); marker && kind == websocket.TextMessage {
			if step >= len(steps) {
				t.Fatalf("a marker for step %d of %d", step, len(steps))
			}
			for _, reply := range steps[step].up {
				if err := connection.WriteMessage(websocket.TextMessage, reply); err != nil {
					t.Fatal(err)
				}
			}
			if err := connection.WriteMessage(websocket.TextMessage, browserViewReplayBarrier); err != nil {
				t.Fatal(err)
			}
			continue
		}
		result.Viewer = append(result.Viewer, browserViewTranscriptLine{Direction: "down", Binary: kind == websocket.BinaryMessage, Data: message})
	}
	result.Driver = awaitDriverReceived(t, workspace, "primary", 0)
	result.Upgrade = driverUpgrade(t, workspace, "primary")
	writeBrowserViewReplay(t, output, result)
	t.Logf("replayed %d messages in %d steps: the viewer received %d, the driver %d; closed %s", len(transcript.messages), len(steps), len(result.Viewer), len(result.Driver), result.Close)
	baseline := os.Getenv("AMBIT_TEST_BROWSER_TRANSCRIPT_BASELINE")
	if baseline == "" {
		return
	}
	previous := readBrowserViewReplay(t, baseline)
	report := compareBrowserViewReplays(previous, result)
	encoded, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filepath.Join(output, "comparison.json"), encoded, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("comparison with %s: %s", baseline, encoded)
	if len(report.Unexplained) != 0 {
		t.Fatalf("%d differences outside the classes this change owns", len(report.Unexplained))
	}
}

func writeBrowserViewReplay(t *testing.T, directory string, result browserViewReplayResult) {
	t.Helper()
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(directory, "replay.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := gzip.NewWriter(file)
	if err := json.NewEncoder(writer).Encode(result); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func readBrowserViewReplay(t *testing.T, directory string) browserViewReplayResult {
	t.Helper()
	file, err := os.Open(filepath.Join(directory, "replay.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	var result browserViewReplayResult
	if err := json.NewDecoder(reader).Decode(&result); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	return result
}

// The classes of difference this change owns. The route no longer rewrites
// what the driver says about pictures and sound, so the driver's own spelling
// of the same JSON reaches the viewer; it no longer drops pictures and sound
// of a subscription the viewer retired, which the viewer drops itself; and it
// no longer drops the viewer's stale acknowledgements and subscriptions,
// which the driver ignores itself. Anything else is unexplained.
type browserViewReplayComparison struct {
	Classes     map[string]int `json:"classes"`
	Unexplained []string       `json:"unexplained"`
	Upgrade     [2]string      `json:"upgrade"`
}

func compareBrowserViewReplays(base, head browserViewReplayResult) browserViewReplayComparison {
	report := browserViewReplayComparison{Classes: map[string]int{}, Upgrade: [2]string{base.Upgrade, head.Upgrade}}
	unexplained := func(format string, values ...any) {
		if len(report.Unexplained) < 20 {
			report.Unexplained = append(report.Unexplained, fmt.Sprintf(format, values...))
		}
	}
	i, j := 0, 0
	for i < len(head.Viewer) {
		h := head.Viewer[i]
		if j < len(base.Viewer) {
			b := base.Viewer[j]
			if b.Binary == h.Binary && bytes.Equal(b.Data, h.Data) {
				report.Classes["viewer: identical bytes"]++
				i, j = i+1, j+1
				continue
			}
			if class, same := browserViewSameMessage(b, h); same {
				report.Classes["viewer: "+class]++
				i, j = i+1, j+1
				continue
			}
		}
		if track := browserViewMediaTrack(h); track != "" {
			report.Classes["viewer: "+track+" the previous route dropped as not subscribed or retired"]++
			i++
			continue
		}
		unexplained("viewer message %d (%s) has no counterpart at base message %d (%s)", i, browserViewDescribe(h), j, browserViewDescribeAt(base.Viewer, j))
		break
	}
	if j < len(base.Viewer) && len(report.Unexplained) == 0 {
		unexplained("the viewer no longer receives base messages %d.. (%s)", j, browserViewDescribeAt(base.Viewer, j))
	}
	if base.Close != head.Close {
		unexplained("the channel closed %q, at base %q", head.Close, base.Close)
	} else {
		report.Classes["close: identical ("+head.Close+")"]++
	}
	i, j = 0, 0
	for i < len(head.Driver) {
		h := head.Driver[i]
		if j < len(base.Driver) && bytes.Equal(base.Driver[j], h) {
			report.Classes["driver: identical bytes"]++
			i, j = i+1, j+1
			continue
		}
		if j < len(base.Driver) && browserViewJSONEqual(base.Driver[j], h) {
			report.Classes["driver: the viewer's own spelling of the same JSON"]++
			i, j = i+1, j+1
			continue
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(h, &envelope) == nil && (envelope.Type == "ack" || envelope.Type == "audio" || envelope.Type == "video") {
			report.Classes["driver: "+envelope.Type+" the previous route dropped as stale or retired"]++
			i++
			continue
		}
		unexplained("driver message %d (%s) has no counterpart at base message %d", i, h, j)
		break
	}
	if j < len(base.Driver) && len(report.Unexplained) == 0 {
		unexplained("the driver no longer receives base messages %d.. (%s)", j, base.Driver[j])
	}
	if !reflect.DeepEqual(browserViewQueryMembers(base.Upgrade), browserViewQueryMembers(head.Upgrade)) {
		unexplained("the driver's upgrade %s, at base %s", head.Upgrade, base.Upgrade)
	} else if base.Upgrade == head.Upgrade {
		report.Classes["upgrade: identical"]++
	} else {
		report.Classes["upgrade: the same members in another order"]++
	}
	return report
}

// browserViewSameMessage reports whether two messages say the same thing in
// another spelling, and names the class: a record of a track with the same
// JSON, or a binary message with the same payload and the same JSON header.
func browserViewSameMessage(base, head browserViewTranscriptLine) (string, bool) {
	if base.Binary != head.Binary {
		return "", false
	}
	if !head.Binary {
		// Only a track's records are the driver's own now; every other record
		// is still the route's projection, byte for byte.
		if track := browserViewMediaTrack(head); track != "" && browserViewJSONEqual(base.Data, head.Data) {
			return track + ": the driver's spelling of the same JSON", true
		}
		return "", false
	}
	baseHeader, basePayload, baseValid := browserBinaryParts(base.Data)
	headHeader, headPayload, headValid := browserBinaryParts(head.Data)
	if !baseValid || !headValid || !bytes.Equal(basePayload, headPayload) || !browserViewJSONEqual(baseHeader, headHeader) {
		return "", false
	}
	var envelope struct {
		Type  string `json:"type"`
		Track string `json:"track"`
	}
	_ = json.Unmarshal(headHeader, &envelope)
	name := envelope.Type
	if envelope.Track != "" {
		name += " " + envelope.Track
	}
	return name + " header: the driver's spelling of the same JSON, payload identical", true
}

// browserViewMediaTrack names the track of a sound or picture unit or record,
// or returns "" for anything else.
func browserViewMediaTrack(message browserViewTranscriptLine) string {
	var envelope struct {
		Type  string `json:"type"`
		Track string `json:"track"`
	}
	if message.Binary {
		header, _, valid := browserBinaryParts(message.Data)
		if !valid || json.Unmarshal(header, &envelope) != nil || envelope.Type != "media" {
			return ""
		}
		return envelope.Track + " unit"
	}
	if json.Unmarshal(message.Data, &envelope) != nil || (envelope.Type != "audio" && envelope.Type != "video") {
		return ""
	}
	return envelope.Type + " record"
}

func browserViewJSONEqual(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && reflect.DeepEqual(left, right)
}

func browserViewQueryMembers(target string) []string {
	_, query, _ := strings.Cut(target, "?")
	members := strings.Split(query, "&")
	sort.Strings(members)
	return members
}

func browserViewDescribe(message browserViewTranscriptLine) string {
	if !message.Binary {
		if len(message.Data) > 160 {
			return string(message.Data[:160]) + "..."
		}
		return string(message.Data)
	}
	if len(message.Data) < 4 {
		return "binary"
	}
	length := int(binary.BigEndian.Uint32(message.Data[:4]))
	if length > len(message.Data)-4 || length > 400 {
		return fmt.Sprintf("binary %d bytes", len(message.Data))
	}
	return fmt.Sprintf("binary %s + %d bytes", message.Data[4:4+length], len(message.Data)-4-length)
}

func browserViewDescribeAt(messages []browserViewTranscriptLine, index int) string {
	if index >= len(messages) {
		return "none"
	}
	return browserViewDescribe(messages[index])
}

// Replay of a transcript made here, without a real driver: the route's own
// guarantees on a short exchange the previous route also carried, so the
// replay machinery itself is exercised on every run.
func TestBrowserViewTranscriptReplayRoundTrip(t *testing.T) {
	scratch := t.TempDir()
	path := filepath.Join(scratch, "transcript.jsonl.gz")
	frame := func(sequence int) []byte { return browserFixtureSequencedFrame(sequence) }
	lines := []any{
		browserViewTranscriptHeader{Declaration: "width=320&height=240&frames=binary&patches=1&frameWindow=8", Viewer: browserFixtureViewer, Driver: "fixture"},
		browserViewTranscriptLine{Direction: "down", Data: []byte(`{"type":"status","connected":true,"screencasting":true}`)},
		browserViewTranscriptLine{Direction: "down", Binary: true, Data: frame(10)},
		browserViewTranscriptLine{Direction: "up", Data: []byte(`{"type":"ack","seq":10}`)},
		browserViewTranscriptLine{Direction: "down", Binary: true, Data: frame(12)},
		browserViewTranscriptLine{Direction: "up", Data: []byte(`{"type":"presentation","width":400,"height":300}`)},
		browserViewTranscriptLine{Direction: "up", Data: []byte(`{"type":"ack","seq":12}`)},
		browserViewTranscriptLine{Direction: "down", Data: []byte(`{"type":"console","text":"` + browserFixtureSecret + `"}`)},
	}
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	for _, line := range lines {
		if err := json.NewEncoder(writer).Encode(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AMBIT_TEST_BROWSER_TRANSCRIPT", path)
	t.Setenv("AMBIT_TEST_BROWSER_TRANSCRIPT_OUT", filepath.Join(scratch, "out"))
	t.Setenv("AMBIT_TEST_BROWSER_TRANSCRIPT_BASELINE", "")
	TestBrowserViewTranscriptReplay(t)
	result := readBrowserViewReplay(t, filepath.Join(scratch, "out"))
	want := []browserViewTranscriptLine{
		{Direction: "down", Data: []byte(`{"type":"status","connected":true,"screencasting":true}`)},
		{Direction: "down", Binary: true, Data: frame(10)},
		{Direction: "down", Binary: true, Data: frame(12)},
	}
	if !reflect.DeepEqual(result.Viewer, want) {
		t.Fatalf("the viewer received %d messages: %v", len(result.Viewer), result.Viewer)
	}
	driver := []string{`{"type":"ack","seq":10}`, string(browserViewReplayBarrier), `{"type":"presentation","width":400,"height":300}`, `{"type":"ack","seq":12}`, string(browserViewReplayBarrier), string(browserViewReplayBarrier)}
	if len(result.Driver) != len(driver) {
		t.Fatalf("the driver received %q", result.Driver)
	}
	for index, message := range driver {
		if string(result.Driver[index]) != message {
			t.Fatalf("the driver received %s at %d, want %s", result.Driver[index], index, message)
		}
	}
	if result.Close != "1011 screencast_failed" {
		t.Fatalf("the replay closed %q", result.Close)
	}
}
