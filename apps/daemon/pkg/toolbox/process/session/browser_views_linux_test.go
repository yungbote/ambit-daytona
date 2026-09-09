//go:build linux

package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daytonaio/daemon/pkg/session"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// browserFixtureSecret stands for anything a driver channel can carry out of
// the task. It must never appear in a viewer's stream.
const browserFixtureSecret = "task-input-that-must-never-reach-a-viewer"

const browserFixtureFrames = 5

// runBrowserFixture stands in for the workspace browser driver. It owns its
// Unix socket, its loopback screencast listener and the port file beside the
// socket exactly as the real driver does, and speaks the same ack-paced record
// protocol, so discovery and relay are exercised against a real process with
// real kernel socket ownership instead of a stub of the daemon's own code.
func runBrowserFixture(args []string) bool {
	if len(args) != 4 || args[0] != "--browser-fixture" {
		return false
	}
	dir, name, mode := args[1], args[2], args[3]
	control, err := net.Listen("unix", filepath.Join(dir, name+".sock"))
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			connection, err := control.Accept()
			if err != nil {
				return
			}
			// Discovery reads only the peer credential. The driver's command
			// channel is never spoken to.
			_ = connection.Close()
		}
	}()
	screencast, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pacing") != "ack" || r.URL.Query().Get("maxFps") != "10" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		serveBrowserFixture(connection, mode)
	})}
	go func() { _ = server.Serve(screencast) }()
	if err := os.WriteFile(filepath.Join(dir, name+".pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		panic(err)
	}
	port := screencast.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(filepath.Join(dir, name+".stream"), []byte(strconv.Itoa(port)+"\n"), 0600); err != nil {
		panic(err)
	}
	// A failed test is bounded even if its cleanup path is broken.
	time.Sleep(30 * time.Second)
	return true
}

func serveBrowserFixture(connection *websocket.Conn, mode string) {
	send := func(record map[string]any) bool { return connection.WriteJSON(record) == nil }
	if !send(map[string]any{"type": "status", "connected": true, "screencasting": true}) {
		return
	}
	if !send(map[string]any{"type": "url", "url": "https://example.test/one", "timestamp": 1}) {
		return
	}
	// Driver channels that carry task input. Neither is visual state.
	if !send(map[string]any{"type": "console", "text": browserFixtureSecret}) {
		return
	}
	if !send(map[string]any{"type": "result", "data": map[string]string{"token": browserFixtureSecret}}) {
		return
	}
	if mode == "driver-error" {
		_ = send(map[string]any{"type": "error", "message": browserFixtureSecret})
		drainBrowserFixture(connection)
		return
	}
	acknowledged := 0
	for sequence := 1; sequence <= browserFixtureFrames; sequence++ {
		// "acks" is how many frames this driver had acknowledged before it
		// produced this one, which is what proves the relay's pacing.
		if !send(map[string]any{"type": "frame", "seq": sequence, "acks": acknowledged, "data": "AA=="}) {
			return
		}
		var ack struct {
			Type string `json:"type"`
			Seq  int    `json:"seq"`
		}
		if err := connection.ReadJSON(&ack); err != nil || ack.Type != "ack" || ack.Seq != sequence {
			return
		}
		acknowledged++
	}
	drainBrowserFixture(connection)
}

func drainBrowserFixture(connection *websocket.Conn) {
	for {
		if _, _, err := connection.ReadMessage(); err != nil {
			return
		}
	}
}

// browserWorkspace is one daemon serving one workspace: real routes, real
// error middleware, a real session service, and a browser socket directory a
// test can own.
type browserWorkspace struct {
	engine    *gin.Engine
	socketDir string
}

func newBrowserWorkspace(t *testing.T) *browserWorkspace {
	t.Helper()
	socketDir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := newSessionEngine(t, t.TempDir(), func(controller *SessionController) {
		controller.browserSocketDir = socketDir
		// The driver stand-in is this test binary, re-executed.
		controller.browserExecutable = executable
	})
	return &browserWorkspace{engine: engine, socketDir: socketDir}
}

// open starts a session and returns its supervisor. Sessions start their
// supervisor as a direct child of this process, so the child that appears is
// the one this create started; naming it is what lets a test end that shell.
func (w *browserWorkspace) open(t *testing.T, sessionID string) int {
	t.Helper()
	before := directChildren(t)
	if code, body := call(t, w.engine, http.MethodPost, "/process/session", CreateSessionRequest{SessionId: sessionID}); code != http.StatusCreated {
		t.Fatalf("CREATE %s = %d %s, want 201", sessionID, code, body)
	}
	t.Cleanup(func() { call(t, w.engine, http.MethodDelete, "/process/session/"+sessionID, nil) })
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		for pid := range directChildren(t) {
			if !before[pid] {
				return pid
			}
		}
	}
	t.Fatalf("session %s started no supervisor", sessionID)
	return 0
}

// runDriver starts the driver stand-in with no wait at all — the zero-wait
// program start an agent uses — and returns once its socket and advertised
// port exist. The command stays running for the rest of the test.
func (w *browserWorkspace) runDriver(t *testing.T, sessionID, name, mode string) int {
	t.Helper()
	code, body := call(t, w.engine, http.MethodPost, "/process/session/"+sessionID+"/exec",
		SessionExecuteRequest{Command: browserFixtureCommand(t, w.socketDir, name, mode), RunAsync: true})
	if code != http.StatusAccepted {
		t.Fatalf("zero-wait driver start = %d %s, want 202", code, body)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(awaitFile(t, filepath.Join(w.socketDir, name+".pid")))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	awaitFile(t, filepath.Join(w.socketDir, name+".stream"))
	awaitPath(t, filepath.Join(w.socketDir, name+".sock"))
	return pid
}

func (w *browserWorkspace) views(t *testing.T) ([]map[string]any, string) {
	t.Helper()
	code, body := call(t, w.engine, http.MethodGet, "/process/browser-views", nil)
	if code != http.StatusOK {
		t.Fatalf("LIST browser views = %d %s, want 200", code, body)
	}
	var views []map[string]any
	if err := json.Unmarshal(body, &views); err != nil {
		t.Fatalf("browser view listing %s: %v", body, err)
	}
	return views, string(body)
}

// only returns the single view this workspace observes, failing otherwise.
func (w *browserWorkspace) only(t *testing.T, sessionID, name string) (string, string) {
	t.Helper()
	views, body := w.views(t)
	if len(views) != 1 {
		t.Fatalf("browser view listing = %s, want exactly one view", body)
	}
	id, _ := views[0]["id"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) {
		t.Fatalf("browser view id %q is not an opaque identity", id)
	}
	if views[0]["name"] != name || views[0]["sessionId"] != sessionID {
		t.Fatalf("browser view %s is not %s/%s", body, sessionID, name)
	}
	return id, body
}

func browserFixtureCommand(t *testing.T, dir, name, mode string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }
	return fmt.Sprintf("%s --browser-fixture %s %s %s </dev/null >/dev/null 2>&1",
		quote(executable), quote(dir), quote(name), quote(mode))
}

// directChildren reads the kernel's own child list for this process, the same
// interface session custody itself relies on.
func directChildren(t *testing.T) map[int]bool {
	t.Helper()
	children := map[int]bool{}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		content, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "children"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range strings.Fields(string(content)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				t.Fatal(err)
			}
			children[pid] = true
		}
	}
	return children
}

// endShellUncleanly is what a crashed or killed session shell looks like: the
// supervisor records no settlement, so the scope becomes unavailable.
func (w *browserWorkspace) endShellUncleanly(t *testing.T, sessionID string, supervisor int) {
	t.Helper()
	if err := syscall.Kill(supervisor, syscall.SIGKILL); err != nil {
		t.Fatalf("end session supervisor %d: %v", supervisor, err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		code, body := call(t, w.engine, http.MethodGet, "/process/session/"+sessionID, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s after an unclean shell exit = %d %s", sessionID, code, body)
		}
		var observed SessionDTO
		if err := json.Unmarshal(body, &observed); err != nil {
			t.Fatal(err)
		}
		if observed.ProcessScope == "unavailable" {
			return
		}
	}
	t.Fatalf("session %s never reported an unclean shell exit", sessionID)
}

func awaitFile(t *testing.T, path string) []byte {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		content, err := os.ReadFile(path)
		if err == nil {
			return content
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	t.Fatalf("%s never appeared", path)
	return nil
}

func awaitPath(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Lstat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	t.Fatalf("%s never appeared", path)
}

func streamRecords(t *testing.T, body io.ReadCloser) chan string {
	t.Helper()
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(body)
		scanner.Buffer(make([]byte, 64<<10), browserFrameLimit)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	t.Cleanup(func() { _ = body.Close() })
	return lines
}

func nextRecord(t *testing.T, records chan string, within time.Duration) map[string]any {
	t.Helper()
	select {
	case line, open := <-records:
		if !open {
			t.Fatal("the browser stream ended before its next record")
		}
		if strings.Contains(line, browserFixtureSecret) {
			t.Fatalf("a driver channel reached the viewer: %s", line)
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("browser stream record %s: %v", line, err)
		}
		return record
	case <-time.After(within):
		t.Fatal("the browser stream produced no record in time")
		return nil
	}
}

func expectStreamEnd(t *testing.T, records chan string, within time.Duration) {
	t.Helper()
	select {
	case line, open := <-records:
		if open {
			t.Fatalf("the browser stream continued past its terminal record: %s", line)
		}
	case <-time.After(within):
		t.Fatal("the browser stream never ended")
	}
}

// openStream reads a view through the real HTTP transport, so backpressure and
// chunked delivery are the ones a client actually gets.
func openStream(t *testing.T, engine *gin.Engine, sessionID, viewID string) (int, chan string) {
	t.Helper()
	server := httptest.NewServer(engine)
	t.Cleanup(server.Close)
	response, err := server.Client().Get(server.URL + "/process/session/" + sessionID + "/browser-views/" + viewID + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return response.StatusCode, nil
	}
	if kind := response.Header.Get("Content-Type"); kind != "application/x-ndjson" {
		t.Fatalf("browser stream content type %q", kind)
	}
	return response.StatusCode, streamRecords(t, response.Body)
}

// Discovery must observe a real driver process through its socket peer identity
// and the kernel's listening-socket ownership, while that session is running
// commands, and must never let one session's state answer for the workspace.
func TestBrowserDiscoveryFollowsProcessCustodyWhileCommandsRun(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	driver := workspace.runDriver(t, "browser-owner", "primary", "frames")

	// A command is in flight for the whole listing below: discovery reads
	// process custody, never command output or shell text, so it neither waits
	// for the command nor is confused by it.
	running := make(chan struct{})
	go func() {
		defer close(running)
		call(t, workspace.engine, http.MethodPost, "/process/session/browser-owner/exec",
			SessionExecuteRequest{Command: "sleep 2"})
	}()
	defer func() { <-running }()

	id, body := workspace.only(t, "browser-owner", "primary")
	port := strings.TrimSpace(string(awaitFile(t, filepath.Join(workspace.socketDir, "primary.stream"))))
	for _, disclosed := range []string{port, workspace.socketDir, strconv.Itoa(driver)} {
		if strings.Contains(body, disclosed) {
			t.Fatalf("browser view listing disclosed %q: %s", disclosed, body)
		}
	}

	// Another session in the same workspace must not be able to read this view,
	// however healthy its own custody is.
	workspace.open(t, "other-owner")
	if code, _ := openStream(t, workspace.engine, "other-owner", id); code != http.StatusNotFound {
		t.Fatalf("cross-session stream = %d, want 404", code)
	}

	// One session whose shell died must not answer for the workspace. Before
	// this, its unclassified custody error joined the workspace-wide lookup and
	// every browser in the workspace disappeared behind a 503.
	idle := workspace.open(t, "idle-owner")
	workspace.endShellUncleanly(t, "idle-owner", idle)
	if again, _ := workspace.only(t, "browser-owner", "primary"); again != id {
		t.Fatalf("browser view identity changed to %s", again)
	}
}

// A viewer is owed one frame at a time and an honest end. The relay holds one
// frame, acknowledges it only after the viewer has it, and reports the browser
// finishing even when the shell under it ended uncleanly.
func TestBrowserStreamPacesFramesAndFinishesOnAnUncleanShellExit(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	supervisor := workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "frames")
	id, _ := workspace.only(t, "browser-owner", "primary")

	code, records := openStream(t, workspace.engine, "browser-owner", id)
	if code != http.StatusOK {
		t.Fatalf("stream = %d, want 200", code)
	}
	if state := nextRecord(t, records, 15*time.Second); state["type"] != "status" {
		t.Fatalf("first record %v, want the view state", state)
	}
	if location := nextRecord(t, records, 5*time.Second); location["type"] != "url" {
		t.Fatalf("second record %v, want the view location", location)
	}
	for sequence := 1; sequence <= browserFixtureFrames; sequence++ {
		frame := nextRecord(t, records, 10*time.Second)
		if frame["type"] != "frame" || frame["seq"] != float64(sequence) {
			t.Fatalf("record %v, want frame %d", frame, sequence)
		}
		// The driver produced this frame with exactly the earlier frames
		// acknowledged, so at most one frame is ever in flight.
		if frame["acks"] != float64(sequence-1) {
			t.Fatalf("frame %d was produced with %v acknowledgements, want %d", sequence, frame["acks"], sequence-1)
		}
	}

	workspace.endShellUncleanly(t, "browser-owner", supervisor)
	if end := nextRecord(t, records, 15*time.Second); end["type"] != "finished" {
		t.Fatalf("terminal record %v, want finished", end)
	}
	expectStreamEnd(t, records, 15*time.Second)
}

// A driver that cannot produce frames is a fact the viewer is owed. Its own
// message can carry task input, so only the daemon's vocabulary is relayed.
func TestBrowserStreamReportsADriverFailureWithoutItsText(t *testing.T) {
	workspace := newBrowserWorkspace(t)
	workspace.open(t, "browser-owner")
	workspace.runDriver(t, "browser-owner", "primary", "driver-error")
	id, _ := workspace.only(t, "browser-owner", "primary")

	code, records := openStream(t, workspace.engine, "browser-owner", id)
	if code != http.StatusOK {
		t.Fatalf("stream = %d, want 200", code)
	}
	if state := nextRecord(t, records, 15*time.Second); state["type"] != "status" {
		t.Fatalf("first record %v, want the view state", state)
	}
	if location := nextRecord(t, records, 5*time.Second); location["type"] != "url" {
		t.Fatalf("second record %v, want the view location", location)
	}
	end := nextRecord(t, records, 10*time.Second)
	if end["type"] != "unavailable" || end["reason"] != "screencast_failed" {
		t.Fatalf("terminal record %v, want an unavailable screencast", end)
	}
	expectStreamEnd(t, records, 10*time.Second)
}

func TestBrowserPortRequiresTheAdvertisedProcessesListeningSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	defer listener.Close()
	if owned, err := processOwnsBrowserPort(os.Getpid(), port); err != nil || !owned {
		t.Fatalf("own listener was not observed: owned=%v error=%v", owned, err)
	}
	listener.Close()
	if owned, err := processOwnsBrowserPort(os.Getpid(), port); err != nil || owned {
		t.Fatalf("closed listener remained owned: owned=%v error=%v", owned, err)
	}
}

func TestVisualStreamRejectsCommandsAndNonvisualData(t *testing.T) {
	for _, value := range []string{
		`{"type":"command","command":"secret task input"}`,
		`{"type":"result","data":{"token":"secret"}}`,
		`{"type":"console","text":"secret task input"}`,
		`{"type":"frame","seq":0}`,
		`{"type":"frame","seq":-1}`,
		`{"type":"frame","seq":"3"}`,
		`not json`,
	} {
		if _, _, kind := browserViewMessage([]byte(value)); kind != browserRecordDropped {
			t.Fatalf("forwarded nonvisual or malformed message: %s", value)
		}
	}
	// A driver failure is a fact the viewer is owed; its text is not.
	if body, _, kind := browserViewMessage([]byte(`{"type":"error","message":"secret task input"}`)); kind != browserRecordFailed || body != nil {
		t.Fatalf("driver failure was relayed as %v with body %s", kind, body)
	}
	frame := []byte(`{"type":"frame","seq":17,"data":"AA==","metadata":{"deviceWidth":1280,"deviceHeight":720}}`)
	if body, ack, kind := browserViewMessage(frame); kind != browserRecordVisual || ack != 17 || string(body) != string(frame) {
		t.Fatal("visual frame lost its acknowledgment identity")
	}
	for _, value := range []string{`{"type":"status","connected":false}`, `{"type":"url","url":"https://example.com"}`} {
		if _, ack, kind := browserViewMessage([]byte(value)); kind != browserRecordVisual || ack != 0 {
			t.Fatalf("visual state was rejected or treated as a frame: %s", value)
		}
	}
}

// A viewer is told a view finished only for a lifecycle fact. A failure to
// observe is not one: it must leave the stream unlabelled rather than claim a
// live browser ended.
func TestBrowserViewEndIsALifecycleFactNotAnObservationFailure(t *testing.T) {
	born := session.OwnedProcess{PID: 41, StartTime: "8100", SessionID: "owner"}
	for name, ended := range map[string]struct {
		observed session.OwnedProcess
		err      error
		want     bool
	}{
		"still the same process":  {born, nil, false},
		"the PID names another":   {session.OwnedProcess{PID: 41, StartTime: "9200"}, nil, true},
		"custody ended":           {session.OwnedProcess{}, session.ErrProcessCustodyEnded, true},
		"no longer owned":         {session.OwnedProcess{}, session.ErrProcessNotOwned, true},
		"the process is gone":     {session.OwnedProcess{}, os.ErrNotExist, true},
		"the owner is unreadable": {session.OwnedProcess{}, os.ErrPermission, false},
	} {
		if browserViewEnded(ended.observed, born.StartTime, ended.err) != ended.want {
			t.Fatalf("%s: view end reported %v, want %v", name, !ended.want, ended.want)
		}
	}
}
