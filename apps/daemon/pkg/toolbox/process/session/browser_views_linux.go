// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	commonerrors "github.com/daytonaio/common-go/pkg/errors"
	nativesession "github.com/daytonaio/daemon/pkg/session"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

const (
	// A frame carries one screencast image. The read limit is the relay's whole
	// per-viewer buffer: ack pacing keeps exactly one frame in flight.
	browserFrameLimit = 32 << 20
	// One write to a viewer, and one acknowledgement to the driver, are bounded
	// so a stalled peer cannot pin this relay or its upstream connection.
	browserViewerWriteTimeout = 30 * time.Second
	browserDriverWriteTimeout = 5 * time.Second
	browserCustodyInterval    = time.Second
	browserDialTimeout        = 2 * time.Second
)

// The daemon's own terminal vocabulary. Neither record carries upstream text,
// because a driver message can contain task input.
var (
	browserFinishedRecord    = []byte(`{"type":"finished"}` + "\n")
	browserUnavailableRecord = []byte(`{"type":"unavailable","reason":"screencast_failed"}` + "\n")
)

type browserView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SessionID  string `json:"sessionId"`
	Namespace  string `json:"namespace,omitempty"`
	pid        int
	born       string
	port       uint16
	listener   string
	socketPath string
}

// browserViewAt uses the driver's Unix peer identity and kernel listening-socket
// ownership. Discovery never waits behind the driver's navigation command lock,
// never starts a screencast merely to discover a view, and never reads command
// output: a browser is proven by process custody, not by shell text.
func (s *SessionController) browserViewAt(ctx context.Context, sessionID, name, socketPath string) (browserView, error) {
	connection, err := (&net.Dialer{Timeout: browserDialTimeout}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return browserView{}, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(browserDialTimeout))
	raw, err := connection.(*net.UnixConn).SyscallConn()
	if err != nil {
		return browserView{}, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return browserView{}, err
	}
	if peerErr != nil {
		return browserView{}, peerErr
	}
	var identity nativesession.OwnedProcess
	if sessionID == "" {
		identity, err = s.sessionService.FindProcessSession(int(peer.Pid))
	} else {
		identity, err = s.sessionService.ObserveOwnedProcess(sessionID, int(peer.Pid))
	}
	if err != nil {
		return browserView{}, err
	}
	sessionID = identity.SessionID
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", peer.Pid))
	if err != nil {
		return browserView{}, err
	}
	if executable != s.browserExecutable {
		return browserView{}, fmt.Errorf("socket peer %q is not the workspace browser driver", executable)
	}
	port, err := browserStreamPort(filepath.Join(filepath.Dir(socketPath), name+".stream"))
	if err != nil {
		return browserView{}, err
	}
	listener, err := processBrowserListener(identity.PID, port)
	if err != nil {
		return browserView{}, err
	}
	if listener == "" {
		return browserView{}, errors.New("browser stream listener changed")
	}
	current, err := s.sessionService.ObserveOwnedProcess(sessionID, identity.PID)
	if err != nil || current != identity {
		return browserView{}, errors.New("browser process custody changed")
	}
	// A stream can be disabled and reopened without replacing the driver.
	// Its listening socket, not only the PID, identifies that visual instance.
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s", sessionID, name, identity.PID, identity.StartTime, listener)))
	return browserView{ID: hex.EncodeToString(hash[:]), Name: name, SessionID: sessionID, pid: identity.PID, born: identity.StartTime, port: port, listener: listener, socketPath: socketPath}, nil
}

// browserStreamPort reads the loopback port the driver advertises beside its
// socket. The file is the driver's own claim; ownership is proven separately.
func browserStreamPort(path string) (uint16, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	advertised, err := io.ReadAll(io.LimitReader(file, 64))
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(strings.TrimSpace(string(advertised)), 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("browser stream port %q is unavailable", strings.TrimSpace(string(advertised)))
	}
	return uint16(port), nil
}

// processSockets returns the kernel identities of every socket this process
// holds open.
func processSockets(pid int) (map[string]bool, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, err
	}
	inodes := map[string]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	return inodes, nil
}

// processHoldsSocket reports whether the process still holds this exact
// socket. A socket keeps its kernel identity until it is closed, so holding
// the listener's identity is holding that listener. This is how a proved view
// is re-proved on every command: the kernel's TCP table would answer the same
// question, but reading it walks every bucket of the host's established hash,
// which costs milliseconds and grows with the host rather than the workspace.
func processHoldsSocket(pid int, inode string) (bool, error) {
	inodes, err := processSockets(pid)
	if err != nil {
		return false, err
	}
	return inodes[inode], nil
}

// processBrowserListener returns the kernel identity of this process's exact
// listening socket. Reopening the same port creates a different view instance.
func processBrowserListener(pid int, port uint16) (string, error) {
	inodes, err := processSockets(pid)
	if err != nil {
		return "", err
	}
	table, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil {
		return "", err
	}
	address := fmt.Sprintf("0100007F:%04X", port)
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[1] == address && fields[3] == "0A" && inodes[fields[9]] {
			return fields[9], nil
		}
	}
	return "", nil
}

// browserViews observes the sockets in the workspace browser directory. With no
// session named, every session is a candidate owner; with one named, only that
// session's custody can answer, which is what keeps one Run's browser out of
// another Run's stream.
func (s *SessionController) browserViews(ctx context.Context, sessionID string) ([]browserView, error) {
	views := []browserView{}
	if sessionID != "" {
		observed, err := s.sessionService.Get(sessionID)
		if err != nil {
			return nil, err
		}
		// A running shell is the only state that can still own a browser. A
		// settled or unavailable scope owns nothing, which is an empty
		// observation rather than a failure to observe.
		if observed.ProcessScope != "running" {
			return views, nil
		}
	}
	entries, err := os.ReadDir(s.browserSocketDir)
	if os.IsNotExist(err) {
		return views, nil
	}
	if err != nil {
		return nil, err
	}
	type socketDirectory struct {
		path, namespace string
		entries         []os.DirEntry
	}
	directories := []socketDirectory{{path: s.browserSocketDir, entries: entries}}
	// The driver supports legacy flat sessions and isolated namespaces. Follow
	// that explicit layout instead of recursively walking arbitrary workspace
	// files or guessing ownership from directory names.
	namespaces, namespaceError := os.ReadDir(filepath.Join(s.browserSocketDir, "namespaces"))
	if namespaceError != nil && !os.IsNotExist(namespaceError) {
		s.logger.DebugContext(ctx, "browser namespaces are not observable", "error", namespaceError)
	}
	for _, namespace := range namespaces {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !namespace.IsDir() {
			continue
		}
		runDirectory := filepath.Join(s.browserSocketDir, "namespaces", namespace.Name(), "run")
		children, err := os.ReadDir(runDirectory)
		if err != nil {
			// An incomplete or retired namespace cannot hide a valid peer.
			continue
		}
		directories = append(directories, socketDirectory{path: runDirectory, namespace: namespace.Name(), entries: children})
	}
	for _, directory := range directories {
		for _, entry := range directory.entries {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			name, socket := strings.CutSuffix(entry.Name(), ".sock")
			if !socket || entry.Type()&os.ModeSocket == 0 {
				continue
			}
			view, err := s.browserViewAt(ctx, sessionID, name, filepath.Join(directory.path, entry.Name()))
			if err != nil {
				// A view is announced only on complete proof of custody. Anything
				// less means this one socket has no observable browser behind it
				// right now; it is never a statement about the sockets beside it,
				// so one retired, idle or half-written entry cannot mask the
				// workspace's other browsers.
				s.logger.DebugContext(ctx, "browser socket has no observable view", "name", name, "error", err)
				continue
			}
			view.Namespace = directory.namespace
			views = append(views, view)
		}
	}
	return views, nil
}

// ListBrowserViews exposes observed views, never daemon paths or loopback ports.
func (s *SessionController) ListBrowserViews(c *gin.Context) {
	views, err := s.browserViews(c.Request.Context(), "")
	if err != nil {
		browserObservationError(c, err)
		return
	}
	c.JSON(http.StatusOK, views)
}

// StreamBrowserView is output-only. Only protocol acknowledgements are sent to
// the driver; application clients cannot send browser input or CDP commands,
// and the driver's endpoint is never disclosed.
func (s *SessionController) StreamBrowserView(c *gin.Context) {
	presentation, valid := parseBrowserPresentation(c.Request)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_view_invalid"})
		return
	}
	sessionID := c.Param("sessionId")
	selected, ok := s.selectBrowserView(c)
	if !ok {
		return
	}
	maxFps := 10
	if presentation != nil {
		// The native presentation owner permits this rate only for the
		// primary connection; secondary viewers remain capped at 10 fps.
		maxFps = 60
	}
	address := fmt.Sprintf("ws://127.0.0.1:%d/?pacing=ack&maxFps=%d", selected.port, maxFps)
	patches := c.Query("patches") == "1"
	if patches {
		address += "&patches=1"
	}
	var headers http.Header
	if presentation != nil {
		address += fmt.Sprintf("&width=%d&height=%d", presentation.Width, presentation.Height)
		headers = http.Header{"X-Ambit-Browser-Viewer": []string{presentation.Viewer}}
	}
	upstream, _, err := (&websocket.Dialer{HandshakeTimeout: 5 * time.Second}).DialContext(c.Request.Context(), address, headers)
	if err != nil {
		c.Status(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	upstream.SetReadLimit(browserFrameLimit)
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()
	var finished atomic.Bool
	go func() {
		ticker := time.NewTicker(browserCustodyInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				upstream.Close()
				return
			case <-ticker.C:
				observed, err := s.sessionService.ObserveOwnedProcess(sessionID, selected.pid)
				if err != nil || observed.StartTime != selected.born {
					finished.Store(browserViewEnded(observed, selected.born, err))
					upstream.Close()
					return
				}
			}
		}
	}()
	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	c.Writer.Flush()
	for {
		_, message, err := upstream.ReadMessage()
		if err != nil {
			// Browser exit closes its socket before the periodic observation
			// necessarily runs. Reobserve this owner before classifying EOF.
			observed, custodyErr := s.sessionService.ObserveOwnedProcess(sessionID, selected.pid)
			if browserViewEnded(observed, selected.born, custodyErr) {
				finished.Store(true)
			}
			if finished.Load() && ctx.Err() == nil {
				_ = writeBrowserRecord(c, browserFinishedRecord)
			}
			return
		}
		filtered, sequence, kind := browserViewMessage(message, patches)
		switch kind {
		case browserRecordFinished:
			// The admitted driver ended this stream explicitly. Do not race
			// its subsequent process exit or forward any of its extra fields.
			_ = writeBrowserRecord(c, browserFinishedRecord)
			return
		case browserRecordFailed:
			// The driver reported that it cannot produce frames. The viewer is
			// owed that fact, never the driver's own text.
			_ = writeBrowserRecord(c, browserUnavailableRecord)
			return
		case browserRecordDropped:
			continue
		}
		// Exactly one upstream frame remains unacknowledged while HTTP output
		// is backpressured. No queue of stale frames is accumulated here.
		if err := writeBrowserRecord(c, append(filtered, '\n')); err != nil {
			return
		}
		if sequence != 0 {
			_ = upstream.SetWriteDeadline(time.Now().Add(browserDriverWriteTimeout))
			if err := upstream.WriteJSON(map[string]any{"type": "ack", "seq": sequence}); err != nil {
				return
			}
		}
	}
}

// writeBrowserRecord bounds one write to the viewer. A viewer that stops
// reading stalls the ack that paces the driver, so the driver stops producing;
// the deadline bounds the stall itself, and an in-process transport that cannot
// carry a deadline still gets the same records.
func writeBrowserRecord(c *gin.Context, record []byte) error {
	_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
	if _, err := c.Writer.Write(record); err != nil {
		return err
	}
	c.Writer.Flush()
	return nil
}

func browserObservationError(c *gin.Context, err error) {
	var absent *commonerrors.NotFoundError
	if errors.As(err, &absent) {
		c.Error(err)
		return
	}
	c.Error(commonerrors.NewCustomError(http.StatusServiceUnavailable, "Browser observation is temporarily unavailable.", "BROWSER_VIEW_UNAVAILABLE"))
}

// browserViewEnded reports that this exact view is over: the process is no
// longer this session's, its custody has ended, or the PID no longer names the
// process the view was admitted for. Anything else is a failure to observe,
// which is not a lifecycle fact and leaves the stream unlabelled.
func browserViewEnded(observed nativesession.OwnedProcess, born string, err error) bool {
	if err == nil {
		return observed.StartTime != born
	}
	return browserCustodyEnded(err) || errors.Is(err, nativesession.ErrProcessNotOwned)
}

func browserCustodyEnded(err error) bool {
	return errors.Is(err, nativesession.ErrProcessCustodyEnded) || errors.Is(err, os.ErrNotExist)
}

type browserRecordKind int

const (
	// Anything that is not part of the visual contract, including upstream
	// command and result payloads that can carry task input.
	browserRecordDropped browserRecordKind = iota
	// A frame, or the view state that frames are read against.
	browserRecordVisual
	// The driver's own failure. Its text never leaves the daemon.
	browserRecordFailed
	// Explicit terminal state from the already-attributed stream publisher.
	browserRecordFinished
)

func browserViewMessage(message []byte, patches bool) ([]byte, uint64, browserRecordKind) {
	var envelope struct {
		Type    string          `json:"type"`
		Seq     uint64          `json:"seq"`
		Surface json.RawMessage `json:"surface"`
	}
	if json.Unmarshal(message, &envelope) != nil {
		return nil, 0, browserRecordDropped
	}
	// One record is one line. A driver that terminates its own records must not
	// put a blank line into a viewer's NDJSON stream.
	body := bytes.TrimSpace(message)
	switch envelope.Type {
	case "frame":
		if envelope.Seq == 0 {
			return nil, 0, browserRecordDropped
		}
		if envelope.Surface != nil {
			var frame struct {
				Type     string              `json:"type"`
				Seq      uint64              `json:"seq"`
				Encoding string              `json:"encoding"`
				Data     string              `json:"data,omitempty"`
				BaseSeq  uint64              `json:"baseSeq,omitempty"`
				Patches  []browserFramePatch `json:"patches,omitempty"`
				Surface  browserSurface      `json:"surface"`
				browserFrameClock
			}
			if json.Unmarshal(message, &frame) != nil || !frame.Surface.valid() || frame.Encoding != "jpeg" || !frame.browserFrameClock.valid(frame.Surface) {
				return nil, 0, browserRecordFailed
			}
			if len(frame.Patches) > 0 {
				if !patches || frame.Data != "" || frame.BaseSeq == 0 || frame.BaseSeq >= frame.Seq || len(frame.Patches) > 64 {
					return nil, 0, browserRecordFailed
				}
				for _, patch := range frame.Patches {
					if !patch.valid(frame.Surface) {
						return nil, 0, browserRecordFailed
					}
				}
			} else if frame.Data == "" || frame.BaseSeq != 0 {
				return nil, 0, browserRecordFailed
			}
			projected, err := json.Marshal(frame)
			if err != nil {
				return nil, 0, browserRecordFailed
			}
			return projected, frame.Seq, browserRecordVisual
		}
		return body, envelope.Seq, browserRecordVisual
	case "status":
		var status struct {
			Type           string  `json:"type"`
			Connected      *bool   `json:"connected,omitempty"`
			Screencasting  *bool   `json:"screencasting,omitempty"`
			ViewportWidth  *uint32 `json:"viewportWidth,omitempty"`
			ViewportHeight *uint32 `json:"viewportHeight,omitempty"`
			Engine         *string `json:"engine,omitempty"`
			Recording      *bool   `json:"recording,omitempty"`
		}
		if json.Unmarshal(message, &status) != nil {
			return nil, 0, browserRecordDropped
		}
		projected, _ := json.Marshal(status)
		return projected, 0, browserRecordVisual
	case "url":
		var location struct {
			Type         string  `json:"type"`
			URL          string  `json:"url"`
			Title        *string `json:"title,omitempty"`
			Timestamp    *uint64 `json:"timestamp,omitempty"`
			CanGoBack    *bool   `json:"canGoBack,omitempty"`
			CanGoForward *bool   `json:"canGoForward,omitempty"`
		}
		if json.Unmarshal(message, &location) != nil {
			return nil, 0, browserRecordDropped
		}
		projected, _ := json.Marshal(location)
		return projected, 0, browserRecordVisual
	case "presentation":
		if projected, valid := browserPresentationMessage(message); valid {
			return projected, 0, browserRecordVisual
		}
		return nil, 0, browserRecordDropped
	case "pointer", "activity":
		if projected, valid := browserActivity(message); valid {
			return projected, 0, browserRecordVisual
		}
		return nil, 0, browserRecordDropped
	case "tabs":
		// A newly attached viewer receives the driver's current tab snapshot,
		// not a navigation event. Project only the active location into our
		// existing visual contract so reconnects do not wait for another click.
		var snapshot struct {
			Tabs []struct {
				Active       bool   `json:"active"`
				URL          string `json:"url"`
				Title        string `json:"title"`
				CanGoBack    *bool  `json:"canGoBack"`
				CanGoForward *bool  `json:"canGoForward"`
			} `json:"tabs"`
		}
		if json.Unmarshal(message, &snapshot) != nil {
			return nil, 0, browserRecordDropped
		}
		active := -1
		for index, tab := range snapshot.Tabs {
			if !tab.Active {
				continue
			}
			if active != -1 || tab.URL == "" {
				return nil, 0, browserRecordDropped
			}
			active = index
		}
		if active == -1 {
			return nil, 0, browserRecordDropped
		}
		tab := snapshot.Tabs[active]
		location, _ := json.Marshal(struct {
			Type         string `json:"type"`
			URL          string `json:"url"`
			Title        string `json:"title,omitempty"`
			CanGoBack    *bool  `json:"canGoBack,omitempty"`
			CanGoForward *bool  `json:"canGoForward,omitempty"`
		}{Type: "url", URL: tab.URL, Title: tab.Title, CanGoBack: tab.CanGoBack, CanGoForward: tab.CanGoForward})
		return location, 0, browserRecordVisual
	case "error":
		return nil, 0, browserRecordFailed
	case "finished":
		return nil, 0, browserRecordFinished
	default:
		return nil, 0, browserRecordDropped
	}
}
