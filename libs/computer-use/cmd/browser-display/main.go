// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// browser-display is a private child of one browser process. It has no listener,
// control lease or replay loop: the driver owns those concerns and serializes
// requests over stdio. DISPLAY and XAUTHORITY are inherited only by this child.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode/utf8"
)

const maximumRequest = 65536
const maximumPixels = 4096 * 4096
const maximumDimension = 4096
const maximumClipboard = 1024 * 1024
const maximumPasteRequest = maximumClipboard*6 + 8192

type request struct {
	ID       uint64       `json:"id"`
	Op       string       `json:"op"`
	Width    int          `json:"width,omitempty"`
	Height   int          `json:"height,omitempty"`
	WindowID uint32       `json:"windowId,omitempty"`
	Events   []inputEvent `json:"events,omitempty"`
	// capture only: composite the cursor (default true), the JPEG byte budget
	// driving quality (0 is none), a full frame even when nothing changed, and
	// permission to answer with patches of the damaged rectangles instead.
	Cursor      *bool `json:"cursor,omitempty"`
	BudgetBytes int   `json:"budgetBytes,omitempty"`
	Force       bool  `json:"force,omitempty"`
	Patches     bool  `json:"patches,omitempty"`
	// capture only: wait up to this many milliseconds for a change before
	// answering unchanged, and report the cursor's identity when it changed.
	WaitMs         int  `json:"waitMs,omitempty"`
	CursorIdentity bool `json:"cursorIdentity,omitempty"`
}
type failure struct {
	Code               string `json:"code"`
	Message            string `json:"message"`
	OperationPerformed any    `json:"operationPerformed"`
}

func (f *failure) Error() string { return f.Message }
func invalid() error             { return &failure{"display_invalid", "The display request is invalid.", false} }
func unavailable() error {
	return &failure{"display_unavailable", "The owned browser display is unavailable.", false}
}
func unknown() error {
	return &failure{"display_outcome_unknown", "The display did not acknowledge the operation. Observe before continuing.", "unknown"}
}

type response struct {
	ID      uint64   `json:"id"`
	Success bool     `json:"success"`
	Data    any      `json:"data,omitempty"`
	Error   *failure `json:"error,omitempty"`
}

func decodeRequest(line []byte) (request, error) {
	var value request
	if len(line) > maximumPasteRequest || !utf8.Valid(line) {
		return value, invalid()
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return value, invalid()
	}
	var extra any
	if d.Decode(&extra) != io.EOF || value.ID == 0 {
		return value, invalid()
	}
	captureFields := value.Cursor != nil || value.BudgetBytes != 0 || value.Force || value.Patches || value.WaitMs != 0 || value.CursorIdentity
	switch value.Op {
	case "capture":
		if value.Width != 0 || value.Height != 0 || value.WindowID != 0 || value.Events != nil || value.BudgetBytes < 0 ||
			value.WaitMs < 0 || value.WaitMs > int(maximumCaptureWait/time.Millisecond) {
			return value, invalid()
		}
	case "info", "copy", "reset", "close":
		if value.Width != 0 || value.Height != 0 || value.WindowID != 0 || value.Events != nil || captureFields {
			return value, invalid()
		}
	case "resize":
		if value.Events != nil || captureFields || !validSize(value.Width, value.Height) {
			return value, invalid()
		}
	case "input":
		if value.Width != 0 || value.Height != 0 || value.WindowID != 0 || captureFields || len(value.Events) < 1 || len(value.Events) > 64 {
			return value, invalid()
		}
	default:
		return value, invalid()
	}
	if len(line) > maximumRequest && !singleClipboardPaste(value) {
		return value, invalid()
	}
	return value, nil
}
func singleClipboardPaste(value request) bool {
	return value.Op == "input" && len(value.Events) == 1 && value.Events[0].Type == "input_keyboard" && value.Events[0].EventType == "insertText" && len(value.Events[0].Text) > 0 && len(value.Events[0].Text) <= maximumClipboard
}
func validSize(width, height int) bool {
	return width > 0 && height > 0 && width <= maximumDimension && height <= maximumDimension && width*height <= maximumPixels
}

func main() {
	pid := flag.Int("chrome-pid", 0, "PID of the browser owning this private display")
	captureFD := flag.Int("capture-fd", 0, "descriptor serving capture requests concurrently with stdin")
	flag.Parse()
	if *pid <= 0 || (*captureFD != 0 && *captureFD < 3) || flag.NArg() != 0 || !regexp.MustCompile(`^:[0-9]+(?:\.[0-9]+)?$`).MatchString(os.Getenv("DISPLAY")) || !filepath.IsAbs(os.Getenv("XAUTHORITY")) {
		fmt.Fprintln(os.Stderr, "A private browser display and its authority are required.")
		os.Exit(2)
	}
	auth, err := os.Stat(os.Getenv("XAUTHORITY"))
	if err != nil || !auth.Mode().IsRegular() || auth.Mode().Perm()&0077 != 0 || !explicitAuthority(os.Getenv("XAUTHORITY"), os.Getenv("DISPLAY")) {
		fmt.Fprintln(os.Stderr, "The private display authority is unavailable.")
		os.Exit(2)
	}
	display, err := openDisplay(*pid)
	if err != nil {
		fmt.Fprintln(os.Stderr, "The private browser display could not be opened.")
		os.Exit(2)
	}
	defer display.close()
	if *captureFD != 0 {
		captures := os.NewFile(uintptr(*captureFD), "capture")
		go display.serve(captures, captures, true)
	}
	display.serve(os.Stdin, os.Stdout, false)
}

// serve answers one channel's line-delimited requests in order until the
// channel ends or a close request succeeds. The capture channel accepts only
// capture, so a frame in flight never delays input on stdin.
func (d *display) serve(in io.Reader, out io.Writer, captureOnly bool) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), maximumPasteRequest+1)
	writer := bufio.NewWriter(out)
	for scanner.Scan() {
		req, err := decodeRequest(scanner.Bytes())
		if err == nil && captureOnly && req.Op != "capture" {
			err = invalid()
		}
		var result any
		if err == nil {
			result, err = d.execute(req)
		}
		reply := response{ID: req.ID, Success: err == nil, Data: result}
		if err != nil {
			var typed *failure
			if !errors.As(err, &typed) {
				typed = unavailable().(*failure)
			}
			reply.Error = typed
			reply.Data = nil
		}
		// Never log requests, clipboard text, page pixels or native error payloads.
		if json.NewEncoder(writer).Encode(reply) != nil || writer.Flush() != nil {
			return
		}
		if req.Op == "close" && err == nil {
			return
		}
	}
}

func (d *display) execute(req request) (any, error) {
	switch req.Op {
	case "info":
		return d.describe()
	case "capture":
		return d.frames.capture(captureOptions{cursor: req.Cursor == nil || *req.Cursor, budget: req.BudgetBytes, force: req.Force, patches: req.Patches,
			wait: time.Duration(req.WaitMs) * time.Millisecond, identity: req.CursorIdentity})
	case "resize":
		return d.resize(req.Width, req.Height, req.WindowID)
	case "input":
		return map[string]any{}, d.input(req.Events)
	case "copy":
		return d.copy()
	case "reset", "close":
		return map[string]any{}, d.reset()
	}
	return nil, invalid()
}
