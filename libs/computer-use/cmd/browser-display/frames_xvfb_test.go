// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/xproto"
)

// startXvfb runs a private authenticated Xvfb for one test and points DISPLAY
// and XAUTHORITY at it.
func startXvfb(t *testing.T, width, height int) {
	t.Helper()
	binary, err := exec.LookPath("Xvfb")
	if err != nil {
		t.Skip("Xvfb is not on PATH")
	}
	authority := filepath.Join(t.TempDir(), "authority")
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		t.Fatal(err)
	}
	record := []byte{0xff, 0xff, 0, 0, 0, 0, 0, 18}
	record = append(record, "MIT-MAGIC-COOKIE-1"...)
	record = append(append(record, 0, 16), cookie...)
	if err := os.WriteFile(authority, record, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	server := exec.Command(binary, "-displayfd", "3", "-screen", "0", fmt.Sprintf("%dx%dx24", width, height), "-nolisten", "tcp", "-auth", authority)
	server.ExtraFiles = []*os.File{writer}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	t.Cleanup(func() {
		_ = server.Process.Signal(syscall.SIGTERM)
		stop := time.AfterFunc(5*time.Second, func() { _ = server.Process.Kill() })
		_ = server.Wait()
		stop.Stop()
	})
	_ = reader.SetReadDeadline(time.Now().Add(20 * time.Second))
	number := make([]byte, 16)
	n, err := reader.Read(number)
	reader.Close()
	if err != nil {
		t.Fatalf("Xvfb did not report its display: %v", err)
	}
	t.Setenv("DISPLAY", ":"+strings.TrimSpace(string(number[:n])))
	t.Setenv("XAUTHORITY", authority)
}

// painter draws on the root window over its own connection, like the browser.
type painter struct {
	conn *xgb.Conn
	root xproto.Window
	gc   xproto.Gcontext
}

func newPainter(t *testing.T) *painter {
	t.Helper()
	c, err := xgb.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		for {
			event, err := c.WaitForEvent()
			if event == nil || err != nil {
				return
			}
		}
	})
	root := xproto.Setup(c).DefaultScreen(c).Root
	gc, err := xproto.NewGcontextId(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.CreateGCChecked(c, gc, xproto.Drawable(root), xproto.GcForeground, []uint32{0}).Check(); err != nil {
		t.Fatal(err)
	}
	return &painter{conn: c, root: root, gc: gc}
}
func (p *painter) fill(t *testing.T, rect image.Rectangle, rgb uint32) {
	t.Helper()
	if err := xproto.ChangeGCChecked(p.conn, p.gc, xproto.GcForeground, []uint32{rgb}).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.PolyFillRectangleChecked(p.conn, xproto.Drawable(p.root), p.gc, []xproto.Rectangle{{X: int16(rect.Min.X), Y: int16(rect.Min.Y), Width: uint16(rect.Dx()), Height: uint16(rect.Dy())}}).Check(); err != nil {
		t.Fatal(err)
	}
}
func (p *painter) warp(t *testing.T, x, y int) {
	t.Helper()
	if err := xproto.WarpPointerChecked(p.conn, 0, p.root, 0, 0, 0, 0, int16(x), int16(y)).Check(); err != nil {
		t.Fatal(err)
	}
}
func (p *painter) glyphCursor(t *testing.T) {
	t.Helper()
	font, err := xproto.NewFontId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.OpenFontChecked(p.conn, font, 6, "cursor").Check(); err != nil {
		t.Fatal(err)
	}
	cursor, err := xproto.NewCursorId(p.conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := xproto.CreateGlyphCursorChecked(p.conn, cursor, font, font, 68, 69, 0, 0, 0, 0xffff, 0xffff, 0xffff).Check(); err != nil {
		t.Fatal(err)
	}
	if err := xproto.ChangeWindowAttributesChecked(p.conn, p.root, xproto.CwCursor, []uint32{uint32(cursor)}).Check(); err != nil {
		t.Fatal(err)
	}
}

func captureFrame(t *testing.T, d *display, options captureOptions) (capturedFrame, bool) {
	t.Helper()
	result, err := d.frames.capture(options)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	switch value := result.(type) {
	case unchangedFrame:
		return capturedFrame{}, false
	case capturedFrame:
		return value, true
	}
	t.Fatalf("capture returned %T", result)
	return capturedFrame{}, false
}
func expectFrame(t *testing.T, d *display, options captureOptions, why string) capturedFrame {
	t.Helper()
	frame, changed := captureFrame(t, d, options)
	if !changed {
		t.Fatalf("%s: reported unchanged", why)
	}
	t.Logf("%s: %dx%d quality %d data %d bytes patches %d timings %+v", why, frame.Width, frame.Height, frame.Quality, len(frame.Data), len(frame.Patches), frame.Timings)
	return frame
}
func expectUnchanged(t *testing.T, d *display, options captureOptions, why string) {
	t.Helper()
	if _, changed := captureFrame(t, d, options); changed {
		t.Fatalf("%s: reported a change", why)
	}
}
func near(actual color.Color, r, g, b uint8) bool {
	ar, ag, ab, _ := actual.RGBA()
	within := func(value uint32, expected uint8) bool {
		difference := int(value>>8) - int(expected)
		return difference >= -12 && difference <= 12
	}
	return within(ar, r) && within(ag, g) && within(ab, b)
}
func darkest(img image.Image, box image.Rectangle) uint32 {
	minimum := uint32(1 << 16)
	for y := box.Min.Y; y < box.Max.Y; y++ {
		for x := box.Min.X; x < box.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			minimum = min(minimum, (r+g+b)/3)
		}
	}
	return minimum >> 8
}

func TestXvfbIncrementalCapture(t *testing.T) {
	startXvfb(t, 1466, 1792)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	cursorOn := captureOptions{cursor: true}
	cursorOff := captureOptions{}

	first := expectFrame(t, d, cursorOn, "first frame")
	if first.Width != 1466 || first.Height != 1792 || first.Encoding != "jpeg" || !first.CursorIncluded || first.Quality != 85 || first.Patches != nil {
		t.Fatalf("first frame shape: %+v", first)
	}
	if decoded := decodeJPEG(t, first.Data); decoded.Rect != image.Rect(0, 0, 1466, 1792) {
		t.Fatalf("first frame decodes to %v", decoded.Rect)
	}
	expectUnchanged(t, d, cursorOn, "second frame")
	started := time.Now()
	for count := 0; count < 100; count++ {
		expectUnchanged(t, d, cursorOn, "idle frame")
	}
	idle := time.Since(started) / 100
	t.Logf("unchanged capture check: %v each", idle)

	page.fill(t, image.Rect(200, 300, 600, 500), 0x235799)
	patched := expectFrame(t, d, captureOptions{cursor: true, patches: true}, "filled rectangle as patch")
	if patched.Data != nil || len(patched.Patches) != 1 || patched.Patches[0].X != 176 || patched.Patches[0].Y != 272 || patched.Patches[0].Width != 448 || patched.Patches[0].Height != 256 || patched.Patches[0].SourceX != 16 || patched.Patches[0].SourceY != 16 {
		t.Fatalf("patch layout: %+v", patched.Patches)
	}
	if pixel := decodeJPEG(t, patched.Patches[0].Data).At(400-176+16, 400-272+16); !near(pixel, 0x23, 0x57, 0x99) {
		t.Fatalf("patch pixel %v", pixel)
	}
	full := expectFrame(t, d, captureOptions{cursor: true, force: true, patches: true}, "forced full frame after patch")
	if full.Data == nil || full.Patches != nil {
		t.Fatal("force did not produce a full frame")
	}
	if pixel := decodeJPEG(t, full.Data).At(400, 400); !near(pixel, 0x23, 0x57, 0x99) {
		t.Fatalf("full frame pixel %v", pixel)
	}
	expectUnchanged(t, d, cursorOn, "after forced frame")

	page.fill(t, image.Rect(400, 400, 700, 700), 0xffffff)
	page.glyphCursor(t)
	page.warp(t, 100, 100)
	expectFrame(t, d, cursorOn, "white background and new cursor")
	expectUnchanged(t, d, cursorOn, "settled cursor")
	page.warp(t, 500, 500)
	shown := expectFrame(t, d, cursorOn, "cursor warped into white")
	box := image.Rect(500, 500, 512, 512)
	if darkest(decodeJPEG(t, shown.Data), box) > 100 {
		t.Fatal("warped cursor is not composited")
	}
	expectUnchanged(t, d, cursorOn, "cursor at rest")
	hidden := expectFrame(t, d, cursorOff, "cursor no longer composited")
	if hidden.CursorIncluded || darkest(decodeJPEG(t, hidden.Data), box) < 200 {
		t.Fatal("composited cursor was not cleaned")
	}
	expectUnchanged(t, d, cursorOff, "cursor ignored at rest")
	page.warp(t, 520, 520)
	expectUnchanged(t, d, cursorOff, "cursor ignored while moving")
	expectFrame(t, d, cursorOn, "cursor composited again")

	if _, err := d.resize(1200, 900, 0); err != nil {
		t.Fatal(err)
	}
	resized := expectFrame(t, d, cursorOn, "resized display")
	if resized.Width != 1200 || resized.Height != 900 || decodeJPEG(t, resized.Data).Rect != image.Rect(0, 0, 1200, 900) {
		t.Fatalf("resized frame %dx%d", resized.Width, resized.Height)
	}
	expectUnchanged(t, d, cursorOn, "after resize")
	forced := expectFrame(t, d, captureOptions{cursor: true, force: true}, "forced unchanged frame")
	if !bytes.Equal(forced.Data, resized.Data) {
		t.Fatal("forced frame differs from the previous frame")
	}
	page.fill(t, image.Rect(0, 880, 1200, 900), 0x00ff00)
	bottom := expectFrame(t, d, cursorOn, "damage after resize")
	if pixel := decodeJPEG(t, bottom.Data).At(600, 890); !near(pixel, 0, 255, 0) {
		t.Fatalf("bottom band pixel %v", pixel)
	}

	var qualities []int
	for _, budget := range []int{1000, 1000, 0, 0, 0} {
		qualities = append(qualities, expectFrame(t, d, captureOptions{cursor: true, force: true, budget: budget}, "budgeted frame").Quality)
	}
	if fmt.Sprint(qualities) != "[85 75 65 75 85]" {
		t.Fatalf("quality ladder %v", qualities)
	}
	page.fill(t, image.Rect(10, 10, 20, 20), 0xff0000)
	if after := expectFrame(t, d, captureOptions{cursor: true, patches: true}, "patch after ladder settled"); after.Patches == nil {
		t.Fatal("patches refused once a full frame exists at the current quality")
	}
}

func TestXvfbInputNeverWaitsBehindCapture(t *testing.T) {
	startXvfb(t, 640, 480)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	// Hold the actual capture lock throughout input, info and reset. Even a
	// paused or backpressured encoder must not prevent their acknowledgement.
	d.frames.mu.Lock()
	defer d.frames.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		if err := d.input([]inputEvent{{Type: "input_mouse", EventType: "mouseMoved", X: 100, Y: 100}}); err != nil {
			done <- err
			return
		}
		if _, err := d.info(); err != nil {
			done <- err
			return
		}
		done <- d.reset()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("input, info or reset waited for the capture lock")
	}
}

func TestXvfbInputLatencyDuringCapture(t *testing.T) {
	startXvfb(t, 1466, 1792)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	expectFrame(t, d, captureOptions{cursor: true}, "first frame")
	measure := func(serialized bool) (worst, mean time.Duration, count int) {
		done := make(chan stageTimings, 1)
		go func() {
			defer close(done)
			var total stageTimings
			for frame := 0; frame < 20; frame++ {
				page.fill(t, image.Rect(0, 0, 1466, 1792), uint32(frame)*0x0a0a0a)
				captured := expectFrame(t, d, captureOptions{cursor: true}, "full-screen repaint")
				total.FetchUs += captured.Timings.FetchUs
				total.ConvertUs += captured.Timings.ConvertUs
				total.EncodeUs += captured.Timings.EncodeUs
				total.AssembleUs += captured.Timings.AssembleUs
			}
			done <- total
		}()
		var sum time.Duration
		for {
			select {
			case total, ok := <-done:
				if !ok {
					t.Fatal("capture stopped before the measurement completed")
				}
				t.Logf("20 full-screen captures, mean stages: fetch %d us convert %d us encode %d us assemble %d us", total.FetchUs/20, total.ConvertUs/20, total.EncodeUs/20, total.AssembleUs/20)
				return worst, sum / time.Duration(max(count, 1)), count
			default:
			}
			started := time.Now()
			if serialized {
				d.frames.mu.Lock()
			}
			err := d.input([]inputEvent{{Type: "input_mouse", EventType: "mouseMoved", X: float64(10 + count%100), Y: 20}})
			if serialized {
				d.frames.mu.Unlock()
			}
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("input: %v", err)
			}
			worst, sum, count = max(worst, elapsed), sum+elapsed, count+1
			time.Sleep(time.Millisecond)
		}
	}
	worst, mean, count := measure(false)
	t.Logf("concurrent channel: %d inputs during captures, worst %v mean %v", count, worst, mean)
	serialWorst, serialMean, serialCount := measure(true)
	t.Logf("single-channel model: %d inputs during captures, worst %v mean %v", serialCount, serialWorst, serialMean)
}

// TestHelperProcess is the helper itself when the protocol test re-executes
// the test binary with the helper's own arguments.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("AMBIT_HELPER_PROCESS") != "1" {
		t.Skip("not the helper process")
	}
	os.Args = []string{"browser-display", "--chrome-pid", os.Getenv("AMBIT_HELPER_PID"), "--capture-fd", "3"}
	main()
	os.Exit(0)
}
func TestXvfbProtocolServesCaptureChannelBesideStdin(t *testing.T) {
	startXvfb(t, 640, 480)
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "capture"), os.NewFile(uintptr(pair[1]), "capture-child")
	defer ours.Close()
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	helper.Env = append(os.Environ(), "AMBIT_HELPER_PROCESS=1", fmt.Sprintf("AMBIT_HELPER_PID=%d", os.Getpid()))
	helper.ExtraFiles = []*os.File{theirs}
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	helper.Stderr = &stderr
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	killer := time.AfterFunc(60*time.Second, func() { _ = helper.Process.Kill() })
	defer killer.Stop()
	replies := map[string]*bufio.Reader{"stdin": bufio.NewReaderSize(stdout, 1<<20), "capture": bufio.NewReaderSize(ours, 1<<20)}
	ask := func(channel, line string) response {
		t.Helper()
		var out *os.File
		if channel == "capture" {
			out = ours
		}
		var err error
		if out != nil {
			_, err = out.Write([]byte(line + "\n"))
		} else {
			_, err = stdin.Write([]byte(line + "\n"))
		}
		if err != nil {
			t.Fatalf("%s write: %v (stderr %q)", channel, err, stderr.String())
		}
		raw, err := replies[channel].ReadBytes('\n')
		if err != nil {
			t.Fatalf("%s reply: %v (stderr %q)", channel, err, stderr.String())
		}
		var reply response
		if err := json.Unmarshal(raw, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	data := func(reply response) map[string]any {
		t.Helper()
		if !reply.Success {
			t.Fatalf("request %d failed: %+v", reply.ID, reply.Error)
		}
		return reply.Data.(map[string]any)
	}
	first := data(ask("capture", `{"id":1,"op":"capture"}`))
	if first["changed"] != true || first["width"] != 640.0 || first["cursorIncluded"] != true || first["data"] == nil || first["timings"] == nil {
		t.Fatalf("first capture %v", first)
	}
	if reply := ask("capture", `{"id":2,"op":"info"}`); reply.Success || reply.Error.Code != "display_invalid" {
		t.Fatalf("capture channel served info: %+v", reply)
	}
	if info := data(ask("stdin", `{"id":3,"op":"info"}`)); info["width"] != 640.0 {
		t.Fatalf("info %v", info)
	}
	forced := data(ask("stdin", `{"id":4,"op":"capture","force":true,"patches":true}`))
	if forced["changed"] != true || forced["data"] == nil || forced["patches"] != nil {
		t.Fatalf("forced capture over stdin %v", forced)
	}
	for _, line := range []string{`{"id":5,"op":"capture","budgetBytes":-1}`, `{"id":6,"op":"resize","width":640,"height":480,"force":true}`, `{"id":7,"op":"info","cursor":true}`, `{"id":8,"op":"capture","patches":1}`} {
		if reply := ask("stdin", line); reply.Success || reply.Error.Code != "display_invalid" {
			t.Fatalf("accepted %s: %+v", line, reply)
		}
	}
	if idle := data(ask("capture", `{"id":9,"op":"capture"}`)); idle["changed"] != false || len(idle) != 1 {
		t.Fatalf("idle capture %v", idle)
	}
	if hidden := data(ask("capture", `{"id":10,"op":"capture","cursor":false}`)); hidden["changed"] != true || hidden["cursorIncluded"] != false {
		t.Fatalf("cursor removal %v", hidden)
	}
	ours.Close()
	if info := data(ask("stdin", `{"id":11,"op":"info"}`)); info["height"] != 480.0 {
		t.Fatalf("stdin after capture channel closed %v", info)
	}
	data(ask("stdin", `{"id":12,"op":"close"}`))
	if err := helper.Wait(); err != nil {
		t.Fatalf("helper exit: %v (stderr %q)", err, stderr.String())
	}
}
