// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/robotn/xgb/xproto"
	"golang.org/x/sys/unix"
)

// newSlot makes the shared memory a driver would hand over.
func newSlot(t *testing.T, size int) (*pixelSlot, int) {
	t.Helper()
	fd, err := unix.MemfdCreate("pixels", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		t.Fatal(err)
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := openPixelSlot(fd)
	if err != nil {
		t.Fatal(err)
	}
	return slot, duplicate
}

func takePicture(t *testing.T, d *display, options pictureOptions) (pictureFrame, bool) {
	t.Helper()
	result, err := d.frames.picture(options)
	if err != nil {
		t.Fatalf("picture: %v", err)
	}
	switch value := result.(type) {
	case unchangedFrame:
		return pictureFrame{}, false
	case pictureFrame:
		return value, true
	}
	t.Fatalf("picture returned %T", result)
	return pictureFrame{}, false
}

// rootPixels reads the root window's pixels as the server stores them.
func rootPixels(t *testing.T, d *display, width, height int) []byte {
	t.Helper()
	reply, err := xproto.GetImage(d.conn, xproto.ImageFormatZPixmap, xproto.Drawable(d.screen.Root), 0, 0, uint16(width), uint16(height), 0xffffffff).Reply()
	if err != nil {
		t.Fatal(err)
	}
	return reply.Data
}

func slotPixel(slot *pixelSlot, width, x, y int) [3]byte {
	at := (y*width + x) * 4
	return [3]byte{slot.memory[at+2], slot.memory[at+1], slot.memory[at]}
}

// A picture writes exactly the rows that changed since the previous picture
// into the slot, as the server has them, and names them; a forced picture
// writes every row; frames and pictures each see every change, whichever took
// it first.
func TestXvfbPicturesWriteWhatChangedIntoTheSlot(t *testing.T) {
	startXvfb(t, 640, 480)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if slices.Contains(d.frames.features(), "pictures") {
		t.Fatal("pictures advertised without a slot")
	}
	if _, err := d.frames.picture(pictureOptions{force: true}); err == nil {
		t.Fatal("a picture without a slot was answered")
	}
	slot, _ := newSlot(t, 4096*4*1024)
	d.frames.attachPixels(slot)
	if !slices.Contains(d.frames.features(), "pictures") {
		t.Fatal("pictures not advertised with a slot")
	}
	page := newPainter(t)
	page.fill(t, image.Rect(0, 0, 640, 480), 0x808080)
	first, changed := takePicture(t, d, pictureOptions{force: true})
	if !changed || first.Width != 640 || first.Height != 480 || first.Stride != 2560 || !slices.Equal(first.Rows, [][2]int{{0, 480}}) {
		t.Fatalf("first picture %+v", first)
	}
	if !bytes.Equal(slot.memory[:640*480*4], rootPixels(t, d, 640, 480)) {
		t.Fatal("the slot differs from the screen")
	}
	if _, changed := takePicture(t, d, pictureOptions{}); changed {
		t.Fatal("an unchanged screen gave a picture")
	}
	// A marker the next picture must not overwrite: only changed rows move.
	copy(slot.memory[:4], []byte{1, 2, 3, 4})
	page.fill(t, image.Rect(200, 300, 600, 400), 0x235799)
	painted, changed := takePicture(t, d, pictureOptions{})
	if !changed || !slices.Equal(painted.Rows, [][2]int{{288, 400}}) {
		t.Fatalf("painted rows %+v", painted.Rows)
	}
	if pixel := slotPixel(slot, 640, 300, 350); pixel != [3]byte{0x23, 0x57, 0x99} {
		t.Fatalf("painted pixel %v", pixel)
	}
	if !bytes.Equal(slot.memory[:4], []byte{1, 2, 3, 4}) {
		t.Fatal("an unchanged row was rewritten")
	}
	// Damage taken by a JPEG frame is still a picture's, and the reverse.
	page.fill(t, image.Rect(0, 0, 32, 32), 0xff0000)
	expectFrame(t, d, captureOptions{}, "frame takes the damage first")
	if taken, changed := takePicture(t, d, pictureOptions{}); !changed || !slices.Equal(taken.Rows, [][2]int{{0, 32}}) {
		t.Fatalf("picture after a frame %+v", taken)
	}
	page.fill(t, image.Rect(0, 460, 32, 480), 0x00ff00)
	if taken, changed := takePicture(t, d, pictureOptions{}); !changed || !slices.Equal(taken.Rows, [][2]int{{448, 480}}) {
		t.Fatalf("picture first %+v", taken)
	}
	expectFrame(t, d, captureOptions{}, "frame after a picture")
	// Forced: every row, and the slot is the screen again.
	forced, _ := takePicture(t, d, pictureOptions{force: true})
	if !slices.Equal(forced.Rows, [][2]int{{0, 480}}) || !bytes.Equal(slot.memory[:640*480*4], rootPixels(t, d, 640, 480)) {
		t.Fatalf("forced picture %+v", forced.Rows)
	}
	// A new framebuffer size rewrites everything at the new stride.
	if _, err := d.resize(512, 400, 0, false); err != nil {
		t.Fatal(err)
	}
	resized, _ := takePicture(t, d, pictureOptions{})
	if resized.Width != 512 || resized.Stride != 2048 || !slices.Equal(resized.Rows, [][2]int{{0, 400}}) ||
		!bytes.Equal(slot.memory[:512*400*4], rootPixels(t, d, 512, 400)) {
		t.Fatalf("resized picture %+v", resized)
	}
}

// A picture composites the cursor only when asked and rewrites the rows it
// drew on when the cursor moves or leaves the picture.
func TestXvfbPicturesCompositeAndRemoveTheCursor(t *testing.T) {
	startXvfb(t, 640, 480)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	slot, _ := newSlot(t, 640*480*4)
	d.frames.attachPixels(slot)
	page := newPainter(t)
	page.fill(t, image.Rect(0, 0, 640, 480), 0xffffff)
	page.glyphCursor(t)
	page.warp(t, 300, 200)
	takePicture(t, d, pictureOptions{force: true})
	shown, changed := takePicture(t, d, pictureOptions{cursor: true})
	if !changed || !shown.CursorIncluded || len(shown.Rows) == 0 {
		t.Fatalf("cursor picture %+v", shown)
	}
	darkest := 255
	for y := 190; y < 215; y++ {
		for x := 290; x < 315; x++ {
			pixel := slotPixel(slot, 640, x, y)
			darkest = min(darkest, int(pixel[0]))
		}
	}
	if darkest > 100 {
		t.Fatal("the cursor was not composited")
	}
	if _, changed := takePicture(t, d, pictureOptions{cursor: true}); changed {
		t.Fatal("a cursor at rest gave a picture")
	}
	hidden, changed := takePicture(t, d, pictureOptions{})
	if !changed || hidden.CursorIncluded {
		t.Fatalf("hiding the cursor %+v", hidden)
	}
	if !bytes.Equal(slot.memory[:640*480*4], rootPixels(t, d, 640, 480)) {
		t.Fatal("the composited cursor was left in the slot")
	}
}

// A capture waiting when a layout settles looks at its paint before the next
// layout begins, however soon that layout follows: a drag of many layouts
// shows the browser at each size. (JPEG frames and pictures wait alike.)
func TestXvfbAWaitingCaptureSeesEveryLayoutsPaint(t *testing.T) {
	startXvfb(t, 640, 480)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	expectFrame(t, d, captureOptions{}, "first frame")
	for step := 0; step < 5; step++ {
		d.frames.beginLayout()
		answered := make(chan any, 1)
		go func() {
			result, _ := d.frames.capture(captureOptions{wait: 200 * time.Millisecond})
			answered <- result
		}()
		// The capture is waiting on the layout; the browser paints; the layout
		// ends and the next begins at once, as a drag does.
		time.Sleep(20 * time.Millisecond)
		page.fill(t, image.Rect(0, step*16, 640, step*16+16), uint32(0x101010*(step+1)))
		d.frames.endLayout(image.Rectangle{})
		d.frames.beginLayout()
		select {
		case result := <-answered:
			if frame, ok := result.(capturedFrame); !ok || !frame.Changed {
				t.Fatalf("step %d: the waiting capture missed the paint: %T %+v", step, result, result)
			}
		case <-time.After(150 * time.Millisecond):
			t.Fatalf("step %d: the waiting capture never looked at the paint", step)
		}
		d.frames.endLayout(image.Rectangle{})
	}
}

// A layout waits for a read of the screen in progress, never for what a
// capture does with the pixels it read: while a capture holds the capture
// lock, as its conversion, encoding or slot copy does, a layout begins and
// ends at once.
func TestXvfbALayoutNeverWaitsForACapturesWorkAfterItsRead(t *testing.T) {
	startXvfb(t, 640, 480)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	d.frames.mu.Lock()
	laid := make(chan struct{})
	go func() {
		defer close(laid)
		d.frames.beginLayout()
		d.frames.endLayout(image.Rectangle{})
	}()
	select {
	case <-laid:
		d.frames.mu.Unlock()
	case <-time.After(time.Second):
		d.frames.mu.Unlock()
		<-laid
		t.Fatal("a layout waited for a capture's work after its read")
	}
}

// A layout that begins while a capture reads the screen waits for the read:
// the server is grabbed so the read stalls, and the layout begins only once
// the read has the pixels, which therefore show nothing of its geometry.
func TestXvfbALayoutWaitsForAReadInProgress(t *testing.T) {
	startXvfb(t, 640, 480)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page, grabber := newPainter(t), newPainter(t)
	expectFrame(t, d, captureOptions{}, "first frame")
	page.fill(t, image.Rect(0, 0, 640, 480), 0x204080)
	if err := xproto.GrabServerChecked(grabber.conn).Check(); err != nil {
		t.Fatal(err)
	}
	ungrabbed := false
	ungrab := func() {
		if !ungrabbed {
			ungrabbed = true
			if err := xproto.UngrabServerChecked(grabber.conn).Check(); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer ungrab()
	captured := make(chan any, 1)
	go func() {
		result, _ := d.frames.capture(captureOptions{})
		captured <- result
	}()
	// The capture is inside its read once it holds the gate.
	for deadline := time.Now().Add(2 * time.Second); d.frames.gate.TryLock(); {
		d.frames.gate.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the capture never began its read")
		}
		time.Sleep(time.Millisecond)
	}
	began := make(chan struct{})
	go func() {
		d.frames.beginLayout()
		close(began)
	}()
	select {
	case <-began:
		t.Fatal("a layout began during a read in progress")
	case <-time.After(100 * time.Millisecond):
	}
	ungrab()
	select {
	case result := <-captured:
		if frame, ok := result.(capturedFrame); !ok || !frame.Changed {
			t.Fatalf("the read in progress was not answered with its pixels: %T", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stalled read never finished")
	}
	select {
	case <-began:
	case <-time.After(time.Second):
		t.Fatal("the layout never began after the read")
	}
	d.frames.endLayout(image.Rectangle{})
}

// The picture channel is found in the environment, answers only pictures, and
// its slot holds the screen; the other channels refuse pictures.
func TestXvfbProtocolServesPicturesOnTheirOwnChannel(t *testing.T) {
	startXvfb(t, 320, 240)
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "pictures"), os.NewFile(uintptr(pair[1]), "pictures-child")
	defer ours.Close()
	pixels, err := unix.MemfdCreate("pixels", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Ftruncate(pixels, 320*240*4); err != nil {
		t.Fatal(err)
	}
	memory, err := unix.Mmap(pixels, 0, 320*240*4, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	// ExtraFiles start at descriptor 3: the capture channel's place. The
	// picture channel is 4 and the slot 5, as the driver passes them.
	capture, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	helper.ExtraFiles = []*os.File{capture, theirs, os.NewFile(uintptr(pixels), "pixels")}
	helper.Env = append(os.Environ(), "AMBIT_HELPER_PROCESS=1", fmt.Sprintf("AMBIT_HELPER_PID=%d", os.Getpid()),
		"BROWSER_DISPLAY_PICTURE_FD=4", "BROWSER_DISPLAY_PIXELS_FD=5")
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	theirs.Close()
	killer := time.AfterFunc(60*time.Second, func() { _ = helper.Process.Kill() })
	defer killer.Stop()
	control, pictures := bufio.NewReader(stdout), bufio.NewReader(ours)
	ask := func(write func([]byte) (int, error), reader *bufio.Reader, line string) response {
		t.Helper()
		if _, err := write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		raw, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var reply response
		if err := json.Unmarshal(raw, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	info := ask(stdin.Write, control, `{"id":1,"op":"info"}`)
	if features, _ := json.Marshal(info.Data.(map[string]any)["features"]); !bytes.Contains(features, []byte(`"pictures"`)) {
		t.Fatalf("info does not list pictures: %s", features)
	}
	first := ask(ours.Write, pictures, `{"id":2,"op":"picture","force":true,"cursor":false}`)
	data, _ := first.Data.(map[string]any)
	if !first.Success || data["changed"] != true || data["stride"] != 1280.0 {
		t.Fatalf("first picture %+v", first)
	}
	reader := newPainter(t)
	screen, err := xproto.GetImage(reader.conn, xproto.ImageFormatZPixmap, xproto.Drawable(reader.root), 0, 0, 320, 240, 0xffffffff).Reply()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(memory, screen.Data) {
		t.Fatal("the driver's view of the slot differs from the screen")
	}
	for _, refused := range []string{`{"id":3,"op":"capture"}`, `{"id":4,"op":"info"}`, `{"id":5,"op":"picture","patches":true}`, `{"id":6,"op":"picture","budgetBytes":1}`} {
		if reply := ask(ours.Write, pictures, refused); reply.Success || reply.Error.Code != "display_invalid" {
			t.Fatalf("the picture channel served %s: %+v", refused, reply)
		}
	}
	if reply := ask(stdin.Write, control, `{"id":7,"op":"picture"}`); reply.Success || reply.Error.Code != "display_invalid" {
		t.Fatalf("stdin served a picture: %+v", reply)
	}
	ask(stdin.Write, control, `{"id":8,"op":"close"}`)
	if err := helper.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
}
