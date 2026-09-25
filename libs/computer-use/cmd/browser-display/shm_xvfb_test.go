// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"image"
	"os"
	"testing"
)

// The retained framebuffer is shared with the server, and its frames are
// byte for byte those of the socket path.
func TestXvfbSharedMemoryFetchMatchesTheSocketFetch(t *testing.T) {
	startXvfb(t, 1466, 900)
	page := newPainter(t)
	page.fill(t, image.Rect(0, 0, 1466, 900), 0xf0f0f0)
	page.fill(t, image.Rect(100, 130, 900, 611), 0x235799)
	page.fill(t, image.Rect(700, 20, 1466, 64), 0x991111)
	shared, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer shared.close()
	socket, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer socket.close()
	socket.frames.shared.disable()
	a := expectFrame(t, shared, captureOptions{}, "shared-memory frame")
	if !shared.frames.shared.holds(shared.frames.pipeline.retained) {
		t.Fatal("the retained framebuffer is not in shared memory")
	}
	b := expectFrame(t, socket, captureOptions{}, "socket frame")
	if socket.frames.shared.holds(socket.frames.pipeline.retained) {
		t.Fatal("a disabled shared image was used")
	}
	if len(a.Data) == 0 || string(a.Data) != string(b.Data) {
		t.Fatal("shared-memory and socket frames differ")
	}
	// Incremental damage lands in shared memory too.
	page.fill(t, image.Rect(300, 300, 340, 340), 0x00ff00)
	patched := expectFrame(t, shared, captureOptions{patches: true}, "shared-memory patch")
	if len(patched.Patches) != 1 || !near(decodeJPEG(t, patched.Patches[0].Data).At(320-patched.Patches[0].X+patched.Patches[0].SourceX, 320-patched.Patches[0].Y+patched.Patches[0].SourceY), 0, 0xff, 0) {
		t.Fatalf("shared-memory patch: %+v", patched.Patches)
	}
}
