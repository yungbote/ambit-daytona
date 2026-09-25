// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bytes"
	"image/png"
	"math/rand"
	"testing"
)

func noisyCursor(side int, seed int64) []uint32 {
	random := rand.New(rand.NewSource(seed))
	pixels := make([]uint32, side*side)
	for index := range pixels {
		alpha := uint32(random.Intn(256))
		channel := func() uint32 { return uint32(random.Intn(int(alpha) + 1)) }
		pixels[index] = alpha<<24 | channel()<<16 | channel()<<8 | channel()
	}
	return pixels
}

// A page's own cursor travels as a PNG of its device pixels. One that does
// not fit the budget is halved once to scale 1; one that still does not fit
// is the default arrow rather than a truncated or missing picture.
func TestUnknownCursorTravelsAsABoundedPNG(t *testing.T) {
	small := make([]uint32, 48*48)
	for index := range small {
		small[index] = 0xffff0000
	}
	identity := describeCursor(7, 48, 48, 24, 24, small)
	if identity.CSS != nil || identity.Image == nil || identity.Image.Scale != 2 || identity.Image.Width != 48 || identity.Image.HotX != 24 || identity.Serial != 7 {
		t.Fatalf("small custom cursor: %+v", identity)
	}
	decoded, err := png.Decode(bytes.NewReader(identity.Image.PNG))
	if err != nil || decoded.Bounds().Dx() != 48 {
		t.Fatalf("cursor PNG does not decode: %v", err)
	}
	if identity.Image.Hash != cursorHash(48, 48, 24, 24, small) || len(identity.Image.Hash) != 16 {
		t.Fatalf("hash %q", identity.Image.Hash)
	}

	// 64x64 of noise is far over 4 KiB; 32x32 of the same noise still is not
	// small, so find a size whose halving fits.
	var halved cursorIdentity
	for side := 40; side <= 64; side += 8 {
		pixels := noisyCursor(side, int64(side))
		if encodeCursorPNG(cursorPixels{side, side, 3, 5, pixels}) != nil {
			continue
		}
		halved = describeCursor(1, side, side, 3, 5, pixels)
		if halved.Image != nil {
			if halved.Image.Scale != 1 || halved.Image.Width != side/2 || halved.Image.HotX != 1 || halved.Image.HotY != 2 || len(halved.Image.PNG) > maximumCursorPNG {
				t.Fatalf("halved cursor: %+v", halved.Image)
			}
			break
		}
	}
	if halved.Image == nil {
		t.Fatal("no oversized cursor was halved")
	}

	huge := describeCursor(2, 256, 256, 0, 0, noisyCursor(256, 9))
	if huge.CSS == nil || *huge.CSS != "default" || huge.Image != nil {
		t.Fatalf("incompressible cursor: %+v", huge)
	}
	malformed := describeCursor(3, 4, 4, 0, 0, make([]uint32, 3))
	if malformed.CSS == nil || *malformed.CSS != "default" {
		t.Fatalf("malformed cursor: %+v", malformed)
	}
}

// A halved cursor keeps its hotspot inside the image, including a hotspot on
// the last column or row of an odd side, which has no half of its own; the
// relay refuses a record whose hotspot lies outside it.
func TestHalvedCursorKeepsItsHotspotInside(t *testing.T) {
	for _, test := range []struct{ side, hot, wantSide, wantHot int }{
		{5, 4, 2, 1}, {5, 2, 2, 1}, {6, 5, 3, 2}, {1, 0, 1, 0}, {49, 48, 24, 23},
	} {
		halved := cursorPixels{test.side, test.side, test.hot, test.hot, make([]uint32, test.side*test.side)}.halved()
		if halved.width != test.wantSide || halved.hotX != test.wantHot || halved.hotY != test.wantHot || halved.hotX >= halved.width {
			t.Errorf("%+v: halved to %dx%d hotspot %d,%d", test, halved.width, halved.height, halved.hotX, halved.hotY)
		}
	}
}

// Identity is reported once per observable change: a new serial for the same
// keyword is not a change, and a return to an earlier cursor is.
func TestCursorIdentityIsReportedOncePerObservableChange(t *testing.T) {
	var tracker cursorTracker
	if tracker.unreported() != nil {
		t.Fatal("reported before any cursor was known")
	}
	set := func(serial uint32, keyword string) {
		tracker.known = true
		tracker.current = cursorIdentity{Serial: serial, CSS: &keyword}
	}
	set(1, "default")
	first := tracker.unreported()
	if first == nil || *first.CSS != "default" {
		t.Fatal("the first identity must always be reported")
	}
	if tracker.unreported() == nil {
		t.Fatal("an undelivered identity was dropped")
	}
	tracker.delivered(first)
	if tracker.unreported() != nil {
		t.Fatal("a delivered identity was repeated")
	}
	set(2, "default")
	if tracker.unreported() != nil {
		t.Fatal("a new serial of the same cursor was reported")
	}
	set(3, "pointer")
	pointer := tracker.unreported()
	tracker.delivered(pointer)
	set(1, "default")
	if again := tracker.unreported(); again == nil || again.Serial != 1 {
		t.Fatal("a return to an earlier cursor was not reported")
	}
}

func TestSizeClassGrowsAtOnceAndShrinksOnlyTwoStepsSmallerOnceSettled(t *testing.T) {
	for _, test := range []struct {
		width, height, currentW, currentH int
		settled                           bool
		wantW, wantH                      int
	}{
		{1418, 1888, 4096, 4096, true, 1536, 2048},  // first layout from the launch size
		{1418, 1888, 4096, 4096, false, 4096, 4096}, // too soon after a change
		{1500, 1900, 1536, 2048, false, 1536, 2048}, // inside the class
		{1600, 1900, 1536, 2048, false, 1792, 2048}, // grows at once
		{1100, 1900, 1536, 2048, true, 1536, 2048},  // one step smaller stays
		{1000, 1500, 1536, 2048, true, 1024, 1536},  // two steps smaller shrinks
		{4000, 10, 1024, 1024, true, 4096, 256},     // bounded by the display limit
		{256, 256, 256, 256, true, 256, 256},        // exact multiples
	} {
		w, h := framebufferFor(test.width, test.height, test.currentW, test.currentH, 4096, 4096, test.settled)
		if w != test.wantW || h != test.wantH {
			t.Errorf("%+v: got %dx%d", test, w, h)
		}
	}
	if w, h := framebufferFor(1000, 900, 512, 512, 1100, 1000, true); w != 1024 || h != 1000 {
		t.Errorf("limit: got %dx%d", w, h)
	}
}
