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
	var tracker cursorTracker
	small := make([]uint32, 48*48)
	for index := range small {
		small[index] = 0xffff0000
	}
	identity := tracker.describe(7, 48, 48, 24, 24, small)
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
		halved = tracker.describe(1, side, side, 3, 5, pixels)
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

	huge := tracker.describe(2, 256, 256, 0, 0, noisyCursor(256, 9))
	if huge.CSS == nil || *huge.CSS != "default" || huge.Image != nil {
		t.Fatalf("incompressible cursor: %+v", huge)
	}
	malformed := tracker.describe(3, 4, 4, 0, 0, make([]uint32, 3))
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

// A capture fetches nothing while the newest announced cursor is the one held,
// or while nothing was announced since the subscription.
func TestCursorTrackerFetchesNothingForTheCursorItHolds(t *testing.T) {
	tracker := cursorTracker{known: true, current: cursorIdentity{Serial: 7}}
	if tracker.begin(nil) != nil {
		t.Fatal("fetched with nothing announced")
	}
	tracker.notify(7)
	if tracker.begin(nil) != nil {
		t.Fatal("fetched the cursor held")
	}
}

// A page cursor's picture is described once per hash, however often the
// browser recreates the cursor, including one that fits no budget, and the
// pictures kept stay bounded.
func TestPageCursorPicturesAreDescribedOncePerHashWithinABound(t *testing.T) {
	var tracker cursorTracker
	solid := func(side int, argb uint32) []uint32 {
		pixels := make([]uint32, side*side)
		for index := range pixels {
			pixels[index] = argb
		}
		return pixels
	}
	pixels := solid(48, 0xff00ff00)
	first := tracker.describe(3, 48, 48, 1, 1, pixels)
	again := tracker.describe(5, 48, 48, 1, 1, pixels)
	if first.Image == nil || again.Serial != 5 || again.Image != first.Image {
		t.Fatalf("a recreated cursor was described again: %+v then %+v", first.Image, again.Image)
	}
	huge := noisyCursor(256, 9)
	if unfit := tracker.describe(6, 256, 256, 0, 0, huge); unfit.CSS == nil || *unfit.CSS != "default" {
		t.Fatalf("unfit cursor: %+v", unfit)
	}
	if picture, kept := tracker.pictures[cursorHash(256, 256, 0, 0, huge)]; !kept || picture != nil {
		t.Fatal("a cursor that fits no budget would be encoded again on every sighting")
	}
	for index := 0; index < 3*maximumCursorPictures; index++ {
		tracker.describe(uint32(10+index), 8, 8, 0, 0, solid(8, 0xff000000|uint32(index)))
		if len(tracker.pictures) > maximumCursorPictures {
			t.Fatalf("%d pictures kept", len(tracker.pictures))
		}
	}
}
