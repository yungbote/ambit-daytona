// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"image"
	"os"
	"testing"
)

// This uses the real X server, fetch/conversion/cache and JPEG decoder. The
// generated red/blue gutter is deliberately outside the owned visible image.
func TestXvfbJPEGApertureKeepsEveryDecodedPixelIndependentOfPrivateGutters(t *testing.T) {
	startXvfb(t, 128, 96)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	for _, visible := range []image.Rectangle{image.Rect(0, 0, 93, 71), image.Rect(13, 11, 97, 83), image.Rect(31, 17, 62, 54)} {
		d.frames.endLayout(visible)
		var previous *image.YCbCr
		for _, secret := range []uint32{0xff0000, 0x0000ff} {
			page.fill(t, image.Rect(0, 0, 128, 96), secret)
			page.fill(t, visible, 0x00ff00)
			frame := expectFrame(t, d, captureOptions{force: true}, "owned aperture")
			if frame.Width != 128 || frame.Height != 96 || frame.Visible == nil || *frame.Visible != (visibleRect{visible.Min.X, visible.Min.Y, visible.Dx(), visible.Dy()}) {
				t.Fatalf("geometry changed: %+v", frame)
			}
			decoded := decodeJPEG(t, frame.Data)
			if previous != nil {
				samePixels(t, previous, decoded, decoded.Bounds(), image.Point{})
			}
			previous = decoded
			for _, point := range []image.Point{visible.Min, visible.Max.Sub(image.Pt(1, 1)), image.Pt(visible.Max.X-1, visible.Min.Y), image.Pt(visible.Min.X, visible.Max.Y-1)} {
				r, g, b, _ := decoded.At(point.X, point.Y).RGBA()
				if r>>8 > 6 || g>>8 < 249 || b>>8 > 6 {
					t.Fatalf("owned edge darkened at%v: %d,%d,%d", point, r>>8, g>>8, b>>8)
				}
			}
		}
	}
}

func TestXvfbJPEGAperturePreservesCompositedCursorAndRetiresOldApertureBands(t *testing.T) {
	startXvfb(t, 128, 96)
	d, err := openDisplay(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	page := newPainter(t)
	page.glyphCursor(t)
	visible := image.Rect(13, 11, 97, 83)
	d.frames.endLayout(visible)
	page.warp(t, 15, 13)
	var previous *image.YCbCr
	for _, secret := range []uint32{0xff0000, 0x0000ff} {
		page.fill(t, image.Rect(0, 0, 128, 96), secret)
		page.fill(t, visible, 0x00ff00)
		frame := expectFrame(t, d, captureOptions{force: true, cursor: true}, "public aperture with pointer")
		if !frame.CursorIncluded {
			t.Fatal("pointer composition metadata changed")
		}
		decoded := decodeJPEG(t, frame.Data)
		if previous != nil {
			samePixels(t, previous, decoded, decoded.Bounds(), image.Point{})
		}
		previous = decoded
	}
	without := decodeJPEG(t, expectFrame(t, d, captureOptions{force: true}, "same aperture without pointer").Data)
	different := false
	for y := visible.Min.Y; y < visible.Max.Y; y++ {
		for x := visible.Min.X; x < visible.Max.X; x++ {
			if previous.At(x, y) != without.At(x, y) {
				different = true
			}
		}
	}
	if !different {
		t.Fatal("public pointer was lost during masking")
	}
	// Pixel content stays unchanged; only the aperture moves/shrinks. Cached
	// full-frame bands must be rebuilt, even without a force request.
	next := image.Rect(31, 17, 62, 54)
	d.frames.endLayout(next)
	frame := expectFrame(t, d, captureOptions{}, "metadata-only new aperture")
	if frame.Visible == nil || *frame.Visible != (visibleRect{next.Min.X, next.Min.Y, next.Dx(), next.Dy()}) {
		t.Fatalf("new aperture missing: %+v", frame)
	}
	decoded := decodeJPEG(t, frame.Data)
	for y := 0; y < 96; y++ {
		for x := 0; x < 128; x++ {
			r, g, b, _ := decoded.At(x, y).RGBA()
			if r>>8 > 6 || g>>8 < 249 || b>>8 > 6 {
				t.Fatalf("retired aperture/private band survived at%d,%d: %d,%d,%d", x, y, r>>8, g>>8, b>>8)
			}
		}
	}
}
