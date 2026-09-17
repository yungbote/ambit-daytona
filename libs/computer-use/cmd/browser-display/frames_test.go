// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
)

var bgrxLayout = pixelLayout{depth: 24, format: xproto.Format{Depth: 24, BitsPerPixel: 32, ScanlinePad: 32}, visual: xproto.VisualInfo{RedMask: 0xff0000, GreenMask: 0xff00, BlueMask: 0xff}, order: xproto.ImageOrderLSBFirst}

// syntheticBGRX is page-like content: gradients, hard edges and a little noise.
func syntheticBGRX(width, height int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	raw := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := (y*width + x) * 4
			raw[offset] = byte(((x/32 + y/32) % 2) * 200)
			raw[offset+1] = byte(y * 255 / max(height-1, 1))
			raw[offset+2] = byte(x*255/max(width-1, 1) + rng.Intn(16))
		}
	}
	return raw
}
func syntheticYCbCr(width, height int, seed int64) *image.YCbCr {
	img := image.NewYCbCr(image.Rect(0, 0, width, height), image.YCbCrSubsampleRatio420)
	rng := rand.New(rand.NewSource(seed))
	for index := range img.Y {
		img.Y[index] = byte((index*7)%251) ^ byte(rng.Intn(8))
	}
	for index := range img.Cb {
		img.Cb[index] = byte(100 + (index*3)%90)
		img.Cr[index] = byte(200 - (index*5)%120)
	}
	return img
}
func newTestPipeline(t testing.TB, width, height int, raw []byte) *framePipeline {
	t.Helper()
	p := &framePipeline{}
	p.init(bgrxLayout, runtime.GOMAXPROCS(0))
	p.resize(width, height)
	if err := p.store(0, bandCount(height)-1, raw); err != nil {
		t.Fatal(err)
	}
	return p
}
func allBands(count int) []bool {
	marked := make([]bool, count)
	for index := range marked {
		marked[index] = true
	}
	return marked
}
func decodeJPEG(t testing.TB, data []byte) *image.YCbCr {
	t.Helper()
	decoded, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	ycc, ok := decoded.(*image.YCbCr)
	if !ok {
		t.Fatalf("decoded %T", decoded)
	}
	return ycc
}
func samePixels(t testing.TB, expected, actual *image.YCbCr, region image.Rectangle, offset image.Point) {
	t.Helper()
	for y := region.Min.Y; y < region.Max.Y; y++ {
		for x := region.Min.X; x < region.Max.X; x++ {
			ax, ay := x-offset.X, y-offset.Y
			if expected.Y[expected.YOffset(x, y)] != actual.Y[actual.YOffset(ax, ay)] || expected.Cb[expected.COffset(x, y)] != actual.Cb[actual.COffset(ax, ay)] || expected.Cr[expected.COffset(x, y)] != actual.Cr[actual.COffset(ax, ay)] {
				t.Fatalf("pixel (%d,%d) differs", x, y)
			}
		}
	}
}
func encodeMonolithic(t testing.TB, img image.Image, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestMosaicDecodesExactlyLikeOneMonolithicEncode(t *testing.T) {
	for _, size := range []image.Point{{1466, 1792}, {730, 898}, {20, 20}} {
		for _, quality := range []int{85, 35} {
			t.Run(fmt.Sprintf("%dx%d_q%d", size.X, size.Y, quality), func(t *testing.T) {
				img := syntheticYCbCr(size.X, size.Y, int64(size.X))
				var m bandMosaic
				m.reset(size.X, size.Y)
				for band := 0; band < bandCount(size.Y); band++ {
					if err := m.store(band, encodeMonolithic(t, img.SubImage(bandRect(band, size.X, size.Y)), quality)); err != nil {
						t.Fatal(err)
					}
				}
				frame, err := m.assemble()
				if err != nil {
					t.Fatal(err)
				}
				expected := decodeJPEG(t, encodeMonolithic(t, img, quality))
				actual := decodeJPEG(t, frame)
				if actual.Rect != img.Rect {
					t.Fatalf("frame bounds %v", actual.Rect)
				}
				samePixels(t, expected, actual, img.Rect, image.Point{})
			})
		}
	}
}
func TestPipelineFullFrameMatchesMonolithicEncodeOfItsConversion(t *testing.T) {
	width, height := 730, 898
	p := newTestPipeline(t, width, height, syntheticBGRX(width, height, 1))
	marked := allBands(bandCount(height))
	p.convert(marked)
	var timings stageTimings
	frame, err := p.encodeFull(marked, &timings)
	if err != nil {
		t.Fatal(err)
	}
	samePixels(t, decodeJPEG(t, encodeMonolithic(t, p.ycc, 85)), decodeJPEG(t, frame), p.surface(), image.Point{})
}
func TestIncrementalUpdateIsByteIdenticalToAFreshFullFrame(t *testing.T) {
	width, height := 1466, 1792
	before := syntheticBGRX(width, height, 2)
	after := append([]byte(nil), before...)
	changed := []int{0, 3, 7, bandCount(height) - 1}
	for _, band := range changed {
		rect := bandRect(band, width, height)
		for index := rect.Min.Y * width * 4; index < rect.Max.Y*width*4; index++ {
			after[index] ^= 0x5a
		}
	}
	p := newTestPipeline(t, width, height, before)
	p.convert(allBands(bandCount(height)))
	var timings stageTimings
	if _, err := p.encodeFull(allBands(bandCount(height)), &timings); err != nil {
		t.Fatal(err)
	}
	marked := make([]bool, bandCount(height))
	for _, band := range changed {
		marked[band] = true
		if err := p.store(band, band, after[bandRect(band, width, height).Min.Y*width*4:]); err != nil {
			t.Fatal(err)
		}
	}
	p.convert(marked)
	incremental, err := p.encodeFull(marked, &timings)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newTestPipeline(t, width, height, after)
	fresh.convert(allBands(bandCount(height)))
	full, err := fresh.encodeFull(allBands(bandCount(height)), &timings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(incremental, full) {
		t.Fatal("incremental frame differs from a fresh full frame")
	}
	original := newTestPipeline(t, width, height, before)
	original.convert(allBands(bandCount(height)))
	originalFrame, err := original.encodeFull(allBands(bandCount(height)), &timings)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(incremental, originalFrame) {
		t.Fatal("changed bands were not re-encoded")
	}
}
func TestPatchesDecodeToTheFullFrameRegion(t *testing.T) {
	width, height := 1466, 1792
	p := newTestPipeline(t, width, height, syntheticBGRX(width, height, 3))
	p.convert(allBands(bandCount(height)))
	var timings stageTimings
	full, err := p.encodeFull(allBands(bandCount(height)), &timings)
	if err != nil {
		t.Fatal(err)
	}
	rects := []image.Rectangle{image.Rect(0, 0, 16, 16), image.Rect(256, 512, 768, 1024), image.Rect(1440, 1776, 1466, 1792), image.Rect(960, 0, 1466, 512)}
	patches, err := p.encodePatches(rects, &timings)
	if err != nil {
		t.Fatal(err)
	}
	expected := decodeJPEG(t, full)
	for index, patch := range patches {
		actual := decodeJPEG(t, patch.Data)
		source := patchSource(rects[index], p.surface())
		if actual.Rect.Size() != source.Size() || patch.X != rects[index].Min.X || patch.Y != rects[index].Min.Y || patch.SourceX != patch.X-source.Min.X || patch.SourceY != patch.Y-source.Min.Y {
			t.Fatalf("patch %d geometry %v %v", index, actual.Rect, patch)
		}
		samePixels(t, expected, actual, rects[index], source.Min)
	}
	for band := range p.mosaic.valid {
		touched := false
		for _, rect := range rects {
			if band >= rect.Min.Y/bandRows && band < (rect.Max.Y+bandRows-1)/bandRows {
				touched = true
			}
		}
		if p.mosaic.valid[band] == touched {
			t.Fatalf("band %d cache validity %v after patches", band, p.mosaic.valid[band])
		}
	}
}
func TestSegmentsParseRealEncoderOutput(t *testing.T) {
	img := syntheticYCbCr(730, 16, 9)
	encoded := encodeMonolithic(t, img, 85)
	segments, err := splitJPEG(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var markers []byte
	for position := 0; position < len(segments.tables); {
		markers = append(markers, segments.tables[position+1])
		position += 2 + (int(segments.tables[position+2])<<8 | int(segments.tables[position+3]))
	}
	if !bytes.Equal(markers, []byte{0xdb, 0xc0, 0xc4}) || segments.tables[segments.frame+1] != 0xc0 {
		t.Fatalf("tables %x", markers)
	}
	if !bytes.Equal(segments.scan[:2], []byte{0xff, 0xda}) || len(segments.entropy) != len(encoded)-2-len(segments.tables)-14-2 {
		t.Fatal("scan layout")
	}
	header, err := frameHeader(segments, 730, 1792)
	if err != nil {
		t.Fatal(err)
	}
	sof := header[2+segments.frame:]
	if int(sof[5])<<8|int(sof[6]) != 1792 || int(sof[7])<<8|int(sof[8]) != 730 {
		t.Fatal("frame size was not rewritten")
	}
	dri := header[len(header)-14-6:]
	if !bytes.Equal(dri[:6], []byte{0xff, 0xdd, 0, 4, 0, 46}) {
		t.Fatalf("restart interval %x", dri[:6])
	}
	if _, err := frameHeader(segments, 731, 1792); err == nil {
		t.Fatal("foreign width accepted")
	}
	for _, malformed := range [][]byte{nil, encoded[1:], encoded[:len(encoded)-1], encoded[:40], append(append([]byte(nil), encoded[:2]...), encoded[len(encoded)-2:]...)} {
		if _, err := splitJPEG(malformed); err == nil {
			t.Fatal("malformed input accepted")
		}
	}
}
func TestQualityLadderStepsOncePerFrameWithHysteresis(t *testing.T) {
	var c qualityController
	steps := []struct {
		frame, budget, quality int
		changed                bool
	}{
		{150, 100, 75, true}, {150, 100, 65, true}, {150, 100, 55, true}, {150, 100, 45, true}, {150, 100, 35, true}, {150, 100, 35, false},
		{60, 100, 35, false}, {54, 100, 45, true}, {100, 100, 45, false}, {54, 100, 55, true},
		{1000, 0, 65, true}, {1000, 0, 75, true}, {1000, 0, 85, true}, {1000, 0, 85, false}, {10, 100, 85, false},
		{150, 100, 75, true}, {150, int(^uint(0) >> 1), 85, true},
	}
	for index, step := range steps {
		if changed := c.adapt(step.frame, step.budget); changed != step.changed || c.quality() != step.quality {
			t.Fatalf("step %d: quality %d changed %v", index, c.quality(), changed)
		}
	}
}
func TestBandRowsCoverPartialLastBandAndBoundaries(t *testing.T) {
	for _, test := range []struct {
		height, top, bottom int
		bands               []int
	}{
		{100, 95, 100, []int{5, 6}}, {100, 16, 32, []int{1}}, {100, 15, 33, []int{0, 1, 2}}, {100, 0, 0, nil}, {100, 15, 15, nil}, {100, 200, 300, nil}, {100, -8, 1, []int{0}}, {100, 96, 400, []int{6}}, {16, 0, 16, []int{0}}, {17, 16, 17, []int{1}},
	} {
		marked := make([]bool, bandCount(test.height))
		markRows(marked, test.top, test.bottom)
		var got []int
		for band, dirty := range marked {
			if dirty {
				got = append(got, band)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(test.bands) {
			t.Fatalf("rows [%d,%d) of %d: bands %v", test.top, test.bottom, test.height, got)
		}
	}
	if bandCount(1792) != 112 || bandCount(898) != 57 || bandCount(1) != 1 || bandRect(56, 730, 898) != image.Rect(0, 896, 730, 898) {
		t.Fatal("band arithmetic")
	}
}
func TestFetchRunsBridgeSmallGaps(t *testing.T) {
	for _, test := range []struct {
		marked string
		runs   string
	}{
		{"1001", "[[0 3]]"}, {"10001", "[[0 0] [4 4]]"}, {"1101", "[[0 3]]"}, {"00", "[]"}, {"1", "[[0 0]]"}, {"0110010001", "[[1 5] [9 9]]"},
	} {
		marked := make([]bool, len(test.marked))
		for index, value := range test.marked {
			marked[index] = value == '1'
		}
		if got := fmt.Sprint(bandRuns(marked, fetchGap)); got != test.runs {
			t.Fatalf("%s: %s", test.marked, got)
		}
	}
}
func TestDamageLogBoundsRectanglesAndClearsOnTake(t *testing.T) {
	var log damageLog
	log.reset(4)
	bands := make([]bool, 4)
	rects, overflow, any := log.take(bands, nil)
	if !any || !overflow || len(rects) != 0 || fmt.Sprint(bands) != "[true true true true]" {
		t.Fatal("reset is not whole-surface damage")
	}
	if _, overflow, any := log.take(bands, rects); any || overflow {
		t.Fatal("take did not clear")
	}
	log.mark(image.Rect(0, 20, 10, 30))
	rects, overflow, any = log.take(bands, rects)
	if !any || overflow || len(rects) != 1 || fmt.Sprint(bands) != "[false true false false]" {
		t.Fatal("mark")
	}
	for index := 0; index <= maximumDamageRects; index++ {
		log.mark(image.Rect(0, 0, 1, 1))
	}
	if rects, overflow, _ = log.take(bands, rects); !overflow || len(rects) != maximumDamageRects {
		t.Fatal("overflow")
	}
	log.mark(image.Rect(0, 1000, 1, 1001))
	if _, _, any := log.take(bands, rects); any {
		t.Fatal("rows past the surface marked a band")
	}
}
func TestPatchLayoutSnapsMergesSplitsAndFallsBack(t *testing.T) {
	surface := image.Rect(0, 0, 1466, 1792)
	layout := func(rects ...image.Rectangle) string {
		patches, ok := patchLayout(rects, surface)
		if !ok {
			return "full"
		}
		return fmt.Sprint(patches)
	}
	if got := layout(image.Rect(3, 5, 20, 30)); got != "[(0,0)-(48,48)]" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(-5, -5, 10, 10), image.Rect(1460, 1790, 2000, 2000)); got != "[(0,0)-(32,32) (1440,1760)-(1466,1792)]" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(0, 0, 16, 16), image.Rect(16, 0, 32, 16)); got != "[(0,0)-(48,32)]" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(0, 0, 16, 16), image.Rect(64, 0, 80, 16)); got != "[(0,0)-(32,32) (48,0)-(96,32)]" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(0, 0, 16, 16), image.Rect(96, 0, 112, 16), image.Rect(48, 0, 64, 16)); got != "[(0,0)-(128,32)]" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(0, 0, 1024, 600)); got != "[(0,0)-(512,512) (512,0)-(1024,512) (1024,0)-(1040,512) (0,512)-(512,624) (512,512)-(1024,624) (1024,512)-(1040,624)]" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(0, 0, 1466, 900)); got != "full" {
		t.Fatal(got)
	}
	var scattered []image.Rectangle
	for index := 0; index < 65; index++ {
		scattered = append(scattered, image.Rect((index%20)*64, (index/20)*64, (index%20)*64+16, (index/20)*64+16))
	}
	if got := layout(scattered...); got != "full" {
		t.Fatal(got)
	}
	if got := layout(scattered[:64]...); got == "full" {
		t.Fatal("64 patches refused")
	}
	if got := layout(); got != "full" {
		t.Fatal(got)
	}
	if got := layout(image.Rect(5, 5, 5, 9), image.Rect(-40, -40, -20, -20)); got != "full" {
		t.Fatal(got)
	}
}
func TestConversionsMatchImageColorFormulasWithEdgeReplication(t *testing.T) {
	reference := func(rgba *image.RGBA) *image.YCbCr {
		width, height := rgba.Rect.Dx(), rgba.Rect.Dy()
		out := image.NewYCbCr(image.Rect(0, 0, width, height), image.YCbCrSubsampleRatio420)
		at := func(x, y int) (uint8, uint8, uint8) {
			pixel := rgba.RGBAAt(rgba.Rect.Min.X+min(x, width-1), rgba.Rect.Min.Y+min(y, height-1))
			return color.RGBToYCbCr(pixel.R, pixel.G, pixel.B)
		}
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				out.Y[out.YOffset(x, y)], _, _ = at(x, y)
			}
		}
		for y := 0; y < height; y += 2 {
			for x := 0; x < width; x += 2 {
				var cb, cr int
				for _, delta := range []image.Point{{0, 0}, {1, 0}, {0, 1}, {1, 1}} {
					_, sampleCb, sampleCr := at(x+delta.X, y+delta.Y)
					cb, cr = cb+int(sampleCb), cr+int(sampleCr)
				}
				out.Cb[out.COffset(x, y)], out.Cr[out.COffset(x, y)] = uint8((cb+2)>>2), uint8((cr+2)>>2)
			}
		}
		return out
	}
	for _, size := range []image.Point{{1466, 16}, {731, 16}, {20, 3}, {1, 1}, {2, 2}, {5, 5}} {
		raw := syntheticBGRX(size.X, size.Y, int64(size.X*size.Y))
		rgba := image.NewRGBA(image.Rect(0, 0, size.X, size.Y))
		bgrxToRGBA(rgba, raw, size.X*4)
		expected := reference(rgba)
		fast := image.NewYCbCr(rgba.Rect, image.YCbCrSubsampleRatio420)
		bgrxToYCbCr(fast, raw, size.X*4)
		generic := image.NewYCbCr(rgba.Rect, image.YCbCrSubsampleRatio420)
		rgbaToYCbCr(generic, rgba)
		for _, actual := range []*image.YCbCr{fast, generic} {
			if !bytes.Equal(actual.Y, expected.Y) || !bytes.Equal(actual.Cb, expected.Cb) || !bytes.Equal(actual.Cr, expected.Cr) {
				t.Fatalf("%v conversion differs", size)
			}
		}
		decoded, err := decodeImage(raw, size.X, size.Y, bgrxLayout.format, bgrxLayout.visual, bgrxLayout.order)
		if err != nil || !bytes.Equal(decoded.Pix, rgba.Pix) {
			t.Fatalf("%v generic decode differs", size)
		}
	}
}
func TestCursorTrackingReencodesWhereItWasAndWhereItIs(t *testing.T) {
	width, height := 200, 100
	raw := make([]byte, width*height*4)
	for index := range raw {
		raw[index] = 0xff
	}
	p := newTestPipeline(t, width, height, raw)
	p.convert(allBands(bandCount(height)))
	square := func(x, y int, serial uint32) *xfixes.GetCursorImageReply {
		reply := &xfixes.GetCursorImageReply{X: int16(x), Y: int16(y), Width: 8, Height: 8, Xhot: 2, Yhot: 2, CursorSerial: serial, CursorImage: make([]uint32, 64)}
		for index := range reply.CursorImage {
			reply.CursorImage[index] = 0xffff0000
		}
		return reply
	}
	var timings stageTimings
	redAt := func(frame []byte, x, y int) bool {
		decoded := decodeJPEG(t, frame)
		r, g, b, _ := decoded.At(x, y).RGBA()
		return r>>8 > 200 && g>>8 < 60 && b>>8 < 60
	}
	changed, rects := p.trackCursor(true, square(10, 10, 1))
	if !changed || fmt.Sprint(rects) != "[(8,8)-(16,16)]" {
		t.Fatalf("first cursor: %v %v", changed, rects)
	}
	frame, err := p.encodeFull(allBands(bandCount(height)), &timings)
	if err != nil || !redAt(frame, 12, 12) {
		t.Fatal("cursor was not composited")
	}
	if changed, rects = p.trackCursor(true, square(10, 10, 1)); changed || rects != nil {
		t.Fatal("unchanged cursor reported")
	}
	changed, rects = p.trackCursor(true, square(100, 50, 1))
	if !changed || fmt.Sprint(rects) != "[(8,8)-(16,16) (98,48)-(106,56)]" {
		t.Fatalf("moved cursor: %v %v", changed, rects)
	}
	marked := make([]bool, bandCount(height))
	for _, rect := range rects {
		markRows(marked, rect.Min.Y, rect.Max.Y)
	}
	if frame, err = p.encodeFull(marked, &timings); err != nil || redAt(frame, 12, 12) || !redAt(frame, 102, 52) {
		t.Fatal("cursor move was not re-encoded")
	}
	if changed, rects = p.trackCursor(true, square(100, 50, 2)); !changed || len(rects) != 2 {
		t.Fatal("serial change ignored")
	}
	changed, rects = p.trackCursor(false, nil)
	if !changed || fmt.Sprint(rects) != "[(98,48)-(106,56)]" {
		t.Fatalf("untracked cursor: %v %v", changed, rects)
	}
	for index := range marked {
		marked[index] = false
	}
	markRows(marked, rects[0].Min.Y, rects[0].Max.Y)
	if frame, err = p.encodeFull(marked, &timings); err != nil || redAt(frame, 102, 52) {
		t.Fatal("composited cursor was not cleaned")
	}
	if changed, rects = p.trackCursor(false, nil); changed || rects != nil {
		t.Fatal("untracked cursor keeps changing")
	}
	invisible := &xfixes.GetCursorImageReply{X: 300, Y: 300, Width: 0, Height: 0, CursorSerial: 3}
	if changed, rects = p.trackCursor(true, invisible); !changed || rects != nil {
		t.Fatalf("invisible cursor: %v %v", changed, rects)
	}
}
func TestPatchSizesForTypicalDamage(t *testing.T) {
	width, height := 1466, 1792
	p := newTestPipeline(t, width, height, syntheticBGRX(width, height, 4))
	p.convert(allBands(bandCount(height)))
	var timings stageTimings
	full, err := p.encodeFull(allBands(bandCount(height)), &timings)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name   string
		damage image.Rectangle
	}{{"typing 160x32", image.Rect(300, 400, 460, 432)}, {"scroll 1466x800", image.Rect(0, 200, 1466, 1000)}, {"cursor 32x32", image.Rect(700, 900, 732, 932)}} {
		layout, ok := patchLayout([]image.Rectangle{scenario.damage}, p.surface())
		if !ok {
			t.Fatalf("%s needs a full frame", scenario.name)
		}
		patches, err := p.encodePatches(layout, &timings)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, patch := range patches {
			total += len(patch.Data)
		}
		t.Logf("%s: %d patches, %d bytes total (full frame %d bytes), encode %d us", scenario.name, len(patches), total, len(full), timings.EncodeUs)
	}
}

func benchmarkPipeline(b *testing.B, width, height int, dirty []int) {
	p := newTestPipeline(b, width, height, syntheticBGRX(width, height, 5))
	all := allBands(bandCount(height))
	p.convert(all)
	var timings stageTimings
	if _, err := p.encodeFull(all, &timings); err != nil {
		b.Fatal(err)
	}
	marked := make([]bool, bandCount(height))
	if dirty == nil {
		marked = all
	}
	for _, band := range dirty {
		marked[band] = true
	}
	var convertUs, encodeUs, assembleUs int64
	var size int
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if dirty == nil {
			p.mosaic.invalidateAll()
		}
		started := time.Now()
		p.convert(marked)
		convertUs += micros(started)
		frame, err := p.encodeFull(marked, &timings)
		if err != nil {
			b.Fatal(err)
		}
		encodeUs, assembleUs, size = encodeUs+timings.EncodeUs, assembleUs+timings.AssembleUs, len(frame)
	}
	b.ReportMetric(float64(convertUs)/float64(b.N), "convert-us/op")
	b.ReportMetric(float64(encodeUs)/float64(b.N), "encode-us/op")
	b.ReportMetric(float64(assembleUs)/float64(b.N), "assemble-us/op")
	b.ReportMetric(float64(size), "frame-bytes")
}
func BenchmarkFullFrame1466x1792(b *testing.B)     { benchmarkPipeline(b, 1466, 1792, nil) }
func BenchmarkTwoBandUpdate1466x1792(b *testing.B) { benchmarkPipeline(b, 1466, 1792, []int{40, 41}) }
func BenchmarkBGRXBandConversion1466(b *testing.B) {
	raw := syntheticBGRX(1466, bandRows, 6)
	band := image.NewYCbCr(image.Rect(0, 0, 1466, bandRows), image.YCbCrSubsampleRatio420)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		bgrxToYCbCr(band, raw, 1466*4)
	}
}
func BenchmarkPatchTyping160x32(b *testing.B) {
	p := newTestPipeline(b, 1466, 1792, syntheticBGRX(1466, 1792, 7))
	p.convert(allBands(bandCount(1792)))
	layout, _ := patchLayout([]image.Rectangle{image.Rect(300, 400, 460, 432)}, p.surface())
	var timings stageTimings
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := p.encodePatches(layout, &timings); err != nil {
			b.Fatal(err)
		}
	}
}
