// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robotn/xgb"
	"github.com/robotn/xgb/damage"
	"github.com/robotn/xgb/shm"
	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
)

type captureOptions struct {
	cursor  bool
	budget  int
	force   bool
	patches bool
	// wait bounds how long an unchanged capture waits for damage, a new
	// cursor identity or a finished layout before answering unchanged.
	wait time.Duration
	// identity asks for the displayed cursor's identity whenever it differs
	// from the one this helper last reported.
	identity bool
}

// The capture features the driver may use; see the README.
var captureFeatures = []string{"captureWait", "cursorIdentity", "layoutGate", "sizeClass"}

const maximumCaptureWait = 250 * time.Millisecond

// A damage report wakes a waiting capture this long before it reads, so the
// rectangles of one browser frame are taken together.
const damageSettle = time.Millisecond

type stageTimings struct {
	WaitUs     int64 `json:"waitUs,omitempty"`
	FetchUs    int64 `json:"fetchUs"`
	ConvertUs  int64 `json:"convertUs"`
	EncodeUs   int64 `json:"encodeUs"`
	AssembleUs int64 `json:"assembleUs"`
}
type framePatch struct {
	X       int    `json:"x"`
	Y       int    `json:"y"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	SourceX int    `json:"sourceX"`
	SourceY int    `json:"sourceY"`
	Data    []byte `json:"data"`
}
type capturedFrame struct {
	Changed        bool         `json:"changed"`
	Width          int          `json:"width"`
	Height         int          `json:"height"`
	Encoding       string       `json:"encoding"`
	Data           []byte       `json:"data,omitempty"`
	Patches        []framePatch `json:"patches,omitempty"`
	CursorIncluded bool         `json:"cursorIncluded"`
	Quality        int          `json:"quality"`
	Timings        stageTimings `json:"timings"`
	// Visible is the browser window inside a larger framebuffer; absent when
	// the window is the whole frame.
	Visible *visibleRect    `json:"visible,omitempty"`
	Cursor  *cursorIdentity `json:"cursor,omitempty"`
	// read is when the frame's pixels were read: its capture clock.
	read time.Time
}
type unchangedFrame struct {
	Changed bool            `json:"changed"`
	Cursor  *cursorIdentity `json:"cursor,omitempty"`
}
type visibleRect struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

func micros(since time.Time) int64 { return time.Since(since).Microseconds() }

// qualityLadder is walked one rung per full frame: down when the frame exceeds
// its byte budget, up when it is below 55% of it. No budget means the top.
var qualityLadder = [...]int{85, 75, 65, 55, 45, 35}

type qualityController struct{ rung int }

func (c *qualityController) quality() int { return qualityLadder[c.rung] }
func (c *qualityController) adapt(frameBytes, budgetBytes int) bool {
	switch {
	case budgetBytes > 0 && frameBytes > budgetBytes:
		if c.rung == len(qualityLadder)-1 {
			return false
		}
		c.rung++
	case budgetBytes <= 0 || float64(frameBytes) < float64(budgetBytes)*0.55:
		if c.rung == 0 {
			return false
		}
		c.rung--
	default:
		return false
	}
	return true
}

// cursorMark is the cursor as composited into the last frame.
type cursorMark struct {
	tracked    bool
	serial     uint32
	x, y       int
	xhot, yhot int
	rect       image.Rectangle // composited screen rectangle; empty when invisible
}

type frameWorker struct {
	buf     flushBuffer
	rgbaPix []uint8
	yccPix  []uint8
}

// flushBuffer lets image/jpeg write into the buffer directly instead of
// through a bufio wrapper allocated per encode.
type flushBuffer struct{ bytes.Buffer }

func (*flushBuffer) Flush() error { return nil }
func (w *frameWorker) rgbaFor(rect image.Rectangle) *image.RGBA {
	need := rect.Dx() * rect.Dy() * 4
	if cap(w.rgbaPix) < need {
		w.rgbaPix = make([]uint8, need)
	}
	return &image.RGBA{Pix: w.rgbaPix[:need], Stride: rect.Dx() * 4, Rect: rect}
}
func (w *frameWorker) yccFor(size image.Point) *image.YCbCr {
	chromaWidth, chromaHeight := (size.X+1)/2, (size.Y+1)/2
	lumaSize, chromaSize := size.X*size.Y, chromaWidth*chromaHeight
	if cap(w.yccPix) < lumaSize+2*chromaSize {
		w.yccPix = make([]uint8, lumaSize+2*chromaSize)
	}
	pix := w.yccPix[:lumaSize+2*chromaSize]
	return &image.YCbCr{Y: pix[:lumaSize], Cb: pix[lumaSize : lumaSize+chromaSize], Cr: pix[lumaSize+chromaSize:], SubsampleRatio: image.YCbCrSubsampleRatio420, YStride: size.X, CStride: chromaWidth, Rect: image.Rect(0, 0, size.X, size.Y)}
}

// framePipeline is the pixel side of a capture, with no X connection: the
// retained framebuffer and its 4:2:0 conversion, cursor compositing, the band
// cache behind full frames and the encoder behind patches.
type framePipeline struct {
	layout        pixelLayout
	width, height int
	stride        int
	retained      []byte       // the root's raw pixels
	ycc           *image.YCbCr // the same pixels converted, without the cursor
	cursor        cursorMark
	cursorImage   *xfixes.GetCursorImageReply
	mosaic        bandMosaic
	workers       []*frameWorker
	quality       qualityController
	fullNeeded    bool // no full frame exists at this size and quality yet
}

func (p *framePipeline) init(layout pixelLayout, workers int) {
	p.layout = layout
	p.workers = make([]*frameWorker, max(1, workers))
	for index := range p.workers {
		p.workers[index] = &frameWorker{}
	}
}
func (p *framePipeline) resize(width, height int) {
	p.width, p.height, p.stride = width, height, p.layout.stride(width)
	size := p.stride * height
	if cap(p.retained) < size {
		p.retained = make([]byte, size)
	}
	p.retained = p.retained[:size]
	p.ycc = image.NewYCbCr(image.Rect(0, 0, width, height), image.YCbCrSubsampleRatio420)
	p.cursor, p.cursorImage = cursorMark{}, nil
	p.mosaic.reset(width, height)
	p.fullNeeded = true
}
func (p *framePipeline) surface() image.Rectangle { return image.Rect(0, 0, p.width, p.height) }

// store keeps fetched rows for bands first through last.
func (p *framePipeline) store(first, last int, data []byte) error {
	top, bottom := bandRect(first, p.width, p.height).Min.Y, bandRect(last, p.width, p.height).Max.Y
	if len(data) < p.stride*(bottom-top) {
		return unavailable()
	}
	copy(p.retained[top*p.stride:bottom*p.stride], data)
	return nil
}
func (p *framePipeline) raw(rect image.Rectangle) []byte {
	return p.retained[rect.Min.Y*p.stride+rect.Min.X*p.layout.bytesPerPixel():]
}

// parallel runs work for every item across the workers. Yield at each band or
// patch boundary so runnable input can proceed even under a single-core quota;
// the runtime's normal CPU preemption interval is too long for native input.
func (p *framePipeline) parallel(items int, work func(worker *frameWorker, item int) error) error {
	count := min(len(p.workers), items)
	if count <= 1 {
		for item := 0; item < items; item++ {
			if err := work(p.workers[0], item); err != nil {
				return err
			}
			runtime.Gosched()
		}
		return nil
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	failures := make([]error, count)
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for {
				item := int(next.Add(1)) - 1
				if item >= items {
					return
				}
				if err := work(p.workers[index], item); err != nil {
					failures[index] = err
					return
				}
				runtime.Gosched()
			}
		}(index)
	}
	wg.Wait()
	return errors.Join(failures...)
}

// convert refreshes the retained conversion of every marked band.
func (p *framePipeline) convert(marked []bool) {
	pending := make([]int, 0, len(marked))
	for band, dirty := range marked {
		if dirty {
			pending = append(pending, band)
		}
	}
	_ = p.parallel(len(pending), func(worker *frameWorker, item int) error {
		rect := bandRect(pending[item], p.width, p.height)
		dst := p.ycc.SubImage(rect).(*image.YCbCr)
		if p.layout.fast() {
			bgrxToYCbCr(dst, p.raw(rect), p.stride)
			return nil
		}
		rgba := worker.rgbaFor(rect)
		p.layout.decode(rgba, p.raw(rect), p.stride)
		rgbaToYCbCr(dst, rgba)
		return nil
	})
}

// source is the region to encode: the retained conversion, or, where the
// cursor overlaps, a scratch copy with the cursor composited before conversion.
func (p *framePipeline) source(worker *frameWorker, rect image.Rectangle) *image.YCbCr {
	if p.cursorImage == nil || !rect.Overlaps(p.cursor.rect) {
		return p.ycc.SubImage(rect).(*image.YCbCr)
	}
	rgba := worker.rgbaFor(rect)
	p.layout.decode(rgba, p.raw(rect), p.stride)
	compositeCursor(rgba, p.cursorImage)
	ycc := worker.yccFor(rect.Size())
	rgbaToYCbCr(ycc, rgba)
	return ycc
}
func (p *framePipeline) encodeRegion(worker *frameWorker, rect image.Rectangle) ([]byte, error) {
	worker.buf.Reset()
	if err := jpeg.Encode(&worker.buf, p.source(worker, rect), &jpeg.Options{Quality: p.quality.quality()}); err != nil {
		return nil, err
	}
	return worker.buf.Bytes(), nil
}

// trackCursor records the cursor for this frame. It returns whether the cursor
// changed and the screen rectangles whose pixels must be re-encoded: where a
// cursor was composited before and where it is now.
func (p *framePipeline) trackCursor(tracked bool, reply *xfixes.GetCursorImageReply) (bool, []image.Rectangle) {
	previous := p.cursor
	p.cursor, p.cursorImage = cursorMark{}, nil
	var rects []image.Rectangle
	if !previous.rect.Empty() {
		rects = append(rects, previous.rect)
	}
	if !tracked || reply == nil {
		return len(rects) > 0, rects
	}
	next := cursorMark{tracked: true, serial: reply.CursorSerial, x: int(reply.X), y: int(reply.Y), xhot: int(reply.Xhot), yhot: int(reply.Yhot)}
	if len(reply.CursorImage) == int(reply.Width)*int(reply.Height) {
		left, top := next.x-next.xhot, next.y-next.yhot
		next.rect = image.Rect(left, top, left+int(reply.Width), top+int(reply.Height)).Intersect(p.surface())
	}
	p.cursor, p.cursorImage = next, reply
	if previous.tracked && previous.serial == next.serial && previous.x == next.x && previous.y == next.y && previous.xhot == next.xhot && previous.yhot == next.yhot {
		return false, nil
	}
	if !next.rect.Empty() {
		rects = append(rects, next.rect)
	}
	return true, rects
}

// encodeFull re-encodes the marked bands and every band the cache lacks, then
// assembles the frame.
func (p *framePipeline) encodeFull(marked []bool, timings *stageTimings) ([]byte, error) {
	pending := make([]int, 0, len(marked))
	for band, dirty := range marked {
		if dirty || !p.mosaic.current(band) {
			pending = append(pending, band)
		}
	}
	started := time.Now()
	err := p.parallel(len(pending), func(worker *frameWorker, item int) error {
		band := pending[item]
		encoded, err := p.encodeRegion(worker, bandRect(band, p.width, p.height))
		if err != nil {
			return err
		}
		return p.mosaic.store(band, encoded)
	})
	timings.EncodeUs = micros(started)
	if err != nil {
		return nil, err
	}
	started = time.Now()
	frame, err := p.mosaic.assemble()
	timings.AssembleUs = micros(started)
	if err != nil {
		return nil, err
	}
	p.fullNeeded = false
	return frame, nil
}

// encodePatches surrounds each drawn rectangle with one MCU of encoded pixels
// so JPEG chroma interpolation has the same neighbors as the full frame.
// sourceX/sourceY locate the drawn crop in that JPEG. The band cache keeps the
// last full frame; touched bands stay stale until a full frame re-encodes them.
func (p *framePipeline) encodePatches(rects []image.Rectangle, timings *stageTimings) ([]framePatch, error) {
	patches := make([]framePatch, len(rects))
	started := time.Now()
	err := p.parallel(len(rects), func(worker *frameWorker, item int) error {
		rect := rects[item]
		source := patchSource(rect, p.surface())
		encoded, err := p.encodeRegion(worker, source)
		if err != nil {
			return err
		}
		patches[item] = framePatch{X: rect.Min.X, Y: rect.Min.Y, Width: rect.Dx(), Height: rect.Dy(), SourceX: rect.Min.X - source.Min.X, SourceY: rect.Min.Y - source.Min.Y, Data: append([]byte(nil), encoded...)}
		return nil
	})
	timings.EncodeUs = micros(started)
	for _, rect := range rects {
		for band := rect.Min.Y / bandRows; band < (rect.Max.Y+bandRows-1)/bandRows; band++ {
			p.mosaic.invalidate(band)
		}
	}
	return patches, err
}

// damageLog is what the observer learned since the last capture: the bands to
// fetch and the raw rectangles behind patch layout. The rectangle list is
// bounded; past the bound only the bands remain and a full frame follows.
type damageLog struct {
	mu       sync.Mutex
	bands    []bool
	rects    []image.Rectangle
	overflow bool
}

func (l *damageLog) reset(bands int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bands = make([]bool, bands)
	for band := range l.bands {
		l.bands[band] = true
	}
	l.rects, l.overflow = l.rects[:0], true
}
func (l *damageLog) mark(rect image.Rectangle) {
	l.mu.Lock()
	defer l.mu.Unlock()
	markRows(l.bands, rect.Min.Y, rect.Max.Y)
	if len(l.rects) < maximumDamageRects {
		l.rects = append(l.rects, rect)
	} else {
		l.overflow = true
	}
}

// take moves the log into the caller's buffers and clears it.
func (l *damageLog) take(bands []bool, rects []image.Rectangle) (taken []image.Rectangle, overflow, any bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for band := range bands {
		bands[band] = l.bands[band]
		any = any || bands[band]
		l.bands[band] = false
	}
	taken = append(rects[:0], l.rects...)
	overflow = l.overflow
	l.rects, l.overflow = l.rects[:0], false
	return taken, overflow, any
}

// bandRuns groups marked bands into fetch requests, bridging up to gap clean
// bands so nearby damage shares one round trip.
func bandRuns(marked []bool, gap int) [][2]int {
	var runs [][2]int
	for band := 0; band < len(marked); band++ {
		if !marked[band] {
			continue
		}
		run := [2]int{band, band}
		for next := band + 1; next < len(marked); next++ {
			if marked[next] {
				run[1] = next
			} else if next-run[1] > gap {
				break
			}
		}
		runs = append(runs, run)
		band = run[1]
	}
	return runs
}

const markerAtomName = "AMB_CAPTURE_MARK"
const fetchGap = 2

// frameEngine observes the root window over its own connection, so a capture
// in flight never delays input, geometry or clipboard requests on the display
// connection. DAMAGE reports mark bands; a capture fetches only those, keeps
// the retained framebuffer current and re-encodes only what changed.
type frameEngine struct {
	conn     *xgb.Conn
	root     xproto.Window
	window   xproto.Window // receives each capture's ordering marker
	marker   xproto.Atom
	damage   damage.Damage
	log      damageLog
	markers  chan uint32
	dead     chan struct{}
	failOnce sync.Once
	// wake holds one pending signal that damage, a cursor change or native
	// pointer input happened since a waiting capture last looked.
	wake   chan struct{}
	cursor cursorTracker

	mu       sync.Mutex
	closed   bool
	serial   uint32
	pipeline framePipeline
	fetch    []bool
	encode   []bool
	rects    []image.Rectangle
	layout   layoutGate
	shared   *sharedImage
}

// layoutGate keeps frames of a window configure the browser has not painted
// from being captured. While pending, captures answer unchanged; damage keeps
// accumulating and the first capture after the paint takes all of it.
type layoutGate struct {
	pending bool
	settled chan struct{}
	visible image.Rectangle // the window inside a larger framebuffer; empty is the whole frame
}

// beginLayout waits for any capture in progress, so no capture reads pixels
// after a geometry change it did not see begin.
func (e *frameEngine) beginLayout() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.layout.pending {
		e.layout.pending, e.layout.settled = true, make(chan struct{})
	}
}

// endLayout reopens capture. The visible rectangle is replaced only when the
// layout's outcome is known.
func (e *frameEngine) endLayout(visible image.Rectangle, known bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if known {
		e.layout.visible = visible
	}
	if e.layout.pending {
		e.layout.pending = false
		close(e.layout.settled)
	}
	e.poke()
}

// poke records that a waiting capture should look again.
func (e *frameEngine) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func openFrames() (*frameEngine, error) {
	c, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	for _, init := range []func(*xgb.Conn) error{xfixes.Init, damage.Init} {
		if err := init(c); err != nil {
			return nil, err
		}
	}
	if _, err := xfixes.QueryVersion(c, 5, 0).Reply(); err != nil {
		return nil, err
	}
	if _, err := damage.QueryVersion(c, 1, 1).Reply(); err != nil {
		return nil, err
	}
	// MIT-SHM is optional. Registering an extension writes xgb's process-wide
	// event tables, which every connection's reader consults, so it too
	// precedes every event source.
	sharedAvailable := shm.Init(c) == nil
	setup := xproto.Setup(c)
	screen := setup.DefaultScreen(c)
	layout, ok := rootLayout(setup, screen)
	if !ok {
		return nil, unavailable()
	}
	e := &frameEngine{conn: c, root: screen.Root, markers: make(chan uint32, 8), dead: make(chan struct{}), wake: make(chan struct{}, 1)}
	e.pipeline.init(layout, runtime.GOMAXPROCS(0))
	atom, err := xproto.InternAtom(c, false, uint16(len(markerAtomName)), markerAtomName).Reply()
	if err != nil {
		return nil, err
	}
	e.marker = atom.Atom
	window, err := xproto.NewWindowId(c)
	if err != nil {
		return nil, err
	}
	if err := xproto.CreateWindowChecked(c, 0, window, e.root, 0, 0, 1, 1, 0, xproto.WindowClassInputOnly, 0, 0, nil).Check(); err != nil {
		return nil, err
	}
	e.window = window
	id, err := damage.NewDamageId(c)
	if err != nil {
		return nil, err
	}
	if err := damage.CreateChecked(c, id, xproto.Drawable(e.root), damage.ReportLevelRawRectangles).Check(); err != nil {
		return nil, err
	}
	e.damage = id
	if err := xfixes.SelectCursorInputChecked(c, e.root, xfixes.CursorNotifyMaskDisplayCursor).Check(); err != nil {
		return nil, err
	}
	if sharedAvailable {
		e.shared = openSharedImage(c)
	}
	go e.observe()
	success = true
	return e, nil
}

// observe applies every damage report to the log and answers ordering
// markers. Any error or the end of the stream ends every later capture: an
// unobserved screen can never be reported unchanged.
func (e *frameEngine) observe() {
	defer e.fail()
	for {
		event, err := e.conn.WaitForEvent()
		if err != nil || event == nil {
			return
		}
		switch value := event.(type) {
		case damage.NotifyEvent:
			e.log.mark(image.Rect(int(value.Area.X), int(value.Area.Y), int(value.Area.X)+int(value.Area.Width), int(value.Area.Y)+int(value.Area.Height)))
			e.poke()
		case xfixes.CursorNotifyEvent:
			e.cursor.notify(value.CursorSerial)
			e.poke()
		case xproto.ClientMessageEvent:
			if value.Window == e.window && value.Type == e.marker && value.Format == 32 && len(value.Data.Data32) > 0 {
				select {
				case e.markers <- value.Data.Data32[0]:
				default:
				}
			}
		}
	}
}
func (e *frameEngine) fail() { e.failOnce.Do(func() { close(e.dead) }) }
func (e *frameEngine) alive() bool {
	select {
	case <-e.dead:
		return false
	default:
		return true
	}
}
func (e *frameEngine) close() {
	// xgb closes its request channel from its reader goroutine when the server
	// goes away; a request racing that shutdown panics inside the library.
	defer func() { _ = recover() }()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	if e.alive() {
		e.shared.release(e.conn)
		_ = damage.DestroyChecked(e.conn, e.damage).Check()
		_ = xproto.DestroyWindowChecked(e.conn, e.window).Check()
		e.conn.Close()
		<-e.dead
	}
}

// capture answers on either channel; the mutex serializes them. A fetch that
// fails because the screen changed size underneath is retried from a full
// frame; every other failure is the display becoming unavailable.
//
// With a wait, an unchanged answer is held until damage, a new cursor
// identity or the end of a pending layout, or until the wait runs out. The
// mutex is released while waiting, so a layout never waits behind an idle
// capture.
func (e *frameEngine) capture(options captureOptions) (result any, err error) {
	defer func() {
		if recover() != nil {
			e.fail()
			result, err = nil, unavailable()
		}
	}()
	started := time.Now()
	deadline := started.Add(min(options.wait, maximumCaptureWait))
	e.mu.Lock()
	defer e.mu.Unlock()
	attempt := 0
	for {
		if e.closed || !e.alive() {
			return nil, unavailable()
		}
		// Anything that arrives from here on is seen by this pass or wakes
		// the wait after it.
		e.drainWake()
		var answer any
		if e.layout.pending {
			identity, err := e.identity(options)
			if err != nil {
				return nil, unavailable()
			}
			answer = unchangedFrame{Cursor: identity}
		} else {
			frame, retry, failure := e.captureOnce(options)
			if failure != nil {
				// Whatever was retained may no longer describe the screen.
				e.pipeline.width, e.pipeline.height = 0, 0
				if !retry || attempt == 2 {
					return nil, unavailable()
				}
				attempt++
				continue
			}
			answer = frame
		}
		unchanged, idle := answer.(unchangedFrame)
		if idle && unchanged.Cursor == nil && e.await(deadline) {
			continue
		}
		switch value := answer.(type) {
		case unchangedFrame:
			e.cursor.delivered(value.Cursor)
		case capturedFrame:
			e.cursor.delivered(value.Cursor)
			if options.wait > 0 {
				// The wait ends where the pixels are read, so the request's
				// time plus the wait is the frame's capture clock; the
				// stages after it are timed on their own.
				value.Timings.WaitUs = value.read.Sub(started).Microseconds()
				answer = value
			}
		}
		return answer, nil
	}
}

func (e *frameEngine) drainWake() {
	select {
	case <-e.wake:
	default:
	}
}

// await releases the capture mutex until something may have changed, and
// reports false once the deadline has passed. A wake for damage is followed by
// a short settle so one browser frame's rectangles are read together.
func (e *frameEngine) await(deadline time.Time) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	var settled chan struct{}
	if e.layout.pending {
		settled = e.layout.settled
	}
	e.mu.Unlock()
	defer e.mu.Lock()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-e.wake:
		time.Sleep(damageSettle)
		return true
	case <-settled:
		return true
	case <-e.dead:
		return true
	case <-timer.C:
		return false
	}
}

// identity reports the displayed cursor when it differs from the last report,
// fetching it only after the server announced a new one.
func (e *frameEngine) identity(options captureOptions) (*cursorIdentity, error) {
	if !options.identity {
		return nil, nil
	}
	cookie, pending := e.cursor.begin(e.conn)
	if err := e.cursor.finish(cookie, pending); err != nil {
		return nil, err
	}
	return e.cursor.unreported(), nil
}

func (e *frameEngine) captureOnce(options captureOptions) (any, bool, error) {
	p := &e.pipeline
	// Damage reported before this point is in the log or precedes the marker,
	// which the observer answers only after applying everything before it.
	subtract := damage.SubtractChecked(e.conn, e.damage, xfixes.RegionNone, xfixes.RegionNone)
	geometry := xproto.GetGeometry(e.conn, xproto.Drawable(e.root))
	serial := e.sendMarker()
	var cursorCookie xfixes.GetCursorImageCookie
	if options.cursor {
		cursorCookie = xfixes.GetCursorImage(e.conn)
	}
	var identityCookie *xfixes.GetCursorImageAndNameCookie
	var identityPending uint64
	if options.identity {
		identityCookie, identityPending = e.cursor.begin(e.conn)
	}
	reply, err := geometry.Reply()
	if err != nil {
		return nil, false, err
	}
	if err := subtract.Check(); err != nil {
		e.fail()
		return nil, false, err
	}
	if !e.awaitMarker(serial) {
		return nil, false, unavailable()
	}
	var cursor *xfixes.GetCursorImageReply
	if options.cursor {
		if cursor, err = cursorCookie.Reply(); err != nil {
			return nil, false, err
		}
	}
	var identity *cursorIdentity
	if options.identity {
		if err := e.cursor.finish(identityCookie, identityPending); err != nil {
			return nil, false, err
		}
		identity = e.cursor.unreported()
	}
	width, height := int(reply.Width), int(reply.Height)
	if !validSize(width, height) {
		return nil, false, unavailable()
	}
	if width != p.width || height != p.height {
		p.retained = e.shared.buffer(e.conn, p.layout.stride(width)*height, p.retained)
		p.resize(width, height)
		bands := bandCount(height)
		e.fetch, e.encode = make([]bool, bands), make([]bool, bands)
		e.log.reset(bands)
	}
	rects, overflow, damaged := e.log.take(e.fetch, e.rects[:0])
	e.rects = rects
	copy(e.encode, e.fetch)
	cursorChanged, cursorRects := p.trackCursor(options.cursor, cursor)
	for _, rect := range cursorRects {
		markRows(e.encode, rect.Min.Y, rect.Max.Y)
	}
	if !damaged && !cursorChanged && !options.force {
		return unchangedFrame{Cursor: identity}, false, nil
	}
	frame := capturedFrame{Changed: true, Width: width, Height: height, Encoding: "jpeg", CursorIncluded: options.cursor, Quality: p.quality.quality(), Cursor: identity}
	if visible := e.layout.visible.Intersect(p.surface()); !visible.Empty() && visible != p.surface() {
		frame.Visible = &visibleRect{X: visible.Min.X, Y: visible.Min.Y, Width: visible.Dx(), Height: visible.Dy()}
	}
	frame.read = time.Now()
	if damaged {
		if err := e.fetchBands(); err != nil {
			return nil, true, err
		}
	}
	frame.Timings.FetchUs = micros(frame.read)
	started := time.Now()
	p.convert(e.fetch)
	frame.Timings.ConvertUs = micros(started)
	if options.patches && !options.force && !p.fullNeeded && !overflow {
		if layout, ok := patchLayout(append(rects, cursorRects...), p.surface()); ok {
			if frame.Patches, err = p.encodePatches(layout, &frame.Timings); err != nil {
				return nil, false, err
			}
			return frame, false, nil
		}
	}
	if frame.Data, err = p.encodeFull(e.encode, &frame.Timings); err != nil {
		return nil, false, err
	}
	if p.quality.adapt(len(frame.Data), options.budget) {
		p.mosaic.invalidateAll()
		p.fullNeeded = true
	}
	return frame, false, nil
}

// sendMarker asks the server to echo a serial after everything it reported so
// far on this connection.
func (e *frameEngine) sendMarker() uint32 {
	e.serial++
	for drained := false; !drained; {
		select {
		case <-e.markers:
		default:
			drained = true
		}
	}
	message := xproto.ClientMessageEvent{Format: 32, Window: e.window, Type: e.marker, Data: xproto.ClientMessageDataUnionData32New([]uint32{e.serial, 0, 0, 0, 0})}
	xproto.SendEvent(e.conn, false, e.window, 0, string(message.Bytes()))
	return e.serial
}
func (e *frameEngine) awaitMarker(serial uint32) bool {
	for {
		select {
		case received := <-e.markers:
			if received == serial {
				return true
			}
		case <-e.dead:
			return false
		}
	}
}

// fetchBands reads every marked band into the retained framebuffer, one
// pipelined request per run. With shared memory the server writes the rows
// into the retained framebuffer itself; otherwise they cross the socket.
func (e *frameEngine) fetchBands() error {
	p := &e.pipeline
	runs := bandRuns(e.fetch, fetchGap)
	if e.shared.holds(p.retained) {
		cookies := make([]shm.GetImageCookie, len(runs))
		for index, run := range runs {
			top, bottom := bandRect(run[0], p.width, p.height).Min.Y, bandRect(run[1], p.width, p.height).Max.Y
			cookies[index] = shm.GetImage(e.conn, xproto.Drawable(e.root), 0, int16(top), uint16(p.width), uint16(bottom-top), 0xffffffff, xproto.ImageFormatZPixmap, e.shared.segment, uint32(top*p.stride))
		}
		for index, cookie := range cookies {
			reply, err := cookie.Reply()
			if err != nil {
				// Retry the capture over the socket; its pixels are the same.
				e.shared.disable()
				return err
			}
			top, bottom := bandRect(runs[index][0], p.width, p.height).Min.Y, bandRect(runs[index][1], p.width, p.height).Max.Y
			if reply.Depth != p.layout.depth || reply.Visual != p.layout.visual.VisualId || int(reply.Size) != p.stride*(bottom-top) {
				return unavailable()
			}
		}
		return nil
	}
	cookies := make([]xproto.GetImageCookie, len(runs))
	for index, run := range runs {
		top, bottom := bandRect(run[0], p.width, p.height).Min.Y, bandRect(run[1], p.width, p.height).Max.Y
		cookies[index] = xproto.GetImage(e.conn, xproto.ImageFormatZPixmap, xproto.Drawable(e.root), 0, int16(top), uint16(p.width), uint16(bottom-top), 0xffffffff)
	}
	for index, cookie := range cookies {
		reply, err := cookie.Reply()
		if err != nil {
			return err
		}
		if reply.Depth != p.layout.depth || reply.Visual != p.layout.visual.VisualId {
			return unavailable()
		}
		if err := p.store(runs[index][0], runs[index][1], reply.Data); err != nil {
			return err
		}
	}
	return nil
}
