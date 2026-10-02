// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

// maxFrameWindow bounds the frames a viewer may have unacknowledged.
const maxFrameWindow = 8

// frameWindow mirrors the producer's paint credit (the toolbox's
// browserFrameWindow): only sequence and byte counts are kept after a send.
// A painted sequence acknowledges cumulatively, and only a prefix that ends
// at a frame actually sent.
type frameWindow struct {
	limit        int
	bytes        int
	acknowledged uint64
	frames       []sentFrame
}

type sentFrame struct {
	sequence uint64
	bytes    int
}

func (w *frameWindow) reserve(sequence uint64, bytes int) bool {
	if len(w.frames) >= w.limit || bytes <= 0 || bytes > MaxMessageBytes-w.bytes {
		return false
	}
	w.frames = append(w.frames, sentFrame{sequence, bytes})
	w.bytes += bytes
	return true
}

// acknowledge releases the prefix a painted frame ends. A stale duplicate is
// harmless and not forwarded; a sequence never sent is invalid.
func (w *frameWindow) acknowledge(sequence uint64) (forward, valid bool) {
	if sequence <= w.acknowledged {
		return false, true
	}
	for index, frame := range w.frames {
		if frame.sequence != sequence {
			continue
		}
		for _, acknowledged := range w.frames[:index+1] {
			w.bytes -= acknowledged.bytes
		}
		w.frames = w.frames[:copy(w.frames, w.frames[index+1:])]
		w.acknowledged = sequence
		return true, true
	}
	return false, false
}

// frames is the JPEG frame path: the previous frame's geometry and sequence
// (a patch applies only to exactly its base) and the paint credit.
type frames struct {
	previous frameHeader
	window   frameWindow
}

func (f *frames) accept(frame frameHeader, bytes int) bool {
	if !frame.Surface.valid() || frame.Seq <= f.previous.Seq || (frame.BaseSeq != 0 &&
		(frame.BaseSeq != f.previous.Seq || frame.Surface.Generation != f.previous.Surface.Generation ||
			frame.Surface.Width != f.previous.Surface.Width || frame.Surface.Height != f.previous.Surface.Height)) {
		return false
	}
	if !f.window.reserve(frame.Seq, bytes) {
		return false
	}
	f.previous = frame
	return true
}
