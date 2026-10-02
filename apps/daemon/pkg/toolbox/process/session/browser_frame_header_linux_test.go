// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

// browserFrameHeader reads a picture's header the way a viewer does, for the
// harnesses that stand where the viewer stands. The route itself no longer
// reads pictures: they are the driver's and the viewer's contract.
type browserFrameHeader struct {
	Type     string         `json:"type"`
	Seq      uint64         `json:"seq"`
	BaseSeq  uint64         `json:"baseSeq,omitempty"`
	Encoding string         `json:"encoding"`
	Surface  browserSurface `json:"surface"`
	browserFrameClock
}
