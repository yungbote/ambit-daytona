// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package rate

import (
	"sync"
	"time"
)

const retainedPaintReceipts = 512

type sentPicture struct {
	sequence, prefix uint64
	bytes            uint64
	at               time.Time
}

// PaintTracker records sent-prefix totals and the send instant of a bounded
// recent window. An evicted old ACK cannot invent a RTT; a later retained
// ACK still measures the entire acknowledged byte prefix correctly.
type PaintTracker struct {
	mu                            sync.Mutex
	stream                        string
	bytes, sequence, acknowledged uint64
	pictures                      []sentPicture
	lastAck                       time.Time
	ackedBytes                    uint64
	sentAtAck                     uint64
	sample                        Paint
}

func (p *PaintTracker) Sent(stream string, sequence uint64, bytes int, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if stream != p.stream || sequence <= p.sequence {
		p.stream, p.bytes, p.sequence, p.acknowledged = stream, 0, 0, 0
		p.pictures = p.pictures[:0]
		p.lastAck, p.ackedBytes, p.sentAtAck, p.sample = time.Time{}, 0, 0, Paint{}
	}
	if bytes <= 0 || sequence == 0 {
		return
	}
	p.bytes += uint64(bytes)
	p.sequence = sequence
	if len(p.pictures) == retainedPaintReceipts {
		copy(p.pictures, p.pictures[1:])
		p.pictures = p.pictures[:len(p.pictures)-1]
	}
	p.pictures = append(p.pictures, sentPicture{sequence, p.bytes, uint64(bytes), now})
}

// Acknowledge is called only after the channel admitted a valid sent-prefix
// ACK. Duplicate, retired or malformed ACKs never reach this measurement.
func (p *PaintTracker) Acknowledge(stream string, sequence uint64, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if stream != p.stream || sequence <= p.acknowledged || sequence > p.sequence {
		return
	}
	index := -1
	for n, picture := range p.pictures {
		if picture.sequence == sequence {
			index = n
			break
		}
	}
	if index < 0 {
		return
	}
	picture := p.pictures[index]
	if now.Before(picture.at) || (!p.lastAck.IsZero() && !now.After(p.lastAck)) {
		return
	}
	rtt := now.Sub(picture.at)
	p.sample.Known, p.sample.RTT, p.sample.LastAck = true, rtt, now
	p.sample.PictureBytes = picture.bytes
	if p.sample.MinimumRTT == 0 || rtt < p.sample.MinimumRTT {
		p.sample.MinimumRTT = rtt
		p.sample.MinimumPictureBytes = picture.bytes
	}
	start := p.lastAck
	if start.IsZero() {
		start = p.pictures[0].at
	}
	if elapsed := now.Sub(start); elapsed > 0 {
		p.sample.DeliveryBytesPerSecond = float64(picture.prefix-p.ackedBytes) / elapsed.Seconds()
		p.sample.SentBytesPerSecond = float64(p.bytes-p.sentAtAck) / elapsed.Seconds()
	}
	p.acknowledged, p.ackedBytes, p.sentAtAck, p.lastAck = sequence, picture.prefix, p.bytes, now
	copy(p.pictures, p.pictures[index+1:])
	p.pictures = p.pictures[:len(p.pictures)-index-1]
}

func (p *PaintTracker) Snapshot() Paint { p.mu.Lock(); defer p.mu.Unlock(); return p.sample }
