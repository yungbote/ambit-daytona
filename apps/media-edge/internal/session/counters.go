// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"log/slog"
	"math"
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
)

// histogram counts durations in microseconds, four buckets per power of two
// (about 19 % resolution), so a percentile is read without keeping samples.
const histogramBuckets = 4 * 40

type histogram struct {
	buckets [histogramBuckets]atomic.Uint64
	count   atomic.Uint64
	max     atomic.Uint64
}

func (h *histogram) observe(d time.Duration) {
	us := uint64(max(d.Microseconds(), 0))
	h.buckets[bucketOf(us)].Add(1)
	h.count.Add(1)
	for {
		current := h.max.Load()
		if us <= current || h.max.CompareAndSwap(current, us) {
			return
		}
	}
}

func bucketOf(us uint64) int {
	if us < 4 {
		return int(us)
	}
	exponent := bits.Len64(us) - 1
	sub := (us >> (exponent - 2)) & 3
	return min(exponent*4+int(sub), histogramBuckets-1)
}

// upper is the largest value a bucket holds.
func upper(bucket int) uint64 {
	if bucket < 4 {
		return uint64(bucket)
	}
	exponent, sub := bucket/4, uint64(bucket%4)
	return (4+sub+1)<<(exponent-2) - 1
}

// quantile is the upper bound of the bucket holding the q-th value, in µs.
func (h *histogram) quantile(q float64) uint64 {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	rank := uint64(math.Ceil(q * float64(count)))
	var seen uint64
	for bucket := range h.buckets {
		if seen += h.buckets[bucket].Load(); seen >= rank {
			return min(upper(bucket), h.max.Load())
		}
	}
	return h.max.Load()
}

func (h *histogram) attrs(name string) slog.Attr {
	return slog.Group(name, "n", h.count.Load(), "p50Us", h.quantile(0.5), "p95Us", h.quantile(0.95),
		"p99Us", h.quantile(0.99), "maxUs", h.max.Load())
}

// flow counts one direction of one kind of message.
type flow struct {
	messages atomic.Uint64
	bytes    atomic.Uint64
}

func (f *flow) add(bytes int) {
	f.messages.Add(1)
	f.bytes.Add(uint64(bytes))
}

// counters are one session's telemetry. Each is written by one flow and read
// by the reports.
type counters struct {
	down         [view.Audio + 1]flow // by view.Kind; 0 counts upstream messages not delivered
	upstreamRead flow
	// hold is the time a unit waits in the edge between the end of its read
	// from the view route and the start of its write to the viewer; write is
	// how long the carrier took to take it (backpressure from the viewer).
	hold  histogram
	write histogram
	// Viewer messages: received, forwarded to the view route, superseded in
	// their slot before they left, and ignored as stale or retired.
	received, forwarded, superseded, ignored atomic.Uint64
	renewed, renewalsIgnored                 atomic.Uint64
	// lastBytes and lastAt give the delivery rate between reports.
	lastBytes uint64
	lastAt    time.Time
}

func (c *counters) deliveredBytes() uint64 {
	var total uint64
	for kind := view.Record; kind <= view.Audio; kind++ {
		total += c.down[kind].bytes.Load()
	}
	return total
}

// attrs is the report, with the delivery rate since the previous one.
func (c *counters) attrs(now time.Time) []any {
	delivered := c.deliveredBytes()
	rate := 0.0
	if elapsed := now.Sub(c.lastAt).Seconds(); elapsed > 0 {
		rate = float64(delivered-c.lastBytes) * 8 / elapsed
	}
	c.lastBytes, c.lastAt = delivered, now
	kind := func(name string, k view.Kind) slog.Attr {
		return slog.Group(name, "n", c.down[k].messages.Load(), "bytes", c.down[k].bytes.Load())
	}
	return []any{
		slog.Group("down", kind("records", view.Record), kind("frames", view.Frame), kind("video", view.Video),
			kind("audio", view.Audio), "undelivered", c.down[0].messages.Load(), "bitsPerSecond", math.Round(rate)),
		slog.Group("upstream", "messages", c.upstreamRead.messages.Load(), "bytes", c.upstreamRead.bytes.Load()),
		c.hold.attrs("holdUs"), c.write.attrs("writeUs"),
		slog.Group("viewer", "received", c.received.Load(), "forwarded", c.forwarded.Load(),
			"superseded", c.superseded.Load(), "ignored", c.ignored.Load(),
			"renewed", c.renewed.Load(), "renewalsIgnored", c.renewalsIgnored.Load()),
	}
}
