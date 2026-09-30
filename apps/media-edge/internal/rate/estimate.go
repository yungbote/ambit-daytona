// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package rate estimates one viewer's delivery budget. The driver remains
// the only picture/encoder pacer; this package only supplies its existing rate
// input from transport measurements and validated consumer paint receipts.
package rate

import (
	"math"
	"time"
)

const (
	InitialBitsPerSecond uint64 = 4_000_000
	MaximumBitsPerSecond uint64 = math.MaxUint32
	MaximumBurstBytes    uint64 = 12 << 20
	MinimumBurstBytes    uint64 = 4097 // maximum video header plus a payload byte
	ReportInterval              = 500 * time.Millisecond
)

// Network is a carrier's snapshot. Bytes and delivery are octets; RTT is a
// duration on the carrier's clock, never the producer's capture timestamp.
type Network struct {
	Known                      bool
	AckedBytes                 uint64
	DeliveryBytesPerSecond     float64
	RTT, MinimumRTT            time.Duration
	WindowBytes, InFlightBytes uint64
	ApplicationLimited         bool
	ObservedAt                 time.Time
	// ProxyHop means this TCP socket ends at ingress, not at the consumer.
	// It cannot independently establish the person's delivery capacity.
	ProxyHop bool
	Shares   uint64
}

// Paint is end-to-end feedback measured at the edge, after protocol validation.
type Paint struct {
	Known                  bool
	DeliveryBytesPerSecond float64
	SentBytesPerSecond     float64
	RTT, MinimumRTT        time.Duration
	LastAck                time.Time
}

type Budget struct{ BitsPerSecond, BurstBytes uint64 }

// Estimator retains only smoothed measurements and the last emitted budget.
// Idle/app-limited streams do not imply a smaller link: no frame demand is
// not evidence of zero capacity.
type Estimator struct {
	rate        float64
	queuedSince time.Time
	last        time.Time
	generation  uint64
	budget      Budget
	observed    time.Time
	paintAck    time.Time
	networkAt   time.Time
	probe       time.Time
	shares      uint64
}

func New() *Estimator { return &Estimator{rate: float64(InitialBitsPerSecond)} }

func (e *Estimator) Published() (uint64, Budget) { return e.generation, e.budget }

// Update answers only for the currently enabled video generation. A generation
// change emits immediately; otherwise >10% change or500ms emits latest state.
func (e *Estimator) Update(now time.Time, generation uint64, network Network, paint Paint) (Budget, bool) {
	if now.Before(e.observed) {
		return Budget{}, false
	}
	e.observed = now
	if generation == 0 {
		e.generation = 0
		return Budget{}, false
	}
	shares := network.Shares
	if shares == 0 || network.ProxyHop {
		shares = 1
	}
	if e.shares == 0 {
		e.shares = 1
	}
	if shares != e.shares {
		e.rate *= float64(e.shares) / float64(shares)
		e.shares = shares
	}
	if e.probe.IsZero() {
		e.probe = now
	}
	minimum := network.MinimumRTT
	rtt := network.RTT
	if network.ProxyHop || !network.Known {
		minimum, rtt = paint.MinimumRTT, paint.RTT
	}
	paintFresh := paint.Known && !paint.LastAck.IsZero() && !now.Before(paint.LastAck) && now.Sub(paint.LastAck) <= time.Second
	newPaint := paintFresh && paint.LastAck.After(e.paintAck)
	if newPaint {
		e.paintAck = paint.LastAck
	}
	queued := minimum > 0 && rtt > minimum+30*time.Millisecond
	if network.ProxyHop || !network.Known {
		queued = queued && paintFresh
	}
	// A transport ACK does not mean the consumer painted the picture. A
	// decoder/main-thread queue must cap a clean QUIC connection as well.
	queued = queued || (paintFresh && paint.MinimumRTT > 0 && paint.RTT > paint.MinimumRTT+30*time.Millisecond)
	if !queued {
		e.queuedSince = time.Time{}
	} else if e.queuedSince.IsZero() {
		e.queuedSince = now
	}
	congested := !e.queuedSince.IsZero() && now.Sub(e.queuedSince) >= 200*time.Millisecond

	// TCP_INFO on the ingress hop can only corroborate paint feedback, never
	// override it. QUIC measures the actual consumer connection, shared by
	// all of its WebTransport sessions.
	delivery := network.DeliveryBytesPerSecond / float64(shares)
	newNetwork := network.ObservedAt.IsZero() || (!now.Before(network.ObservedAt) && network.ObservedAt.After(e.networkAt))
	if newNetwork && !network.ObservedAt.IsZero() {
		e.networkAt = network.ObservedAt
	}
	measured := newNetwork && network.Known && !network.ProxyHop && !network.ApplicationLimited && validDelivery(delivery)
	if network.ProxyHop || !network.Known {
		delivery = paint.DeliveryBytesPerSecond
		measured = newPaint && congested && validDelivery(delivery)
	} else if newPaint && validDelivery(paint.DeliveryBytesPerSecond) && congested {
		delivery = math.Min(delivery, paint.DeliveryBytesPerSecond)
		measured = validDelivery(delivery)
	}
	if measured {
		target := delivery * 8 * 0.85
		if congested {
			target = math.Min(target, e.rate*0.85)
		} else {
			// Demand already limited by our encoder budget is a lower bound
			// on capacity. Applying85% repeatedly would ratchet it to zero.
			target = math.Max(target, e.rate)
		}
		if e.last.IsZero() {
			e.rate = target
		} else {
			e.rate = e.rate*0.8 + target*0.2
		}
	}
	// End-to-end ACKs cannot reveal spare bandwidth directly. Under fresh
	// budget-consuming demand, test10% more at most twice per second. An
	// inflated RTT stops probes and the same controller reduces the budget.
	if !congested && !queued && newPaint && validDelivery(paint.DeliveryBytesPerSecond) && validDelivery(paint.SentBytesPerSecond) && paint.DeliveryBytesPerSecond*8 >= e.rate*0.8 && paint.SentBytesPerSecond*8 >= e.rate*0.8 && now.Sub(e.probe) >= ReportInterval {
		e.rate *= 1.1
		e.probe = now
	}
	// A congestion window can bound an initial QUIC guess, but a proxy's
	// window must never be interpreted as the person's path capacity.
	if network.Known && !network.ProxyHop && minimum > 0 && network.WindowBytes > 0 {
		ceiling := float64(network.WindowBytes) * 8 / minimum.Seconds() / float64(shares)
		e.rate = math.Min(e.rate, ceiling)
	}
	e.rate = math.Max(1000, math.Min(float64(MaximumBitsPerSecond), e.rate))
	bits := uint64(e.rate)
	flight := minimum
	if flight < 250*time.Millisecond {
		flight = 250 * time.Millisecond
	}
	burst := uint64(math.Max(float64(MinimumBurstBytes), math.Min(float64(MaximumBurstBytes), float64(bits)/8*flight.Seconds())))
	budget := Budget{bits, burst}
	changed := e.budget.BitsPerSecond == 0 || math.Abs(float64(bits)-float64(e.budget.BitsPerSecond)) > float64(e.budget.BitsPerSecond)*0.1 || math.Abs(float64(burst)-float64(e.budget.BurstBytes)) > float64(e.budget.BurstBytes)*0.1
	if generation != e.generation || changed || now.Sub(e.last) >= ReportInterval {
		e.generation, e.budget, e.last = generation, budget, now
		return budget, true
	}
	return Budget{}, false
}

func validDelivery(value float64) bool {
	return value > 0 && !math.IsInf(value, 0) && !math.IsNaN(value)
}
