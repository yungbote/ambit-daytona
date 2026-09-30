// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package rate

import (
	"math"
	"testing"
	"time"
)

func TestNoDemandDoesNotCollapseCapacityOrInventAProxyCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{Known: true, ProxyHop: true, DeliveryBytesPerSecond: 1e12, RTT: time.Microsecond, MinimumRTT: time.Microsecond, WindowBytes: 1 << 20}
	first, ok := e.Update(now, 1, proxy, Paint{})
	if !ok || first.BitsPerSecond != InitialBitsPerSecond {
		t.Fatalf("proxy/idle budget: %+v %v", first, ok)
	}
	for n := 1; n <= 100; n++ {
		budget, _ := e.Update(now.Add(time.Duration(n)*ReportInterval), 1, proxy, Paint{Known: true, DeliveryBytesPerSecond: 100, SentBytesPerSecond: 100, RTT: time.Millisecond, MinimumRTT: time.Millisecond, LastAck: now.Add(time.Duration(n) * ReportInterval)})
		if budget.BitsPerSecond != InitialBitsPerSecond {
			t.Fatalf("app-limited demand collapsed capacity: %+v", budget)
		}
	}
}

func TestReceivedPrefixSeedsOnlyMeasuredCurrentGenerationBeforePaint(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{Known: true, ProxyHop: true, DeliveryBytesPerSecond: 1e12}
	if _, emit := e.UpdateReceived(now, 1, proxy, Paint{}); emit {
		t.Fatal("chunks emitted heuristic bootstrap rate")
	}
	feedback := Paint{Known: true, DeliveryBytesPerSecond: 62500, SentBytesPerSecond: 62500, RTT: 20 * time.Millisecond, MinimumRTT: 20 * time.Millisecond, LastAck: now, PictureBytes: 1024, MinimumPictureBytes: 1024}
	budget, emit := e.UpdateReceived(now, 1, proxy, feedback)
	if !emit || budget.BitsPerSecond != 425000 {
		t.Fatalf("prefix rate ignored person and used proxy/initial guess: %+v", budget)
	}
	if _, emit := e.UpdateReceived(now.Add(time.Second), 2, proxy, Paint{}); emit {
		t.Fatal("new generation inherited old delivered prefix")
	}
	feedback.DeliveryBytesPerSecond, feedback.SentBytesPerSecond = 12500, 12500
	feedback.LastAck = now.Add(2 * time.Second)
	budget, emit = e.UpdateReceived(feedback.LastAck, 2, proxy, feedback)
	if !emit || budget.BitsPerSecond > 100000 {
		t.Fatalf("new generation did not seed from own slow prefix: %+v", budget)
	}
}

func TestSharedConsumerCapacityAndGenerationRetirement(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	sample := Network{Known: true, DeliveryBytesPerSecond: 1_000_000, MinimumRTT: 20 * time.Millisecond, RTT: 20 * time.Millisecond, WindowBytes: 1 << 20, Shares: 2}
	budget, ok := e.Update(now, 1, sample, Paint{})
	if !ok || budget.BitsPerSecond != 3_400_000 {
		t.Fatalf("shared capacity: %+v", budget)
	}
	if _, ok := e.Update(now.Add(time.Millisecond), 0, sample, Paint{}); ok {
		t.Fatal("retired generation emitted")
	}
	if _, ok := e.Update(now.Add(2*time.Millisecond), 2, sample, Paint{}); !ok {
		t.Fatal("new generation did not emit at once")
	}
}

func TestSustainedPaintQueueCapsTheIngressHop(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{Known: true, ProxyHop: true, DeliveryBytesPerSecond: 1e9}
	paint := Paint{Known: true, DeliveryBytesPerSecond: 375000, SentBytesPerSecond: 500000, MinimumRTT: 26 * time.Millisecond, RTT: 80 * time.Millisecond, LastAck: now}
	first, _ := e.Update(now, 1, proxy, paint)
	if first.BitsPerSecond != InitialBitsPerSecond {
		t.Fatal("paint queue reduced rate before the200ms persistence threshold")
	}
	paint.LastAck = now.Add(250 * time.Millisecond)
	if _, ok := e.Update(paint.LastAck, 1, proxy, paint); ok {
		t.Fatal("small change emitted before the500ms interval")
	}
	paint.LastAck = now.Add(500 * time.Millisecond)
	budget, ok := e.Update(paint.LastAck, 1, proxy, paint)
	if !ok || budget.BitsPerSecond >= InitialBitsPerSecond {
		t.Fatalf("consumer ceiling lost: %+v %v", budget, ok)
	}
	for n := 6; n <= 50; n++ {
		paint.LastAck = now.Add(time.Duration(n) * 100 * time.Millisecond)
		if next, emit := e.Update(paint.LastAck, 1, proxy, paint); emit {
			budget = next
		}
	}
	if budget.BitsPerSecond > 3_000_000 {
		t.Fatalf("sustained consumer queue failed to converge: %+v", budget)
	}
}

func TestBoundsClockRegressionAndInvalidMeasurements(t *testing.T) {
	now := time.Unix(100, 0)
	for _, delivery := range []float64{math.Inf(1), math.NaN(), 0, -1, 1e20, 1} {
		e := New()
		budget, ok := e.Update(now, 1, Network{Known: true, DeliveryBytesPerSecond: delivery, RTT: time.Hour, MinimumRTT: time.Hour, WindowBytes: math.MaxUint64}, Paint{})
		if !ok || budget.BitsPerSecond < 1000 || budget.BitsPerSecond > MaximumBitsPerSecond || budget.BurstBytes < MinimumBurstBytes || budget.BurstBytes > MaximumBurstBytes {
			t.Fatalf("invalid bounds: %+v", budget)
		}
		if _, ok := e.Update(now.Add(-time.Second), 1, Network{}, Paint{}); ok {
			t.Fatal("backward clock emitted")
		}
	}
}

func TestSelfLimitedPaintRecoversInsteadOfRatchetingDown(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{Known: true, ProxyHop: true, DeliveryBytesPerSecond: 1e12}
	budget, _ := e.Update(now, 1, proxy, Paint{})
	for n := 1; n <= 60; n++ {
		at := now.Add(time.Duration(n) * 100 * time.Millisecond)
		// The producer is consuming its budget. A clean path carrying that
		// demand is a lower bound, not proof that capacity is85% of demand.
		paint := Paint{Known: true, DeliveryBytesPerSecond: float64(budget.BitsPerSecond) / 8, SentBytesPerSecond: float64(budget.BitsPerSecond) / 8, RTT: 26 * time.Millisecond, MinimumRTT: 26 * time.Millisecond, LastAck: at}
		if next, emit := e.Update(at, 1, proxy, paint); emit {
			budget = next
		}
	}
	if budget.BitsPerSecond < InitialBitsPerSecond*2 {
		t.Fatalf("self-capped output never recovered higher capacity: %+v", budget)
	}
}

func TestAppLimitedViewersShareTheInitialBudgetAndJoiningCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	network := Network{Known: true, ApplicationLimited: true, Shares: 2, MinimumRTT: 20 * time.Millisecond, RTT: 20 * time.Millisecond, WindowBytes: 1 << 20}
	budget, _ := e.Update(now, 1, network, Paint{})
	if budget.BitsPerSecond != InitialBitsPerSecond/2 {
		t.Fatalf("each idle viewer received the full connection guess: %+v", budget)
	}
	network.Shares = 4
	budget, _ = e.Update(now.Add(100*time.Millisecond), 1, network, Paint{})
	if budget.BitsPerSecond != InitialBitsPerSecond/4 {
		t.Fatalf("joining viewers duplicated capacity: %+v", budget)
	}
	network.Shares = 1
	budget, _ = e.Update(now.Add(200*time.Millisecond), 1, network, Paint{})
	if budget.BitsPerSecond != InitialBitsPerSecond {
		t.Fatalf("departed viewers retained a share: %+v", budget)
	}
}

func TestSharedViewersDivideTheGuessBeforeTheFirstRTTSample(t *testing.T) {
	e := New()
	budget, _ := e.Update(time.Unix(100, 0), 1, Network{Shares: 2}, Paint{})
	if budget.BitsPerSecond != InitialBitsPerSecond/2 {
		t.Fatalf("connection sharing waited for RTT and duplicated the initial keys: %+v", budget)
	}
}

func TestFuturePaintAndBackwardObservationCannotChangeCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	_, _ = e.Update(now, 1, Network{ProxyHop: true}, Paint{})
	paint := Paint{Known: true, DeliveryBytesPerSecond: 1000, SentBytesPerSecond: 500000, RTT: time.Second, MinimumRTT: time.Millisecond, LastAck: now.Add(time.Hour)}
	_, _ = e.Update(now.Add(500*time.Millisecond), 1, Network{ProxyHop: true}, paint)
	_, published := e.Published()
	if published.BitsPerSecond != InitialBitsPerSecond {
		t.Fatalf("future paint changed capacity: %+v", published)
	}
	_, _ = e.Update(now.Add(600*time.Millisecond), 1, Network{}, Paint{})
	if _, emit := e.Update(now.Add(550*time.Millisecond), 2, Network{}, Paint{}); emit {
		t.Fatal("clock regression after an unreported observation emitted")
	}
}

func TestRepeatedPaintDoesNotInventProbeDemand(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{ProxyHop: true}
	_, _ = e.Update(now, 1, proxy, Paint{})
	paint := Paint{Known: true, DeliveryBytesPerSecond: 500000, SentBytesPerSecond: 500000, RTT: 26 * time.Millisecond, MinimumRTT: 26 * time.Millisecond, LastAck: now.Add(500 * time.Millisecond)}
	budget, _ := e.Update(paint.LastAck, 1, proxy, paint)
	if budget.BitsPerSecond != 4_400_000 {
		t.Fatalf("fresh demand did not probe: %+v", budget)
	}
	for n := 6; n <= 30; n++ {
		_, _ = e.Update(now.Add(time.Duration(n)*100*time.Millisecond), 1, proxy, paint)
	}
	_, budget = e.Published()
	if budget.BitsPerSecond != 4_400_000 {
		t.Fatalf("same/stale ACK generated repeated probes: %+v", budget)
	}
}

func TestConsumerPaintQueueCapsACleanQUICConnection(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	network := Network{Known: true, DeliveryBytesPerSecond: 1000000, RTT: 20 * time.Millisecond, MinimumRTT: 20 * time.Millisecond, WindowBytes: 1 << 20, Shares: 1}
	_, _ = e.Update(now, 1, network, Paint{})
	var budget Budget
	for n := 1; n <= 20; n++ {
		at := now.Add(time.Duration(n) * 100 * time.Millisecond)
		network.ObservedAt = at
		paint := Paint{Known: true, DeliveryBytesPerSecond: 100000, SentBytesPerSecond: 500000, RTT: 200 * time.Millisecond, MinimumRTT: 26 * time.Millisecond, LastAck: at}
		if next, emit := e.Update(at, 1, network, paint); emit {
			budget = next
		}
	}
	if budget.BitsPerSecond >= InitialBitsPerSecond || budget.BitsPerSecond > 1_500_000 {
		t.Fatalf("transport ACK capacity overrode sustained consumer paint queue: %+v", budget)
	}
}

func TestIndivisiblePictureSerializationCannotRatchetTheBudget(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{ProxyHop: true}
	_, _ = e.Update(now, 1, proxy, Paint{})
	budget := Budget{BitsPerSecond: InitialBitsPerSecond}
	for n := 1; n <= 80; n++ {
		at := now.Add(time.Duration(n) * 1500 * time.Millisecond)
		paint := Paint{Known: true, DeliveryBytesPerSecond: 500000, SentBytesPerSecond: 500000, RTT: 1276 * time.Millisecond, MinimumRTT: 26 * time.Millisecond, LastAck: at, PictureBytes: 625000}
		// One indivisible625KB picture uses1.25s of a4Mbit/s link.
		// The latency is serialization, not repeated backlog growth.
		for step := 0; step < 5; step++ {
			if next, emit := e.Update(at.Add(time.Duration(step)*100*time.Millisecond), 1, proxy, paint); emit {
				budget = next
			}
		}
	}
	if budget.BitsPerSecond < 3_500_000 {
		t.Fatalf("valid large pictures repeatedly reduced stable capacity: %+v", budget)
	}
}

func TestFirstLargePictureCannotInflateTheFlightBudget(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{ProxyHop: true}
	_, _ = e.Update(now, 1, proxy, Paint{})
	paint := Paint{Known: true, DeliveryBytesPerSecond: 500000, SentBytesPerSecond: 500000, RTT: 1276 * time.Millisecond, MinimumRTT: 1276 * time.Millisecond, LastAck: now.Add(1500 * time.Millisecond), PictureBytes: 625000, MinimumPictureBytes: 625000}
	budget, _ := e.Update(paint.LastAck, 1, proxy, paint)
	if budget.BurstBytes > 150000 {
		t.Fatalf("key serialization was mistaken for path flight time: %+v", budget)
	}
}

func TestClosedLoopConsumerQueueAdaptsAndRecovers(t *testing.T) {
	now := time.Unix(100, 0)
	e := New()
	proxy := Network{ProxyHop: true}
	budget, _ := e.Update(now, 1, proxy, Paint{})
	queuedBytes := float64(0)
	var constrained Budget
	for n := 1; n <= 300; n++ {
		capacity := float64(1_000_000)
		if n > 150 {
			capacity = 8_000_000
		}
		sent := float64(budget.BitsPerSecond) / 8 * 0.1
		delivered := math.Min(queuedBytes+sent, capacity/8*0.1)
		queuedBytes = math.Max(0, queuedBytes+sent-delivered)
		at := now.Add(time.Duration(n) * 100 * time.Millisecond)
		paint := Paint{Known: true, DeliveryBytesPerSecond: delivered / 0.1, SentBytesPerSecond: sent / 0.1, RTT: 26*time.Millisecond + time.Duration(queuedBytes*8/capacity*float64(time.Second)), MinimumRTT: 26 * time.Millisecond, LastAck: at}
		if next, emit := e.Update(at, 1, proxy, paint); emit {
			budget = next
		}
		if n == 150 {
			constrained = budget
			if budget.BitsPerSecond > 1_300_000 || queuedBytes > 32000 {
				t.Fatalf("constrained path never drained: budget=%+v queue=%fB", budget, queuedBytes)
			}
		}
	}
	if budget.BitsPerSecond < 4_000_000 || queuedBytes > 80000 {
		t.Fatalf("recovered path stayed pinned or queued: budget=%+v queue=%fB", budget, queuedBytes)
	}
	t.Logf("100ms deterministic consumer queue model: constrained=%d bit/s recovered=%d bit/s final queue=%.0fB; not a native/link measurement", constrained.BitsPerSecond, budget.BitsPerSecond, queuedBytes)
}
