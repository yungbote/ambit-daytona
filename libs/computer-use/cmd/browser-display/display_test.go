// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"testing"
	"time"
)

func TestSizeClassGrowsAtOnceAndShrinksOnlyTwoStepsSmallerWhenAllowed(t *testing.T) {
	for _, test := range []struct {
		width, height, currentW, currentH int
		shrink                            bool
		wantW, wantH                      int
	}{
		{1418, 1888, 4096, 4096, true, 1536, 2048},  // first layout from the launch size
		{1418, 1888, 4096, 4096, false, 4096, 4096}, // the smaller need has not held
		{1500, 1900, 1536, 2048, false, 1536, 2048}, // inside the class
		{1600, 1900, 1536, 2048, false, 1792, 2048}, // grows at once
		{1100, 1900, 1536, 2048, true, 1536, 2048},  // one step smaller stays
		{1000, 1500, 1536, 2048, true, 1024, 1536},  // two steps smaller shrinks
		{4000, 10, 1024, 1024, true, 4096, 256},     // bounded by the display limit
		{256, 256, 256, 256, true, 256, 256},        // exact multiples
		{1600, 1700, 1600, 2400, false, 1600, 2400}, // an exact framebuffer that holds the window stays
		{1601, 1700, 1600, 2400, false, 1792, 2400}, // and grows to a class only when the window exceeds it
	} {
		w, h := framebufferFor(test.width, test.height, test.currentW, test.currentH, 4096, 4096, test.shrink)
		if w != test.wantW || h != test.wantH {
			t.Errorf("%+v: got %dx%d", test, w, h)
		}
	}
	if w, h := framebufferFor(1000, 900, 512, 512, 1100, 1000, true); w != 1024 || h != 1000 {
		t.Errorf("limit: got %dx%d", w, h)
	}
}

// The lead's drag: 300 CSS px (600 device px) back and forth from the default
// dock, a step every frame, for a minute. The framebuffer grows on the first
// outward pass only (a class has no headroom, so each step crossed is one
// growth), and never shrinks, because the window never needs a smaller class
// for ten seconds on end. Held smaller for ten seconds, it shrinks at the next
// layout.
func TestADragBackAndForthNeverShrinksAndHeldSmallerForTenSecondsDoes(t *testing.T) {
	origin := time.Now()
	var clock shrinkClock
	width, height := 1536, 2048
	layout := func(windowW int, at time.Duration) bool {
		shrink := clock.allows(oversized(windowW, 1888, width, height, 4096, 4096), origin.Add(at))
		w, h := framebufferFor(windowW, 1888, width, height, 4096, 4096, shrink)
		changed := w != width || h != height
		if changed {
			width, height = w, h
			clock.reset()
		}
		return changed
	}
	for step := 0; step < 3600; step++ {
		offset := step % 60
		if (step/60)%2 == 1 {
			offset = 60 - offset
		}
		if layout(1418+offset*10, time.Duration(step)*16*time.Millisecond) && step >= 60 {
			t.Fatalf("the framebuffer changed at step %d to %dx%d", step, width, height)
		}
	}
	if width != 2048 || height != 2048 {
		t.Fatalf("framebuffer %dx%d", width, height)
	}
	end := 3600 * 16 * time.Millisecond
	layout(2000, end)
	layout(900, end+time.Second)
	if layout(900, end+10*time.Second) {
		t.Fatalf("shrank after 9 s smaller: %d", width)
	}
	if !layout(900, end+11*time.Second) || width != 1024 {
		t.Fatalf("held smaller for 10 s: %d", width)
	}
}

func TestTheShrinkClockStartsOverWheneverTheClassIsNeeded(t *testing.T) {
	origin := time.Now()
	at := func(seconds int) time.Time { return origin.Add(time.Duration(seconds) * time.Second) }
	var clock shrinkClock
	for _, step := range []struct {
		smaller bool
		second  int
		allowed bool
	}{
		{true, 0, false},
		{true, 9, false},
		{false, 10, false}, // needed again: starts over
		{true, 11, false},
		{true, 20, false},
		{true, 21, true},
	} {
		if got := clock.allows(step.smaller, at(step.second)); got != step.allowed {
			t.Fatalf("%+v: %v", step, got)
		}
	}
}
