// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import "testing"

func TestSizeClassGrowsAtOnceAndShrinksOnlyTwoStepsSmallerOnceSettled(t *testing.T) {
	for _, test := range []struct {
		width, height, currentW, currentH int
		settled                           bool
		wantW, wantH                      int
	}{
		{1418, 1888, 4096, 4096, true, 1536, 2048},  // first layout from the launch size
		{1418, 1888, 4096, 4096, false, 4096, 4096}, // too soon after a change
		{1500, 1900, 1536, 2048, false, 1536, 2048}, // inside the class
		{1600, 1900, 1536, 2048, false, 1792, 2048}, // grows at once
		{1100, 1900, 1536, 2048, true, 1536, 2048},  // one step smaller stays
		{1000, 1500, 1536, 2048, true, 1024, 1536},  // two steps smaller shrinks
		{4000, 10, 1024, 1024, true, 4096, 256},     // bounded by the display limit
		{256, 256, 256, 256, true, 256, 256},        // exact multiples
		{1600, 1700, 1600, 2400, false, 1600, 2400}, // an exact framebuffer that holds the window stays
		{1601, 1700, 1600, 2400, false, 1792, 2400}, // and grows to a class only when the window exceeds it
	} {
		w, h := framebufferFor(test.width, test.height, test.currentW, test.currentH, 4096, 4096, test.settled)
		if w != test.wantW || h != test.wantH {
			t.Errorf("%+v: got %dx%d", test, w, h)
		}
	}
	if w, h := framebufferFor(1000, 900, 512, 512, 1100, 1000, true); w != 1024 || h != 1000 {
		t.Errorf("limit: got %dx%d", w, h)
	}
}
