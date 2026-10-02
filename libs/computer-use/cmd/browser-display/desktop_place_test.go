// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"testing"

	"github.com/robotn/xgb"
)

func TestContainedPlacementCentresAndShrinksOnlyWhatDoesNotFit(t *testing.T) {
	gtk := minimumSize{width: 543, height: 362}
	for _, test := range []struct {
		name            string
		parent, current placement
		minimum         minimumSize
		want            placement
	}{
		// The measured GTK chooser at a 390 CSS px dock (device scale 2).
		{"phone dock", placement{0, 0, 780, 1688}, placement{0, 0, 1096, 845}, gtk, placement{0, 421, 780, 845}},
		{"tablet dock", placement{0, 0, 1536, 1688}, placement{0, 0, 1096, 845}, gtk, placement{220, 421, 1096, 845}},
		{"desktop dock", placement{0, 0, 2560, 1440}, placement{0, 0, 1096, 845}, gtk, placement{732, 297, 1096, 845}},
		{"parent away from the origin", placement{100, 40, 780, 900}, placement{0, 0, 1096, 845}, gtk, placement{100, 67, 780, 845}},
		{"short parent", placement{0, 0, 2560, 600}, placement{0, 0, 1096, 845}, gtk, placement{732, 0, 1096, 600}},
		{"no declared minimum", placement{0, 0, 300, 300}, placement{0, 0, 1096, 845}, minimumSize{}, placement{0, 0, 300, 300}},
		// Below the toolkit's minimum nothing shrinks further: the leading
		// edge stays at the parent's so the dialog's start is in the picture.
		{"minimum wider than the parent", placement{0, 0, 400, 1688}, placement{0, 0, 1096, 845}, gtk, placement{0, 421, 543, 845}},
		{"minimum taller than the parent", placement{0, 0, 780, 300}, placement{0, 0, 1096, 845}, gtk, placement{0, 0, 780, 362}},
		{"already contained", placement{0, 0, 2560, 1440}, placement{732, 297, 1096, 845}, gtk, placement{732, 297, 1096, 845}},
	} {
		if got := containedPlacement(test.parent, test.current, test.minimum); got != test.want {
			t.Errorf("%s: got %+v, want %+v", test.name, got, test.want)
		}
	}
}

func TestReadMinimumSizeTakesOnlyADeclaredPMinSize(t *testing.T) {
	hints := func(flags uint32, minWidth, minHeight uint32) []byte {
		value := make([]byte, 18*4)
		xgb.Put32(value, flags)
		xgb.Put32(value[5*4:], minWidth)
		xgb.Put32(value[6*4:], minHeight)
		return value
	}
	// GTK's measured hints: PMinSize|PBaseSize|PWinGravity.
	if got := readMinimumSize(hints(784, 543, 362)); got != (minimumSize{543, 362}) {
		t.Fatalf("declared minimum: %+v", got)
	}
	if got := readMinimumSize(hints(256|512, 543, 362)); got != (minimumSize{}) {
		t.Fatalf("an undeclared minimum was read: %+v", got)
	}
	if got := readMinimumSize(hints(784, 543, 362)[:6*4]); got != (minimumSize{}) {
		t.Fatalf("a truncated property was read: %+v", got)
	}
}
