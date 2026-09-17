// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import "image"

const (
	patchGrid      = bandRows
	maximumPatch   = 512
	maximumPatches = 64
	// The observer keeps this many raw damage rectangles between captures; more
	// is a full-frame capture, never a partial list.
	maximumDamageRects = 256
)

// patchLayout turns damage into the rectangles a patch frame encodes: each
// snapped to the MCU grid, then expanded to cover chroma interpolation around
// every changed block. Touching rectangles merge and sides above 512 pixels
// split. ok is false without visible damage, for patches covering more than
// half the surface, or for more than 64 patches.
func patchLayout(damage []image.Rectangle, surface image.Rectangle) (patches []image.Rectangle, ok bool) {
	merged := make([]image.Rectangle, 0, len(damage))
	for _, raw := range damage {
		raw = raw.Intersect(surface)
		if raw.Empty() {
			continue
		}
		// JPEG quantization can change any pixel of the affected MCU, then a
		// decoder's chroma interpolation changes its adjacent pixels too.
		rect := snapToGrid(snapToGrid(raw).Inset(-1)).Intersect(surface)
		if rect.Empty() {
			continue
		}
		// Absorb everything the rectangle touches; the union may touch more.
		for absorbed := true; absorbed; {
			absorbed = false
			kept := merged[:0]
			for _, other := range merged {
				if touching(rect, other) {
					rect = rect.Union(other)
					absorbed = true
				} else {
					kept = append(kept, other)
				}
			}
			merged = kept
		}
		merged = append(merged, rect)
	}
	if len(merged) == 0 {
		return nil, false
	}
	area := 0
	for _, rect := range merged {
		area += rect.Dx() * rect.Dy()
	}
	if area*2 > surface.Dx()*surface.Dy() {
		return nil, false
	}
	for _, rect := range merged {
		for y := rect.Min.Y; y < rect.Max.Y; y += maximumPatch {
			for x := rect.Min.X; x < rect.Max.X; x += maximumPatch {
				patches = append(patches, image.Rect(x, y, min(x+maximumPatch, rect.Max.X), min(y+maximumPatch, rect.Max.Y)))
				if len(patches) > maximumPatches {
					return nil, false
				}
			}
		}
	}
	return patches, true
}

func patchSource(rect, surface image.Rectangle) image.Rectangle {
	return rect.Inset(-patchGrid).Intersect(surface)
}
func snapToGrid(rect image.Rectangle) image.Rectangle {
	floor := func(value int) int { return value - ((value%patchGrid)+patchGrid)%patchGrid }
	return image.Rect(floor(rect.Min.X), floor(rect.Min.Y), floor(rect.Max.X+patchGrid-1), floor(rect.Max.Y+patchGrid-1))
}

// touching is overlap or a shared edge or corner: a closed-interval test.
func touching(a, b image.Rectangle) bool {
	return a.Min.X <= b.Max.X && b.Min.X <= a.Max.X && a.Min.Y <= b.Max.Y && b.Min.Y <= a.Max.Y
}
