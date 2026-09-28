// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"image"

	"github.com/robotn/xgb/xfixes"
	"golang.org/x/sys/unix"
)

// pixelSlot is shared memory the driver created and handed over at spawn:
// the framebuffer as the server stores it (32-bit B, G, R, X), rows packed at
// the framebuffer's width. The helper writes it only while answering a picture
// request, under the frame engine's lock, and the driver reads it between
// requests, so pixels never cross a socket and nothing is encoded here.
type pixelSlot struct {
	memory []byte
}

// openPixelSlot maps the driver's descriptor. The mapping lives as long as the
// helper; the descriptor is not needed after it.
func openPixelSlot(fd int) (*pixelSlot, error) {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil || status.Size <= 0 || status.Size > 64<<20 {
		return nil, unavailable()
	}
	memory, err := unix.Mmap(fd, 0, int(status.Size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, unavailable()
	}
	_ = unix.Close(fd)
	return &pixelSlot{memory: memory}, nil
}

// holds reports whether a width x height framebuffer fits.
func (s *pixelSlot) holds(width, height int) bool {
	return s != nil && width > 0 && height > 0 && width*4*height <= len(s.memory)
}

// copyRows writes rows [top, bottom) of a framebuffer whose rows are stride
// bytes apart, packed at width*4 bytes per row.
func (s *pixelSlot) copyRows(retained []byte, stride, width, top, bottom int) {
	row := width * 4
	if stride == row {
		copy(s.memory[top*row:bottom*row], retained[top*stride:bottom*stride])
		return
	}
	for y := top; y < bottom; y++ {
		copy(s.memory[y*row:(y+1)*row], retained[y*stride:y*stride+row])
	}
}

// composite blends the XFixes cursor (premultiplied ARGB) onto the rows the
// slot holds for a width x height framebuffer, at the cursor's screen
// position, and answers the rectangle it drew.
func (s *pixelSlot) composite(cursor *xfixes.GetCursorImageReply, width, height int) image.Rectangle {
	if cursor == nil || len(cursor.CursorImage) != int(cursor.Width)*int(cursor.Height) {
		return image.Rectangle{}
	}
	left, top := int(cursor.X)-int(cursor.Xhot), int(cursor.Y)-int(cursor.Yhot)
	drawn := image.Rect(left, top, left+int(cursor.Width), top+int(cursor.Height)).Intersect(image.Rect(0, 0, width, height))
	for y := drawn.Min.Y; y < drawn.Max.Y; y++ {
		for x := drawn.Min.X; x < drawn.Max.X; x++ {
			argb := cursor.CursorImage[(y-top)*int(cursor.Width)+x-left]
			a := argb >> 24
			offset := (y*width + x) * 4
			pixel := s.memory[offset : offset+3 : offset+3]
			pixel[0] = byte(min(255, (argb&255)+uint32(pixel[0])*(255-a)/255))
			pixel[1] = byte(min(255, ((argb>>8)&255)+uint32(pixel[1])*(255-a)/255))
			pixel[2] = byte(min(255, ((argb>>16)&255)+uint32(pixel[2])*(255-a)/255))
		}
	}
	return drawn
}
