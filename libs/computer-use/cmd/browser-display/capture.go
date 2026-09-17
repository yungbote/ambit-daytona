// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"image"
	"math/bits"

	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
)

// pixelLayout is the wire format of the root drawable. The server fixes it for
// the life of the display; every capture reads it, never re-negotiates it.
type pixelLayout struct {
	depth  byte
	visual xproto.VisualInfo
	format xproto.Format
	order  byte
}

func rootLayout(setup *xproto.SetupInfo, screen *xproto.ScreenInfo) (pixelLayout, bool) {
	layout := pixelLayout{depth: screen.RootDepth, order: setup.ImageByteOrder}
	for _, candidate := range setup.PixmapFormats {
		if candidate.Depth == screen.RootDepth {
			layout.format = candidate
			break
		}
	}
	for _, depth := range screen.AllowedDepths {
		for _, candidate := range depth.Visuals {
			if candidate.VisualId == screen.RootVisual {
				layout.visual = candidate
			}
		}
	}
	return layout, layout.valid()
}
func (l pixelLayout) valid() bool {
	return (l.format.BitsPerPixel == 32 || l.format.BitsPerPixel == 24) && l.format.ScanlinePad != 0 && l.visual.RedMask != 0 && l.visual.GreenMask != 0 && l.visual.BlueMask != 0
}

// fast reports the common layout of 32-bit little-endian pixels whose bytes
// are B, G, R, X. It converts by direct byte indexing.
func (l pixelLayout) fast() bool {
	return l.format.BitsPerPixel == 32 && l.order == xproto.ImageOrderLSBFirst && l.visual.RedMask == 0xff0000 && l.visual.GreenMask == 0xff00 && l.visual.BlueMask == 0xff
}
func (l pixelLayout) bytesPerPixel() int { return int(l.format.BitsPerPixel) / 8 }
func (l pixelLayout) stride(width int) int {
	pad := int(l.format.ScanlinePad)
	return ((width*int(l.format.BitsPerPixel) + pad - 1) / pad) * pad / 8
}

func decodeImage(raw []byte, width, height int, format xproto.Format, visual xproto.VisualInfo, order byte) (*image.RGBA, error) {
	layout := pixelLayout{format: format, visual: visual, order: order}
	if !validSize(width, height) || !layout.valid() {
		return nil, unavailable()
	}
	stride := layout.stride(width)
	if len(raw) != stride*height {
		return nil, unavailable()
	}
	result := image.NewRGBA(image.Rect(0, 0, width, height))
	layout.decode(result, raw, stride)
	return result, nil
}

// decode converts dst's rows from raw pixels whose first byte is dst's first
// pixel and whose rows are stride bytes apart.
func (l pixelLayout) decode(dst *image.RGBA, raw []byte, stride int) {
	if l.fast() {
		bgrxToRGBA(dst, raw, stride)
		return
	}
	width, height := dst.Rect.Dx(), dst.Rect.Dy()
	bpp := l.bytesPerPixel()
	channel := func(pixel, mask uint32) byte {
		shift := bits.TrailingZeros32(mask)
		value := (pixel & mask) >> shift
		maximum := mask >> shift
		return byte(value * 255 / maximum)
	}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			source := raw[y*stride+x*bpp:]
			var pixel uint32
			if l.order == xproto.ImageOrderLSBFirst {
				for b := bpp - 1; b >= 0; b-- {
					pixel = (pixel << 8) | uint32(source[b])
				}
			} else {
				for b := 0; b < bpp; b++ {
					pixel = (pixel << 8) | uint32(source[b])
				}
			}
			offset := y*dst.Stride + x*4
			dst.Pix[offset] = channel(pixel, l.visual.RedMask)
			dst.Pix[offset+1] = channel(pixel, l.visual.GreenMask)
			dst.Pix[offset+2] = channel(pixel, l.visual.BlueMask)
			dst.Pix[offset+3] = 255
		}
	}
}
func bgrxToRGBA(dst *image.RGBA, raw []byte, stride int) {
	width, height := dst.Rect.Dx(), dst.Rect.Dy()
	for y := 0; y < height; y++ {
		source := raw[y*stride : y*stride+width*4]
		target := dst.Pix[y*dst.Stride : y*dst.Stride+width*4]
		for x := 0; x+3 < len(source); x += 4 {
			target[x] = source[x+2]
			target[x+1] = source[x+1]
			target[x+2] = source[x]
			target[x+3] = 255
		}
	}
}

// The integer formulas are image/color's RGBToYCbCr, split so they inline.
func luma(r, g, b int32) uint8 { return uint8((19595*r + 38470*g + 7471*b + 1<<15) >> 16) }
func chroma(value int32) uint8 {
	if uint32(value)&0xff000000 == 0 {
		return uint8(value >> 16)
	}
	return uint8(^(value >> 31))
}
func blue(r, g, b int32) int32 { return -11056*r - 21712*g + 32768*b + 257<<15 }
func red(r, g, b int32) int32  { return 32768*r - 27440*g - 5328*b + 257<<15 }

// bgrxToYCbCr converts rows of B, G, R, X pixels straight into a 4:2:0 image
// the way image/jpeg treats RGBA input: per-pixel chroma averaged over each
// 2x2 group with (sum+2)>>2, the last column and row replicated at odd edges.
// dst's rows start at raw's first byte; its height may be odd.
func bgrxToYCbCr(dst *image.YCbCr, raw []byte, stride int) {
	width, height := dst.Rect.Dx(), dst.Rect.Dy()
	for y := 0; y < height; y += 2 {
		y1 := min(y+1, height-1)
		row0 := raw[y*stride : y*stride+width*4]
		row1 := raw[y1*stride : y1*stride+width*4]
		luma0 := dst.Y[y*dst.YStride : y*dst.YStride+width]
		luma1 := dst.Y[y1*dst.YStride : y1*dst.YStride+width]
		cbRow := dst.Cb[(y/2)*dst.CStride : (y/2)*dst.CStride+(width+1)/2]
		crRow := dst.Cr[(y/2)*dst.CStride : (y/2)*dst.CStride+(width+1)/2]
		for x := 0; x < width; x += 2 {
			x1 := min(x+1, width-1)
			r00, g00, b00 := int32(row0[x*4+2]), int32(row0[x*4+1]), int32(row0[x*4])
			r01, g01, b01 := int32(row0[x1*4+2]), int32(row0[x1*4+1]), int32(row0[x1*4])
			r10, g10, b10 := int32(row1[x*4+2]), int32(row1[x*4+1]), int32(row1[x*4])
			r11, g11, b11 := int32(row1[x1*4+2]), int32(row1[x1*4+1]), int32(row1[x1*4])
			luma0[x], luma0[x1] = luma(r00, g00, b00), luma(r01, g01, b01)
			luma1[x], luma1[x1] = luma(r10, g10, b10), luma(r11, g11, b11)
			cbRow[x/2] = uint8((int32(chroma(blue(r00, g00, b00))) + int32(chroma(blue(r01, g01, b01))) + int32(chroma(blue(r10, g10, b10))) + int32(chroma(blue(r11, g11, b11))) + 2) >> 2)
			crRow[x/2] = uint8((int32(chroma(red(r00, g00, b00))) + int32(chroma(red(r01, g01, b01))) + int32(chroma(red(r10, g10, b10))) + int32(chroma(red(r11, g11, b11))) + 2) >> 2)
		}
	}
}

// rgbaToYCbCr is bgrxToYCbCr for decoded RGBA rows, the path every other pixel
// layout and every cursor-composited region takes.
func rgbaToYCbCr(dst *image.YCbCr, src *image.RGBA) {
	width, height := dst.Rect.Dx(), dst.Rect.Dy()
	for y := 0; y < height; y += 2 {
		y1 := min(y+1, height-1)
		row0 := src.Pix[y*src.Stride : y*src.Stride+width*4]
		row1 := src.Pix[y1*src.Stride : y1*src.Stride+width*4]
		luma0 := dst.Y[y*dst.YStride : y*dst.YStride+width]
		luma1 := dst.Y[y1*dst.YStride : y1*dst.YStride+width]
		cbRow := dst.Cb[(y/2)*dst.CStride : (y/2)*dst.CStride+(width+1)/2]
		crRow := dst.Cr[(y/2)*dst.CStride : (y/2)*dst.CStride+(width+1)/2]
		for x := 0; x < width; x += 2 {
			x1 := min(x+1, width-1)
			r00, g00, b00 := int32(row0[x*4]), int32(row0[x*4+1]), int32(row0[x*4+2])
			r01, g01, b01 := int32(row0[x1*4]), int32(row0[x1*4+1]), int32(row0[x1*4+2])
			r10, g10, b10 := int32(row1[x*4]), int32(row1[x*4+1]), int32(row1[x*4+2])
			r11, g11, b11 := int32(row1[x1*4]), int32(row1[x1*4+1]), int32(row1[x1*4+2])
			luma0[x], luma0[x1] = luma(r00, g00, b00), luma(r01, g01, b01)
			luma1[x], luma1[x1] = luma(r10, g10, b10), luma(r11, g11, b11)
			cbRow[x/2] = uint8((int32(chroma(blue(r00, g00, b00))) + int32(chroma(blue(r01, g01, b01))) + int32(chroma(blue(r10, g10, b10))) + int32(chroma(blue(r11, g11, b11))) + 2) >> 2)
			crRow[x/2] = uint8((int32(chroma(red(r00, g00, b00))) + int32(chroma(red(r01, g01, b01))) + int32(chroma(red(r10, g10, b10))) + int32(chroma(red(r11, g11, b11))) + 2) >> 2)
		}
	}
}

// compositeCursor blends the XFixes cursor onto img at its screen position;
// img.Rect is in screen coordinates.
func compositeCursor(img *image.RGBA, cursor *xfixes.GetCursorImageReply) {
	if cursor == nil || len(cursor.CursorImage) != int(cursor.Width)*int(cursor.Height) {
		return
	}
	left, top := int(cursor.X)-int(cursor.Xhot), int(cursor.Y)-int(cursor.Yhot)
	for y := 0; y < int(cursor.Height); y++ {
		for x := 0; x < int(cursor.Width); x++ {
			px, py := left+x, top+y
			if !image.Pt(px, py).In(img.Bounds()) {
				continue
			}
			argb := cursor.CursorImage[y*int(cursor.Width)+x]
			a := argb >> 24
			offset := img.PixOffset(px, py)
			// XFixes ARGB is premultiplied; preserve the actual native cursor shape.
			img.Pix[offset] = byte(min(255, ((argb>>16)&255)+uint32(img.Pix[offset])*(255-a)/255))
			img.Pix[offset+1] = byte(min(255, ((argb>>8)&255)+uint32(img.Pix[offset+1])*(255-a)/255))
			img.Pix[offset+2] = byte(min(255, (argb&255)+uint32(img.Pix[offset+2])*(255-a)/255))
		}
	}
}
