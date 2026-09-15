// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bytes"
	"image"
	"image/jpeg"
	"math/bits"

	"github.com/robotn/xgb/xfixes"
	"github.com/robotn/xgb/xproto"
)

type capturedFrame struct {
	Width          int    `json:"width"`
	Height         int    `json:"height"`
	Encoding       string `json:"encoding"`
	Data           []byte `json:"data"`
	CursorIncluded bool   `json:"cursorIncluded"`
}

func (d *display) capture() (capturedFrame, error) {
	width, height, err := d.size()
	if err != nil {
		return capturedFrame{}, err
	}
	raw, err := xproto.GetImage(d.conn, xproto.ImageFormatZPixmap, xproto.Drawable(d.screen.Root), 0, 0, uint16(width), uint16(height), 0xffffffff).Reply()
	if err != nil {
		return capturedFrame{}, err
	}
	setup := xproto.Setup(d.conn)
	var format xproto.Format
	for _, candidate := range setup.PixmapFormats {
		if candidate.Depth == raw.Depth {
			format = candidate
			break
		}
	}
	var visual xproto.VisualInfo
	for _, depth := range d.screen.AllowedDepths {
		for _, candidate := range depth.Visuals {
			if candidate.VisualId == raw.Visual {
				visual = candidate
			}
		}
	}
	decoded, err := decodeImage(raw.Data, width, height, format, visual, setup.ImageByteOrder)
	if err != nil {
		return capturedFrame{}, err
	}
	cursor, err := xfixes.GetCursorImage(d.conn).Reply()
	if err != nil {
		return capturedFrame{}, err
	}
	compositeCursor(decoded, cursor)
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, decoded, &jpeg.Options{Quality: 85}); err != nil {
		return capturedFrame{}, err
	}
	return capturedFrame{Width: width, Height: height, Encoding: "jpeg", Data: encoded.Bytes(), CursorIncluded: true}, nil
}
func decodeImage(raw []byte, width, height int, format xproto.Format, visual xproto.VisualInfo, order byte) (*image.RGBA, error) {
	if !validSize(width, height) || (format.BitsPerPixel != 32 && format.BitsPerPixel != 24) || format.ScanlinePad == 0 || visual.RedMask == 0 || visual.GreenMask == 0 || visual.BlueMask == 0 {
		return nil, unavailable()
	}
	stride := ((width*int(format.BitsPerPixel) + int(format.ScanlinePad) - 1) / int(format.ScanlinePad)) * int(format.ScanlinePad) / 8
	if len(raw) != stride*height {
		return nil, unavailable()
	}
	result := image.NewRGBA(image.Rect(0, 0, width, height))
	bpp := int(format.BitsPerPixel) / 8
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
			if order == xproto.ImageOrderLSBFirst {
				for b := bpp - 1; b >= 0; b-- {
					pixel = (pixel << 8) | uint32(source[b])
				}
			} else {
				for b := 0; b < bpp; b++ {
					pixel = (pixel << 8) | uint32(source[b])
				}
			}
			offset := y*result.Stride + x*4
			result.Pix[offset] = channel(pixel, visual.RedMask)
			result.Pix[offset+1] = channel(pixel, visual.GreenMask)
			result.Pix[offset+2] = channel(pixel, visual.BlueMask)
			result.Pix[offset+3] = 255
		}
	}
	return result, nil
}
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
			offset := py*img.Stride + px*4
			// XFixes ARGB is premultiplied; preserve the actual native cursor shape.
			img.Pix[offset] = byte(min(255, ((argb>>16)&255)+uint32(img.Pix[offset])*(255-a)/255))
			img.Pix[offset+1] = byte(min(255, ((argb>>8)&255)+uint32(img.Pix[offset+1])*(255-a)/255))
			img.Pix[offset+2] = byte(min(255, (argb&255)+uint32(img.Pix[offset+2])*(255-a)/255))
		}
	}
}
