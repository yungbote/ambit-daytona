// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package websocket_test

import (
	"bytes"
	"image"
	"image/jpeg"
)

// jpeg16 is a 16x16 JPEG: the fixture frame's whole raster.
var jpeg16 = func() []byte {
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 16, 16)), nil); err != nil {
		panic(err)
	}
	return encoded.Bytes()
}()
