// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"bytes"
	"errors"
	"image"
	"sync"
)

// bandRows is one MCU row at 4:2:0 chroma subsampling: the unit of damage
// tracking, pixel fetch, encoding and caching.
const bandRows = 16

func bandCount(height int) int { return (height + bandRows - 1) / bandRows }
func bandRect(band, width, height int) image.Rectangle {
	top := band * bandRows
	return image.Rect(0, top, width, min(top+bandRows, height))
}

// markRows sets every band intersecting rows [top, bottom) of bands.
func markRows(bands []bool, top, bottom int) {
	top, bottom = max(top, 0), min(bottom, len(bands)*bandRows)
	if top >= bottom {
		return
	}
	for band := top / bandRows; band < (bottom+bandRows-1)/bandRows; band++ {
		bands[band] = true
	}
}

// bandMosaic assembles one baseline JPEG from independently encoded bands.
// The standard encoder starts DC prediction at zero and pads its final byte
// with one bits on every call, which is exactly a decoder's state after a
// restart marker. With a restart interval of one MCU row, the entropy-coded
// segment of a band encoded on its own is byte-identical to that row of one
// monolithic encode, so the frame decodes to the same pixels while only bands
// whose pixels changed are re-encoded. Tables depend only on quality, the
// frame header only on size; both come from any band's own output.
type bandMosaic struct {
	width, height int
	headerMu      sync.Mutex
	header        []byte   // SOI through SOS for this size; nil until a band is stored
	bands         [][]byte // entropy-coded segment per band
	valid         []bool   // bands[i] reflects the current pixels and quality
}

func (m *bandMosaic) reset(width, height int) {
	m.width, m.height = width, height
	m.header = nil
	count := bandCount(height)
	if cap(m.bands) < count {
		m.bands = make([][]byte, count)
		m.valid = make([]bool, count)
	}
	m.bands, m.valid = m.bands[:count], m.valid[:count]
	m.invalidateAll()
}

// invalidateAll keeps the size and drops every segment, as a quality change
// requires.
func (m *bandMosaic) invalidateAll() {
	m.header = nil
	for band := range m.valid {
		m.valid[band] = false
	}
}
func (m *bandMosaic) invalidate(band int) { m.valid[band] = false }
func (m *bandMosaic) current(band int) bool {
	return m.header != nil && m.valid[band]
}
func (m *bandMosaic) complete() bool {
	if m.header == nil {
		return false
	}
	for _, valid := range m.valid {
		if !valid {
			return false
		}
	}
	return true
}

// store keeps the entropy-coded segment of one band's complete JPEG. Calls for
// distinct bands may run concurrently.
func (m *bandMosaic) store(band int, encoded []byte) error {
	segments, err := splitJPEG(encoded)
	if err != nil {
		return err
	}
	m.bands[band] = append(m.bands[band][:0], segments.entropy...)
	m.valid[band] = true
	m.headerMu.Lock()
	defer m.headerMu.Unlock()
	if m.header == nil {
		m.header, err = frameHeader(segments, m.width, m.height)
	}
	return err
}

// assemble concatenates the cached bands into one frame.
func (m *bandMosaic) assemble() ([]byte, error) {
	if !m.complete() {
		return nil, errors.New("frame bands are not all encoded")
	}
	size := len(m.header) + 2*len(m.bands) + 2
	for _, band := range m.bands {
		size += len(band)
	}
	frame := make([]byte, 0, size)
	frame = append(frame, m.header...)
	for band, segment := range m.bands {
		frame = append(frame, segment...)
		if band+1 < len(m.bands) {
			frame = append(frame, 0xff, 0xd0+byte(band%8))
		}
	}
	return append(frame, 0xff, 0xd9), nil
}

// jpegSegments is one baseline JPEG taken apart at its markers.
type jpegSegments struct {
	tables  []byte // every segment between SOI and SOS: DQT, SOF0 and DHT
	frame   int    // offset of the SOF0 marker within tables
	scan    []byte // the 14-byte three-component SOS segment
	entropy []byte // entropy-coded data up to EOI
}

func splitJPEG(data []byte) (jpegSegments, error) {
	var segments jpegSegments
	malformed := errors.New("unexpected JPEG layout")
	if len(data) < 4 || data[0] != 0xff || data[1] != 0xd8 || data[len(data)-2] != 0xff || data[len(data)-1] != 0xd9 {
		return segments, malformed
	}
	frame := -1
	for position := 2; ; {
		if position+4 > len(data) || data[position] != 0xff {
			return segments, malformed
		}
		marker := data[position+1]
		length := int(data[position+2])<<8 | int(data[position+3])
		if length < 2 || position+2+length > len(data)-2 {
			return segments, malformed
		}
		switch marker {
		case 0xc0:
			frame = position - 2
		case 0xda:
			if length != 12 || frame < 0 {
				return segments, malformed
			}
			segments.tables = data[2:position]
			segments.frame = frame
			segments.scan = data[position : position+14]
			segments.entropy = data[position+14 : len(data)-2]
			return segments, nil
		}
		position += 2 + length
	}
}

// frameHeader builds SOI through SOS for a whole frame from one band's
// segments: the frame height replaces the band height in SOF0 and a DRI
// segment sets the restart interval to one MCU row.
func frameHeader(segments jpegSegments, width, height int) ([]byte, error) {
	sof := segments.tables[segments.frame:]
	// FF C0, length, precision, height, width.
	if len(sof) < 9 || int(sof[7])<<8|int(sof[8]) != width {
		return nil, errors.New("band frame header does not match the frame")
	}
	interval := (width + bandRows - 1) / bandRows
	var header bytes.Buffer
	header.Grow(2 + len(segments.tables) + 6 + len(segments.scan))
	header.Write([]byte{0xff, 0xd8})
	header.Write(segments.tables)
	rewritten := header.Bytes()[2+segments.frame+5:]
	rewritten[0], rewritten[1] = byte(height>>8), byte(height)
	header.Write([]byte{0xff, 0xdd, 0x00, 0x04, byte(interval >> 8), byte(interval)})
	header.Write(segments.scan)
	return header.Bytes(), nil
}
