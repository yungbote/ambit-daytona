// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package view

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
)

// The fixtures are the toolbox tests' own (browser_frames_linux_test.go and
// the video, audio and cursor tests), so the ported cases mean the same.

const fixtureSecret = "task-input-that-must-never-reach-a-viewer"

const (
	videoEpoch     = "5b0c0b1e-6f0a-4c1c-9d59-0e3f2b7a9c11"
	videoNextEpoch = "9a1d7c42-3a55-4f0e-8a7b-5d2c8e6f4b20"
	audioEpoch     = "849653a5-972a-4cb7-8eb1-4a78b00d18a8"
	audioNextEpoch = "cf744786-e37b-451a-b8ba-8d2d44c5249c"
)

func fixtureJPEG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetRGBA(x, y, color.RGBA{R: byte(x), G: byte(y), B: 90, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 85}); err != nil {
		panic(err)
	}
	return encoded.Bytes()
}

var wholeJPEG, patchJPEG = fixtureJPEG(640, 480), fixtureJPEG(32, 32)

func fixtureSurface() map[string]any {
	return map[string]any{"kind": "browser-window", "coordinateSpace": "display-pixels", "generation": "11111111-1111-4111-8111-111111111111", "width": 640, "height": 480, "originX": 0, "originY": 0, "deviceScaleFactor": 2, "cursorIncluded": false, "private": fixtureSecret}
}

// fixtureFrame is a whole frame (seq 10) or a patch set on it (seq 12).
func fixtureFrame(patched bool) (map[string]any, []byte) {
	header := map[string]any{"type": "frame", "seq": 10, "encoding": "jpeg", "surface": fixtureSurface(), "private": fixtureSecret}
	if !patched {
		payload := append([]byte(nil), wholeJPEG...)
		header["byteLength"] = len(payload)
		return header, payload
	}
	payload := append([]byte(nil), patchJPEG...)
	header["seq"], header["baseSeq"] = 12, 10
	header["patches"] = []any{map[string]any{"x": 624, "y": 464, "width": 16, "height": 16, "sourceX": 16, "sourceY": 16, "byteLength": len(payload), "private": fixtureSecret}}
	return header, payload
}

// frameAt is a whole frame at sequence seq, or a patch set on base.
func frameAt(seq, base int) []byte {
	header, payload := fixtureFrame(base != 0)
	header["seq"] = seq
	if base != 0 {
		header["baseSeq"] = base
	}
	return pack(header, payload)
}

func pack(header map[string]any, payload []byte) []byte {
	encoded, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	return packHeader(encoded, payload)
}

func packHeader(header, payload []byte) []byte {
	result := make([]byte, 4, 4+len(header)+len(payload))
	binary.BigEndian.PutUint32(result, uint32(len(header)))
	result = append(result, header...)
	return append(result, payload...)
}

// wire is a delivery exactly as a carrier writes it.
func wire(d *Delivery) []byte {
	if d.Kind == Record {
		return d.Text
	}
	return packHeader(d.Header, d.Payload)
}

func jsonOf(fields map[string]any) []byte {
	encoded, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return encoded
}

func videoHeaderFixture(seq int, key bool, payload int) map[string]any {
	header := map[string]any{"type": "media", "track": "video", "codec": "av1", "streamId": videoEpoch, "seq": seq, "ts": 1234567 + seq,
		"key": key, "coded": map[string]any{"width": 2048, "height": 2048}, "visible": map[string]any{"x": 0, "y": 0, "width": 1840, "height": 1888},
		"surface": fixtureSurface(), "inputSeq": 7, "quality": "motion", "byteLength": payload, "private": fixtureSecret}
	if key {
		header["codecString"] = "av01.0.12M.08"
	}
	return header
}

func videoUnit(epoch string, seq int, key bool) []byte {
	payload := bytes.Repeat([]byte{byte(seq)}, 64)
	header := videoHeaderFixture(seq, key, len(payload))
	header["streamId"] = epoch
	return pack(header, payload)
}

func audioHeaderFixture(codec string) map[string]any {
	return map[string]any{"type": "media", "track": "audio", "codec": codec, "streamId": audioEpoch, "seq": 1, "ts": 1234567, "samples": 480, "byteLength": 1920}
}

func audioPacket(epoch string, seq int) []byte {
	header := audioHeaderFixture("pcm-s16le")
	header["streamId"], header["seq"], header["ts"] = epoch, seq, 1234567+seq
	return pack(header, make([]byte, 1920))
}

func cursorPNG(width, height int) string {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewNRGBA(image.Rect(0, 0, width, height))); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(encoded.Bytes())
}
