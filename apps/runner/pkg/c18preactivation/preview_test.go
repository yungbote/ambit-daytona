// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestArtifactPreviewParsesExactBodyAndCommandValidation(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	body := "Exact preview text."
	view, err := generationstop.CanonicalJSON(PreviewTextViewV1{
		Body: body, ByteLength: int64(len(body)), Digest: sha256Digest([]byte(body)),
		Kind: "text", Label: "Preview", MediaType: "text/plain", Ordinal: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	validation := make([]PreviewValidationV1, len(command.PackRequiredChecks))
	for index, check := range command.PackRequiredChecks {
		validation[index] = PreviewValidationV1{Check: check.Check, Label: check.Label, Status: "passed"}
	}
	preview := ArtifactPreviewV1{
		Contract: previewContractV1, Facet: command.Facet, Facts: []PreviewFactV1{},
		Limitations: []PreviewLimitationV1{}, SchemaVersion: 1, Summary: "Exact summary.",
		Title: "Exact title", Validation: validation, Views: []json.RawMessage{view},
	}
	preview.Digest, err = sealedDigest(preview)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := generationstop.CanonicalJSON(preview)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseArtifactPreviewV1(encoded, command)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest != preview.Digest {
		t.Fatal("preview semantic digest drifted")
	}

	preview.Validation[0].Label = "Substituted label"
	preview.Digest, err = sealedDigest(preview)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = generationstop.CanonicalJSON(preview)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseArtifactPreviewV1(encoded, command); err == nil {
		t.Fatal("preview validation-label substitution was admitted")
	}

	preview.Validation[0].Label = command.PackRequiredChecks[0].Label
	preview.Facts = nil
	preview.Digest, err = sealedDigest(preview)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = generationstop.CanonicalJSON(preview)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseArtifactPreviewV1(encoded, command); err == nil {
		t.Fatal("preview facts:null was admitted in place of the exact empty roster")
	}
}

func TestPreviewRejectsTextOutsideBackendUTF16Bounds(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	body := "Exact preview text."
	view, err := generationstop.CanonicalJSON(PreviewTextViewV1{
		Body: body, ByteLength: int64(len(body)), Digest: sha256Digest([]byte(body)),
		Kind: "text", Label: "Preview", MediaType: "text/plain", Ordinal: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	validation := make([]PreviewValidationV1, len(command.PackRequiredChecks))
	for index, check := range command.PackRequiredChecks {
		validation[index] = PreviewValidationV1{Check: check.Check, Label: check.Label, Status: "passed"}
	}
	preview := ArtifactPreviewV1{
		Contract: previewContractV1, Facet: command.Facet, Facts: []PreviewFactV1{},
		Limitations: []PreviewLimitationV1{}, SchemaVersion: 1, Summary: "Exact summary.",
		Title: "Exact title", Validation: validation, Views: []json.RawMessage{view},
	}
	// JavaScript and Python define this contract in UTF-16 code units. Each
	// astral rune counts as two, so 129 runes exceed the 256-unit title bound.
	preview.Title = strings.Repeat("😀", 129)
	preview.Digest = resealForTest(t, preview)
	encoded, err := generationstop.CanonicalJSON(preview)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseArtifactPreviewV1(encoded, command); err == nil {
		t.Fatal("preview title outside the backend UTF-16 bound was admitted")
	}
}

func TestPreviewPlainTextRejectsBackendForbiddenAstralCodeUnits(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	body := "Astral text is otherwise well formed 😀"
	view, err := generationstop.CanonicalJSON(PreviewTextViewV1{
		Body: body, ByteLength: int64(len([]byte(body))), Digest: sha256Digest([]byte(body)),
		Kind: "text", Label: "Preview", MediaType: "text/plain", Ordinal: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeTestImagePreview(t, command, []json.RawMessage{view})
	if _, err := ParseArtifactPreviewV1(encoded, command); err == nil {
		t.Fatal("plain-text preview admitted a backend-forbidden astral UTF-16 pair")
	}
}

func TestArtifactPreviewImageProofAndEveryAggregateBound(t *testing.T) {
	golden := loadRenderGolden(t)
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON([]byte(golden.Request), &command); err != nil {
		t.Fatal(err)
	}
	validPNG := encodeTestPNG(t, 2, 3)
	positive := encodeTestImagePreview(t, command, []json.RawMessage{
		encodeTestImageView(t, validPNG, 2, 3, 1, ""),
	})
	parsed, err := ParseArtifactPreviewV1(positive, command)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Views) != 1 {
		t.Fatal("real PNG preview did not retain its exact image view")
	}

	forgedPNG := append([]byte(nil), validPNG...)
	forgedPNG[0] ^= 0xff
	oversizedDimensionPNG := rewritePNGDimensions(validPNG, 4_097, 1)
	oversizedPixelsPNG := rewritePNGDimensions(validPNG, 4_096, 2_049)
	aggregatePixelPNG := rewritePNGDimensions(validPNG, 3_100, 2_200)
	paddedPNG := append(append([]byte(nil), validPNG...), make([]byte, 512*1024-len(validPNG))...)

	forgedBase64View := decodeTestImageView(t, encodeTestImageView(t, validPNG, 2, 3, 1, ""))
	forgedBase64View.BodyBase64 += "="
	forgedBase64Bytes, err := generationstop.CanonicalJSON(forgedBase64View)
	if err != nil {
		t.Fatal(err)
	}

	aggregatePixelViews := make([]json.RawMessage, 5)
	for index := range aggregatePixelViews {
		aggregatePixelViews[index] = encodeTestImageView(t, aggregatePixelPNG, 3_100, 2_200, index+1, "")
	}
	aggregateByteViews := make([]json.RawMessage, 9)
	for index := range aggregateByteViews {
		aggregateByteViews[index] = encodeTestImageView(t, paddedPNG, 2, 3, index+1, "")
	}
	aggregateImageViews := make([]json.RawMessage, 129)
	for index := range aggregateImageViews {
		aggregateImageViews[index] = encodeTestImageView(t, validPNG, 2, 3, index+1, "")
	}

	tests := []struct {
		name  string
		views []json.RawMessage
	}{
		{name: "forged PNG signature", views: []json.RawMessage{encodeTestImageView(t, forgedPNG, 2, 3, 1, "")}},
		{name: "forged base64 digest", views: []json.RawMessage{encodeTestImageView(t, validPNG, 2, 3, 1, "sha256:"+repeatHex("f"))}},
		{name: "noncanonical base64", views: []json.RawMessage{forgedBase64Bytes}},
		{name: "IHDR dimension mismatch", views: []json.RawMessage{encodeTestImageView(t, validPNG, 3, 3, 1, "")}},
		{name: "per-image dimension", views: []json.RawMessage{encodeTestImageView(t, oversizedDimensionPNG, 4_097, 1, 1, "")}},
		{name: "per-image pixels", views: []json.RawMessage{encodeTestImageView(t, oversizedPixelsPNG, 4_096, 2_049, 1, "")}},
		{name: "aggregate image count", views: aggregateImageViews},
		{name: "aggregate pixels", views: aggregatePixelViews},
		{name: "aggregate bytes", views: aggregateByteViews},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := encodeTestImagePreview(t, command, test.views)
			if _, err := ParseArtifactPreviewV1(encoded, command); err == nil {
				t.Fatal("invalid image preview proof was admitted")
			}
		})
	}
}

func encodeTestPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, width, height))); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func rewritePNGDimensions(source []byte, width, height uint32) []byte {
	result := append([]byte(nil), source...)
	binary.BigEndian.PutUint32(result[16:20], width)
	binary.BigEndian.PutUint32(result[20:24], height)
	return result
}

func encodeTestImageView(
	t *testing.T,
	payload []byte,
	width, height int64,
	ordinal int,
	digest string,
) json.RawMessage {
	t.Helper()
	if digest == "" {
		digest = sha256Digest(payload)
	}
	encoded, err := generationstop.CanonicalJSON(PreviewImageViewV1{
		AltText: "Exact image preview", BodyBase64: base64.StdEncoding.EncodeToString(payload),
		ByteLength: int64(len(payload)), Digest: digest, Height: height, Kind: "image",
		Label: "Preview", MediaType: "image/png", Ordinal: ordinal, Width: width,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeTestImageView(t *testing.T, encoded json.RawMessage) PreviewImageViewV1 {
	t.Helper()
	var view PreviewImageViewV1
	if err := generationstop.DecodeCanonicalJSON(encoded, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func encodeTestImagePreview(
	t *testing.T,
	command RenderCommandV2,
	views []json.RawMessage,
) []byte {
	t.Helper()
	validation := make([]PreviewValidationV1, len(command.PackRequiredChecks))
	for index, check := range command.PackRequiredChecks {
		validation[index] = PreviewValidationV1{Check: check.Check, Label: check.Label, Status: "passed"}
	}
	preview := ArtifactPreviewV1{
		Contract: previewContractV1, Facet: command.Facet, Facts: []PreviewFactV1{},
		Limitations: []PreviewLimitationV1{}, SchemaVersion: 1, Summary: "Exact image summary.",
		Title: "Exact image title", Validation: validation, Views: views,
	}
	preview.Digest = resealForTest(t, preview)
	encoded, err := generationstop.CanonicalJSON(preview)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
