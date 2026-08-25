// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/daytonaio/runner/pkg/generationstop"
	"golang.org/x/text/unicode/norm"
)

const previewContractV1 = "ambit.c18-specialist-artifact-preview/v1"

type ArtifactPreviewV1 struct {
	Contract      string                `json:"contract"`
	Digest        string                `json:"digest"`
	Facet         string                `json:"facet"`
	Facts         []PreviewFactV1       `json:"facts"`
	Limitations   []PreviewLimitationV1 `json:"limitations"`
	SchemaVersion int                   `json:"schemaVersion"`
	Summary       string                `json:"summary"`
	Title         string                `json:"title"`
	Validation    []PreviewValidationV1 `json:"validation"`
	Views         []json.RawMessage     `json:"views"`
}

type PreviewFactV1 struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Value string `json:"value"`
}

type PreviewLimitationV1 struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

type PreviewValidationV1 struct {
	Check  string `json:"check"`
	Label  string `json:"label"`
	Status string `json:"status"`
}

type PreviewImageViewV1 struct {
	AltText    string `json:"altText"`
	BodyBase64 string `json:"bodyBase64"`
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	Height     int64  `json:"height"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	MediaType  string `json:"mediaType"`
	Ordinal    int    `json:"ordinal"`
	Width      int64  `json:"width"`
}

type PreviewTextViewV1 struct {
	Body       string `json:"body"`
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	MediaType  string `json:"mediaType"`
	Ordinal    int    `json:"ordinal"`
}

func ParseArtifactPreviewV1(encoded []byte, command RenderCommandV2) (ArtifactPreviewV1, error) {
	if len(encoded) == 0 || int64(len(encoded)) > command.Output.MaximumPreviewBytes || len(encoded) > 16*1024*1024 {
		return ArtifactPreviewV1{}, errors.New("C18 preview bytes exceed their bound")
	}
	var preview ArtifactPreviewV1
	if err := generationstop.DecodeCanonicalJSON(encoded, &preview); err != nil {
		return ArtifactPreviewV1{}, fmt.Errorf("decode C18 preview: %w", err)
	}
	if preview.Contract != previewContractV1 || preview.SchemaVersion != 1 || preview.Facet != command.Facet ||
		!printableBounded(preview.Title, 256, 1_024) || !printableBounded(preview.Summary, 4_096, 16_384) ||
		preview.Views == nil || preview.Facts == nil || preview.Validation == nil || preview.Limitations == nil ||
		len(preview.Views) < 1 || len(preview.Views) > 128 || len(preview.Facts) > 128 ||
		len(preview.Validation) < 1 || len(preview.Validation) > 256 || len(preview.Limitations) > 128 {
		return ArtifactPreviewV1{}, errors.New("C18 preview envelope is invalid")
	}
	if err := verifySealedDigest(preview, preview.Digest); err != nil {
		return ArtifactPreviewV1{}, err
	}
	var aggregateBytes int64
	var aggregatePixels int64
	for index, raw := range preview.Views {
		var discriminator struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw, &discriminator); err != nil {
			return ArtifactPreviewV1{}, errors.New("C18 preview view discriminator is invalid")
		}
		switch discriminator.Kind {
		case "image":
			var view PreviewImageViewV1
			if err := generationstop.DecodeCanonicalJSON(raw, &view); err != nil {
				return ArtifactPreviewV1{}, fmt.Errorf("decode C18 preview image: %w", err)
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(view.BodyBase64)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != view.BodyBase64 ||
				view.Ordinal != index+1 || view.MediaType != "image/png" || view.ByteLength < 1 ||
				view.ByteLength > 512*1024 || int64(len(decoded)) != view.ByteLength ||
				sha256Digest(decoded) != view.Digest || !printableBounded(view.Label, 256, 1_024) ||
				!printableBounded(view.AltText, 2_048, 8_192) {
				return ArtifactPreviewV1{}, errors.New("C18 preview image view is invalid")
			}
			width, height, ok := pngDimensions(decoded)
			if !ok || width != view.Width || height != view.Height || width < 1 || height < 1 ||
				width > 4_096 || height > 4_096 || width*height > 8*1024*1024 {
				return ArtifactPreviewV1{}, errors.New("C18 preview PNG dimensions are invalid")
			}
			aggregateBytes += view.ByteLength
			aggregatePixels += width * height
		case "text":
			var view PreviewTextViewV1
			if err := generationstop.DecodeCanonicalJSON(raw, &view); err != nil {
				return ArtifactPreviewV1{}, fmt.Errorf("decode C18 preview text: %w", err)
			}
			bodyBytes := []byte(view.Body)
			if view.Ordinal != index+1 || view.MediaType != "text/plain" || view.ByteLength < 1 ||
				view.ByteLength > 1024*1024 || int64(len(bodyBytes)) != view.ByteLength ||
				sha256Digest(bodyBytes) != view.Digest || !canonicalPlainText(view.Body) ||
				!printableBounded(view.Label, 256, 1_024) {
				return ArtifactPreviewV1{}, errors.New("C18 preview text view is invalid")
			}
			aggregateBytes += view.ByteLength
		default:
			return ArtifactPreviewV1{}, errors.New("C18 preview view kind is invalid")
		}
	}
	if aggregateBytes > 4*1024*1024 || aggregatePixels > 32*1024*1024 {
		return ArtifactPreviewV1{}, errors.New("C18 preview aggregate view bound is exceeded")
	}
	factKeys := make([]string, len(preview.Facts))
	for index, fact := range preview.Facts {
		if !canonicalTokenValue(fact.Key) || !printableBounded(fact.Label, 256, 1_024) ||
			!printableBounded(fact.Value, 1_024, 4_096) {
			return ArtifactPreviewV1{}, errors.New("C18 preview fact is invalid")
		}
		factKeys[index] = fact.Key
	}
	if !sortedUnique(factKeys) {
		return ArtifactPreviewV1{}, errors.New("C18 preview facts are not sorted and unique")
	}
	if len(preview.Validation) != len(command.PackRequiredChecks) {
		return ArtifactPreviewV1{}, errors.New("C18 preview validation roster is incomplete")
	}
	for index, validation := range preview.Validation {
		expected := command.PackRequiredChecks[index]
		if validation.Check != expected.Check || validation.Label != expected.Label || validation.Status != "passed" {
			return ArtifactPreviewV1{}, errors.New("C18 preview validation differs from command authority")
		}
	}
	limitationCodes := make([]string, len(preview.Limitations))
	for index, limitation := range preview.Limitations {
		if !canonicalTokenValue(limitation.Code) ||
			(limitation.Severity != "info" && limitation.Severity != "warning") ||
			!printableBounded(limitation.Message, 2_048, 8_192) {
			return ArtifactPreviewV1{}, errors.New("C18 preview limitation is invalid")
		}
		limitationCodes[index] = limitation.Code
	}
	if !sortedUnique(limitationCodes) {
		return ArtifactPreviewV1{}, errors.New("C18 preview limitations are not sorted and unique")
	}
	return preview, nil
}

func pngDimensions(value []byte) (int64, int64, bool) {
	if len(value) < 24 || !bytes.Equal(value[:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}) ||
		binary.BigEndian.Uint32(value[8:12]) != 13 || string(value[12:16]) != "IHDR" {
		return 0, 0, false
	}
	return int64(binary.BigEndian.Uint32(value[16:20])), int64(binary.BigEndian.Uint32(value[20:24])), true
}

func canonicalPlainText(value string) bool {
	if value == "" || !utf8.ValidString(value) || len([]byte(value)) > 1024*1024 ||
		!norm.NFC.IsNormalString(value) || bytes.IndexByte([]byte(value), '\r') >= 0 {
		return false
	}
	for _, character := range value {
		if character <= 0x08 || character == 0x0b || character == 0x0c ||
			(character >= 0x0e && character <= 0x1f) || (character >= 0x7f && character <= 0x9f) ||
			(character >= 0xd800 && character <= 0xdfff) || character > 0xffff {
			return false
		}
	}
	return true
}

func printableBounded(value string, maximumCharacters, maximumBytes int) bool {
	return len([]rune(value)) <= maximumCharacters && len([]byte(value)) <= maximumBytes && printable(value, maximumCharacters)
}
