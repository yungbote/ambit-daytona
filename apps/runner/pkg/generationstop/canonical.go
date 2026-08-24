// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package generationstop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

const receiptKind = "agent_workspace_stopped_generation_receipt"

type canonicalReceiptPayload struct {
	Version            int                `json:"version"`
	Kind               string             `json:"kind"`
	Request            StopRequest        `json:"request"`
	TerminalGeneration TerminalGeneration `json:"terminalGeneration"`
	StoppedAt          string             `json:"stoppedAt"`
}

// deriveReceiptIdentity hashes exactly the canonical UTF-8 JSON encoding of
// {version:1, kind, request, terminalGeneration, stoppedAt}. ReceiptRef and
// ReceiptDigest are deliberately excluded because both are derived from that
// payload. Object keys are recursively sorted lexicographically and no
// insignificant whitespace is emitted.
func deriveReceiptIdentity(
	request StopRequest,
	terminal TerminalGeneration,
	stoppedAt string,
) (receiptDigest string, receiptRef string, err error) {
	payload, err := canonicalJSON(canonicalReceiptPayload{
		Version:            1,
		Kind:               receiptKind,
		Request:            request,
		TerminalGeneration: terminal,
		StoppedAt:          stoppedAt,
	})
	if err != nil {
		return "", "", fmt.Errorf("canonicalize stopped-generation receipt: %w", err)
	}
	digest := sha256.Sum256(payload)
	receiptDigest = "sha256:" + hex.EncodeToString(digest[:])
	receiptRef = "ambit.stopped-generation-receipt:v1:" + receiptDigest
	return receiptDigest, receiptRef, nil
}

// canonicalJSON first applies the declared JSON field contract (including
// omitempty), then rewrites the resulting JSON tree with recursively sorted
// object keys. Numbers are retained as their exact base-10 JSON token rather
// than passing through float64.
func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeRawJSON(raw)
}

// CanonicalJSON exposes the repository's cross-language canonical JSON
// encoding to adjacent provider-authority protocols. Keeping one encoder
// prevents stopped-generation and specialist-render receipts from drifting.
func CanonicalJSON(value any) ([]byte, error) {
	return canonicalJSON(value)
}

// DecodeCanonicalJSON decodes an exact declared schema and additionally
// requires the wire bytes themselves to be the canonical encoding.
func DecodeCanonicalJSON(data []byte, target any) error {
	if err := DecodeExactJSON(data, target); err != nil {
		return err
	}
	expected, err := canonicalJSON(target)
	if err != nil {
		return fmt.Errorf("re-encode canonical JSON contract: %w", err)
	}
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("JSON wire bytes are not canonical")
	}
	return nil
}

func canonicalizeRawJSON(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var tree any
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := writeCanonicalJSON(&output, tree); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// DecodeExactJSON decodes an external JSON envelope while enforcing the exact
// declared nested schema. It rejects invalid UTF-8, duplicate keys at any
// depth, unknown or case-aliased keys, missing required zero-valued fields,
// explicit nulls for omitted variant fields, and trailing values. Object key
// order and insignificant whitespace remain wire-irrelevant.
func DecodeExactJSON(data []byte, target any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	if err := rejectUnpairedSurrogateEscapes(data); err != nil {
		return err
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	actual, err := canonicalizeRawJSON(data)
	if err != nil {
		return err
	}
	expected, err := canonicalJSON(target)
	if err != nil {
		return fmt.Errorf("re-encode exact JSON contract: %w", err)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("JSON does not match the exact declared nested contract")
	}
	return nil
}

// rejectUnpairedSurrogateEscapes closes encoding/json's deliberate replacement
// behavior for lone UTF-16 surrogate escapes. Exact authority wires must not
// allow multiple invalid code-unit sequences to collapse to the same U+FFFD
// string. Valid adjacent high+low pairs remain admitted.
func rejectUnpairedSurrogateEscapes(data []byte) error {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			if index+1 >= len(data) {
				return fmt.Errorf("truncated JSON escape")
			}
			if data[index+1] != 'u' {
				index++
				continue
			}
			codeUnit, ok := decodeHexCodeUnit(data[index+2:])
			if !ok {
				return fmt.Errorf("invalid JSON Unicode escape")
			}
			index += 5
			switch {
			case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
				if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
					return fmt.Errorf("unpaired high-surrogate JSON escape")
				}
				low, ok := decodeHexCodeUnit(data[index+3:])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("high-surrogate JSON escape is not followed by a low surrogate")
				}
				index += 6
			case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
				return fmt.Errorf("unpaired low-surrogate JSON escape")
			}
		}
	}
	return nil
}

func decodeHexCodeUnit(data []byte) (uint16, bool) {
	if len(data) < 4 {
		return 0, false
	}
	var value uint16
	for _, character := range data[:4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeCanonicalJSON(output *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if value {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		if err := writeCanonicalJSONString(output, value); err != nil {
			return err
		}
	case json.Number:
		if _, err := value.Int64(); err != nil {
			return fmt.Errorf("non-integral canonical number %q", value)
		}
		output.WriteString(value.String())
	case []any:
		output.WriteByte('[')
		for index, item := range value {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSONString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeCanonicalJSON(output, value[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON node %T", value)
	}
	return nil
}

// writeCanonicalJSONString emits the minimal JSON escaping used by the
// cross-language receipt contract: valid Unicode remains UTF-8, quote and
// reverse solidus are escaped, and controls use the shortest JSON escape (or
// lowercase \u00xx when no short escape exists). In particular, it does not
// apply Go's optional HTML escaping.
func writeCanonicalJSONString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("canonical JSON string is not valid UTF-8")
	}
	const hexadecimal = "0123456789abcdef"
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hexadecimal[byte(character)>>4])
				output.WriteByte(hexadecimal[byte(character)&0x0f])
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
	return nil
}
