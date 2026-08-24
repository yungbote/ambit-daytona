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
