// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package grant verifies the tokens the backend signs for the media edge: a
// grant admits one viewer to one browser view, and a revocation withdraws the
// grants issued before it. The format is the grant contract
// (artifacts/browser-frontier-20260927/transport/grant-contract.md, rev 1).
package grant

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// MaxTokenBytes bounds a token, grant or revocation, as it travels.
const MaxTokenBytes = 3584

// Refusals. Each names why a token admits nothing; none carries token text.
var (
	ErrMalformed = errors.New("grant: malformed token")
	ErrSignature = errors.New("grant: signature does not verify")
	ErrAudience  = errors.New("grant: issued for another edge")
	ErrExpired   = errors.New("grant: expired")
	ErrLifetime  = errors.New("grant: lifetime exceeds its bound or starts in the future")
	ErrRevoked   = errors.New("grant: revoked")
	ErrBinding   = errors.New("grant: names another session")
)

// KeySource yields the public keys a token may be signed with.
type KeySource interface {
	PublicKeys() []ed25519.PublicKey
}

// verified checks the signature over the payload segment exactly as it was
// transmitted and only then returns the payload's bytes.
func verified(token string, keys KeySource) ([]byte, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return nil, ErrMalformed
	}
	segment, signatureSegment, found := strings.Cut(token, ".")
	if !found || strings.Contains(signatureSegment, ".") {
		return nil, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureSegment)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return nil, ErrMalformed
	}
	for _, key := range keys.PublicKeys() {
		if ed25519.Verify(key, []byte(segment), signature) {
			return payload, nil
		}
	}
	return nil, ErrSignature
}

// object reads a JSON object with each member exactly once. A duplicate
// member, trailing data or a non-object is malformed: two readers of one
// signed payload must never disagree about what it says.
func object(payload []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(payload) {
		return nil, ErrMalformed
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if open, err := decoder.Token(); err != nil || open != json.Delim('{') {
		return nil, ErrMalformed
	}
	members := map[string]json.RawMessage{}
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, ErrMalformed
		}
		key, isString := name.(string)
		if _, duplicate := members[key]; !isString || duplicate {
			return nil, ErrMalformed
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, ErrMalformed
		}
		members[key] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, ErrMalformed
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrMalformed
	}
	return members, nil
}

// fields reads a closed shape: every required member, optional members only
// from the given set, and nothing else.
type fields struct {
	members map[string]json.RawMessage
	seen    int
	failed  bool
}

func (f *fields) raw(name string, required bool) (json.RawMessage, bool) {
	value, present := f.members[name]
	if !present {
		if required {
			f.failed = true
		}
		return nil, false
	}
	f.seen++
	return value, true
}

func (f *fields) text(name string, required bool, valid func(string) bool) string {
	raw, present := f.raw(name, required)
	if !present {
		return ""
	}
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || !valid(value) {
		f.failed = true
	}
	return value
}

// integer reads a plain positive JSON integer no larger than 2^53-1, the
// largest a JavaScript signer writes exactly.
func (f *fields) integer(name string, required bool) int64 {
	raw, present := f.raw(name, required)
	if !present {
		return 0
	}
	if len(raw) == 0 || len(raw) > 16 || raw[0] < '1' || raw[0] > '9' {
		f.failed = true
		return 0
	}
	var value int64
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			f.failed = true
			return 0
		}
		value = value*10 + int64(digit-'0')
	}
	if value > 1<<53-1 {
		f.failed = true
	}
	return value
}

// closed reports whether every member was read and all were valid.
func (f *fields) closed() bool { return !f.failed && f.seen == len(f.members) }
