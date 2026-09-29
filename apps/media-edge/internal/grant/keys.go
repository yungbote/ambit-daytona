// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package grant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync/atomic"
)

// ParsePublicKeys reads one or more PEM "PUBLIC KEY" (SPKI) blocks, each an
// Ed25519 key. Anything else in the file makes it invalid as a whole.
func ParsePublicKeys(data []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, errors.New("grant keys: content outside PEM blocks")
			}
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, errors.New("grant keys: a block is not a PUBLIC KEY")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, isEd25519 := parsed.(ed25519.PublicKey)
		if !isEd25519 {
			return nil, errors.New("grant keys: a key is not Ed25519")
		}
		keys = append(keys, key)
		data = rest
	}
	if len(keys) == 0 {
		return nil, errors.New("grant keys: no public key")
	}
	return keys, nil
}

// KeyRing holds the keys currently in force; Apply replaces them atomically,
// so a rotation never leaves a moment without a valid set.
type KeyRing struct {
	keys atomic.Pointer[[]ed25519.PublicKey]
}

// Apply parses a key file's content and puts it in force. A file that does
// not parse leaves the previous keys in force.
func (k *KeyRing) Apply(data []byte) error {
	keys, err := ParsePublicKeys(data)
	if err != nil {
		return err
	}
	k.keys.Store(&keys)
	return nil
}

// PublicKeys is the set in force (none before the first Apply).
func (k *KeyRing) PublicKeys() []ed25519.PublicKey {
	if keys := k.keys.Load(); keys != nil {
		return *keys
	}
	return nil
}
