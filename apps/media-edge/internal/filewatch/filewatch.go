// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package filewatch re-reads a mounted file (a Kubernetes Secret volume
// swaps its content in place) and applies it again when its content changes.
package filewatch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"
)

// MaxBytes bounds a watched file.
const MaxBytes = 1 << 20

// Watch applies the file's content now and returns that result, so a process
// refuses to start on a missing or invalid file. It then checks the file every
// interval until ctx ends and applies each changed content; a read or apply
// failure is reported and the last good content stays in force.
func Watch(ctx context.Context, path string, every time.Duration, apply func([]byte) error, report func(error)) error {
	current, err := read(path)
	if err == nil {
		err = apply(current)
	}
	if err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		// A content that failed is reported once, not on every check.
		var rejected []byte
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			next, err := read(path)
			if err == nil && (bytes.Equal(next, current) || (rejected != nil && bytes.Equal(next, rejected))) {
				continue
			}
			if err == nil {
				if err = apply(next); err != nil {
					rejected = next
				}
			}
			if err != nil {
				report(err)
				continue
			}
			current, rejected = next, nil
		}
	}()
	return nil
}

func read(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, MaxBytes)
	}
	return data, nil
}
