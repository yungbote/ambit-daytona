// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

const pictureWriteChunk = 32 << 10

type progressStream interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// A valid unit can take longer than the idle timeout on a slow link. Each
// bounded write rearms after preceding accepted-byte progress; this measures
// admission to QUIC's stream buffer, not ACKs, decoded pictures or paint.
// Partial deadline writes continue only their exact unwritten suffix.
func writeWithProgress(ctx context.Context, stream progressStream, idle time.Duration, parts ...[]byte) error {
	for _, part := range parts {
		for len(part) > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := stream.SetWriteDeadline(time.Now().Add(idle)); err != nil {
				return err
			}
			size := min(len(part), pictureWriteChunk)
			n, err := stream.Write(part[:size])
			if n < 0 || n > size {
				return io.ErrShortWrite
			}
			part = part[n:]
			if err != nil {
				if n > 0 && errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
					continue
				}
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}
