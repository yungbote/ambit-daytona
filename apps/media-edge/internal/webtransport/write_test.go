// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/view"
)

type partialDeadlineStream struct {
	bytes.Buffer
	deadlines int
	maximum   int
	terminal  error
	cancel    context.CancelFunc
	zero      bool
}

func (w *partialDeadlineStream) SetWriteDeadline(time.Time) error { w.deadlines++; return nil }
func (w *partialDeadlineStream) Write(part []byte) (int, error) {
	w.maximum = max(w.maximum, len(part))
	if w.zero {
		return 0, w.terminal
	}
	n := min(len(part), 1000)
	_, _ = w.Buffer.Write(part[:n])
	if w.cancel != nil {
		w.cancel()
	}
	if w.terminal != nil {
		return n, w.terminal
	}
	if n < len(part) {
		return n, os.ErrDeadlineExceeded
	}
	return n, nil
}

func TestProgressWritesKeepExactSuffixAndBoundEachCall(t *testing.T) {
	stream := &partialDeadlineStream{}
	parts := [][]byte{{1, 2, 3}, bytes.Repeat([]byte{7}, 130000), {9, 8, 7}}
	if err := writeWithProgress(context.Background(), stream, time.Second, parts...); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream.Bytes(), bytes.Join(parts, nil)) {
		t.Fatal("partial timeout duplicated or discarded bytes")
	}
	if stream.maximum > pictureWriteChunk || stream.deadlines < 130 {
		t.Fatalf("progress calls were unbounded/unobserved: chunk%d deadlines%d", stream.maximum, stream.deadlines)
	}
}

func TestProgressWritesStopOnZeroProgressTerminalFailureOrCancellation(t *testing.T) {
	terminal := errors.New("stream reset")
	for _, test := range []struct {
		name   string
		stream *partialDeadlineStream
		want   error
	}{
		{"zero", &partialDeadlineStream{zero: true}, io.ErrShortWrite},
		{"terminal", &partialDeadlineStream{terminal: terminal}, terminal},
		{"idle", &partialDeadlineStream{zero: true, terminal: os.ErrDeadlineExceeded}, os.ErrDeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := writeWithProgress(context.Background(), test.stream, time.Second, []byte("some data"))
			if !errors.Is(err, test.want) || test.stream.deadlines != 1 {
				t.Fatalf("no-progress/terminal write retried: %v %d", err, test.stream.deadlines)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &partialDeadlineStream{cancel: cancel, terminal: os.ErrDeadlineExceeded}
	err := writeWithProgress(ctx, stream, time.Second, bytes.Repeat([]byte{1}, 10000))
	if !errors.Is(err, os.ErrDeadlineExceeded) || stream.deadlines != 1 {
		t.Fatalf("cancelled partial deadline retried: %v %d", err, stream.deadlines)
	}
}

func TestRealQUICProgressCanOutliveTheIdleInterval(t *testing.T) {
	payload := bytes.Repeat([]byte{43}, 128<<10)
	finished := make(chan error, 1)
	s, _, ctx, _, _ := pair(t, func(c *carrier) {
		stream, err := c.session.OpenUniStreamSync(c.session.Context())
		if err == nil {
			err = writeWithProgress(c.session.Context(), stream, 200*time.Millisecond, payload)
		}
		if err == nil {
			err = stream.Close()
		}
		finished <- err
	})
	stream, err := s.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var received bytes.Buffer
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	started := time.Now()
	for received.Len() < len(payload) {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("paced read expired")
		}
		part := make([]byte, 1024)
		n, err := stream.Read(part)
		received.Write(part[:n])
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if time.Since(started) <= 200*time.Millisecond || !bytes.Equal(received.Bytes(), payload) {
		t.Fatal("progress gate did not exercise a slow complete write")
	}
	t.Logf("real QUIC exact128KiB paced consumer: %s with200ms idle interval", time.Since(started))
}

func TestRealQUICStallTimesOutAndSessionCancelFreesAdmittedPicture(t *testing.T) {
	stalled := make(chan error, 1)
	s, _, ctx, _, _ := pair(t, func(c *carrier) {
		stream, err := c.session.OpenUniStreamSync(c.session.Context())
		if err == nil {
			err = writeWithProgress(c.session.Context(), stream, 100*time.Millisecond, bytes.Repeat([]byte{1}, 128<<10))
			stream.CancelWrite(1)
		}
		stalled <- err
	})
	if _, err := s.AcceptUniStream(ctx); err != nil {
		t.Fatal(err)
	} // intentionally unread32KiB window
	if err := <-stalled; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled stream did not hit idle bound: %v", err)
	}
	carrierReady := make(chan *carrier, 1)
	_, _, _, _, _ = pair(t, func(c *carrier) {
		if err := c.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: bytes.Repeat([]byte{1}, 2<<20)}); err != nil {
			t.Error(err)
			return
		}
		carrierReady <- c
	})
	c := <-carrierReady
	started := time.Now()
	c.Close(0, "")
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		c.mu.Lock()
		remaining, changed := c.bytes, c.changed
		c.mu.Unlock()
		if remaining == 0 {
			break
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("cancelled picture retained admitted memory")
		}
	}
	if len(c.writes) != 0 || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("session cancellation delayed/free slots missing: %s %d", time.Since(started), len(c.writes))
	}
	t.Logf("actual unread2MiB picture released on session cancellation in%s", time.Since(started))
}
