// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package webtransport

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/daytonaio/media-edge/internal/rate"
	"github.com/daytonaio/media-edge/internal/view"
)

func TestRealQUICTracerMeasuresTheDeliveredConnection(t *testing.T) {
	measured := make(chan rate.Network, 1)
	r := newMetricsRegistry()
	s, control, ctx, _, _ := pair(t, func(c *carrier) {
		if err := c.Send(&view.Delivery{Kind: view.Video, Header: []byte(`{"track":"video"}`), Payload: bytes.Repeat([]byte{1}, 128<<10)}); err != nil {
			t.Error(err)
			return
		}
		if _, _, err := c.Receive(); err != nil {
			t.Error(err)
			return
		}
		measured <- c.Network()
	}, r)
	picture, err := s.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, picture); err != nil {
		t.Fatal(err)
	}
	message := []byte(`{"type":"ack","seq":1}`)
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(message)))
	if _, err := control.Write(append(prefix[:], message...)); err != nil {
		t.Fatal(err)
	}
	select {
	case sample := <-measured:
		if !sample.Known || sample.MinimumRTT <= 0 || sample.WindowBytes == 0 || sample.AckedBytes == 0 || sample.ProxyHop || sample.Shares != 1 {
			t.Fatalf("real QUIC metrics missing/wrong boundary: %+v", sample)
		}
		t.Logf("real QUIC: acked=%dB minRTT=%s window=%dB shares=%d", sample.AckedBytes, sample.MinimumRTT, sample.WindowBytes, sample.Shares)
	case <-time.After(time.Second):
		t.Fatal("QUIC metrics did not settle")
	}
}
