// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package webtransport adapts the existing view session to independent QUIC
// lanes: ordered records, one reliable stream per picture, audio datagrams.
package webtransport

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daytonaio/media-edge/internal/control"
	"github.com/daytonaio/media-edge/internal/rate"
	"github.com/daytonaio/media-edge/internal/view"
	"github.com/quic-go/quic-go"
	wt "github.com/quic-go/webtransport-go"
)

const (
	Magic                 = "AMBWT001"
	MaxViewerMessageBytes = control.MaxRequestBytes
	writeTimeout          = 30 * time.Second
)

type carrier struct {
	session  *wt.Session
	control  *wt.Stream
	controls atomic.Uint64
	pictures uint64
	records  sync.Mutex
	once     sync.Once
	// Eight decoder units and 12MiB are the existing view's bounds. Picture
	// writes run independently so a blocked picture never holds a record/audio
	// write behind it; pressure beyond the bound still reaches the producer.
	writes         chan struct{}
	mu             sync.Mutex
	bytes          int
	changed        chan struct{}
	metrics        *connectionMetrics
	releaseMetrics func()
	parts          map[*wt.SendStream]*pendingPart
}

type pendingPart struct {
	stream   *wt.SendStream
	streamID string
	retired  bool
}

func newCarrier(session *wt.Session, registries ...*metricsRegistry) (*carrier, error) {
	control, err := session.OpenStreamSync(session.Context())
	if err != nil {
		return nil, err
	}
	_ = control.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := io.WriteString(control, Magic); err != nil {
		return nil, err
	}
	c := &carrier{session: session, control: control, writes: make(chan struct{}, 8), changed: make(chan struct{})}
	if len(registries) > 0 {
		c.metrics, c.releaseMetrics = registries[0].attach(session.Context())
	}
	return c, nil
}

func (c *carrier) Network() rate.Network { return c.metrics.snapshot(time.Now()) }

func (c *carrier) PartBytes(d *view.Delivery) int { return d.Size() + 17 }

func (c *carrier) Receive() (bool, []byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(c.control, prefix[:]); err != nil {
		return false, nil, err
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size == 0 || size > MaxViewerMessageBytes {
		c.Close(1008, "browser_view_invalid_message")
		return false, nil, errors.New("invalid viewer message length")
	}
	message := make([]byte, size)
	_, err := io.ReadFull(c.control, message)
	return true, message, err
}

func (c *carrier) Send(d *view.Delivery) error {
	if d.Size() > view.MaxMessageBytes {
		return errors.New("view delivery exceeds its bound")
	}
	if d.Kind == view.Record {
		c.records.Lock()
		defer c.records.Unlock()
		var video struct{ Type, State, StreamID string }
		if json.Unmarshal(d.Text, &video) == nil && video.Type == "video" && video.State != "available" {
			c.retireParts(video.StreamID)
		}
		_ = c.control.SetWriteDeadline(time.Now().Add(writeTimeout))
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(d.Text)))
		if _, err := c.control.Write(prefix[:]); err != nil {
			return err
		}
		if _, err := c.control.Write(d.Text); err != nil {
			return err
		}
		c.controls.Add(1)
		return nil
	}
	if d.Kind == view.Audio {
		// The common Opus packet fits one datagram. QUIC's actual path limit,
		// not an assumed MTU, decides when a packet needs its own stream.
		data := make([]byte, 8+d.Size())
		binary.BigEndian.PutUint64(data, c.controls.Load())
		binary.BigEndian.PutUint32(data[8:], uint32(len(d.Header)))
		copy(data[12:], d.Header)
		copy(data[12+len(d.Header):], d.Payload)
		if err := c.session.SendDatagram(data); err == nil {
			return nil
		} else {
			var tooLarge *quic.DatagramTooLargeError
			if !errors.As(err, &tooLarge) {
				return err
			}
		}
	}
	select {
	case c.writes <- struct{}{}:
	case <-c.session.Context().Done():
		return c.session.Context().Err()
	}
	for {
		c.mu.Lock()
		// A logical picture may exceed pending credit. Admit it alone and
		// charge its full bytes; a larger source allowance never expands
		// the retained pending budget or permits several large pictures.
		if c.bytes == 0 || c.bytes+d.Size() <= 12<<20 {
			c.bytes += d.Size()
			c.mu.Unlock()
			break
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-c.session.Context().Done():
			<-c.writes
			return c.session.Context().Err()
		}
	}
	stream, err := c.session.OpenUniStreamSync(c.session.Context())
	if err != nil {
		c.release(d.Size())
		return err
	}
	var part *pendingPart
	if d.Transfer.Offset > 0 {
		part = &pendingPart{stream: stream, streamID: d.Transfer.StreamID}
		c.mu.Lock()
		if c.parts == nil {
			c.parts = make(map[*wt.SendStream]*pendingPart)
		}
		c.parts[stream] = part
		c.mu.Unlock()
	}
	var prefix [17]byte
	prefix[0] = 1
	if d.Kind == view.Audio {
		prefix[0] = 2
	} else {
		c.pictures++
	}
	binary.BigEndian.PutUint64(prefix[1:9], c.controls.Load())
	if d.Kind != view.Audio {
		binary.BigEndian.PutUint64(prefix[9:], c.pictures)
	}
	// Upstream.Read reuses its buffer; this write retains one bounded copy.
	copy := &view.Delivery{Kind: d.Kind, Header: append([]byte(nil), d.Header...), Payload: append([]byte(nil), d.Payload...)}
	go func() {
		defer func() {
			if part != nil {
				c.mu.Lock()
				delete(c.parts, stream)
				c.mu.Unlock()
			}
			c.release(copy.Size())
		}()
		var headerLength [4]byte
		binary.BigEndian.PutUint32(headerLength[:], uint32(len(copy.Header)))
		err = writeWithProgress(c.session.Context(), stream, writeTimeout, prefix[:], headerLength[:], copy.Header, copy.Payload)
		if err == nil {
			err = stream.Close()
		}
		if err != nil {
			stream.CancelWrite(1)
			c.mu.Lock()
			retired := part != nil && part.retired
			c.mu.Unlock()
			if !retired {
				c.Close(1011, "browser_view_unavailable")
			}
		}
	}()
	return nil
}

func (c *carrier) retireParts(streamID string) {
	c.mu.Lock()
	var retiring []*wt.SendStream
	for stream, part := range c.parts {
		if part.streamID != streamID {
			part.retired = true
			retiring = append(retiring, stream)
		}
	}
	c.mu.Unlock()
	for _, stream := range retiring {
		stream.CancelWrite(1)
	}
}

func (c *carrier) release(size int) {
	c.mu.Lock()
	c.bytes -= size
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	<-c.writes
}

func (c *carrier) Close(code int, reason string) {
	c.once.Do(func() {
		if c.releaseMetrics != nil {
			c.releaseMetrics()
		}
		c.control.CancelRead(0)
		c.control.CancelWrite(0)
		_ = c.session.CloseWithError(wt.SessionErrorCode(code), reason)
	})
}
