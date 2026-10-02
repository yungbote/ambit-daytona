// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package daytona reaches browser views in Daytona sandboxes through the
// toolbox proxy, with the host credential the backend uses, dialing exactly
// what the backend's provider dials today.
package daytona

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/daytonaio/media-edge/internal/control"
	"github.com/daytonaio/media-edge/internal/session"
	"github.com/daytonaio/media-edge/internal/view"
)

const (
	// handshakeTimeout is the backend's dial deadline for a view channel.
	handshakeTimeout = 10 * time.Second
	// routeWrites bounds one viewer message to the route.
	routeWrites = 10 * time.Second
	// retainedReadBytes is the largest read buffer a route keeps between
	// messages: every usual unit fits it, while a rare large one (up to
	// view.MaxMessageBytes) is not held for the rest of the view.
	retainedReadBytes = 1 << 20
)

// Upstream dials view routes through one toolbox proxy.
type Upstream struct {
	proxy        *url.URL
	credential   string
	organization string
	dialer       websocket.Dialer
}

// New takes the toolbox proxy's base URL (DAYTONA_TOOLBOX_PROXY_URL, the
// route before the sandbox id), the host credential and, when the credential
// needs one, the organization id.
func New(proxy, credential, organization string) (*Upstream, error) {
	base, err := url.Parse(proxy)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" || strings.Contains(base.Path, "//") {
		return nil, errors.New("daytona: the toolbox proxy URL must be an http(s) URL with a path and nothing else")
	}
	if credential == "" {
		return nil, errors.New("daytona: the host credential is empty")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/"
	if base.Scheme == "https" {
		base.Scheme = "wss"
	} else {
		base.Scheme = "ws"
	}
	return &Upstream{proxy: base, credential: credential, organization: organization, dialer: websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  4 << 10,
	}}, nil
}

// Address is the view route for a target and a declaration.
func (u *Upstream) Address(target session.Target, declaration view.Declaration) string {
	return u.address(target, "channel") + "?" + declaration.Query()
}

func (u *Upstream) address(target session.Target, route string) string {
	segments := []string{target.SandboxID, "process", "session", target.SessionID, "browser-views", target.ViewID}
	for index, segment := range segments {
		segments[index] = encodeURIComponent(segment)
	}
	return u.proxy.String() + strings.Join(segments, "/") + "/" + route
}

// DialControl carries only input to the unchanged toolbox control route.
// The backend remains the writer of acquire/renew/release commands.
func (u *Upstream) DialControl(ctx context.Context, target session.Target) (session.Conn, error) {
	headers := http.Header{"Accept": {"application/json"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer " + u.credential}, "X-Daytona-Source": {"ambit-media-edge"}}
	if u.organization != "" {
		headers.Set("X-Daytona-Organization-ID", u.organization)
	}
	conn, response, err := u.dialer.DialContext(ctx, u.address(target, "control/channel"), headers)
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("daytona: the control route answered %d", response.StatusCode)
		}
		return nil, fmt.Errorf("daytona: control dial: %w", err)
	}
	conn.SetReadLimit(control.MaxReplyBytes)
	return &route{conn: conn}, nil
}

// DialView opens the view route with the backend's headers.
func (u *Upstream) DialView(ctx context.Context, target session.Target, viewerID string, declaration view.Declaration) (session.Conn, error) {
	headers := http.Header{
		"Accept":                 {"application/octet-stream"},
		"Authorization":          {"Bearer " + u.credential},
		"Content-Type":           {"application/json"},
		"X-Daytona-Source":       {"ambit-media-edge"},
		"X-Ambit-Browser-Viewer": {viewerID},
	}
	if u.organization != "" {
		headers.Set("X-Daytona-Organization-ID", u.organization)
	}
	conn, response, err := u.dialer.DialContext(ctx, u.Address(target, declaration), headers)
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("daytona: the view route answered %d", response.StatusCode)
		}
		return nil, fmt.Errorf("daytona: dial: %w", err)
	}
	limit := view.MaxMessageBytes
	if !declaration.VideoCapacity {
		limit = view.MaxLegacyMessageBytes
	}
	conn.SetReadLimit(int64(limit))
	return &route{conn: conn, viewMessages: true, rateInput: response != nil && response.Header.Get("X-Ambit-Browser-View-Pipe") == "1"}, nil
}

// route is one open view route. Its read buffer is reused up to
// retainedReadBytes: a message is valid until the next Read, and a 200 KB
// frame costs no allocation.
type route struct {
	conn         *websocket.Conn
	buffer       bytes.Buffer
	rateInput    bool
	viewMessages bool
}

func (r *route) RateInput() bool { return r.rateInput }

func (r *route) Read() (bool, []byte, error) {
	if r.buffer.Cap() > retainedReadBytes {
		r.buffer = bytes.Buffer{}
	}
	kind, reader, err := r.conn.NextReader()
	if err == nil {
		r.buffer.Reset()
		if r.viewMessages && kind == websocket.BinaryMessage {
			var prefix [4]byte
			_, err = io.ReadFull(reader, prefix[:])
			length := binary.BigEndian.Uint32(prefix[:])
			if err == nil && (length == 0 || length > 64<<10) {
				err = errors.New("invalid view envelope header")
			}
			if err == nil {
				header := make([]byte, int(length))
				_, err = io.ReadFull(reader, header)
				limit, valid := view.BinaryPayloadLimit(header)
				if err == nil && !valid {
					err = errors.New("invalid view envelope header")
				}
				if err == nil {
					_, _ = r.buffer.Write(prefix[:])
					_, _ = r.buffer.Write(header)
					var count int64
					count, err = r.buffer.ReadFrom(io.LimitReader(reader, int64(limit)+1))
					if err == nil && count > int64(limit) {
						err = errors.New("view body exceeds declared capacity")
					}
				}
			}
		} else if r.viewMessages {
			// Preserve legacy whole-image JSON fallback, while a larger video
			// envelope never expands arbitrary text/control admission.
			var count int64
			count, err = r.buffer.ReadFrom(io.LimitReader(reader, view.MaxLegacyMessageBytes+1))
			if err == nil && count > view.MaxLegacyMessageBytes {
				err = errors.New("view text exceeds legacy envelope")
			}
		} else {
			_, err = r.buffer.ReadFrom(reader)
		}
	}
	if err != nil {
		var closed *websocket.CloseError
		if errors.As(err, &closed) {
			return false, nil, &session.Closed{Code: closed.Code, Reason: closed.Text}
		}
		return false, nil, err
	}
	return kind == websocket.TextMessage, r.buffer.Bytes(), nil
}

func (r *route) Write(message []byte) error {
	_ = r.conn.SetWriteDeadline(time.Now().Add(routeWrites))
	return r.conn.WriteMessage(websocket.TextMessage, message)
}

func (r *route) Close() { _ = r.conn.Close() }

// encodeURIComponent escapes as JavaScript's does, so each path segment is
// the backend's to the byte.
func encodeURIComponent(value string) string {
	var escaped strings.Builder
	for _, b := range []byte(value) {
		switch {
		case 'A' <= b && b <= 'Z', 'a' <= b && b <= 'z', '0' <= b && b <= '9', strings.IndexByte("-_.!~*'()", b) >= 0:
			escaped.WriteByte(b)
		default:
			fmt.Fprintf(&escaped, "%%%02X", b)
		}
	}
	return escaped.String()
}
