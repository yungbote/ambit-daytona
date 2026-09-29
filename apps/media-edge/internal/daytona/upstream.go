// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package daytona reaches browser views in Daytona sandboxes through the
// toolbox proxy, with the host credential the backend uses, dialing exactly
// what the backend's provider dials today.
package daytona

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

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
	segments := []string{target.SandboxID, "process", "session", target.SessionID, "browser-views", target.ViewID, "channel"}
	for index, segment := range segments {
		segments[index] = encodeURIComponent(segment)
	}
	return u.proxy.String() + strings.Join(segments, "/") + "?" + declaration.Query()
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
	conn.SetReadLimit(view.MaxMessageBytes)
	return &route{conn: conn}, nil
}

// route is one open view route. Its read buffer is reused up to
// retainedReadBytes: a message is valid until the next Read, and a 200 KB
// frame costs no allocation.
type route struct {
	conn   *websocket.Conn
	buffer bytes.Buffer
}

func (r *route) Read() (bool, []byte, error) {
	if r.buffer.Cap() > retainedReadBytes {
		r.buffer = bytes.Buffer{}
	}
	kind, reader, err := r.conn.NextReader()
	if err == nil {
		r.buffer.Reset()
		_, err = r.buffer.ReadFrom(reader)
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
