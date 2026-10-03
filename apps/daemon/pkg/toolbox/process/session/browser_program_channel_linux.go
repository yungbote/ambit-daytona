// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daytonaio/daemon/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ProgramBrowserViewChannel relays only a native-issued, filtered program
// tunnel. It accepts no code, environment, host path, or caller endpoint.
// Product proves the current grant and code/host bindings before reaching
// this private toolbox route; native status proves the exact Action lease.
func (s *SessionController) ProgramBrowserViewChannel(c *gin.Context) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		c.Status(http.StatusUpgradeRequired)
		return
	}
	query := c.Request.URL.Query()
	programID, actionID, generation := c.Param("programId"), query.Get("actionId"), query.Get("ownerGeneration")
	if len(query) != 2 || len(query["actionId"]) != 1 || len(query["ownerGeneration"]) != 1 || !validBrowserUUID(programID) || !validBrowserUUID(actionID) || !validProgramGeneration(generation) {
		c.JSON(http.StatusBadRequest, gin.H{"code": "browser_program_invalid"})
		return
	}
	view, ok := s.selectBrowserView(c)
	if !ok {
		return
	}
	link, failure := s.dialBrowserControl(c.Request.Context(), *view)
	if link == nil {
		c.JSON(failure.status, failure.body)
		return
	}
	// A fresh status channel neither takes input ownership nor owns the lease.
	endpoint, ok := browserProgramEndpoint(link, *view, programID, actionID, generation)
	_ = link.Close()
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"code": "browser_program_unavailable"})
		return
	}
	parsed, port, ok := nativeProgramEndpoint(endpoint)
	if !ok {
		c.JSON(http.StatusBadGateway, gin.H{"code": "browser_program_endpoint_invalid"})
		return
	}
	// The endpoint must be listening in the already peer-proved daemon, rather
	// than another process that happens to occupy a workspace loopback port.
	listener, err := processBrowserListener(view.pid, port)
	if err != nil || listener == "" {
		c.JSON(http.StatusConflict, gin.H{"code": "browser_program_unavailable"})
		return
	}
	upstream, _, err := (&websocket.Dialer{HandshakeTimeout: browserDialTimeout}).DialContext(c.Request.Context(), parsed.String(), nil)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "browser_program_unavailable"})
		return
	}
	defer upstream.Close()
	client, err := util.UpgradeToWebSocket(c.Writer, c.Request)
	if err != nil {
		return
	}
	defer client.Close()
	relayBrowserProgram(c.Request.Context(), client, upstream)
}

func validProgramGeneration(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	number, err := strconv.ParseUint(value, 10, 63)
	return err == nil && number > 0
}

func nativeProgramEndpoint(value string) (*url.URL, uint16, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "ws" || parsed.Hostname() != "127.0.0.1" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || len(parsed.Path) != 33 || parsed.Path[0] != '/' {
		return nil, 0, false
	}
	for _, character := range parsed.Path[1:] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return nil, 0, false
		}
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 || parsed.Host != "127.0.0.1:"+strconv.FormatUint(port, 10) {
		return nil, 0, false
	}
	return parsed, uint16(port), true
}

func browserProgramEndpoint(link *browserControlLink, view browserView, programID, actionID, generation string) (string, bool) {
	_ = link.connection.SetDeadline(time.Now().Add(browserAgentWriteTimeout))
	reader := bufio.NewReaderSize(link.connection, 4096)
	frames := []map[string]any{
		{"action": browserAgentAction, "type": "hello", "id": 1, "protocol": 1, "channel": uuid.NewString(), "binding": map[string]any{"version": 1, "namespace": view.Namespace, "session": view.Name, "requireSandbox": true, "browserHost": true}},
		{"action": browserAgentAction, "type": "program.status", "id": 2, "programId": programID, "actionId": actionID, "ownerGeneration": generation},
	}
	for index, frame := range frames {
		if json.NewEncoder(link.connection).Encode(frame) != nil {
			return "", false
		}
		line, err := readBrowserControlReply(reader, 4096)
		var reply struct {
			ID      int             `json:"id"`
			Success bool            `json:"success"`
			Data    json.RawMessage `json:"data"`
		}
		if err != nil || json.Unmarshal(line, &reply) != nil || reply.ID != index+1 || !reply.Success {
			return "", false
		}
		if index == 1 {
			var status struct {
				ProgramID          string `json:"programId"`
				State              string `json:"state"`
				Endpoint           string `json:"endpoint"`
				RemainingTimeoutMS uint64 `json:"remainingTimeoutMs"`
			}
			if json.Unmarshal(reply.Data, &status) != nil || status.ProgramID != programID || status.State != "active" || status.RemainingTimeoutMS == 0 || status.RemainingTimeoutMS > 120000 {
				return "", false
			}
			return status.Endpoint, true
		}
	}
	return "", false
}

// Native owns filtering, input settlement and the operation deadline. This
// byte relay never implements another CDP policy or replays a dropped command.
func relayBrowserProgram(parent context.Context, client, upstream *websocket.Conn) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = upstream.Close() })
	defer stop()
	var copying sync.WaitGroup
	copying.Add(2)
	copyFrames := func(destination, source *websocket.Conn) {
		defer copying.Done()
		defer cancel()
		// Matches the native tungstenite message bound, including screenshot
		// responses. Model operation/result bounds remain their existing limits.
		source.SetReadLimit(64 << 20)
		for {
			kind, frame, err := source.ReadMessage()
			if err != nil {
				return
			}
			_ = destination.SetWriteDeadline(time.Now().Add(browserViewerWriteTimeout))
			if destination.WriteMessage(kind, frame) != nil {
				return
			}
		}
	}
	go copyFrames(upstream, client)
	go copyFrames(client, upstream)
	copying.Wait()
}
