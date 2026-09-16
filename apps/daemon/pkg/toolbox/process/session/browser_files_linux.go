// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package session

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"math"
	"path/filepath"
	"strings"
)

type browserFileDestination struct {
	DestinationID string `json:"destinationId"`
	Kind          string `json:"kind"`
	Accept        string `json:"accept"`
	Multiple      bool   `json:"multiple"`
}

func (d *browserFileDestination) valid() bool {
	return d != nil && validBrowserUUID(d.DestinationID) && (d.Kind == "chooser" || d.Kind == "input" || d.Kind == "drop") && len(d.Accept) <= 4096
}

type browserCompletedDownload struct {
	ID                string `json:"id"`
	GUID              string `json:"guid"`
	FrameID           string `json:"frameId"`
	SuggestedFilename string `json:"suggestedFilename"`
	Status            string `json:"status"`
	ReceivedBytes     uint64 `json:"receivedBytes"`
	Path              string `json:"path"`
}

func browserFileResponse(body json.RawMessage, request browserControlRequest, status string) (gin.H, bool) {
	var data struct {
		Chooser     *browserFileDestination    `json:"chooser"`
		Destination *browserFileDestination    `json:"destination"`
		Downloads   []browserCompletedDownload `json:"downloads"`
	}
	if json.Unmarshal(body, &data) != nil {
		return nil, false
	}
	if request.Op == "drop" {
		if status == "duplicate" && data.Destination == nil {
			return gin.H{}, true
		}
		if (status != "destination" && status != "duplicate") || !data.Destination.valid() {
			return nil, false
		}
		return gin.H{"destination": data.Destination}, true
	}
	if status != "files" || (data.Chooser != nil && !data.Chooser.valid()) || data.Downloads == nil || len(data.Downloads) > 256 {
		return nil, false
	}
	for _, item := range data.Downloads {
		if !validBrowserUUID(item.GUID) || item.ID != item.GUID || len(item.FrameID) == 0 || len(item.FrameID) > 256 || len(item.SuggestedFilename) > 4096 || item.Status != "completed" || item.ReceivedBytes > 9_007_199_254_740_991 || !validBrowserFilePath(item.Path) {
			return nil, false
		}
	}
	return gin.H{"chooser": data.Chooser, "downloads": data.Downloads}, true
}
func validBrowserFilePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsRune(path, 0)
}
func validBrowserFileRequest(r browserControlRequest) bool {
	if !validBrowserUUID(r.ControllerID) || r.ExpiresAt != 0 || len(r.Events) != 0 {
		return false
	}
	if r.Op == "files" {
		return r.Sequence == 0 && r.DestinationID == "" && len(r.Files) == 0 && r.X == nil && r.Y == nil
	}
	if r.Op == "dismissfiles" {
		return r.Sequence == 0 && validBrowserUUID(r.DestinationID) && len(r.Files) == 0 && r.X == nil && r.Y == nil
	}
	if r.Sequence == 0 || r.Sequence > 9_007_199_254_740_991 {
		return false
	}
	if r.Op == "drop" {
		return r.DestinationID == "" && len(r.Files) == 0 && r.X != nil && r.Y != nil && !math.IsNaN(*r.X) && !math.IsNaN(*r.Y) && *r.X >= 0 && *r.X <= 32768 && *r.Y >= 0 && *r.Y <= 32768
	}
	if !validBrowserUUID(r.DestinationID) || len(r.Files) == 0 || len(r.Files) > 64 || r.X != nil || r.Y != nil {
		return false
	}
	for _, path := range r.Files {
		if !validBrowserFilePath(path) {
			return false
		}
	}
	return true
}
