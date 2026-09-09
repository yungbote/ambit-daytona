// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build !linux

package session

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func (s *SessionController) ListBrowserViews(c *gin.Context)  { c.JSON(http.StatusOK, []any{}) }
func (s *SessionController) StreamBrowserView(c *gin.Context) { c.Status(http.StatusNotFound) }
