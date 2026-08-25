// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestControllerSurfacesPreterminalResponseCleanupFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	cleanupFailure := errors.New("injected preterminal response cleanup failure")
	abortSpecialistRenderStream(ctx, cleanupFailure)
	if !ctx.IsAborted() || len(ctx.Errors) != 1 || !errors.Is(ctx.Errors[0].Err, cleanupFailure) {
		t.Fatalf("controller discarded preterminal cleanup failure: aborted=%t errors=%v", ctx.IsAborted(), ctx.Errors)
	}
}
