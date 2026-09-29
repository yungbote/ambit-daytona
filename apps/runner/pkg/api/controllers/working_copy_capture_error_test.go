// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/runner/pkg/common"
	"github.com/daytonaio/runner/pkg/workingcopy"
	"github.com/gin-gonic/gin"
)

// A build outside its deployment's pin is a server fault the caller cannot
// retry away: 500 with its own code, the sentence naming both revisions intact.
func TestWorkingCopyCapturePinMismatchAnswersServerFaultNamingBothRevisions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	refusal := fmt.Errorf("%w: runner build v0.0.0-dev is not its pin's source revision %s",
		workingcopy.ErrPinMismatch, strings.Repeat("a", 40))
	router := gin.New()
	router.Use(common_errors.NewErrorMiddleware(common.HandlePossibleDockerError, false))
	router.POST("/capture", func(ctx *gin.Context) { writeWorkingCopyCaptureError(ctx, refusal) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/capture", nil))
	var body common_errors.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusInternalServerError || body.StatusCode != http.StatusInternalServerError ||
		body.Code != "WORKING_COPY_CAPTURE_PIN_MISMATCH" || body.Message != refusal.Error() {
		t.Fatalf("pin refusal answered %d %#v", recorder.Code, body)
	}
}
