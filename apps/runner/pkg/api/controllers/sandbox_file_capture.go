// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/runner/pkg/workingcopy"
	"github.com/gin-gonic/gin"
	"net/http"
)

// CaptureSandboxFile godoc
//
// @Tags sandbox
// @Summary Capture an immutable native sandbox file once
// @Description Provider organization authority is supplied by the authenticated API, not a Product Run. File capture admits only work/outputs regular files and requires native descriptor cloning. Component measurement is not runtime qualification.
// @Accept json
// @Produce json
// @Param sandboxId path string true "Sandbox ID"
// @Param request body workingcopy.SandboxFileRequest true "Native file capture operation"
// @Success 200 {object} workingcopy.SandboxFileReceipt
// @Failure 400 {object} common_errors.ErrorResponse
// @Failure 409 {object} common_errors.ErrorResponse
// @Failure 503 {object} common_errors.ErrorResponse
// @Security Bearer
// @Router /sandboxes/{sandboxId}/working-copy-captures/sandbox-files [post]
// @id CaptureSandboxFile
func CaptureSandboxFile(ctx *gin.Context) {
	var request workingcopy.SandboxFileRequest
	if err := decodeExactCaptureBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewBadRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	result, err := service.CaptureSandboxFile(ctx.Request.Context(), ctx.Param("sandboxId"), request)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, result)
}

// ObserveSandboxFile godoc
//
// @Tags sandbox
// @Summary Observe a native sandbox file operation without source effects
// @Description Provider organization authority is supplied by the authenticated API, not a Product Run. File capture admits only work/outputs regular files and requires native descriptor cloning. Component measurement is not runtime qualification.
// @Accept json
// @Produce json
// @Param sandboxId path string true "Sandbox ID"
// @Param request body workingcopy.SandboxFileObserveRequest true "Native file capture operation"
// @Success 200 {object} workingcopy.SandboxFileObservation
// @Failure 400 {object} common_errors.ErrorResponse
// @Failure 409 {object} common_errors.ErrorResponse
// @Failure 503 {object} common_errors.ErrorResponse
// @Security Bearer
// @Router /sandboxes/{sandboxId}/working-copy-captures/sandbox-files/observe [post]
// @id ObserveSandboxFile
func ObserveSandboxFile(ctx *gin.Context) {
	var request workingcopy.SandboxFileObserveRequest
	if err := decodeExactCaptureBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewBadRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	result, err := service.ObserveSandboxFile(ctx.Request.Context(), ctx.Param("sandboxId"), request)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, result)
}

// ReadSandboxFile godoc
//
// @Tags sandbox
// @Summary Read a bounded immutable native file capture
// @Description Provider organization authority is supplied by the authenticated API, not a Product Run. File capture admits only work/outputs regular files and requires native descriptor cloning. Component measurement is not runtime qualification.
// @Accept json
// @Produce json
// @Param sandboxId path string true "Sandbox ID"
// @Param request body workingcopy.SandboxFileReadRequest true "Native file capture operation"
// @Success 200 {object} workingcopy.SandboxFileReadResponse
// @Failure 400 {object} common_errors.ErrorResponse
// @Failure 409 {object} common_errors.ErrorResponse
// @Failure 503 {object} common_errors.ErrorResponse
// @Security Bearer
// @Router /sandboxes/{sandboxId}/working-copy-captures/sandbox-files/read [post]
// @id ReadSandboxFile
func ReadSandboxFile(ctx *gin.Context) {
	var request workingcopy.SandboxFileReadRequest
	if err := decodeExactCaptureBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewBadRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	result, err := service.ReadSandboxFile(ctx.Request.Context(), ctx.Param("sandboxId"), request)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, result)
}

// DeleteSandboxFile godoc
//
// @Tags sandbox
// @Summary Retire a native file operation and release its private bytes
// @Description Provider organization authority is supplied by the authenticated API, not a Product Run. File capture admits only work/outputs regular files and requires native descriptor cloning. Component measurement is not runtime qualification. Retirement accepts a receipt or operationId with optional path assertion and retries private-byte cleanup even after retirement.
// @Accept json
// @Produce json
// @Param sandboxId path string true "Sandbox ID"
// @Param request body workingcopy.SandboxFileDeleteRequest true "Native file capture operation"
// @Success 200 {object} workingcopy.SandboxFileDeleteReceipt
// @Failure 400 {object} common_errors.ErrorResponse
// @Failure 409 {object} common_errors.ErrorResponse
// @Failure 503 {object} common_errors.ErrorResponse
// @Security Bearer
// @Router /sandboxes/{sandboxId}/working-copy-captures/sandbox-files/delete [post]
// @id DeleteSandboxFile
func DeleteSandboxFile(ctx *gin.Context) {
	var request workingcopy.SandboxFileDeleteRequest
	if err := decodeExactCaptureBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewBadRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	result, err := service.DeleteSandboxFile(ctx.Request.Context(), ctx.Param("sandboxId"), request)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, result)
}
