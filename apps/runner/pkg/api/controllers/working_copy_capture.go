// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/runner/pkg/runner"
	"github.com/daytonaio/runner/pkg/workingcopy"
	"github.com/gin-gonic/gin"
)

const maximumWorkingCopyCaptureRequestBytes = 128 * 1024

// CaptureWorkingCopy godoc
//
//	@Tags			sandbox
//	@Summary		Capture one stopped sandbox working-copy file
//	@Description	Persist one host-admitted regular file from the exact stopped container generation.
//	@Param			sandboxId	path	string						true	"Sandbox ID"
//	@Param			body		body	workingcopy.CaptureBinding	true	"Exact capture binding"
//	@Produce		json
//	@Success		200	{object}	workingcopy.CaptureReceipt
//	@Failure		400	{object}	common_errors.ErrorResponse
//	@Failure		401	{object}	common_errors.ErrorResponse
//	@Failure		409	{object}	common_errors.ErrorResponse
//	@Failure		503	{object}	common_errors.ErrorResponse
//	@Router			/sandboxes/{sandboxId}/working-copy-captures [post]
//
//	@id				CaptureWorkingCopy
func CaptureWorkingCopy(ctx *gin.Context) {
	var binding workingcopy.CaptureBinding
	if err := decodeExactCaptureBody(ctx, &binding); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	receipt, err := service.Capture(ctx.Request.Context(), ctx.Param("sandboxId"), binding)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, receipt)
}

// ObserveWorkingCopyCapture godoc
//
//	@Tags		sandbox
//	@Summary	Observe an exact working-copy capture
//	@Param		sandboxId	path	string						true	"Sandbox ID"
//	@Param		body		body	workingcopy.CaptureBinding	true	"Exact capture binding"
//	@Produce	json
//	@Success	200	{object}	workingcopy.CaptureObservation
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/working-copy-captures/observe [post]
//
//	@id			ObserveWorkingCopyCapture
func ObserveWorkingCopyCapture(ctx *gin.Context) {
	var binding workingcopy.CaptureBinding
	if err := decodeExactCaptureBody(ctx, &binding); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	observation, err := service.Observe(ctx.Request.Context(), ctx.Param("sandboxId"), binding)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, observation)
}

// ReadWorkingCopyCapture godoc
//
//	@Tags		sandbox
//	@Summary	Read an exact immutable working-copy capture
//	@Param		sandboxId	path	string							true	"Sandbox ID"
//	@Param		body		body	workingcopy.CaptureReadRequest	true	"Exact capture identity and read bounds"
//	@Produce	json
//	@Success	200	{object}	workingcopy.CaptureReadResponse
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/working-copy-captures/read [post]
//
//	@id			ReadWorkingCopyCapture
func ReadWorkingCopyCapture(ctx *gin.Context) {
	var request workingcopy.CaptureReadRequest
	if err := decodeExactCaptureBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	response, err := service.Read(ctx.Request.Context(), ctx.Param("sandboxId"), request)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

// StoppedWorkingCopyDirectoryRoster godoc
//
//	@Tags			sandbox
//	@Summary		List one bounded directory from an exact stopped sandbox generation
//	@Description	Stream and validate a content-digested regular-file/directory roster through Docker host authority; archive link entries, special files, escapes, and bound overflows fail closed. Accepted regular-file entries are independent exact bytes; inode/link identity is not preserved.
//	@Param			sandboxId	path	string										true	"Sandbox ID"
//	@Param			body		body	workingcopy.StoppedDirectoryRosterRequest	true	"Exact anchor, directory selector, and bounds"
//	@Produce		json
//	@Success		200	{object}	workingcopy.StoppedDirectoryRosterReceipt
//	@Failure		400	{object}	common_errors.ErrorResponse
//	@Failure		401	{object}	common_errors.ErrorResponse
//	@Failure		409	{object}	common_errors.ErrorResponse
//	@Failure		503	{object}	common_errors.ErrorResponse
//	@Router			/sandboxes/{sandboxId}/working-copy-captures/stopped-directory-roster [post]
//
//	@id				StoppedWorkingCopyDirectoryRoster
func StoppedWorkingCopyDirectoryRoster(ctx *gin.Context) {
	var request workingcopy.StoppedDirectoryRosterRequest
	if err := decodeExactCaptureBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	receipt, err := service.StoppedDirectoryRoster(ctx.Request.Context(), ctx.Param("sandboxId"), request)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, receipt)
}

// DeleteWorkingCopyCapture godoc
//
//	@Tags		sandbox
//	@Summary	Delete an exact private working-copy capture
//	@Param		sandboxId	path	string						true	"Sandbox ID"
//	@Param		body		body	workingcopy.CaptureIdentity	true	"Exact capture identity"
//	@Produce	json
//	@Success	200	{object}	workingcopy.CaptureDeleteReceipt
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/working-copy-captures/delete [post]
//
//	@id			DeleteWorkingCopyCapture
func DeleteWorkingCopyCapture(ctx *gin.Context) {
	var identity workingcopy.CaptureIdentity
	if err := decodeExactCaptureBody(ctx, &identity); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	receipt, err := service.Delete(ctx.Request.Context(), ctx.Param("sandboxId"), identity)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, receipt)
}

// WorkingCopyCaptureExists godoc
//
//	@Tags		sandbox
//	@Summary	Check an exact private working-copy capture identity
//	@Param		sandboxId	path	string						true	"Sandbox ID"
//	@Param		body		body	workingcopy.CaptureIdentity	true	"Exact capture identity"
//	@Produce	json
//	@Success	200	{object}	workingcopy.CaptureExistsResponse
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/working-copy-captures/exists [post]
//
//	@id			WorkingCopyCaptureExists
func WorkingCopyCaptureExists(ctx *gin.Context) {
	var identity workingcopy.CaptureIdentity
	if err := decodeExactCaptureBody(ctx, &identity); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := workingCopyCaptureService()
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	response, err := service.Exists(ctx.Request.Context(), ctx.Param("sandboxId"), identity)
	if err != nil {
		writeWorkingCopyCaptureError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func workingCopyCaptureService() (*workingcopy.Service, error) {
	instance, err := runner.GetInstance(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: runner is not initialized", workingcopy.ErrUnavailable)
	}
	if instance.WorkingCopyCaptures == nil {
		return nil, fmt.Errorf("%w: private capture storage is not configured", workingcopy.ErrUnavailable)
	}
	return instance.WorkingCopyCaptures, nil
}

func writeWorkingCopyCaptureError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, workingcopy.ErrInvalidRequest):
		ctx.Error(common_errors.NewBadRequestError(err))
	case errors.Is(err, workingcopy.ErrOutcomeUnknown):
		ctx.Error(common_errors.NewCustomError(
			http.StatusServiceUnavailable,
			err.Error(),
			"WORKING_COPY_CAPTURE_OUTCOME_UNKNOWN",
		))
	case errors.Is(err, workingcopy.ErrUnavailable):
		ctx.Error(common_errors.NewCustomError(
			http.StatusServiceUnavailable,
			err.Error(),
			"WORKING_COPY_CAPTURE_UNAVAILABLE",
		))
	case errors.Is(err, workingcopy.ErrConflict):
		ctx.Error(common_errors.NewConflictError(err))
	default:
		ctx.Error(err)
	}
}

func decodeExactCaptureBody(ctx *gin.Context, target any) error {
	data, err := io.ReadAll(io.LimitReader(ctx.Request.Body, maximumWorkingCopyCaptureRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(data) == 0 || len(data) > maximumWorkingCopyCaptureRequestBytes {
		return errors.New("request body is empty or exceeds the bounded capture envelope")
	}
	return workingcopy.DecodeExactJSON(data, target)
}
