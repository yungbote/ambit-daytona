// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/runner"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"github.com/gin-gonic/gin"
)

const specialistRenderContentType = "application/vnd.ambit.runtime-provider-specialist-render+jsonl;version=1"

// ExecuteSpecialistRender godoc
//
//	@Tags		sandbox
//	@Summary	Execute one provider-owned specialist render stream
//	@Param		sandboxId	path	string	true	"Sandbox ID"
//	@Param		body		body	string	true	"Exact canonical provider JSONL stream"
//	@Produce	application/vnd.ambit.runtime-provider-specialist-render+jsonl
//	@Success	200	{string}	string	"Exact provider response stream"
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	404	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	422	{string}	string	"Validated failed render stream"
//	@Failure	502	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Failure	504	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/specialist-renders [post]
//
//	@id			ExecuteSpecialistRender
func ExecuteSpecialistRender(ctx *gin.Context) {
	if ctx.GetHeader("Content-Type") != specialistRenderContentType {
		ctx.Error(common_errors.NewBadRequestError(errors.New("specialist-render content type is invalid")))
		return
	}
	service, err := specialistRenderService()
	if err != nil {
		writeSpecialistRenderError(ctx, err)
		return
	}
	admission, err := service.Acquire(ctx.Request.Context())
	if err != nil {
		writeSpecialistRenderError(ctx, err)
		return
	}
	defer admission.Release()
	stream, err := specialistrender.DecodeRequestStream(ctx.Request.Body)
	if err != nil {
		writeSpecialistRenderError(ctx, err)
		return
	}
	defer stream.Close()
	if stream.Request.Source.ProviderResourceID != ctx.Param("sandboxId") {
		writeSpecialistRenderError(ctx, fmt.Errorf("%w: source providerResourceId differs from sandbox", specialistrender.ErrInvalidRequest))
		return
	}
	result, executeErr := service.ExecuteAdmitted(
		ctx.Request.Context(), admission, stream.Request, stream.Input, stream.Source,
	)
	if executeErr != nil && !errors.Is(executeErr, specialistrender.ErrRenderFailed) {
		writeSpecialistRenderError(ctx, executeErr)
		return
	}
	for _, payload := range result.Files {
		defer payload.Cleanup()
	}
	ctx.Header("Content-Type", specialistRenderContentType)
	ctx.Header("X-Content-Type-Options", "nosniff")
	status := http.StatusOK
	if errors.Is(executeErr, specialistrender.ErrRenderFailed) {
		status = http.StatusUnprocessableEntity
	}
	ctx.Status(status)
	if err := specialistrender.EncodeResponseStream(ctx.Request.Context(), ctx.Writer, result); err != nil {
		// Headers have already committed. Plaintext or JSON would corrupt the
		// typed stream, so only abort the transport; the client must discard it
		// without provider_response_end.
		ctx.Abort()
		return
	}
}

// ObserveSpecialistRender godoc
//
//	@Tags		sandbox
//	@Summary	Observe durable specialist-render operation state
//	@Param		sandboxId	path	string	true	"Sandbox ID"
//	@Param		body		body	specialistrender.ObserveRequest	true	"Exact operation authority"
//	@Produce	json
//	@Success	200	{object}	specialistrender.Observation
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	404	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/specialist-renders/observe [post]
//
//	@id			ObserveSpecialistRender
func ObserveSpecialistRender(ctx *gin.Context) {
	data, err := io.ReadAll(io.LimitReader(ctx.Request.Body, 32*1024+1))
	if err != nil || len(data) == 0 || len(data) > 32*1024 {
		ctx.Error(common_errors.NewInvalidBodyRequestError(errors.New("specialist-render observe body is invalid")))
		return
	}
	var request specialistrender.ObserveRequest
	if err := generationstop.DecodeExactJSON(data, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	if request.Source.ProviderResourceID != ctx.Param("sandboxId") {
		writeSpecialistRenderError(ctx, fmt.Errorf("%w: source providerResourceId differs from sandbox", specialistrender.ErrInvalidRequest))
		return
	}
	service, err := specialistRenderService()
	if err != nil {
		writeSpecialistRenderError(ctx, err)
		return
	}
	observation, err := service.Observe(ctx.Request.Context(), request)
	if err != nil {
		writeSpecialistRenderError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, observation)
}

func specialistRenderService() (*specialistrender.Service, error) {
	instance, err := runner.GetInstance(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: runner is not initialized", specialistrender.ErrUnavailable)
	}
	if instance.SpecialistRenders == nil {
		return nil, fmt.Errorf("%w: specialist-render service is not configured", specialistrender.ErrUnavailable)
	}
	return instance.SpecialistRenders, nil
}

func writeSpecialistRenderError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, specialistrender.ErrInvalidRequest):
		ctx.Error(common_errors.NewBadRequestError(err))
	case errors.Is(err, specialistrender.ErrNotFound):
		ctx.Error(common_errors.NewNotFoundError(err))
	case errors.Is(err, specialistrender.ErrConflict):
		ctx.Error(common_errors.NewConflictError(err))
	case errors.Is(err, specialistrender.ErrOutcomeUnknown):
		ctx.Error(common_errors.NewCustomError(
			http.StatusBadGateway, err.Error(), "SPECIALIST_RENDER_OUTCOME_UNKNOWN",
		))
	case errors.Is(err, specialistrender.ErrUnavailable):
		ctx.Error(common_errors.NewCustomError(
			http.StatusServiceUnavailable, err.Error(), "SPECIALIST_RENDER_UNAVAILABLE",
		))
	case errors.Is(err, context.DeadlineExceeded):
		ctx.Error(common_errors.NewCustomError(
			http.StatusGatewayTimeout, err.Error(), "SPECIALIST_RENDER_DEADLINE_EXCEEDED",
		))
	default:
		ctx.Error(err)
	}
}
