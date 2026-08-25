// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/runner"
	"github.com/gin-gonic/gin"
)

const maximumGenerationStopRequestBytes = 128 * 1024

// ObserveSandboxGeneration godoc
//
//	@Tags		sandbox
//	@Summary	Observe one exact provider-owned container generation
//	@Param		sandboxId	path	string										true	"Sandbox ID"
//	@Param		body		body	generationstop.GenerationObservationRequest	true	"Exact source, owner and fence"
//	@Produce	json
//	@Success	200	{object}	generationstop.GenerationObservation
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	404	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/generation/observe [post]
//
//	@id			ObserveSandboxGeneration
func ObserveSandboxGeneration(ctx *gin.Context) {
	var request generationstop.GenerationObservationRequest
	if err := decodeExactGenerationBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := generationStopService()
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	if request.Source.ProviderResourceID != ctx.Param("sandboxId") {
		writeGenerationStopError(ctx, fmt.Errorf("%w: source providerResourceId differs from sandbox", generationstop.ErrInvalidRequest))
		return
	}
	observation, err := service.ObserveCurrent(ctx.Request.Context(), request)
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, observation)
}

// ObserveCurrentSandboxGeneration godoc
//
//	@Tags		sandbox
//	@Summary	Observe current generation with provider-observable owner authority
//	@Param		sandboxId	path	string										true	"Sandbox ID"
//	@Param		body		body	generationstop.ProviderGenerationObservationRequest	true	"Exact provider source, owner and fence"
//	@Produce	json
//	@Success	200	{object}	generationstop.ProviderGenerationObservation
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/generation/observe-current [post]
//
//	@id			ObserveCurrentSandboxGeneration
func ObserveCurrentSandboxGeneration(ctx *gin.Context) {
	var request generationstop.ProviderGenerationObservationRequest
	if err := decodeExactGenerationBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := generationStopService()
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	if request.Source.ProviderResourceID != ctx.Param("sandboxId") {
		writeGenerationStopError(ctx, fmt.Errorf("%w: source providerResourceId differs from sandbox", generationstop.ErrInvalidRequest))
		return
	}
	observation, err := service.ObserveProviderCurrent(ctx.Request.Context(), request)
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	writeCanonicalJSONResponse(ctx, http.StatusOK, observation)
}

// StopSandboxGenerationOnce godoc
//
//	@Tags		sandbox
//	@Summary	Durably stop one exact sandbox generation once
//	@Param		sandboxId	path	string						true	"Sandbox ID"
//	@Param		body		body	generationstop.StopRequest	true	"Exact idempotent stopped-generation request"
//	@Produce	json
//	@Success	200	{object}	generationstop.Receipt
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/stop-generation-once [post]
//
//	@id			StopSandboxGenerationOnce
func StopSandboxGenerationOnce(ctx *gin.Context) {
	var request generationstop.StopRequest
	if err := decodeExactGenerationBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := generationStopService()
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	if request.Source.ProviderResourceID != ctx.Param("sandboxId") {
		writeGenerationStopError(ctx, fmt.Errorf("%w: source providerResourceId differs from sandbox", generationstop.ErrInvalidRequest))
		return
	}
	receipt, err := service.StopOnce(ctx.Request.Context(), request)
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, receipt)
}

// ObserveSandboxGenerationStop godoc
//
//	@Tags		sandbox
//	@Summary	Observe one exact durable stopped-generation operation
//	@Param		sandboxId	path	string						true	"Sandbox ID"
//	@Param		body		body	generationstop.StopRequest	true	"Exact stopped-generation request"
//	@Produce	json
//	@Success	200	{object}	generationstop.Observation
//	@Failure	400	{object}	common_errors.ErrorResponse
//	@Failure	401	{object}	common_errors.ErrorResponse
//	@Failure	409	{object}	common_errors.ErrorResponse
//	@Failure	503	{object}	common_errors.ErrorResponse
//	@Router		/sandboxes/{sandboxId}/stop-generation-once/observe [post]
//
//	@id			ObserveSandboxGenerationStop
func ObserveSandboxGenerationStop(ctx *gin.Context) {
	var request generationstop.StopRequest
	if err := decodeExactGenerationBody(ctx, &request); err != nil {
		ctx.Error(common_errors.NewInvalidBodyRequestError(err))
		return
	}
	service, err := generationStopService()
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	if request.Source.ProviderResourceID != ctx.Param("sandboxId") {
		writeGenerationStopError(ctx, fmt.Errorf("%w: source providerResourceId differs from sandbox", generationstop.ErrInvalidRequest))
		return
	}
	observation, err := service.Observe(ctx.Request.Context(), request)
	if err != nil {
		writeGenerationStopError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, observation)
}

func generationStopService() (*generationstop.Service, error) {
	instance, err := runner.GetInstance(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: runner is not initialized", generationstop.ErrUnavailable)
	}
	if instance.GenerationStops == nil {
		return nil, fmt.Errorf("%w: stopped-generation service is not configured", generationstop.ErrUnavailable)
	}
	return instance.GenerationStops, nil
}

func writeGenerationStopError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, generationstop.ErrInvalidRequest):
		ctx.Error(common_errors.NewBadRequestError(err))
	case errors.Is(err, generationstop.ErrNotFound):
		ctx.Error(common_errors.NewNotFoundError(err))
	case errors.Is(err, generationstop.ErrOutcomeUnknown):
		ctx.Error(common_errors.NewCustomError(
			http.StatusServiceUnavailable,
			err.Error(),
			"STOPPED_GENERATION_OUTCOME_UNKNOWN",
		))
	case errors.Is(err, generationstop.ErrUnavailable):
		ctx.Error(common_errors.NewCustomError(
			http.StatusServiceUnavailable,
			err.Error(),
			"STOPPED_GENERATION_UNAVAILABLE",
		))
	case errors.Is(err, generationstop.ErrConflict):
		ctx.Error(common_errors.NewConflictError(err))
	default:
		ctx.Error(err)
	}
}

func decodeExactGenerationBody(ctx *gin.Context, target any) error {
	data, err := io.ReadAll(io.LimitReader(ctx.Request.Body, maximumGenerationStopRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(data) == 0 || len(data) > maximumGenerationStopRequestBytes {
		return errors.New("request body is empty or exceeds the bounded stopped-generation envelope")
	}
	return generationstop.DecodeExactJSON(data, target)
}
