// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/gin-gonic/gin"
)

// writeCanonicalJSONResponse preserves the exact cross-language JSON authority
// required by backend control clients. Gin's ordinary JSON renderer preserves
// Go struct field order, while the shared contract recursively sorts object
// keys. Encode before committing headers so an unsupported value fails without
// publishing a partial success response.
func writeCanonicalJSONResponse(ctx *gin.Context, status int, value any) {
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		_ = ctx.Error(err)
		return
	}
	ctx.Header("Content-Type", "application/json")
	ctx.Status(status)
	if _, err := ctx.Writer.Write(encoded); err != nil {
		// Headers may already be committed. Additional JSON would corrupt the
		// canonical response, so terminate the transport instead.
		ctx.Abort()
	}
}
