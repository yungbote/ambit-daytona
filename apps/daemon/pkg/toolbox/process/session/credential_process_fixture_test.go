//go:build linux

package session

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	native "github.com/daytonaio/daemon/pkg/session"
	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
)

// A cross-repository synthetic fixture invokes the compiled real HTTP/session
// owner, with stdin as its lifetime. It has no provider credential or tenant
// auth substitute: caller authority is qualified independently by the backend.
func runCredentialProcessFixture(args []string) bool {
	if len(args) != 2 || args[0] != "--credential-process-fixture" {
		return false
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	service, err := native.NewSessionService(logger, args[1], 250*time.Millisecond, 25*time.Millisecond)
	if err != nil {
		panic(err)
	}
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(sloggin.New(logger), common_errors.NewErrorMiddleware(func(ctx *gin.Context, err error) common_errors.ErrorResponse {
		return common_errors.ErrorResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}, false))
	controller := NewSessionController(logger, args[1], service)
	routes := engine.Group("/process/session")
	routes.POST("", controller.CreateSession)
	routes.GET("", controller.ListSessions)
	routes.GET("/:sessionId", controller.GetSession)
	routes.DELETE("/:sessionId", controller.DeleteSession)
	routes.POST("/:sessionId/exec", controller.SessionExecuteCommand)
	routes.GET("/:sessionId/command/:commandId/logs", controller.GetSessionCommandLogs)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := &http.Server{Handler: engine}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	fmt.Fprintln(os.Stdout, "http://"+listener.Addr().String())
	_, _ = io.Copy(io.Discard, os.Stdin)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if sessions, err := service.List(); err == nil {
		for _, session := range sessions {
			if err := service.Delete(ctx, session.SessionId); err != nil {
				panic(err)
			}
		}
	}
	if err := server.Shutdown(ctx); err != nil {
		panic(err)
	}
	<-done
	return true
}
