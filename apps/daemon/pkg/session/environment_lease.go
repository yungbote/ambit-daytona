package session

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/google/uuid"
)

// EnvironmentLease exists only during authenticated native dispatch. Command
// custody retains its ID and deadline, never these environment values.
type EnvironmentLease struct {
	Version   int               `json:"version"`
	ID        string            `json:"id"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Values    map[string]string `json:"values"`
}

type environmentLeaseCustody struct {
	ID        string
	ExpiresAt time.Time
}

func EnvironmentLeaseVersion() int {
	if runtime.GOOS == "linux" {
		return 2
	}
	return 0
}

func environmentValues(values map[string]string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, errors.New("environment lease has no declared values")
	}
	detached := make(map[string]string, len(values))
	for name, value := range values {
		if name == "" || strings.ContainsAny(name, "=\x00") || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("environment lease value is not a native environment string")
		}
		detached[name] = value
	}
	return detached, nil
}

func processEnvironment(base []string, values map[string]string) []string {
	environment := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := values[name]; !replaced {
			environment = append(environment, entry)
		}
	}
	for name, value := range values {
		environment = append(environment, name+"="+value)
	}
	return environment
}

// Called with the existing session lifecycle mutex held, before command
// persistence. A lease can enter only the session's first finite invocation.
func (s *SessionService) admitEnvironmentLease(owned *session, lease *EnvironmentLease) (*processScope, error) {
	if lease.Version != EnvironmentLeaseVersion() || lease.Version != 2 {
		return nil, common_errors.NewBadRequestError(errors.New("environment lease protocol is unsupported"))
	}
	if _, err := uuid.Parse(lease.ID); err != nil {
		return nil, common_errors.NewBadRequestError(errors.New("environment lease identity is invalid"))
	}
	if lease.ExpiresAt.IsZero() || !lease.ExpiresAt.After(time.Now()) {
		return nil, common_errors.NewGoneError(errors.New("environment lease has expired"))
	}
	values, err := environmentValues(lease.Values)
	if err != nil {
		return nil, common_errors.NewBadRequestError(err)
	}
	if owned.commands.Count() != 0 || owned.environmentLease.Load() != nil {
		return nil, common_errors.NewConflictError(errors.New("environment lease requires a fresh isolated session"))
	}
	previous := owned.scope.Load()
	if previous == nil || previous.state() != "running" || owned.ctx.Err() != nil {
		return nil, common_errors.NewGoneError(errors.New("session is no longer accepting commands"))
	}
	previous.cancel()
	cleanup, stop := context.WithTimeout(context.Background(), s.terminationGracePeriod+2*time.Second)
	err = previous.awaitSettlement(cleanup)
	stop()
	if err != nil {
		return nil, err
	}
	finite, expire := context.WithDeadline(owned.ctx, lease.ExpiresAt)
	dispatch := &EnvironmentLease{Version: lease.Version, ID: lease.ID, ExpiresAt: lease.ExpiresAt, Values: values}
	scope, err := startProcessScope(finite, previous.shell, previous.cmd.Dir, s.terminationGracePeriod, s.terminationCheckInterval, dispatch)
	if scope == nil {
		// A canceled startup may return no recipient at all. Keep the prior
		// settled scope as deletion's proof instead of erasing that custody.
		expire()
		if err == nil {
			err = errors.New("environment lease started no recipient")
		}
		return nil, err
	}
	owned.scope.Store(scope)
	go func() {
		<-scope.done
		expire()
	}()
	if err != nil {
		expire()
		scope.cancel()
		cleanup, stop := context.WithTimeout(context.Background(), s.terminationGracePeriod+2*time.Second)
		cleanupErr := scope.awaitSettlement(cleanup)
		stop()
		return nil, errors.Join(err, cleanupErr)
	}
	if owned.ctx.Err() != nil || !lease.ExpiresAt.After(time.Now()) {
		expire()
		scope.cancel()
		return nil, common_errors.NewGoneError(errors.New("environment lease expired before command acceptance"))
	}
	owned.environmentLease.Store(&environmentLeaseCustody{ID: lease.ID, ExpiresAt: lease.ExpiresAt})
	return scope, nil
}
