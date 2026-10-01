//go:build linux

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func syntheticEnvironmentLease() *EnvironmentLease {
	// nosecret: generated synthetic material, never a provider credential.
	return &EnvironmentLease{Version: 1, ID: uuid.NewString(), ExpiresAt: time.Now().Add(5 * time.Second), Values: map[string]string{"api_key": "synthetic-" + uuid.NewString(), "empty_value": ""}}
}

func assertNoStoredEnvironment(t *testing.T, directory, value string) {
	t.Helper()
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(value)) {
			t.Error("native dispatch persisted environment material")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentLeaseDispatchIsTransientAndFinite(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "leased")
	openSession(t, svc, "ordinary")
	before, err := svc.Get("leased")
	if err != nil || before.EnvironmentLeaseVersion != 1 {
		t.Fatal("native environment reader capability missing")
	}
	lease := syntheticEnvironmentLease()
	lease.Values["HOME"] = filepath.Join(t.TempDir(), "recipient-home")
	result, err := svc.ExecuteEnvironmentLease("leased", `test -z "$empty_value" && printf '%s' "$api_key" | sha256sum; printf '%s' "$HOME" | sha256sum`, false, true, true, true, lease)
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatal("native environment recipient failed", err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(lease.Values["api_key"])))
	if result.Output == nil || !strings.Contains(*result.Output, expected) {
		t.Fatal("actual process did not receive its exact synthetic environment")
	}
	if !strings.Contains(*result.Output, fmt.Sprintf("%x", sha256.Sum256([]byte(lease.Values["HOME"])))) {
		t.Fatal("native recipient did not receive its leased home override")
	}
	if result.EnvironmentLeaseID != lease.ID || !result.InputClosed {
		t.Fatal("environment dispatch lost its finite native identity")
	}
	observed, err := svc.Get("leased")
	if err != nil || observed.EnvironmentLeaseID != lease.ID {
		t.Fatal("accepted environment lease cannot be recovered from native custody")
	}
	if before.HomeDirectory == "" || observed.HomeDirectory != before.HomeDirectory || observed.HomeDirectory == lease.Values["HOME"] {
		t.Fatal("ordinary native context was replaced by recipient environment")
	}
	encoded, err := svc.Execute("ordinary", "ordinary-check", `test -z "$api_key" && printf ordinary`, false, true, true, true)
	if err != nil || encoded.Output == nil || !strings.Contains(*encoded.Output, "ordinary") {
		t.Fatal("environment escaped into another native session")
	}
	owned, _ := svc.sessions.Get("leased")
	for _, entry := range owned.scope.Load().cmd.Env {
		if strings.Contains(entry, lease.Values["api_key"]) {
			t.Fatal("recipient environment contaminated the custody supervisor")
		}
	}
	assertNoStoredEnvironment(t, owned.Dir(svc.configDir), lease.Values["api_key"])
	assertNoStoredEnvironment(t, owned.Dir(svc.configDir), lease.Values["HOME"])
	for _, command := range observed.Commands {
		if strings.Contains(command.Command, lease.Values["api_key"]) {
			t.Fatal("environment entered stored command text")
		}
	}
}

func TestEnvironmentLeaseExpiryKillsReparentedDescendants(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "expiring")
	lease := syntheticEnvironmentLease()
	// The fixture re-executes this binary during double-fork startup. Under
	// -race, every natural Go exit includes the detector's default 1s delay.
	path := filepath.Join(t.TempDir(), "actor.pid")
	result, err := svc.ExecuteEnvironmentLease("expiring", fixtureCommand("fork", path), false, true, true, true, lease)
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatal("finite descendant fixture failed", err)
	}
	fd := actorFD(t, path)
	if !fdTerminated(t, fd, time.Until(lease.ExpiresAt)+svc.terminationGracePeriod+time.Second) {
		t.Fatal("native expiry left a double-forked setsid recipient alive")
	}
	if err := svc.Delete(context.Background(), "expiring"); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentLeaseCancellationKillsTheOwnedTreeOnly(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "cancel-leased")
	openSession(t, svc, "keep-ordinary")
	lease := syntheticEnvironmentLease()
	path, other := filepath.Join(t.TempDir(), "leased.pid"), filepath.Join(t.TempDir(), "ordinary.pid")
	if _, err := svc.ExecuteEnvironmentLease("cancel-leased", fixtureCommand("fork", path), false, true, true, true, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Execute("keep-ordinary", "ordinary", fixtureCommand("fork", other), false, true, true, true, true); err != nil {
		t.Fatal(err)
	}
	fd, otherFD := actorFD(t, path), actorFD(t, other)
	if err := svc.Delete(context.Background(), "cancel-leased"); err != nil {
		t.Fatal(err)
	}
	if !fdTerminated(t, fd, 0) || fdTerminated(t, otherFD, 0) {
		t.Fatal("environment cancellation lost exact native process ownership")
	}
}

func TestEnvironmentLeaseRejectsExpiredAndMalformedDispatchBeforeCommand(t *testing.T) {
	for _, state := range []string{"expired", "protocol", "nul", "name", "identity"} {
		t.Run(state, func(t *testing.T) {
			svc := newStdinTestService(t)
			openSession(t, svc, "refused")
			lease := syntheticEnvironmentLease()
			switch state {
			case "expired":
				lease.ExpiresAt = time.Now().Add(-time.Second)
			case "protocol":
				lease.Version = 0
			case "nul":
				lease.Values["api_key"] += "\x00"
			case "name":
				lease.Values["bad-name"] = "synthetic"
			case "identity":
				lease.ID = "../not-an-opaque-lease"
			}
			if _, err := svc.ExecuteEnvironmentLease("refused", "printf must-not-run", false, true, true, true, lease); err == nil {
				t.Fatal("invalid native environment dispatch was accepted")
			}
			observed, err := svc.Get("refused")
			if err != nil || len(observed.Commands) != 0 || observed.EnvironmentLeaseID != "" {
				t.Fatal("refused environment dispatch persisted an accepted command")
			}
		})
	}
}

func TestEnvironmentLeaseLoaderAndShellHooksCannotReplaceCustody(t *testing.T) {
	for _, mode := range []string{"BASH_ENV", "LD_PRELOAD"} {
		t.Run(mode, func(t *testing.T) {
			svc := newStdinTestService(t)
			openSession(t, svc, "hostile-recipient")
			lease := syntheticEnvironmentLease()
			path := filepath.Join(t.TempDir(), "recipient-hook")
			if mode == "BASH_ENV" {
				if err := os.WriteFile(path, []byte("exit 73\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				source := path + ".c"
				if err := os.WriteFile(source, []byte("#include <unistd.h>\n__attribute__((constructor)) static void refuse(void) { _exit(73); }\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := exec.Command("cc", "-shared", "-fPIC", "-o", path, source).Run(); err != nil {
					t.Fatal("native loader fixture compilation failed", err)
				}
			}
			lease.Values[mode] = path
			result, dispatchErr := svc.ExecuteEnvironmentLease("hostile-recipient", "true", false, true, true, true, lease)
			if dispatchErr == nil && result.ExitCode != nil && *result.ExitCode == 0 {
				t.Fatal("recipient did not honor its loader or shell environment hook")
			}
			owned, _ := svc.sessions.Get("hostile-recipient")
			scope := owned.scope.Load()
			for _, entry := range scope.cmd.Env {
				if strings.Contains(entry, path) {
					t.Fatal("recipient loader or shell hook entered the supervisor environment")
				}
			}
			ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			if err := scope.awaitSettlement(ctx); err != nil {
				t.Fatal("recipient failure broke native child settlement", err)
			}
		})
	}
}

func TestEnvironmentLeaseParentDeathAndRestartDoNotRestoreEnvironment(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "actor.pid")
	owner := exec.Command("/proc/self/exe", "--custody-fixture", "environment-owner", path)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Process.Kill() })
	fd := actorFD(t, path)
	if err := owner.Wait(); err != nil {
		t.Fatal(err)
	}
	if !fdTerminated(t, fd, 3*time.Second) {
		t.Fatal("daemon exit left a credential recipient descendant alive")
	}
	configDir := filepath.Join(directory, "owner-state")
	restarted := newTestServiceIn(t, configDir)
	if sessions, err := restarted.List(); err != nil || len(sessions) != 0 {
		t.Fatal("restart restored a retired credential process")
	}
	openSession(t, restarted, "owner-dies")
	result, err := restarted.Execute("owner-dies", "restarted", `test -z "$api_key" && test -z "$empty_value" && printf clean`, false, true, true, true)
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatal("restart restored secret environment or unusable shell state", err)
	}
}

func TestEnvironmentLeaseUsesTheKernelEnvironmentLimit(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "kernel-limit")
	lease := syntheticEnvironmentLease()
	// Linux limits one argument/environment string to 32 pages, independent
	// of the combined ARG_MAX. No application value-length cap is substituted.
	lease.Values["large"] = strings.Repeat("x", os.Getpagesize()*32)
	if _, err := svc.ExecuteEnvironmentLease("kernel-limit", "true", false, true, true, true, lease); err == nil || !strings.Contains(err.Error(), "argument list too long") {
		t.Fatal("native dispatch did not expose the actual kernel environment limit")
	}
	observed, err := svc.Get("kernel-limit")
	if err != nil || len(observed.Commands) != 0 || observed.EnvironmentLeaseID != "" {
		t.Fatal("failed native startup claimed command acceptance")
	}
}

func TestEnvironmentLeaseFailedSetupCannotAdmitAnotherCommand(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "setup-fails")
	lease := syntheticEnvironmentLease()
	owned, _ := svc.sessions.Get("setup-fails")
	// The exact first command directory cannot be created. This fails only
	// after the recipient shell has accepted its transient environment.
	if err := os.WriteFile(filepath.Join(owned.Dir(svc.configDir), lease.ID), []byte("blocked directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteEnvironmentLease("setup-fails", "true", false, true, true, true, lease); err == nil {
		t.Fatal("fixture did not fail first command setup")
	}
	if _, err := svc.Execute("setup-fails", "second", "true", false, true, true, true); err == nil {
		t.Fatal("ordinary command entered a credential shell after failed setup")
	}
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := owned.scope.Load().awaitSettlement(ctx); err != nil {
		t.Fatal("failed credential command kept its recipient alive", err)
	}
}

func TestEnvironmentLeaseSupervisorRefusesExpiredPrivateDispatch(t *testing.T) {
	lease := syntheticEnvironmentLease()
	lease.ExpiresAt = time.Now().Add(-time.Second)
	scope, err := startProcessScope(context.Background(), "/bin/bash", "", 100*time.Millisecond, 10*time.Millisecond, lease)
	if scope == nil || err == nil || !strings.Contains(err.Error(), "expired before recipient startup") {
		if scope != nil {
			scope.cancel()
		}
		t.Fatal("supervisor did not apply its own current clock before recipient startup")
	}
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := scope.awaitSettlement(ctx); err != nil {
		t.Fatal("refused environment startup lost descendant settlement", err)
	}
}

type environmentInputCloseNotice struct {
	io.WriteCloser
	closed chan struct{}
	once   sync.Once
}

func (input *environmentInputCloseNotice) Close() error {
	err := input.WriteCloser.Close()
	input.once.Do(func() { close(input.closed) })
	return err
}

func TestEnvironmentLeaseOverlappingDeleteRetainsPriorScopeWhenNoRecipientStarts(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "delete-during-replacement")
	owned, _ := svc.sessions.Get("delete-during-replacement")
	previous := owned.scope.Load()
	path := filepath.Join(t.TempDir(), "old-actor.pid")
	// A real old-scope descendant ignores SIGTERM, keeping settlement pending
	// after cancellation's input-close event. No public command is recorded.
	if _, err := previous.input.Write([]byte(fixtureCommand("fork", path) + "\n")); err != nil {
		t.Fatal(err)
	}
	fd := actorFD(t, path)
	notice := &environmentInputCloseNotice{WriteCloser: previous.input, closed: make(chan struct{})}
	previous.input = notice
	dispatched := make(chan error, 1)
	go func() {
		_, err := svc.ExecuteEnvironmentLease("delete-during-replacement", "true", false, true, true, true, syntheticEnvironmentLease())
		dispatched <- err
	}()
	select {
	case <-notice.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("lease did not begin old-scope settlement")
	}
	deleted := make(chan error, 1)
	go func() { deleted <- svc.Delete(context.Background(), "delete-during-replacement") }()
	select {
	case <-owned.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("overlapping delete did not cancel admission")
	}
	if err := <-dispatched; err == nil {
		t.Fatal("canceled native admission launched a credential command")
	}
	if err := <-deleted; err != nil {
		t.Fatal("no-recipient cancellation lost prior settled custody", err)
	}
	if !fdTerminated(t, fd, 0) {
		t.Fatal("overlapping delete left its old descendant alive")
	}
	if _, exists := svc.sessions.Get("delete-during-replacement"); exists {
		t.Fatal("settled deletion retained an unreachable owner")
	}
}
