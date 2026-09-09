//go:build linux

package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
)

func TestProcessObservationFollowsNativeCustodyAndRetirement(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "browser-owner")
	openSession(t, svc, "other-owner")
	marker := filepath.Join(t.TempDir(), "actor.pid")
	if _, err := svc.Execute("browser-owner", "start", fixtureCommand("fork", marker), false, true, true, false, true); err != nil {
		t.Fatal(err)
	}
	actorFD(t, marker)
	value, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(value))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := svc.ObserveOwnedProcess("browser-owner", pid)
	if err != nil || identity.PID != pid || identity.StartTime == "" {
		t.Fatalf("detached descendant lost custody: identity=%+v error=%v", identity, err)
	}
	if found, err := svc.FindProcessSession(pid); err != nil || found != identity || found.SessionID != "browser-owner" {
		t.Fatalf("workspace lookup changed process custody: identity=%+v error=%v", found, err)
	}
	if _, err := svc.ObserveOwnedProcess("other-owner", pid); err == nil {
		t.Fatal("another session adopted the browser process")
	}
	if _, err := svc.ObserveOwnedProcess("browser-owner", os.Getpid()); err == nil {
		t.Fatal("a process outside the session was attributed to it")
	}
	if err := svc.Delete(context.Background(), "browser-owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ObserveOwnedProcess("browser-owner", pid); err == nil {
		t.Fatal("retired custody remained visible")
	}
}

// A session is registered while its supervisor starts, so custody can be asked
// about before it exists. That is an answer about the session — it owns nothing
// — and it must not become an unclassified failure, because a workspace-wide
// lookup would then hide the owner that does hold the process.
func TestCustodyAnswersNotOwnedBeforeItBegins(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "browser-owner")
	pid := startFixtureActor(t, svc, "browser-owner")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.sessions.Set("starting", &session{id: "starting", commands: cmap.New[*Command](), ctx: ctx, cancel: cancel})

	if _, err := svc.ObserveOwnedProcess("starting", pid); !errors.Is(err, ErrProcessNotOwned) {
		t.Fatalf("a session without custody answered %v, want not owned", err)
	}
	found, err := svc.FindProcessSession(pid)
	if err != nil || found.SessionID != "browser-owner" {
		t.Fatalf("a session without custody masked the owner: identity=%+v error=%v", found, err)
	}
}

// A shell that exits uncleanly has ended its custody just as surely as one that
// settles. Reporting that as an unclassified failure made a live browser stream
// read as a transport fault instead of a finished view, and made one crashed
// session answer for every other session's processes.
func TestUncleanShellExitEndsCustody(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "browser-owner")
	openSession(t, svc, "crashed-owner")
	pid := startFixtureActor(t, svc, "browser-owner")

	crashed, _ := svc.sessions.Get("crashed-owner")
	scope := crashed.scope.Load()
	if err := syscall.Kill(scope.cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for scope.state() == "running" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if state := scope.state(); state != "unavailable" {
		t.Fatalf("a killed shell settled as %q, want unavailable", state)
	}

	if _, err := svc.ObserveOwnedProcess("crashed-owner", pid); !errors.Is(err, ErrProcessCustodyEnded) {
		t.Fatalf("an unclean shell exit answered %v, want ended custody", err)
	}
	found, err := svc.FindProcessSession(pid)
	if err != nil || found.SessionID != "browser-owner" {
		t.Fatalf("a crashed session masked the live owner: identity=%+v error=%v", found, err)
	}
}

func startFixtureActor(t *testing.T, svc *SessionService, sessionID string) int {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "actor.pid")
	if _, err := svc.Execute(sessionID, "start", fixtureCommand("fork", marker), false, true, true, false, true); err != nil {
		t.Fatal(err)
	}
	actorFD(t, marker)
	value, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(value))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}
