//go:build linux

package session

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
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
