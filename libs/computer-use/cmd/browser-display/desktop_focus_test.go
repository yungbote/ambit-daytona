// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDesktopBindingPreservesAbsentScopeAndRequiresExactLiveBirth(t *testing.T) {
	process, err := desktopBinding("")
	if err != nil || process != nil {
		t.Fatalf("legacy scope changed: %v %v", process, err)
	}
	pid := uint32(os.Getpid())
	started, live := processStarted(pid)
	if !live {
		t.Fatal("current process was not live")
	}
	raw, _ := json.Marshal(desktopProcess{PID: pid, Started: started})
	process, err = desktopBinding(string(raw))
	if err != nil || process == nil || process.PID != pid || process.Started != started {
		t.Fatalf("exact owned birth refused: %v %v", process, err)
	}
	for _, invalid := range []string{"null", "{}", `{"pid":0,"started":1}`, `{"pid":1,"started":0}`, `{"pid":1,"started":1,"extra":true}`, string(raw) + " {}", string(raw) + " trailing"} {
		if _, err := desktopBinding(invalid); err == nil {
			t.Fatalf("malformed binding admitted: %s", invalid)
		}
	}
	wrong, _ := json.Marshal(desktopProcess{PID: pid, Started: started + 1})
	if _, err := desktopBinding(string(wrong)); err == nil {
		t.Fatal("reused PID birth admitted")
	}
}
