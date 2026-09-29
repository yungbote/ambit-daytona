// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package grant

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The backend creates these synthetic grants using its real PostgreSQL
// proof/lease services. No production key or credential is in this fixture.
func TestLaterBackendProofRecoversAmbiguousControl(t *testing.T) {
	path := os.Getenv("MEDIA_EDGE_CONTROL_RECOVERY_FIXTURE")
	if path == "" {
		t.Skip("MEDIA_EDGE_CONTROL_RECOVERY_FIXTURE required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Nosecret                                              bool
		Now                                                   int64
		Audience, PublicKey, First, Tied, Later, ControllerID string
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || !fixture.Nosecret {
		t.Fatalf("synthetic fixture: %v", err)
	}
	verifier := Verifier{Keys: ringOf(t, fixture.PublicKey), Audience: fixture.Audience, Now: func() time.Time { return time.UnixMilli(fixture.Now) }}
	first, err := verifier.Grant(fixture.First)
	if err != nil {
		t.Fatal(err)
	}
	tied, err := verifier.Grant(fixture.Tied)
	if err != nil {
		t.Fatal(err)
	}
	later, err := verifier.Grant(fixture.Later)
	if err != nil {
		t.Fatal(err)
	}
	if first.IssuedAt != tied.IssuedAt || first.ControllerID == tied.ControllerID || later.IssuedAt <= tied.IssuedAt {
		t.Fatal("fixture did not exercise tied takeover and a later proof")
	}
	for _, order := range [][]Grant{{first, tied}, {tied, first}} {
		a := NewAuthority(order[0])
		if err := a.Add(order[1], fixture.Now); err != nil {
			t.Fatal(err)
		}
		if _, ok := a.Control(fixture.Now); ok {
			t.Fatal("tied proof selected a controller")
		}
		if _, ok := a.ViewUntil(fixture.Now); !ok {
			t.Fatal("ambiguity ended valid viewing")
		}
		if err := a.Add(later, fixture.Now); err != nil {
			t.Fatal(err)
		}
		if current, ok := a.Control(fixture.Now); !ok || current.ControllerID != fixture.ControllerID {
			t.Fatal("real later backend proof did not restore current control")
		}
	}
	t.Log("two backend-signed tied controllers refused in either order; later PostgreSQL proof+lease renewal restores current controller and preserves viewing")
}
