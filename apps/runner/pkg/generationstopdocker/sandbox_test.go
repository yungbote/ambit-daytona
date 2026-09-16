// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package generationstopdocker

import (
	"context"
	"testing"
)

func TestNativeSandboxObservationDerivesProviderOwnerWithoutProductLabels(t *testing.T) {
	api := newFakeDockerAPI()
	api.inspect.Config.Labels = map[string]string{
		"daytona.runner.container-kind": "sandbox",
		"daytona.organization_id":       "11111111-1111-4111-8111-111111111111",
	}
	adapter, _ := New(api)
	observed, err := adapter.InspectSandboxGeneration(context.Background(), "sandbox-1")
	if err != nil {
		t.Fatal(err)
	}
	if observed.SandboxID != "sandbox-1" || observed.OrganizationID != api.inspect.Config.Labels["daytona.organization_id"] ||
		observed.Generation.ContainerID != api.inspect.ID || !observed.State.Running || observed.State.PID != api.inspect.State.Pid {
		t.Fatalf("native ownership was not physically derived: %#v", observed)
	}
	for name, mutate := range map[string]func(){
		"name":         func() { api.inspect.Name = "/other" },
		"organization": func() { delete(api.inspect.Config.Labels, "daytona.organization_id") },
		"kind":         func() { api.inspect.Config.Labels["daytona.runner.container-kind"] = "specialist-render" },
	} {
		t.Run(name, func(t *testing.T) {
			originalName := api.inspect.Name
			originalOrg := api.inspect.Config.Labels["daytona.organization_id"]
			originalKind := api.inspect.Config.Labels["daytona.runner.container-kind"]
			mutate()
			if _, err := adapter.InspectSandboxGeneration(context.Background(), "sandbox-1"); err == nil {
				t.Fatal("missing or substituted ownership admitted")
			}
			api.inspect.Name = originalName
			api.inspect.Config.Labels["daytona.organization_id"] = originalOrg
			api.inspect.Config.Labels["daytona.runner.container-kind"] = originalKind
		})
	}
	if api.stopCalls != 0 {
		t.Fatal("native observation dispatched stop")
	}
}
