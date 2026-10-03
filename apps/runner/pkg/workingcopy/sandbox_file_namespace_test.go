// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestNativeFileNamespaceSelectionAndLegacyJSON(t *testing.T) {
	for _, selected := range []string{"/tmp/fixture.txt", "/home/daytona/fixture.txt", "/workspace/outputs/fixture.txt", "/tmp/line\nname", "/tmp/back\\slash"} {
		selector, err := sandboxFileSelectorIn(selected, "code_program")
		if err != nil || selector.SemanticZoneRef != codeProgramFileZone || sandboxFilePath(selector) != selected {
			t.Fatalf("valid CODE namespace path differs: %q %#v %v", selected, selector, err)
		}
	}
	for _, selected := range []string{"/", "relative", "/tmp/../file", "/tmp//file", "/tmp/file/", "/tmp/" + strings.Repeat("a", 256), "/tmp/\x00file", "/tmp/\xff"} {
		if _, err := sandboxFileSelectorIn(selected, "code_program"); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid CODE selector accepted: %q %v", selected, err)
		}
	}
	for _, namespace := range []string{"", "foreign"} {
		if _, err := sandboxFileSelectorIn("/tmp/fixture.txt", namespace); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ordinary/unknown namespace expanded to tmp: %q %v", namespace, err)
		}
	}
	_, _, _, request := nativeFixture(t)
	bytes, err := json.Marshal(request)
	if err != nil || strings.Contains(string(bytes), "sourceNamespace") {
		t.Fatalf("historical request bytes gained a field: %s %v", bytes, err)
	}
}

// The fixture below proves persisted scope/replay semantics, not filesystem
// permissions or atomic cloning in a real CODE container.
func TestNativeFileNamespacePersistsWithoutOperationRebinding(t *testing.T) {
	service, _, physical, request := nativeFixture(t)
	request.SourceNamespace = "code_program"
	request.Path = "/tmp/fixture.html"
	ctx := context.Background()
	receipt, err := service.CaptureSandboxFile(ctx, nativeSandboxID, request)
	if err != nil || receipt.SourceNamespace != request.SourceNamespace || receipt.Path != request.Path {
		t.Fatalf("source namespace lost in receipt: %#v %v", receipt, err)
	}
	lookup := SandboxFileObserveRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID, SourceNamespace: request.SourceNamespace}
	observed, err := service.ObserveSandboxFile(ctx, nativeSandboxID, lookup)
	if err != nil || observed.Receipt == nil || *observed.Receipt != receipt || physical.captureCalls != 1 {
		t.Fatalf("retained receipt changed: %#v %v", observed, err)
	}
	lookup.SourceNamespace = ""
	if _, err := service.ObserveSandboxFile(ctx, nativeSandboxID, lookup); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown legacy namespace adopted programme operation: %v", err)
	}
	other := request
	other.SourceNamespace = ""
	other.Path = "/workspace/outputs/fixture.html"
	if _, err := service.CaptureSandboxFile(ctx, nativeSandboxID, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("programme operation rebound to ordinary source: %v", err)
	}
	if _, err := service.DeleteSandboxFile(ctx, nativeSandboxID, SandboxFileDeleteRequest{Receipt: &receipt}); err != nil {
		t.Fatal(err)
	}
	lookup.SourceNamespace = request.SourceNamespace
	if got, err := service.ObserveSandboxFile(ctx, nativeSandboxID, lookup); err != nil || got.Status != "retired" {
		t.Fatalf("programme retirement unreadable: %#v %v", got, err)
	}
	if _, err := service.CaptureSandboxFile(ctx, nativeSandboxID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("programme retirement reopened capture: %v", err)
	}
}

func TestNativeFileNamespaceRetirementBeforeAdmissionIsExact(t *testing.T) {
	service, _, physical, request := nativeFixture(t)
	lookup := SandboxFileObserveRequest{OrganizationID: request.OrganizationID, OperationID: request.OperationID, SourceNamespace: "code_program"}
	ctx := context.Background()
	_, err := service.DeleteSandboxFile(ctx, nativeSandboxID, SandboxFileDeleteRequest{OrganizationID: lookup.OrganizationID, OperationID: lookup.OperationID, SourceNamespace: lookup.SourceNamespace})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := service.ObserveSandboxFile(ctx, nativeSandboxID, lookup); err != nil || got.Status != "retired" {
		t.Fatalf("pathless programme retirement unreadable: %#v %v", got, err)
	}
	lookup.SourceNamespace = ""
	if _, err := service.ObserveSandboxFile(ctx, nativeSandboxID, lookup); !errors.Is(err, ErrConflict) {
		t.Fatalf("retirement changed namespace: %v", err)
	}
	lookup.SourceNamespace = "foreign"
	if _, err := service.ObserveSandboxFile(ctx, nativeSandboxID, lookup); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown namespace observed even without a path: %v", err)
	}
	if physical.inspectCalls != 0 || physical.captureCalls != 0 {
		t.Fatal("retirement invented source custody")
	}
}
