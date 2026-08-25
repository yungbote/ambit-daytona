// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const providerRequestSourceAuthoritySHA256 = "sha256:4ca19ce96d429b13a3a33099798744f1801fa76eb7cc288397651481263eb133"
const providerLiveRunGoldenSHA256 = "sha256:e16f69d8bc45e2b61b5653fbcd52c5fbf36e90b67c17250ad8c0a3f8e404d4e7"
const minIOIntegrationRunGoldenSHA256 = "sha256:e95d8a96f85224e821a5462e3b0ec2b1060d534638706fbcfb6869ef21f50da1"

func TestProviderRequestSourceAuthorityIsExactReleaseSource(t *testing.T) {
	path := filepath.Join(
		repoRoot(t),
		"images/ambit-agent-workspace/capabilities/c18-specialist-packs/protocol/provider-live-request-source-authority.v1.json",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(data) != providerRequestSourceAuthoritySHA256 {
		t.Fatalf("provider request source authority digest changed: %s", digestBytes(data))
	}
	authority, err := ParseProviderRequestSourceAuthority(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(authority.Selections) != providerSuccessConcurrency {
		t.Fatalf("provider request source authority coverage differs: %#v", authority)
	}

	forged := append([]byte(nil), data...)
	forged = []byte(string(forged[:len(forged)-2]) + `-changed"}]}`)
	if _, err := ParseProviderRequestSourceAuthority(forged); err == nil {
		t.Fatal("changed provider request source authority was accepted")
	}
}

func TestProviderAndMinIORunGoldensAreExactCrossLanguageAuthority(t *testing.T) {
	providerBytes, err := os.ReadFile(filepath.Join("testdata", "c18-provider-live-run.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(providerBytes) != providerLiveRunGoldenSHA256 {
		t.Fatalf("provider live run golden digest changed: %s", digestBytes(providerBytes))
	}
	var provider ProviderLiveRun
	providerWire := bytes.TrimSuffix(providerBytes, []byte{'\n'})
	if err := generationstop.DecodeCanonicalJSON(providerWire, &provider); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProviderLiveRun(provider); err != nil {
		t.Fatal(err)
	}
	reencoded, err := CanonicalProviderLiveRun(provider)
	if err != nil || !bytes.Equal(reencoded, providerWire) {
		t.Fatalf("provider live run golden changed across parse: %v", err)
	}

	changedGeneration := cloneProviderLiveRun(t, provider)
	changedGeneration.Target.ExpectedGeneration.ContainerID = "changed"
	if err := ValidateProviderLiveRun(changedGeneration); err == nil {
		t.Fatal("changed target generation was accepted")
	}
	changedTimeout := cloneProviderLiveRun(t, provider)
	changedTimeout.Timeouts.ExecuteSeconds--
	if err := ValidateProviderLiveRun(changedTimeout); err == nil {
		t.Fatal("changed source-issued timeout was accepted")
	}
	changedSource := cloneProviderLiveRun(t, provider)
	changedSource.Executions[1].Source.ByteLength++
	if err := ValidateProviderLiveRun(changedSource); err == nil {
		t.Fatal("different cancel/success source authority was accepted")
	}

	minioBytes, err := os.ReadFile(filepath.Join("testdata", "c18-minio-integration-run.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(minioBytes) != minIOIntegrationRunGoldenSHA256 {
		t.Fatalf("MinIO integration run golden digest changed: %s", digestBytes(minioBytes))
	}
	var minio MinIOIntegrationRun
	minioWire := bytes.TrimSuffix(minioBytes, []byte{'\n'})
	if err := generationstop.DecodeCanonicalJSON(minioWire, &minio); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMinIOIntegrationRun(minio); err != nil {
		t.Fatal(err)
	}
	reencodedMinIO, err := CanonicalMinIOIntegrationRun(minio)
	if err != nil || !bytes.Equal(reencodedMinIO, minioWire) {
		t.Fatalf("MinIO integration run golden changed across parse: %v", err)
	}
}

func cloneProviderLiveRun(t *testing.T, value ProviderLiveRun) ProviderLiveRun {
	t.Helper()
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone ProviderLiveRun
	if err := generationstop.DecodeCanonicalJSON(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
