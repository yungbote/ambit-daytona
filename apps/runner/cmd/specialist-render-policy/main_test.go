// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestPolicyGenerationReceiptGoldenIsCanonicalAndPathPrivate(t *testing.T) {
	policyBytes, receipt, _ := policyAuthorityFixture(t)
	encoded, err := generationstop.CanonicalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyGolden(t, "c18-runner-policy-generation-receipt.golden.json", encoded)
	parsed, err := parsePolicyGenerationReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest != receipt.Digest || parsed.Policy.FileSHA256 != digestBytes(policyBytes) {
		t.Fatalf("parsed generation receipt differs: %#v", parsed)
	}
	if bytes.Contains(encoded, []byte("/home/")) || bytes.Contains(encoded, []byte("source-root")) ||
		bytes.Contains(encoded, []byte("endpoint")) || bytes.Contains(encoded, []byte("token")) {
		t.Fatalf("receipt leaked host or credential authority: %s", encoded)
	}
}

func TestPolicyGenerationReceiptRejectsRuntimePathAndImageSubstitution(t *testing.T) {
	_, receipt, _ := policyAuthorityFixture(t)
	for _, mutate := range []func(*policyGenerationReceipt){
		func(value *policyGenerationReceipt) { value.Inputs.SeccompRuntimePath = "/host/private/seccomp.json" },
		func(value *policyGenerationReceipt) {
			value.Images[0], value.Images[1] = value.Images[1], value.Images[0]
		},
		func(value *policyGenerationReceipt) { value.Inputs.SeccompCopiedFileSHA256 = policyDigestSeed(99) },
		func(value *policyGenerationReceipt) { value.Registry.InspectAuthority = "https://registry.test" },
		func(value *policyGenerationReceipt) {
			value.Images[0].InspectImageRef = value.Images[0].RuntimeImageRef
		},
	} {
		candidate := receipt
		candidate.Images = append([]policyReceiptImage(nil), receipt.Images...)
		mutate(&candidate)
		candidate.Digest = policyDigestSeed(100)
		encoded, _ := generationstop.CanonicalJSON(candidate)
		if _, err := parsePolicyGenerationReceipt(encoded); err == nil {
			t.Fatal("forged policy generation receipt was accepted")
		}
	}
}

func TestPublishAuthorityDirectoryCommitsExactPrivateThreeFileRoster(t *testing.T) {
	policyBytes, receipt, seccompBytes := policyAuthorityFixture(t)
	receiptBytes, _ := generationstop.CanonicalJSON(receipt)
	outputRoot := filepath.Join(t.TempDir(), "c18-authority")
	if err := publishAuthorityDirectory(outputRoot, policyBytes, receiptBytes, seccompBytes); err != nil {
		t.Fatal(err)
	}
	if err := validateAuthorityDirectory(outputRoot, receipt); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(outputRoot)
	if err != nil || rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("authority root mode differs: %#v %v", rootInfo, err)
	}
	entries, _ := os.ReadDir(outputRoot)
	if len(entries) != 3 {
		t.Fatalf("authority file count differs: %#v", entries)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Fatalf("authority file mode differs: %s %#v %v", entry.Name(), info, err)
		}
	}
	copied, err := os.ReadFile(filepath.Join(outputRoot, seccompFileName))
	if err != nil || !bytes.Equal(copied, seccompBytes) {
		t.Fatal("runtime seccomp copy differs")
	}
	if err := publishAuthorityDirectory(outputRoot, policyBytes, receiptBytes, seccompBytes); err == nil {
		t.Fatal("preexisting authority root was overwritten")
	}
}

func TestPublishAuthorityDirectoryLeavesNoRootWhenInputsDiffer(t *testing.T) {
	policyBytes, receipt, seccompBytes := policyAuthorityFixture(t)
	receipt.Policy.FileSHA256 = policyDigestSeed(200)
	resealed, err := sealPolicyGenerationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, _ := generationstop.CanonicalJSON(resealed)
	outputRoot := filepath.Join(t.TempDir(), "c18-authority")
	if err := publishAuthorityDirectory(outputRoot, policyBytes, receiptBytes, seccompBytes); err == nil {
		t.Fatal("detached policy bytes were published")
	}
	if _, err := os.Lstat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("failed transaction left an authority root: %v", err)
	}
}

func TestAuthorityPathsRejectNormalizationAndInputSymlinks(t *testing.T) {
	parent := t.TempDir()
	if err := preflightAuthorityOutputRoot(parent + "/child/../authority"); err == nil {
		t.Fatal("non-normalized output root was accepted")
	}
	target := filepath.Join(parent, "target")
	if err := os.WriteFile(target, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFileSnapshot(link, 1024); err == nil {
		t.Fatal("symlink input was accepted")
	}
	if !absoluteNormalizedPath(runtimeSeccompPath) ||
		absoluteNormalizedPath("/opt/ambit/c18-authority/../secret") {
		t.Fatal("runtime path normalization differs")
	}
}

func TestRegistryInspectionRewritesOnlyTheAuthority(t *testing.T) {
	manifest := policyDigestSeed(10)
	runtimeRef := "registry:6000/ambit-c18-data-research@" + manifest
	inspectRef, runtimeAuthority, observedManifest, err := rewriteRegistryAuthority(
		runtimeRef, "127.0.0.1:5001",
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspectRef != "127.0.0.1:5001/ambit-c18-data-research@"+manifest ||
		runtimeAuthority != "registry:6000" || observedManifest != manifest {
		t.Fatalf("registry rewrite differs: %q %q %q", inspectRef, runtimeAuthority, observedManifest)
	}
	for _, candidate := range []struct {
		ref       string
		authority string
	}{
		{runtimeRef, "https://127.0.0.1:5001"},
		{runtimeRef, "127.0.0.1:5001/path"},
		{runtimeRef, "127.00.0.1:5001"},
		{runtimeRef, "Registry.Test:5001"},
		{"2130706433:6000/ambit@" + manifest, "127.0.0.1:5001"},
		{"0x7f000001:6000/ambit@" + manifest, "127.0.0.1:5001"},
		{"registry:6000/../ambit@" + manifest, "127.0.0.1:5001"},
		{"registry:6000/Ambit@" + manifest, "127.0.0.1:5001"},
		{"registry:6000/ambit:tag@" + manifest, "127.0.0.1:5001"},
	} {
		if _, _, _, err := rewriteRegistryAuthority(candidate.ref, candidate.authority); err == nil {
			t.Fatalf("invalid registry rewrite was accepted: %#v", candidate)
		}
	}
}

func TestReadExecutableSnapshotRehashesCurrentBinary(t *testing.T) {
	data, err := readExecutableSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || !exactSHA256(digestBytes(data)) {
		t.Fatal("current executable was not rehashed")
	}
}

func policyAuthorityFixture(t *testing.T) ([]byte, policyGenerationReceipt, []byte) {
	t.Helper()
	seccompBytes, err := os.ReadFile(filepath.Join(policyRepoRoot(t), "images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	packs := []string{"data-research", "office-authoring", "pdf-ocr", "web-browser"}
	documents := make([]specialistrender.PolicyDocument, len(packs))
	images := make([]policyReceiptImage, len(packs))
	for index, pack := range packs {
		manifestDigest := policyDigestSeed(10 + index)
		image := specialistrender.ImagePin{
			Ref:          "registry:6000/ambit-c18-" + pack + "@" + manifestDigest,
			ConfigDigest: policyDigestSeed(20 + index), PackID: pack,
			PackRef: "ambit.runtime-pack/" + pack + "@1",
		}
		documents[index] = specialistrender.PolicyDocument{
			Image: image, SeccompPath: runtimeSeccompPath,
			SeccompDigest: specialistrender.SpecialistSeccompDigest,
		}
		images[index] = policyReceiptImage{
			PackID: pack, RuntimeImageRef: image.Ref,
			InspectImageRef: "127.0.0.1:5001/ambit-c18-" + pack + "@" + manifestDigest,
			ManifestDigest:  manifestDigest, ConfigDigest: image.ConfigDigest,
		}
	}
	policyBytes, err := generationstop.CanonicalJSON(specialistrender.PolicySet{
		Schema: specialistrender.PolicySetSchema, Policies: documents,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := sealPolicyGenerationReceipt(policyGenerationReceipt{
		ObservedAt: "2026-08-25T05:00:00.000Z",
		Source: policyReceiptSource{
			Revision: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40),
			SourceSetDigest: policyDigestSeed(3), SourceContractsFileSHA256: policyDigestSeed(3),
		},
		Generator: policyReceiptGenerator{ExecutableSHA256: policyDigestSeed(4)},
		Registry: policyReceiptRegistry{
			InspectAuthority: "127.0.0.1:5001", RuntimeAuthority: "registry:6000",
		},
		Inputs: policyReceiptInputs{
			CompositionFileSHA256: policyDigestSeed(5), RoutingFileSHA256: policyDigestSeed(6),
			SeccompSourceFileSHA256: specialistrender.SpecialistSeccompDigest,
			SeccompCopiedFileSHA256: specialistrender.SpecialistSeccompDigest,
			SeccompRuntimePath:      runtimeSeccompPath,
		},
		Images: images,
		Policy: policyReceiptPolicy{
			Schema: specialistrender.PolicySetSchema, RowCount: 4, FileSHA256: digestBytes(policyBytes),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policyBytes, receipt, seccompBytes
}

func policyRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path is unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

func assertPolicyGolden(t *testing.T, name string, actual []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_C18_POLICY_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, actual, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Fatalf("golden %s differs; run with UPDATE_C18_POLICY_GOLDEN=1", name)
	}
}

func policyDigestSeed(seed int) string {
	return fmt.Sprintf("sha256:%064x", seed)
}
