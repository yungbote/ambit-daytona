// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestPublisherPublishesAndIdempotentlyRevalidatesFourArchives(t *testing.T) {
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})

	first := runTestPublication(t, request, requestDigest, server.Client())
	if first.Outcome != "succeeded" || len(first.PublishedArchives) != 4 {
		t.Fatalf("unexpected first receipt: %#v", first)
	}
	for _, published := range first.PublishedArchives {
		if published.ImageTagState != "absent" || published.Manifest.Disposition != "uploaded" ||
			published.Config.Disposition != "uploaded" || published.Layers[0].Disposition != "uploaded" {
			t.Fatalf("fresh publication was not recorded as uploaded: %#v", published)
		}
		if published.RuntimeImageRef != request.Registry.RuntimeAuthority+"/"+published.Archive.Repository+"@"+published.Manifest.Digest {
			t.Fatalf("runtime digest reference drifted: %q", published.RuntimeImageRef)
		}
	}
	encoded, err := CanonicalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(encoded)
	if err != nil || parsed.Digest != first.Digest {
		t.Fatalf("sealed receipt did not round-trip: %v", err)
	}

	second := runTestPublication(t, request, requestDigest, server.Client())
	for _, published := range second.PublishedArchives {
		if published.ImageTagState != "absent" || published.Manifest.Disposition != "already_present" ||
			published.Config.Disposition != "already_present" || published.Layers[0].Disposition != "already_present" {
			t.Fatalf("idempotent publication did not record existing content: %#v", published)
		}
	}
	if registry.tagWrites != 0 {
		t.Fatalf("idempotent replay rewrote tags: got %d writes", registry.tagWrites)
	}
	for _, archive := range request.Archives {
		registry.tags[registryKey(archive.Repository, request.ImageTag)] = archive.ManifestDigest
	}
	third := runTestPublication(t, request, requestDigest, server.Client())
	for _, published := range third.PublishedArchives {
		if published.ImageTagState != "present_exact" {
			t.Fatalf("exact preexisting image tag was not observed: %#v", published)
		}
	}

	output := filepath.Join(t.TempDir(), "receipt.json")
	if err := WriteReceiptExclusive(output, second); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("private receipt metadata is invalid: %v %#v", err, info)
	}
	if err := WriteReceiptExclusive(output, second); err == nil {
		t.Fatal("receipt output was overwritten")
	}
	ambiguousPath := filepath.Join(t.TempDir(), "receipt.json")
	ambiguousOutput, err := OpenReceiptOutput(ambiguousPath)
	if err != nil {
		t.Fatal(err)
	}
	ambiguousOutput.syncDirectory = func(int) error { return errors.New("synthetic directory sync failure") }
	err = ambiguousOutput.CommitAndClose(second)
	var ambiguity *ReceiptCommitAmbiguityError
	if !errors.As(err, &ambiguity) {
		t.Fatalf("committed receipt sync failure was not typed: %v", err)
	}
	committedBytes, readErr := os.ReadFile(ambiguousPath)
	if readErr != nil {
		t.Fatalf("ambiguous committed receipt is missing: %v", readErr)
	}
	if _, parseErr := ParseReceipt(committedBytes); parseErr != nil {
		t.Fatalf("ambiguous committed receipt bytes are invalid: %v", parseErr)
	}
}

func TestPublisherRefusesPreexistingDifferentImageTagWithoutMutation(t *testing.T) {
	for conflictIndex := range expectedPackIDs {
		t.Run(expectedPackIDs[conflictIndex], func(t *testing.T) {
			registry := newFakeRegistry(t)
			server := httptest.NewServer(registry)
			t.Cleanup(server.Close)
			request, requestDigest := testRequest(t, server.URL, archiveVariation{})
			foreignDigest := shaString([]byte("foreign"))
			conflicting := request.Archives[conflictIndex]
			registry.tags[registryKey(conflicting.Repository, request.ImageTag)] = foreignDigest
			registry.manifests[registryKey(conflicting.Repository, foreignDigest)] = []byte("foreign")
			before := registry.mutations
			publisher := testPublisher(t, server.Client())
			if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
				!strings.Contains(err.Error(), "already names") {
				t.Fatalf("different preexisting image tag was not rejected: %v", err)
			}
			if registry.mutations != before {
				t.Fatal("tag conflict caused a registry mutation")
			}
		})
	}
}

func TestPublisherRejectsRegistryRedirectAndCrossOriginUploadLocation(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		registry := newFakeRegistry(t)
		registry.redirectPing = true
		server := httptest.NewServer(registry)
		t.Cleanup(server.Close)
		request, requestDigest := testRequest(t, server.URL, archiveVariation{})
		publisher := testPublisher(t, server.Client())
		if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
			!strings.Contains(err.Error(), "redirect rejected") {
			t.Fatalf("registry redirect was not rejected: %v", err)
		}
	})

	t.Run("cross-origin-location", func(t *testing.T) {
		registry := newFakeRegistry(t)
		registry.crossOriginUpload = true
		server := httptest.NewServer(registry)
		t.Cleanup(server.Close)
		request, requestDigest := testRequest(t, server.URL, archiveVariation{})
		publisher := testPublisher(t, server.Client())
		if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
			!strings.Contains(err.Error(), "cross-origin Location") {
			t.Fatalf("cross-origin upload location was not rejected: %v", err)
		}
	})

	t.Run("oversized-v2-body", func(t *testing.T) {
		registry := newFakeRegistry(t)
		registry.pingBody = bytes.Repeat([]byte("x"), 4*1024+1)
		server := httptest.NewServer(registry)
		t.Cleanup(server.Close)
		request, requestDigest := testRequest(t, server.URL, archiveVariation{})
		publisher := testPublisher(t, server.Client())
		if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
			!strings.Contains(err.Error(), "exceeds its bound") {
			t.Fatalf("oversized registry probe body was not rejected: %v", err)
		}
		if registry.mutations != 0 {
			t.Fatal("oversized registry probe body reached mutation")
		}
	})
}

func TestPublisherRejectsRegistryReadbackSubstitution(t *testing.T) {
	registry := newFakeRegistry(t)
	registry.corruptBlobReadback = true
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	publisher := testPublisher(t, server.Client())
	if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
		!strings.Contains(err.Error(), "readback") {
		t.Fatalf("substituted registry blob readback was not rejected: %v", err)
	}
}

func TestPublisherBoundsStalledUploadAndCancelsOpenUpload(t *testing.T) {
	registry := newFakeRegistry(t)
	registry.stallPatch = true
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	publisher := testPublisher(t, server.Client())
	publisher.transferPolicy = fastTransferPolicy()
	started := time.Now()
	if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil {
		t.Fatal("stalled upload was admitted")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("stalled upload exceeded its bounded cancellation window")
	}
	open, cancelled := registry.uploadState()
	if open != 0 || cancelled != 1 {
		t.Fatalf("stalled upload was not cleaned up: open=%d cancelled=%d", open, cancelled)
	}
}

func TestPublisherBoundsStalledReadback(t *testing.T) {
	registry := newFakeRegistry(t)
	registry.stallBlobReadback = true
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	publisher := testPublisher(t, server.Client())
	publisher.transferPolicy = fastTransferPolicy()
	started := time.Now()
	if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil {
		t.Fatal("stalled registry readback was admitted")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("stalled readback exceeded its bounded cancellation window")
	}
}

func TestPublisherSurfacesBoundedUploadCleanupFailure(t *testing.T) {
	registry := newFakeRegistry(t)
	registry.failPatch = true
	registry.stallCleanup = true
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	publisher := testPublisher(t, server.Client())
	publisher.transferPolicy = fastTransferPolicy()
	started := time.Now()
	_, err := publisher.Publish(context.Background(), request, requestDigest)
	if err == nil || !strings.Contains(err.Error(), "cancel registry blob upload") {
		t.Fatalf("stalled cleanup was not surfaced: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("stalled cleanup exceeded its bounded cancellation window")
	}
}

func TestPublisherRejectsInvalidOCIArchivesBeforeRegistryMutation(t *testing.T) {
	cases := []struct {
		name      string
		variation archiveVariation
		contains  string
	}{
		{name: "blob-digest", variation: archiveVariation{corruptLayer: true}, contains: "content digest"},
		{name: "descriptor-size", variation: archiveVariation{wrongLayerSize: true}, contains: "different size"},
		{name: "traversal", variation: archiveVariation{traversal: true}, contains: "traversing path"},
		{name: "link", variation: archiveVariation{link: true}, contains: "regular files"},
		{name: "unreferenced-blob", variation: archiveVariation{unreferencedBlob: true}, contains: "unreferenced blob"},
		{name: "source-label", variation: archiveVariation{wrongSourceLabel: true}, contains: "differs from source authority"},
		{name: "architecture", variation: archiveVariation{wrongArchitecture: true}, contains: "architecture is invalid"},
		{name: "operating-system", variation: archiveVariation{wrongOperatingSystem: true}, contains: "operating system is invalid"},
		{name: "rootfs-cardinality", variation: archiveVariation{wrongDiffIDCount: true}, contains: "rootfs topology is invalid"},
		{name: "rootfs-digest", variation: archiveVariation{wrongDiffIDDigest: true}, contains: "rootfs diff ID is invalid"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			registry := newFakeRegistry(t)
			server := httptest.NewServer(registry)
			t.Cleanup(server.Close)
			request, requestDigest := testRequest(t, server.URL, testCase.variation)
			publisher := testPublisher(t, server.Client())
			if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
				!strings.Contains(err.Error(), testCase.contains) {
				t.Fatalf("invalid archive was not rejected with %q: %v", testCase.contains, err)
			}
			if registry.mutations != 0 {
				t.Fatal("archive validation failure reached registry mutation")
			}
		})
	}
}

func TestPublisherRejectsArchivePathSubstitution(t *testing.T) {
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	replacement := request.Archives[1].ArchivePath
	if err := os.Rename(replacement, request.Archives[0].ArchivePath); err != nil {
		t.Fatal(err)
	}
	publisher := testPublisher(t, server.Client())
	if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
		!strings.Contains(err.Error(), "SHA-256 differs") {
		t.Fatalf("archive pathname substitution was not rejected: %v", err)
	}
	if registry.mutations != 0 {
		t.Fatal("archive substitution reached registry mutation")
	}
}

func TestPublisherRejectsArchiveSymlink(t *testing.T) {
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	path := request.Archives[0].ArchivePath
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(request.Archives[1].ArchivePath, path); err != nil {
		t.Fatal(err)
	}
	publisher := testPublisher(t, server.Client())
	if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil {
		t.Fatal("symlinked archive was admitted")
	}
	if registry.mutations != 0 {
		t.Fatal("symlinked archive reached registry mutation")
	}
}

func TestPublisherRejectsArchivePathSubstitutionAfterAdmissionBeforeMutation(t *testing.T) {
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	path := request.Archives[0].ArchivePath
	registry.onPing = func() {
		if err := os.Rename(path, path+".held"); err != nil {
			t.Errorf("rename admitted archive: %v", err)
			return
		}
		if err := os.WriteFile(path, []byte("substituted"), 0o600); err != nil {
			t.Errorf("install archive substitute: %v", err)
		}
	}
	publisher := testPublisher(t, server.Client())
	if _, err := publisher.Publish(context.Background(), request, requestDigest); err == nil ||
		!strings.Contains(err.Error(), "no longer names the admitted inode") {
		t.Fatalf("post-admission archive substitution was not rejected: %v", err)
	}
	if registry.mutations != 0 {
		t.Fatal("post-admission archive substitution reached registry mutation")
	}
}

func TestPublisherHonorsCancellationBeforeArchiveRead(t *testing.T) {
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	publisher := testPublisher(t, server.Client())
	if _, err := publisher.Publish(ctx, request, requestDigest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled archive inspection did not preserve context cause: %v", err)
	}
	if registry.mutations != 0 {
		t.Fatal("cancelled archive inspection reached registry mutation")
	}
}

func TestRequestRejectsNoncanonicalEndpointAndRoster(t *testing.T) {
	request := Request{
		Contract: RequestContract,
		Registry: RegistryAuthority{PublicationOrigin: "http://localhost:5000", RuntimeAuthority: "registry:6000"},
		Source:   SourceAuthority{Revision: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40), SourceSetDigest: shaString([]byte("source"))},
		ImageTag: strings.Repeat("1", 9),
	}
	if err := ValidateRequest(request); err == nil {
		t.Fatal("DNS publication origin was admitted")
	}
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	valid, _ := testRequest(t, server.URL, archiveVariation{})
	valid.ImageTag = strings.Repeat("2", 9)
	if err := ValidateRequest(valid); err == nil {
		t.Fatal("image tag detached from the source revision was admitted")
	}
	valid, _ = testRequest(t, server.URL, archiveVariation{})
	valid.Registry.RuntimeAuthority = "127.0.0.1:6000"
	if err := ValidateRequest(valid); err == nil {
		t.Fatal("loopback runtime registry authority was admitted")
	}
}

func TestReadRequestRequiresCanonicalPinnedRegularFile(t *testing.T) {
	registry := newFakeRegistry(t)
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	request, requestDigest := testRequest(t, server.URL, archiveVariation{})
	encoded := mustCanonical(t, request)
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "request.json")
	if err := os.WriteFile(requestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, observed, err := ReadRequest(context.Background(), requestPath, requestDigest)
	if err != nil || parsed.ImageTag != request.ImageTag || !bytes.Equal(observed, encoded) {
		t.Fatalf("valid pinned request did not round-trip: %v", err)
	}
	if _, _, err := ReadRequest(context.Background(), requestPath, shaString([]byte("wrong"))); err == nil {
		t.Fatal("wrong request pin was admitted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ReadRequest(cancelled, requestPath, requestDigest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request read did not preserve context cause: %v", err)
	}
	symlinkPath := filepath.Join(directory, "request-link.json")
	if err := os.Symlink(requestPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRequest(context.Background(), symlinkPath, requestDigest); err == nil {
		t.Fatal("symlinked request was admitted")
	}
	noncanonicalPath := filepath.Join(directory, "request-noncanonical.json")
	if err := os.WriteFile(noncanonicalPath, append(append([]byte(nil), encoded...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRequest(context.Background(), noncanonicalPath, digestBytes(append(append([]byte(nil), encoded...), '\n'))); err == nil {
		t.Fatal("noncanonical request bytes were admitted")
	}
}

func TestLocalArchiveFilesystemAdmission(t *testing.T) {
	if !localArchiveFilesystem(0xef53) || !localArchiveFilesystem(0x01021994) {
		t.Fatal("required local ext/tmpfs filesystems were rejected")
	}
	if localArchiveFilesystem(0x65735546) {
		t.Fatal("FUSE filesystem was admitted for bounded archive custody")
	}
}

func TestReceiptOutputRejectsParentDirectoryRebinding(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	output, err := OpenReceiptOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	moved := directory + "-moved"
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := output.Commit(Receipt{}); err == nil || !strings.Contains(err.Error(), "held descriptor") {
		t.Fatalf("rebound output directory was admitted: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(moved, "receipt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt was written through rebound parent: %v", err)
	}
}

type archiveVariation struct {
	corruptLayer         bool
	wrongLayerSize       bool
	traversal            bool
	link                 bool
	unreferencedBlob     bool
	wrongSourceLabel     bool
	wrongDiffIDCount     bool
	wrongDiffIDDigest    bool
	wrongArchitecture    bool
	wrongOperatingSystem bool
}

func testRequest(t *testing.T, origin string, firstVariation archiveVariation) (Request, string) {
	t.Helper()
	directory := t.TempDir()
	archives := make([]ArchiveRequest, 0, 4)
	for index, packID := range expectedPackIDs {
		variation := archiveVariation{}
		if index == 0 {
			variation = firstVariation
		}
		archives = append(archives, writeTestOCIArchive(t, directory, packID, variation))
	}
	request := Request{
		Contract: RequestContract,
		Registry: RegistryAuthority{PublicationOrigin: origin, RuntimeAuthority: "registry:6000"},
		Source: SourceAuthority{
			Revision: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40),
			SourceSetDigest: shaString([]byte("source-set")),
		},
		UpstreamCertification: UpstreamCertification{
			Ref:    "ambit://supply-chain/c18-specialist-release/" + strings.Repeat("3", 64),
			Digest: shaString([]byte("upstream certification")),
		},
		ImageTag: strings.Repeat("1", 9),
		Archives: archives,
	}
	encoded, err := CanonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(encoded); err != nil {
		t.Fatalf("test request is invalid: %v", err)
	}
	return request, digestBytes(encoded)
}

func writeTestOCIArchive(t *testing.T, directory, packID string, variation archiveVariation) ArchiveRequest {
	t.Helper()
	sourceRevision := strings.Repeat("1", 40)
	if variation.wrongSourceLabel {
		sourceRevision = strings.Repeat("9", 40)
	}
	architecture := "amd64"
	if variation.wrongArchitecture {
		architecture = "arm64"
	}
	operatingSystem := "linux"
	if variation.wrongOperatingSystem {
		operatingSystem = "windows"
	}
	diffIDs := []string{shaString([]byte("diff-id-" + packID))}
	if variation.wrongDiffIDCount {
		diffIDs = []string{}
	}
	if variation.wrongDiffIDDigest {
		diffIDs = []string{"not-a-digest"}
	}
	configBytes := mustCanonical(t, map[string]any{
		"architecture": architecture,
		"config": map[string]any{"Labels": map[string]string{
			"org.opencontainers.image.revision": sourceRevision,
			"io.ambit.source-tree":              strings.Repeat("2", 40),
			"io.ambit.source-set-sha256":        strings.TrimPrefix(shaString([]byte("source-set")), "sha256:"),
			"io.ambit.runtime-pack":             "ambit.runtime-pack/" + packID + "@1",
			"org.opencontainers.image.title":    "ambit-c18-" + packID,
		}},
		"os": operatingSystem, "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	configDigest := digestBytes(configBytes)
	layerBytes := []byte("layer-for-" + packID)
	layerDigest := digestBytes(layerBytes)
	layerPathDigest := layerDigest
	if variation.corruptLayer {
		layerBytes = append([]byte(nil), layerBytes...)
		layerBytes[0] ^= 0xff
	}
	layerSize := int64(len(layerBytes))
	if variation.wrongLayerSize {
		layerSize++
	}
	manifest := ociManifest{
		SchemaVersion: 2, MediaType: ociManifestMediaType,
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: int64(len(configBytes))},
		Layers: []ociDescriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: layerPathDigest, Size: layerSize}},
	}
	manifestBytes := mustCanonical(t, manifest)
	manifestDigest := digestBytes(manifestBytes)
	indexBytes := mustCanonical(t, ociIndex{
		SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{{
			MediaType: ociManifestMediaType, Digest: manifestDigest, Size: int64(len(manifestBytes)),
			Platform: &ociPlatform{Architecture: "amd64", OS: "linux"},
			Annotations: map[string]string{
				"io.containerd.image.name":          "docker.io/library/ambit-c18-" + packID + ":" + strings.Repeat("1", 9),
				"org.opencontainers.image.ref.name": strings.Repeat("1", 9),
			},
		}},
	})
	layoutBytes := mustCanonical(t, ociLayout{ImageLayoutVersion: "1.0.0"})

	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	writeTarDirectory(t, writer, "blobs/")
	writeTarDirectory(t, writer, "blobs/sha256/")
	writeTarFile(t, writer, "oci-layout", layoutBytes)
	writeTarFile(t, writer, "index.json", indexBytes)
	writeTarFile(t, writer, blobPath(manifestDigest), manifestBytes)
	writeTarFile(t, writer, blobPath(configDigest), configBytes)
	writeTarFile(t, writer, blobPath(layerPathDigest), layerBytes)
	if variation.unreferencedBlob {
		extra := []byte("unreferenced")
		writeTarFile(t, writer, blobPath(digestBytes(extra)), extra)
	}
	if variation.traversal {
		writeTarFile(t, writer, "../escape", []byte("escape"))
	}
	if variation.link {
		if err := writer.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "index.json", Mode: 0o777}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(directory, packID+".oci.tar")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return ArchiveRequest{
		PackID: packID, PackRevisionRef: "ambit.runtime-pack/" + packID + "@1",
		ArchivePath: archivePath, ArchiveSHA256: digestBytes(archive.Bytes()),
		Repository: "ambit-c18-" + packID, ManifestDigest: manifestDigest, ConfigDigest: configDigest,
	}
}

func writeTarDirectory(t *testing.T, writer *tar.Writer, name string) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
}

func writeTarFile(t *testing.T, writer *tar.Writer, name string, body []byte) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
}

func blobPath(digest string) string { return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:") }

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testPublisher(t *testing.T, client *http.Client) *Publisher {
	t.Helper()
	index := 0
	instants := []time.Time{
		time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC),
	}
	publisher, err := NewPublisher(client, func() time.Time {
		instant := instants[index]
		if index < len(instants)-1 {
			index++
		}
		return instant
	}, shaString([]byte("publisher executable")))
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func fastTransferPolicy() transferPolicy {
	return transferPolicy{
		minimumBytesPerSecond: 1,
		baseTimeout:           100 * time.Millisecond,
		idleTimeout:           20 * time.Millisecond,
		maximumTimeout:        250 * time.Millisecond,
		cleanupTimeout:        30 * time.Millisecond,
	}
}

func runTestPublication(t *testing.T, request Request, requestDigest string, client *http.Client) Receipt {
	t.Helper()
	publisher := testPublisher(t, client)
	receipt, err := publisher.Publish(context.Background(), request, requestDigest)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func shaString(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type fakeRegistry struct {
	t                   *testing.T
	mu                  sync.Mutex
	blobs               map[string][]byte
	manifests           map[string][]byte
	tags                map[string]string
	uploads             map[string]*fakeUpload
	nextUpload          int
	mutations           int
	tagWrites           int
	redirectPing        bool
	crossOriginUpload   bool
	corruptBlobReadback bool
	onPing              func()
	pingBody            []byte
	failPatch           bool
	stallPatch          bool
	stallBlobReadback   bool
	stallCleanup        bool
	cancelCount         int
}

type fakeUpload struct {
	repository string
	body       bytes.Buffer
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	return &fakeRegistry{
		t: t, blobs: make(map[string][]byte), manifests: make(map[string][]byte),
		tags: make(map[string]string), uploads: make(map[string]*fakeUpload), pingBody: []byte("{}"),
	}
}

func (value *fakeRegistry) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if request.URL.Path == "/v2/" {
		if value.redirectPing {
			writer.Header().Set("Location", "http://example.invalid/v2/")
			writer.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if value.onPing != nil {
			callback := value.onPing
			value.onPing = nil
			callback()
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(value.pingBody)
		return
	}
	trimmed := strings.TrimPrefix(request.URL.Path, "/v2/")
	if repository, tail, found := strings.Cut(trimmed, "/blobs/uploads/"); found {
		value.handleUpload(writer, request, repository, tail)
		return
	}
	if repository, digest, found := strings.Cut(trimmed, "/blobs/"); found {
		value.handleBlob(writer, request, repository, digest)
		return
	}
	if repository, reference, found := strings.Cut(trimmed, "/manifests/"); found {
		value.handleManifest(writer, request, repository, reference)
		return
	}
	http.NotFound(writer, request)
}

func (value *fakeRegistry) handleUpload(writer http.ResponseWriter, request *http.Request, repository, uploadID string) {
	switch request.Method {
	case http.MethodPost:
		if uploadID != "" {
			http.Error(writer, "invalid upload start", http.StatusBadRequest)
			return
		}
		value.nextUpload++
		id := fmt.Sprintf("upload=%d", value.nextUpload)
		value.uploads[id] = &fakeUpload{repository: repository}
		value.mutations++
		if value.crossOriginUpload {
			writer.Header().Set("Location", "http://example.invalid/v2/foreign/blobs/uploads/evil")
		} else {
			writer.Header().Set("Location", "/v2/"+repository+"/blobs/uploads/"+id+"?_state=start%3D"+fmt.Sprint(value.nextUpload))
		}
		writer.WriteHeader(http.StatusAccepted)
	case http.MethodPatch:
		upload, exists := value.uploads[uploadID]
		if !exists || upload.repository != repository {
			http.NotFound(writer, request)
			return
		}
		if request.URL.Query().Get("_state") == "" {
			http.Error(writer, "upload state missing", http.StatusBadRequest)
			return
		}
		if value.failPatch {
			http.Error(writer, "synthetic patch failure", http.StatusInternalServerError)
			return
		}
		if value.stallPatch {
			value.waitForRequestCancellation(request)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = upload.body.Write(body)
		value.mutations++
		writer.Header().Set("Location", "/v2/"+repository+"/blobs/uploads/"+uploadID+"?_state=next%3D"+fmt.Sprint(value.nextUpload))
		writer.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		upload, exists := value.uploads[uploadID]
		digest := request.URL.Query().Get("digest")
		if !exists || upload.repository != repository || request.URL.Query().Get("_state") == "" ||
			digestBytes(upload.body.Bytes()) != digest {
			http.Error(writer, "invalid upload completion", http.StatusBadRequest)
			return
		}
		value.blobs[registryKey(repository, digest)] = append([]byte(nil), upload.body.Bytes()...)
		delete(value.uploads, uploadID)
		value.mutations++
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.Header().Set("Location", "/v2/"+repository+"/blobs/"+digest)
		writer.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if value.stallCleanup {
			value.waitForRequestCancellation(request)
			return
		}
		if _, exists := value.uploads[uploadID]; !exists {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		delete(value.uploads, uploadID)
		value.cancelCount++
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (value *fakeRegistry) handleBlob(writer http.ResponseWriter, request *http.Request, repository, digest string) {
	body, exists := value.blobs[registryKey(repository, digest)]
	if !exists {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Docker-Content-Digest", digest)
	writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
	switch request.Method {
	case http.MethodHead:
		writer.WriteHeader(http.StatusOK)
	case http.MethodGet:
		writer.WriteHeader(http.StatusOK)
		if value.stallBlobReadback {
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			value.waitForRequestCancellation(request)
			return
		}
		if value.corruptBlobReadback {
			value.corruptBlobReadback = false
			corrupt := append([]byte(nil), body...)
			corrupt[0] ^= 0xff
			_, _ = writer.Write(corrupt)
			return
		}
		_, _ = writer.Write(body)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (value *fakeRegistry) handleManifest(writer http.ResponseWriter, request *http.Request, repository, reference string) {
	digest := reference
	if !exactSHA256(reference) {
		digest = value.tags[registryKey(repository, reference)]
	}
	body, exists := value.manifests[registryKey(repository, digest)]
	switch request.Method {
	case http.MethodHead:
		if !exists {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.WriteHeader(http.StatusOK)
	case http.MethodGet:
		if !exists {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.Header().Set("Content-Type", ociManifestMediaType)
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	case http.MethodPut:
		encoded, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		observedDigest := digestBytes(encoded)
		if exactSHA256(reference) && reference != observedDigest {
			http.Error(writer, "manifest digest mismatch", http.StatusBadRequest)
			return
		}
		if !exactSHA256(reference) {
			value.tagWrites++
			http.Error(writer, "mutable tag PUT is forbidden", http.StatusConflict)
			return
		}
		value.manifests[registryKey(repository, observedDigest)] = append([]byte(nil), encoded...)
		value.mutations++
		writer.Header().Set("Docker-Content-Digest", observedDigest)
		writer.Header().Set("Location", "/v2/"+repository+"/manifests/"+observedDigest)
		writer.WriteHeader(http.StatusCreated)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (value *fakeRegistry) uploadState() (open, cancelled int) {
	value.mu.Lock()
	defer value.mu.Unlock()
	return len(value.uploads), value.cancelCount
}

func (value *fakeRegistry) waitForRequestCancellation(request *http.Request) {
	value.mu.Unlock()
	select {
	case <-request.Context().Done():
	case <-time.After(250 * time.Millisecond):
	}
	value.mu.Lock()
}

func registryKey(repository, identity string) string { return repository + "\x00" + identity }
