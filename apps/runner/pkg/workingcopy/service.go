// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daytonaio/runner/pkg/storage"
	containertypes "github.com/docker/docker/api/types/container"
)

const (
	captureRoleRef         = "ambit.runtime-component/working-copy-capture@1"
	captureProtocolRef     = "ambit.runtime-interface/working-copy-capture@1"
	privateRoot            = "private/working-copy-captures/v1"
	maximumIntentBytes     = 32 * 1024
	maximumReceiptBytes    = 32 * 1024
	maximumArchiveOverhead = 1024 * 1024
)

var (
	ErrInvalidRequest = errors.New("invalid working-copy capture request")
	ErrConflict       = errors.New("working-copy capture conflict")
	ErrUnavailable    = errors.New("working-copy capture unavailable")
)

type ContainerClient interface {
	ContainerInspect(ctx context.Context, containerID string) (containertypes.InspectResponse, error)
	ContainerStatPath(ctx context.Context, containerID, path string) (containertypes.PathStat, error)
	CopyFromContainer(ctx context.Context, containerID, path string) (io.ReadCloser, containertypes.PathStat, error)
}

type clock func() time.Time

type Service struct {
	containers ContainerClient
	objects    storage.PrivateObjectStorageClient
	now        clock
	locks      keyedLocks
}

type keyedLocks struct {
	mu    sync.Mutex
	items map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

type containerGeneration struct {
	ID      string `json:"id"`
	Created string `json:"created"`
}

type captureIntent struct {
	Version            int                 `json:"version"`
	Binding            CaptureBinding      `json:"binding"`
	ProviderResourceID string              `json:"providerResourceId"`
	Generation         containerGeneration `json:"generation"`
}

type objectKeys struct {
	intent  string
	content string
	receipt string
}

type capturedFile struct {
	bytes      []byte
	digest     string
	capturedAt string
}

func NewService(
	containers ContainerClient,
	objects storage.PrivateObjectStorageClient,
) (*Service, error) {
	if containers == nil {
		return nil, fmt.Errorf("%w: Docker archive client is not configured", ErrUnavailable)
	}
	if objects == nil {
		return nil, fmt.Errorf("%w: private object storage is not configured", ErrUnavailable)
	}
	return &Service{
		containers: containers,
		objects:    objects,
		now:        time.Now,
		locks:      keyedLocks{items: make(map[string]*keyedLock)},
	}, nil
}

func (s *Service) Capture(
	ctx context.Context,
	sandboxID string,
	binding CaptureBinding,
) (CaptureReceipt, error) {
	zonePath, err := validateBinding(sandboxID, binding)
	if err != nil {
		return CaptureReceipt{}, err
	}

	bindingRoot := bindingObjectRoot(binding)
	release := s.locks.acquire(bindingRoot)
	defer release()

	existing, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil {
		return CaptureReceipt{}, err
	}
	if exists {
		if err := requireBinding(existing.Binding, binding); err != nil {
			return CaptureReceipt{}, err
		}
		return s.resumeCapture(ctx, sandboxID, zonePath, existing)
	}

	generation, err := s.inspectStoppedGeneration(ctx, sandboxID)
	if err != nil {
		return CaptureReceipt{}, err
	}
	intent := captureIntent{
		Version:            1,
		Binding:            binding,
		ProviderResourceID: providerResourceID(binding, generation),
		Generation:         generation,
	}
	intentBytes, err := json.Marshal(intent)
	if err != nil {
		return CaptureReceipt{}, fmt.Errorf("marshal capture intent: %w", err)
	}
	if err := s.objects.CreatePrivateObject(
		ctx,
		intentKey(bindingRoot),
		intentBytes,
		"application/json",
		map[string]string{"contract": "ambit-working-copy-capture-intent-v1"},
	); err != nil {
		if !errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
			return CaptureReceipt{}, fmt.Errorf("persist capture intent: %w", err)
		}
		winner, winnerExists, readErr := s.readIntent(ctx, bindingRoot)
		if readErr != nil {
			return CaptureReceipt{}, readErr
		}
		if !winnerExists {
			return CaptureReceipt{}, fmt.Errorf("%w: capture intent disappeared during admission", ErrConflict)
		}
		if err := requireBinding(winner.Binding, binding); err != nil {
			return CaptureReceipt{}, err
		}
		return s.resumeCapture(ctx, sandboxID, zonePath, winner)
	}

	return s.resumeCapture(ctx, sandboxID, zonePath, intent)
}

func (s *Service) Observe(
	ctx context.Context,
	sandboxID string,
	binding CaptureBinding,
) (CaptureObservation, error) {
	if _, err := validateBinding(sandboxID, binding); err != nil {
		return CaptureObservation{}, err
	}
	bindingRoot := bindingObjectRoot(binding)
	release := s.locks.acquire(bindingRoot)
	defer release()

	intent, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil {
		return CaptureObservation{}, err
	}
	if !exists {
		copy := binding
		return CaptureObservation{Status: "absent", Binding: &copy}, nil
	}
	if err := requireBinding(intent.Binding, binding); err != nil {
		return CaptureObservation{}, err
	}
	identity := identityFromIntent(intent)
	receipt, complete, err := s.readReceipt(ctx, intent)
	if err != nil {
		return CaptureObservation{}, err
	}
	if !complete {
		return CaptureObservation{Status: "partial", Identity: &identity}, nil
	}
	if err := s.verifyContentMetadata(ctx, intent, receipt); err != nil {
		return CaptureObservation{}, err
	}
	return CaptureObservation{Status: "complete", Receipt: &receipt}, nil
}

func (s *Service) Read(
	ctx context.Context,
	sandboxID string,
	request CaptureReadRequest,
) ([]byte, error) {
	if _, err := validateBinding(sandboxID, request.CaptureBinding); err != nil {
		return nil, err
	}
	if err := validateProviderResourceID(request.ProviderResourceID); err != nil {
		return nil, err
	}
	if request.ExpectedByteLength < 0 ||
		request.MaximumBytes < 0 ||
		request.MaximumBytes > MaximumCaptureBytes ||
		request.ExpectedByteLength > request.MaximumBytes {
		return nil, invalidf("capture read bounds are invalid")
	}

	bindingRoot := bindingObjectRoot(request.CaptureBinding)
	release := s.locks.acquire(bindingRoot)
	defer release()
	intent, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("%w: capture identity is absent", ErrConflict)
	}
	if err := requireIdentity(intent, request.CaptureIdentity); err != nil {
		return nil, err
	}
	receipt, complete, err := s.readReceipt(ctx, intent)
	if err != nil {
		return nil, err
	}
	if !complete {
		return nil, fmt.Errorf("%w: capture is partial", ErrConflict)
	}
	if request.ExpectedByteLength != receipt.ByteLength {
		return nil, fmt.Errorf("%w: capture length authority changed", ErrConflict)
	}
	data, err := s.objects.GetPrivateObject(
		ctx,
		keysForIntent(intent).content,
		request.MaximumBytes,
	)
	if err != nil {
		return nil, objectReadError("read capture content", err)
	}
	if int64(len(data)) != receipt.ByteLength || sha256Digest(data) != receipt.ProviderSHA256Digest {
		return nil, fmt.Errorf("%w: captured content drifted", ErrConflict)
	}
	return data, nil
}

func (s *Service) Delete(
	ctx context.Context,
	sandboxID string,
	identity CaptureIdentity,
) error {
	if _, err := validateBinding(sandboxID, identity.CaptureBinding); err != nil {
		return err
	}
	if err := validateProviderResourceID(identity.ProviderResourceID); err != nil {
		return err
	}
	bindingRoot := bindingObjectRoot(identity.CaptureBinding)
	release := s.locks.acquire(bindingRoot)
	defer release()

	intent, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := requireIdentity(intent, identity); err != nil {
		return err
	}
	keys := keysForIntent(intent)
	// The intent is deleted last. Any interrupted deletion remains observable as
	// partial and can be resumed or deleted again using the same identity.
	for _, key := range []string{keys.receipt, keys.content, keys.intent} {
		if err := s.objects.DeletePrivateObject(ctx, key); err != nil {
			return fmt.Errorf("delete capture object: %w", err)
		}
	}
	return nil
}

func (s *Service) Exists(
	ctx context.Context,
	sandboxID string,
	identity CaptureIdentity,
) (bool, error) {
	if _, err := validateBinding(sandboxID, identity.CaptureBinding); err != nil {
		return false, err
	}
	if err := validateProviderResourceID(identity.ProviderResourceID); err != nil {
		return false, err
	}
	bindingRoot := bindingObjectRoot(identity.CaptureBinding)
	release := s.locks.acquire(bindingRoot)
	defer release()
	intent, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil || !exists {
		return false, err
	}
	if err := requireIdentity(intent, identity); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) resumeCapture(
	ctx context.Context,
	sandboxID string,
	zonePath string,
	intent captureIntent,
) (CaptureReceipt, error) {
	if receipt, complete, err := s.readReceipt(ctx, intent); err != nil {
		return CaptureReceipt{}, err
	} else if complete {
		if err := s.verifyContentMetadata(ctx, intent, receipt); err != nil {
			return CaptureReceipt{}, err
		}
		return receipt, nil
	}

	keys := keysForIntent(intent)
	staged, stagedExists, err := s.readStagedContent(ctx, intent)
	if err != nil {
		return CaptureReceipt{}, err
	}
	if !stagedExists {
		generation, err := s.inspectStoppedGeneration(ctx, sandboxID)
		if err != nil {
			return CaptureReceipt{}, err
		}
		if generation != intent.Generation {
			return CaptureReceipt{}, fmt.Errorf("%w: sandbox container generation changed", ErrConflict)
		}

		staged, err = s.captureStableFile(ctx, sandboxID, zonePath, generation)
		if err != nil {
			return CaptureReceipt{}, err
		}
		metadata := map[string]string{
			"captured-at":          staged.capturedAt,
			"sha256":               staged.digest,
			"byte-length":          strconv.FormatInt(int64(len(staged.bytes)), 10),
			"provider-resource-id": intent.ProviderResourceID,
			"contract":             "ambit-working-copy-capture-content-v1",
		}
		if err := s.objects.CreatePrivateObject(
			ctx,
			keys.content,
			staged.bytes,
			"application/octet-stream",
			metadata,
		); err != nil {
			if !errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
				return CaptureReceipt{}, fmt.Errorf("persist capture content: %w", err)
			}
			winner, winnerExists, readErr := s.readStagedContent(ctx, intent)
			if readErr != nil {
				return CaptureReceipt{}, readErr
			}
			if !winnerExists {
				return CaptureReceipt{}, fmt.Errorf("%w: capture content disappeared during admission", ErrConflict)
			}
			staged = winner
		}
	}

	receipt := receiptFromIntent(intent, staged)
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return CaptureReceipt{}, fmt.Errorf("marshal capture receipt: %w", err)
	}
	if err := s.objects.CreatePrivateObject(
		ctx,
		keys.receipt,
		receiptBytes,
		"application/json",
		map[string]string{"contract": "ambit-working-copy-capture-receipt-v1"},
	); err != nil {
		if !errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
			return CaptureReceipt{}, fmt.Errorf("publish capture receipt: %w", err)
		}
		winner, complete, readErr := s.readReceipt(ctx, intent)
		if readErr != nil {
			return CaptureReceipt{}, readErr
		}
		if !complete || winner != receipt {
			return CaptureReceipt{}, fmt.Errorf("%w: capture receipt publication conflicted", ErrConflict)
		}
		return winner, nil
	}
	return receipt, nil
}

func (s *Service) captureStableFile(
	ctx context.Context,
	sandboxID string,
	zonePath string,
	generation containerGeneration,
) (capturedFile, error) {
	before, err := s.statPathChain(ctx, sandboxID, zonePath)
	if err != nil {
		return capturedFile{}, err
	}
	fileBefore := before[len(before)-1]
	archive, copyStat, err := s.containers.CopyFromContainer(ctx, sandboxID, zonePath)
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: Docker archive read failed: %v", ErrConflict, err)
	}
	defer archive.Close()
	if !samePathStat(fileBefore, copyStat) {
		return capturedFile{}, fmt.Errorf("%w: source descriptor changed before archive read", ErrConflict)
	}

	archiveBytes, err := io.ReadAll(io.LimitReader(
		archive,
		MaximumCaptureBytes+maximumArchiveOverhead+1,
	))
	if err != nil {
		return capturedFile{}, fmt.Errorf("%w: Docker archive stream failed: %v", ErrConflict, err)
	}
	if int64(len(archiveBytes)) > MaximumCaptureBytes+maximumArchiveOverhead {
		return capturedFile{}, invalidf("Docker archive exceeds the bounded single-file envelope")
	}
	content, err := readExactRegularTar(archiveBytes, fileBefore, path.Base(zonePath))
	if err != nil {
		return capturedFile{}, err
	}

	after, err := s.statPathChain(ctx, sandboxID, zonePath)
	if err != nil {
		return capturedFile{}, err
	}
	if !samePathStatChain(before, after) {
		return capturedFile{}, fmt.Errorf("%w: source path changed during capture", ErrConflict)
	}
	afterGeneration, err := s.inspectStoppedGeneration(ctx, sandboxID)
	if err != nil {
		return capturedFile{}, err
	}
	if afterGeneration != generation {
		return capturedFile{}, fmt.Errorf("%w: sandbox container generation changed during capture", ErrConflict)
	}

	return capturedFile{
		bytes:      content,
		digest:     sha256Digest(content),
		capturedAt: s.now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) inspectStoppedGeneration(
	ctx context.Context,
	sandboxID string,
) (containerGeneration, error) {
	inspect, err := s.containers.ContainerInspect(ctx, sandboxID)
	if err != nil {
		return containerGeneration{}, fmt.Errorf("%w: inspect sandbox container: %v", ErrConflict, err)
	}
	if inspect.ID == "" || inspect.Created == "" || inspect.State == nil {
		return containerGeneration{}, fmt.Errorf("%w: sandbox container identity is incomplete", ErrConflict)
	}
	state := inspect.State
	if state.Status != containertypes.StateExited ||
		state.Running || state.Paused || state.Restarting || state.Dead || state.Pid != 0 {
		return containerGeneration{}, fmt.Errorf("%w: sandbox container is not exactly stopped", ErrConflict)
	}
	return containerGeneration{ID: inspect.ID, Created: inspect.Created}, nil
}

func (s *Service) statPathChain(
	ctx context.Context,
	sandboxID string,
	zonePath string,
) ([]containertypes.PathStat, error) {
	parts := strings.Split(strings.TrimPrefix(zonePath, "/"), "/")
	stats := make([]containertypes.PathStat, 0, len(parts))
	current := ""
	for index, part := range parts {
		current += "/" + part
		stat, err := s.containers.ContainerStatPath(ctx, sandboxID, current)
		if err != nil {
			return nil, fmt.Errorf("%w: stat admitted source path: %v", ErrConflict, err)
		}
		if stat.Name != part || stat.LinkTarget != "" || stat.Mode&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: source path contains a symlink or mismatched descriptor", ErrConflict)
		}
		if index < len(parts)-1 {
			if !stat.Mode.IsDir() {
				return nil, fmt.Errorf("%w: source parent is not a directory", ErrConflict)
			}
		} else if !stat.Mode.IsRegular() {
			return nil, fmt.Errorf("%w: source is not one regular file", ErrConflict)
		}
		stats = append(stats, stat)
	}
	if len(stats) == 0 || stats[len(stats)-1].Size < 0 || stats[len(stats)-1].Size > MaximumCaptureBytes {
		return nil, invalidf("source file exceeds the capture limit")
	}
	return stats, nil
}

func (s *Service) readIntent(
	ctx context.Context,
	bindingRoot string,
) (captureIntent, bool, error) {
	data, err := s.objects.GetPrivateObject(ctx, intentKey(bindingRoot), maximumIntentBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return captureIntent{}, false, nil
	}
	if err != nil {
		return captureIntent{}, false, objectReadError("read capture intent", err)
	}
	var intent captureIntent
	if err := strictJSON(data, &intent); err != nil || intent.Version != 1 {
		return captureIntent{}, false, fmt.Errorf("%w: capture intent is not canonical", ErrConflict)
	}
	if _, err := validateBinding(intent.Binding.Source.ProviderResourceID, intent.Binding); err != nil {
		return captureIntent{}, false, fmt.Errorf("%w: stored capture binding is invalid", ErrConflict)
	}
	if err := validateProviderResourceID(intent.ProviderResourceID); err != nil ||
		intent.ProviderResourceID != providerResourceID(intent.Binding, intent.Generation) ||
		intent.Generation.ID == "" || intent.Generation.Created == "" {
		return captureIntent{}, false, fmt.Errorf("%w: capture intent identity is invalid", ErrConflict)
	}
	return intent, true, nil
}

func (s *Service) readReceipt(
	ctx context.Context,
	intent captureIntent,
) (CaptureReceipt, bool, error) {
	data, err := s.objects.GetPrivateObject(ctx, keysForIntent(intent).receipt, maximumReceiptBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return CaptureReceipt{}, false, nil
	}
	if err != nil {
		return CaptureReceipt{}, false, objectReadError("read capture receipt", err)
	}
	var receipt CaptureReceipt
	if err := strictJSON(data, &receipt); err != nil {
		return CaptureReceipt{}, false, fmt.Errorf("%w: capture receipt is not canonical", ErrConflict)
	}
	if err := requireIdentity(intent, receipt.CaptureIdentity); err != nil ||
		receipt.ByteLength < 0 || receipt.ByteLength > MaximumCaptureBytes ||
		!isSHA256Digest(receipt.ProviderSHA256Digest) {
		return CaptureReceipt{}, false, fmt.Errorf("%w: capture receipt is invalid", ErrConflict)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, receipt.CapturedAt); err != nil ||
		parsed.Location() != time.UTC {
		return CaptureReceipt{}, false, fmt.Errorf("%w: capture receipt time is invalid", ErrConflict)
	}
	return receipt, true, nil
}

func (s *Service) readStagedContent(
	ctx context.Context,
	intent captureIntent,
) (capturedFile, bool, error) {
	key := keysForIntent(intent).content
	info, err := s.objects.StatPrivateObject(ctx, key)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return capturedFile{}, false, nil
	}
	if err != nil {
		return capturedFile{}, false, objectReadError("stat capture content", err)
	}
	if info.Size < 0 || info.Size > MaximumCaptureBytes {
		return capturedFile{}, false, fmt.Errorf("%w: staged capture length is invalid", ErrConflict)
	}
	metadata := lowerMetadata(info.UserMetadata)
	byteLength, lengthErr := strconv.ParseInt(metadata["byte-length"], 10, 64)
	capturedAt, timeErr := time.Parse(time.RFC3339Nano, metadata["captured-at"])
	if lengthErr != nil || byteLength != info.Size ||
		metadata["provider-resource-id"] != intent.ProviderResourceID ||
		metadata["contract"] != "ambit-working-copy-capture-content-v1" ||
		!isSHA256Digest(metadata["sha256"]) ||
		timeErr != nil || capturedAt.Location() != time.UTC {
		return capturedFile{}, false, fmt.Errorf("%w: staged capture metadata is invalid", ErrConflict)
	}
	data, err := s.objects.GetPrivateObject(ctx, key, MaximumCaptureBytes)
	if err != nil {
		return capturedFile{}, false, objectReadError("read staged capture content", err)
	}
	if int64(len(data)) != info.Size || sha256Digest(data) != metadata["sha256"] {
		return capturedFile{}, false, fmt.Errorf("%w: staged capture content drifted", ErrConflict)
	}
	return capturedFile{
		bytes:      data,
		digest:     metadata["sha256"],
		capturedAt: metadata["captured-at"],
	}, true, nil
}

func (s *Service) verifyContentMetadata(
	ctx context.Context,
	intent captureIntent,
	receipt CaptureReceipt,
) error {
	info, err := s.objects.StatPrivateObject(ctx, keysForIntent(intent).content)
	if err != nil {
		return objectReadError("stat completed capture content", err)
	}
	metadata := lowerMetadata(info.UserMetadata)
	if info.Size != receipt.ByteLength ||
		metadata["byte-length"] != strconv.FormatInt(receipt.ByteLength, 10) ||
		metadata["sha256"] != receipt.ProviderSHA256Digest ||
		metadata["captured-at"] != receipt.CapturedAt ||
		metadata["provider-resource-id"] != receipt.ProviderResourceID ||
		metadata["contract"] != "ambit-working-copy-capture-content-v1" {
		return fmt.Errorf("%w: completed capture metadata drifted", ErrConflict)
	}
	return nil
}

func validateBinding(sandboxID string, binding CaptureBinding) (string, error) {
	if !boundedRef(binding.ProviderName, 512) {
		return "", invalidf("providerName is invalid")
	}
	if len(binding.RequestFingerprint) != 64 || !isLowerHex(binding.RequestFingerprint) {
		return "", invalidf("requestFingerprint must be 64 lowercase hexadecimal characters")
	}
	if err := validateAuthority(binding.Authority); err != nil {
		return "", err
	}
	if !boundedRef(sandboxID, 512) || binding.Source.ProviderResourceID != sandboxID {
		return "", invalidf("source providerResourceId does not match the sandbox")
	}
	if !boundedRef(binding.Source.WorkspaceID, 512) ||
		!boundedRef(binding.Source.TenantID, 512) ||
		!boundedRef(binding.Source.UserID, 512) ||
		binding.Source.ExpectedProfile != "managed-container" ||
		binding.Source.ExpectedRuntimeKind != "container" {
		return "", invalidf("source address is not an admitted managed container")
	}
	root, ok := map[string]string{
		"ambit.workspace-zone/work@1":    "/workspace/work",
		"ambit.workspace-zone/outputs@1": "/workspace/outputs",
	}[binding.Selector.SemanticZoneRef]
	if !ok {
		return "", invalidf("semantic zone is not admitted for capture")
	}
	relative := binding.Selector.ZoneRelativePath
	if !canonicalRelativePath(relative) {
		return "", invalidf("zoneRelativePath is not a bounded canonical relative path")
	}
	return root + "/" + relative, nil
}

func validateAuthority(authority CaptureAuthority) error {
	if authority.RoleRef != captureRoleRef ||
		authority.Protocol.Ref != captureProtocolRef ||
		!isSHA256Digest(authority.Protocol.Digest) ||
		!isSHA256Digest(authority.Helper.Digest) ||
		authority.Helper.Ref != "runtime-component-artifact:"+authority.Helper.Digest {
		return invalidf("capture authority lineage is invalid")
	}
	expected := captureAuthorityRef(authority)
	if authority.AuthorityRef != expected {
		return invalidf("capture authority reference is invalid")
	}
	return nil
}

func captureAuthorityRef(authority CaptureAuthority) string {
	preimage := strings.Join([]string{
		"ambit.working-copy-capture-authority/v1",
		authority.RoleRef,
		authority.Protocol.Ref,
		authority.Protocol.Digest,
		authority.Helper.Ref,
		authority.Helper.Digest,
	}, "\n")
	return "ambit.working-copy-capture-authority:v1:sha256:" + hashHex(preimage)
}

func canonicalRelativePath(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) ||
		strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "\\") || path.Clean(value) != value || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return false
		}
	}
	return true
}

func readExactRegularTar(
	archive []byte,
	stat containertypes.PathStat,
	expectedName string,
) ([]byte, error) {
	reader := tar.NewReader(bytes.NewReader(archive))
	header, err := reader.Next()
	if err != nil {
		return nil, fmt.Errorf("%w: Docker archive has no exact file entry", ErrConflict)
	}
	if header.Name != expectedName || path.Base(header.Name) != header.Name ||
		header.Linkname != "" ||
		(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) ||
		!header.FileInfo().Mode().IsRegular() {
		return nil, fmt.Errorf("%w: Docker archive entry is not the admitted regular file", ErrConflict)
	}
	if header.Size < 0 || header.Size > MaximumCaptureBytes || header.Size != stat.Size {
		return nil, fmt.Errorf("%w: Docker archive descriptor size drifted", ErrConflict)
	}
	content, err := io.ReadAll(io.LimitReader(reader, MaximumCaptureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: Docker archive content read failed", ErrConflict)
	}
	if int64(len(content)) != header.Size {
		return nil, fmt.Errorf("%w: Docker archive content size drifted", ErrConflict)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: Docker archive contains multiple entries", ErrConflict)
	}
	return content, nil
}

func bindingObjectRoot(binding CaptureBinding) string {
	tenantDigest := hashHex("ambit-working-copy-capture-tenant/v1\n" + binding.Source.TenantID)
	bindingDigest := hashHex(strings.Join([]string{
		"ambit-working-copy-capture-binding/v1",
		binding.ProviderName,
		binding.RequestFingerprint,
	}, "\n"))
	return privateRoot + "/" + tenantDigest + "/" + bindingDigest
}

func providerResourceID(binding CaptureBinding, generation containerGeneration) string {
	digest := hashHex(strings.Join([]string{
		"ambit-working-copy-capture-generation/v1",
		binding.ProviderName,
		binding.RequestFingerprint,
		generation.ID,
		generation.Created,
	}, "\n"))
	return "daytona-working-copy-capture:v1:sha256:" + digest
}

func intentKey(bindingRoot string) string {
	return bindingRoot + "/intent.json"
}

func keysForIntent(intent captureIntent) objectKeys {
	root := bindingObjectRoot(intent.Binding)
	generationDigest := strings.TrimPrefix(intent.ProviderResourceID, "daytona-working-copy-capture:v1:sha256:")
	return objectKeys{
		intent:  intentKey(root),
		content: root + "/" + generationDigest + "/content.bin",
		receipt: root + "/" + generationDigest + "/receipt.json",
	}
}

func identityFromIntent(intent captureIntent) CaptureIdentity {
	return CaptureIdentity{CaptureBinding: intent.Binding, ProviderResourceID: intent.ProviderResourceID}
}

func receiptFromIntent(intent captureIntent, staged capturedFile) CaptureReceipt {
	return CaptureReceipt{
		CaptureIdentity:      identityFromIntent(intent),
		ByteLength:           int64(len(staged.bytes)),
		ProviderSHA256Digest: staged.digest,
		CapturedAt:           staged.capturedAt,
	}
}

func requireBinding(actual, expected CaptureBinding) error {
	if actual != expected {
		return fmt.Errorf("%w: provider name or exact binding is already owned by another capture", ErrConflict)
	}
	return nil
}

func requireIdentity(intent captureIntent, expected CaptureIdentity) error {
	if err := requireBinding(intent.Binding, expected.CaptureBinding); err != nil {
		return err
	}
	if intent.ProviderResourceID != expected.ProviderResourceID {
		return fmt.Errorf("%w: provider capture generation does not match", ErrConflict)
	}
	return nil
}

func validateProviderResourceID(value string) error {
	const prefix = "daytona-working-copy-capture:v1:sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 || !isLowerHex(strings.TrimPrefix(value, prefix)) {
		return invalidf("providerResourceId is invalid")
	}
	return nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func samePathStat(left, right containertypes.PathStat) bool {
	return left.Name == right.Name &&
		left.Size == right.Size &&
		left.Mode == right.Mode &&
		left.Mtime.Equal(right.Mtime) &&
		left.LinkTarget == right.LinkTarget
}

func samePathStatChain(left, right []containertypes.PathStat) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !samePathStat(left[index], right[index]) {
			return false
		}
	}
	return true
}

func boundedRef(value string, maximum int) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func isSHA256Digest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && isLowerHex(strings.TrimPrefix(value, "sha256:"))
}

func isLowerHex(value string) bool {
	if value == "" {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func hashHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func sha256Digest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func lowerMetadata(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[strings.ToLower(strings.TrimPrefix(key, "x-amz-meta-"))] = value
	}
	return result
}

func objectReadError(action string, err error) error {
	if errors.Is(err, storage.ErrPrivateObjectNotFound) || errors.Is(err, storage.ErrPrivateObjectTooLarge) {
		return fmt.Errorf("%w: %s: %v", ErrConflict, action, err)
	}
	return fmt.Errorf("%s: %w", action, err)
}

func invalidf(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, message)
}

func (locks *keyedLocks) acquire(key string) func() {
	locks.mu.Lock()
	item := locks.items[key]
	if item == nil {
		item = &keyedLock{}
		locks.items[key] = item
	}
	item.refs++
	locks.mu.Unlock()

	item.mu.Lock()
	return func() {
		item.mu.Unlock()
		locks.mu.Lock()
		item.refs--
		if item.refs == 0 {
			delete(locks.items, key)
		}
		locks.mu.Unlock()
	}
}
