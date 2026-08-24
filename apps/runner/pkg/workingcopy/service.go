// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package workingcopy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/storage"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/errdefs"
)

const (
	captureRoleRef         = "ambit.runtime-component/working-copy-capture@2"
	captureProtocolRef     = "ambit.runtime-interface/working-copy-capture@2"
	privateRoot            = "private/working-copy-captures/v2"
	maximumIntentBytes     = 32 * 1024
	maximumReceiptBytes    = 32 * 1024
	maximumDeletionBytes   = 32 * 1024
	maximumArchiveOverhead = 1024 * 1024
)

var (
	ErrInvalidRequest = errors.New("invalid working-copy capture request")
	ErrConflict       = errors.New("working-copy capture conflict")
	ErrUnavailable    = errors.New("working-copy capture unavailable")
	ErrOutcomeUnknown = errors.New("working-copy capture outcome is unknown")
)

type ContainerClient interface {
	ContainerStatPath(ctx context.Context, containerID, path string) (containertypes.PathStat, error)
	CopyFromContainer(ctx context.Context, containerID, path string) (io.ReadCloser, containertypes.PathStat, error)
}

type StoppedGenerationAuthority interface {
	RequireCurrentReceipt(
		ctx context.Context,
		expectedSource generationstop.Source,
		expectedOwner generationstop.Owner,
		expectedPurpose generationstop.Purpose,
		authority generationstop.StopAuthority,
	) (generationstop.Receipt, error)
}

type clock func() time.Time

type Service struct {
	containers        ContainerClient
	objects           storage.PrivateObjectStorageClient
	stops             StoppedGenerationAuthority
	admittedAuthority CaptureAuthority
	now               clock
	locks             keyedLocks
}

type keyedLocks struct {
	mu    sync.Mutex
	items map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

type captureIntent struct {
	Version            int                               `json:"version"`
	Binding            CaptureBinding                    `json:"binding"`
	ProviderResourceID string                            `json:"providerResourceId"`
	Generation         generationstop.TerminalGeneration `json:"generation"`
}

type captureDeletion struct {
	Version  int             `json:"version"`
	Identity CaptureIdentity `json:"identity"`
}

type objectKeys struct {
	intent   string
	content  string
	receipt  string
	deletion string
}

type capturedFile struct {
	bytes      []byte
	digest     string
	capturedAt string
}

func NewService(
	containers ContainerClient,
	objects storage.PrivateObjectStorageClient,
	stops StoppedGenerationAuthority,
	admittedAuthority CaptureAuthority,
) (*Service, error) {
	if containers == nil {
		return nil, fmt.Errorf("%w: Docker archive client is not configured", ErrUnavailable)
	}
	if objects == nil {
		return nil, fmt.Errorf("%w: private object storage is not configured", ErrUnavailable)
	}
	if stops == nil {
		return nil, fmt.Errorf("%w: stopped-generation authority is not configured", ErrUnavailable)
	}
	if err := validateAuthority(admittedAuthority); err != nil {
		return nil, fmt.Errorf("%w: admitted capture authority is invalid: %v", ErrUnavailable, err)
	}
	return &Service{
		containers:        containers,
		objects:           objects,
		stops:             stops,
		admittedAuthority: admittedAuthority,
		now:               time.Now,
		locks:             keyedLocks{items: make(map[string]*keyedLock)},
	}, nil
}

func NewCaptureAuthority(lineageRef, protocolDigest, helperDigest string) (CaptureAuthority, error) {
	authority := CaptureAuthority{
		LineageRef: lineageRef,
		RoleRef:    captureRoleRef,
		Protocol:   CaptureAuthorityArtifact{Ref: captureProtocolRef, Digest: protocolDigest},
		Helper: CaptureAuthorityArtifact{
			Ref: "runtime-component-artifact:" + helperDigest, Digest: helperDigest,
		},
	}
	authority.AuthorityRef = captureAuthorityRef(authority)
	if err := validateAuthority(authority); err != nil {
		return CaptureAuthority{}, err
	}
	return authority, nil
}

func (s *Service) Capture(
	ctx context.Context,
	sandboxID string,
	binding CaptureBinding,
) (CaptureReceipt, error) {
	zonePath, err := s.validateBinding(sandboxID, binding)
	if err != nil {
		return CaptureReceipt{}, err
	}

	bindingRoot := bindingObjectRoot(binding)
	release := s.locks.acquire(bindingRoot)
	defer release()
	if deletion, deleting, err := s.readDeletion(ctx, bindingRoot); err != nil {
		return CaptureReceipt{}, err
	} else if deleting {
		if err := requireBinding(deletion.Identity.CaptureBinding, binding); err != nil {
			return CaptureReceipt{}, err
		}
		if cleanupErr := s.deleteOperationalObjects(ctx, deletion.Identity); cleanupErr != nil {
			return CaptureReceipt{}, errors.Join(
				fmt.Errorf("%w: capture has been retired", ErrConflict),
				cleanupErr,
			)
		}
		return CaptureReceipt{}, fmt.Errorf("%w: capture has been retired", ErrConflict)
	}

	existing, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil {
		return CaptureReceipt{}, err
	}
	if exists {
		if err := requireBinding(existing.Binding, binding); err != nil {
			return CaptureReceipt{}, err
		}
		return s.resumeCapture(ctx, zonePath, existing)
	}

	stopReceipt, err := s.requireCurrentStop(ctx, binding)
	if err != nil {
		return CaptureReceipt{}, err
	}
	generation := stopReceipt.TerminalGeneration
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
		map[string]string{"contract": "ambit-working-copy-capture-intent-v2"},
	); err != nil {
		winner, winnerExists, readErr := s.readIntent(ctx, bindingRoot)
		if readErr != nil {
			return CaptureReceipt{}, errors.Join(
				fmt.Errorf("%w: persist capture intent: %v", ErrOutcomeUnknown, err),
				readErr,
			)
		}
		if !winnerExists {
			if errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
				return CaptureReceipt{}, fmt.Errorf("%w: capture intent disappeared during admission", ErrConflict)
			}
			return CaptureReceipt{}, fmt.Errorf("%w: persist capture intent: %v", ErrOutcomeUnknown, err)
		}
		if err := requireBinding(winner.Binding, binding); err != nil {
			return CaptureReceipt{}, err
		}
		return s.resumeCapture(ctx, zonePath, winner)
	}

	return s.resumeCapture(ctx, zonePath, intent)
}

func (s *Service) Observe(
	ctx context.Context,
	sandboxID string,
	binding CaptureBinding,
) (CaptureObservation, error) {
	if _, err := s.validateBinding(sandboxID, binding); err != nil {
		return CaptureObservation{}, err
	}
	bindingRoot := bindingObjectRoot(binding)
	release := s.locks.acquire(bindingRoot)
	defer release()
	return s.observeLocked(ctx, binding, nil)
}

func (s *Service) observeLocked(
	ctx context.Context,
	binding CaptureBinding,
	expectedIdentity *CaptureIdentity,
) (CaptureObservation, error) {
	bindingRoot := bindingObjectRoot(binding)
	deletion, deleting, err := s.readDeletion(ctx, bindingRoot)
	if err != nil {
		return CaptureObservation{}, err
	}
	if deleting {
		if err := requireBinding(deletion.Identity.CaptureBinding, binding); err != nil {
			return CaptureObservation{}, err
		}
		if expectedIdentity != nil {
			if deletion.Identity != *expectedIdentity {
				return CaptureObservation{}, fmt.Errorf("%w: deletion identity differs", ErrConflict)
			}
		}
		present, presentErr := s.operationalObjectsPresent(ctx, deletion.Identity)
		if presentErr != nil {
			return CaptureObservation{}, presentErr
		}
		if present {
			identity := deletion.Identity
			return CaptureObservation{Status: "partial", Identity: &identity}, nil
		}
		copy := binding
		return CaptureObservation{Status: "absent", Binding: &copy}, nil
	}

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
	if expectedIdentity != nil && identity != *expectedIdentity {
		return CaptureObservation{}, fmt.Errorf("%w: provider capture generation does not match", ErrConflict)
	}
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
	// A deletion tombstone can win after the first read in another runner
	// process. Never certify complete custody once that durable authority exists.
	if deletion, deleting, err := s.readDeletion(ctx, bindingRoot); err != nil {
		return CaptureObservation{}, err
	} else if deleting {
		if deletion.Identity != identity {
			return CaptureObservation{}, fmt.Errorf("%w: deletion identity differs", ErrConflict)
		}
		present, presentErr := s.operationalObjectsPresent(ctx, deletion.Identity)
		if presentErr != nil {
			return CaptureObservation{}, presentErr
		}
		if present {
			return CaptureObservation{Status: "partial", Identity: &identity}, nil
		}
		copy := binding
		return CaptureObservation{Status: "absent", Binding: &copy}, nil
	}
	return CaptureObservation{Status: "complete", Receipt: &receipt}, nil
}

func (s *Service) Read(
	ctx context.Context,
	sandboxID string,
	request CaptureReadRequest,
) (CaptureReadResponse, error) {
	if _, err := s.validateBinding(sandboxID, request.CaptureBinding); err != nil {
		return CaptureReadResponse{}, err
	}
	if err := validateProviderResourceID(request.ProviderResourceID); err != nil {
		return CaptureReadResponse{}, err
	}
	if request.ExpectedTotalByteLength < 0 || request.ExpectedTotalByteLength > MaximumCaptureBytes ||
		!isSHA256Digest(request.ExpectedProviderSHA256Digest) ||
		request.Offset < 0 || request.Offset > request.ExpectedTotalByteLength ||
		request.MaximumBytes <= 0 || request.MaximumBytes > MaximumReadBytes {
		return CaptureReadResponse{}, invalidf("capture read bounds are invalid")
	}

	bindingRoot := bindingObjectRoot(request.CaptureBinding)
	release := s.locks.acquire(bindingRoot)
	defer release()
	if deletion, deleting, err := s.readDeletion(ctx, bindingRoot); err != nil {
		return CaptureReadResponse{}, err
	} else if deleting {
		if deletion.Identity != request.CaptureIdentity {
			return CaptureReadResponse{}, fmt.Errorf("%w: deletion identity differs", ErrConflict)
		}
		return CaptureReadResponse{}, fmt.Errorf("%w: capture is deleting or absent", ErrConflict)
	}
	intent, exists, err := s.readIntent(ctx, bindingRoot)
	if err != nil {
		return CaptureReadResponse{}, err
	}
	if !exists {
		return CaptureReadResponse{}, fmt.Errorf("%w: capture identity is absent", ErrConflict)
	}
	if err := requireIdentity(intent, request.CaptureIdentity); err != nil {
		return CaptureReadResponse{}, err
	}
	receipt, complete, err := s.readReceipt(ctx, intent)
	if err != nil {
		return CaptureReadResponse{}, err
	}
	if !complete {
		return CaptureReadResponse{}, fmt.Errorf("%w: capture is partial", ErrConflict)
	}
	if request.ExpectedTotalByteLength != receipt.TotalByteLength ||
		request.ExpectedProviderSHA256Digest != receipt.ProviderSHA256Digest {
		return CaptureReadResponse{}, fmt.Errorf("%w: capture receipt authority changed", ErrConflict)
	}
	if err := s.verifyContentMetadata(ctx, intent, receipt); err != nil {
		return CaptureReadResponse{}, err
	}
	remaining := receipt.TotalByteLength - request.Offset
	readLength := min(request.MaximumBytes, remaining)
	var data []byte
	if readLength > 0 {
		data, err = s.objects.GetPrivateObjectRange(
			ctx,
			keysForIntent(intent).content,
			request.Offset,
			readLength,
		)
		if err != nil {
			return CaptureReadResponse{}, objectReadError("read capture content range", err)
		}
		if int64(len(data)) != readLength {
			return CaptureReadResponse{}, fmt.Errorf("%w: captured content range is short", ErrConflict)
		}
	}
	return CaptureReadResponse{
		CaptureIdentity:      receipt.CaptureIdentity,
		TotalByteLength:      receipt.TotalByteLength,
		ProviderSHA256Digest: receipt.ProviderSHA256Digest,
		Offset:               request.Offset,
		ByteLength:           int64(len(data)),
		EOF:                  request.Offset+int64(len(data)) == receipt.TotalByteLength,
		BytesBase64:          base64.StdEncoding.EncodeToString(data),
	}, nil
}

func (s *Service) Delete(
	ctx context.Context,
	sandboxID string,
	identity CaptureIdentity,
) (CaptureDeleteReceipt, error) {
	if _, err := s.validateBinding(sandboxID, identity.CaptureBinding); err != nil {
		return CaptureDeleteReceipt{}, err
	}
	if err := validateProviderResourceID(identity.ProviderResourceID); err != nil {
		return CaptureDeleteReceipt{}, err
	}
	bindingRoot := bindingObjectRoot(identity.CaptureBinding)
	release := s.locks.acquire(bindingRoot)
	defer release()

	deletion, deleting, err := s.readDeletion(ctx, bindingRoot)
	if err != nil {
		return CaptureDeleteReceipt{}, err
	}
	if deleting && deletion.Identity != identity {
		return CaptureDeleteReceipt{}, fmt.Errorf("%w: deletion identity differs", ErrConflict)
	}
	if !deleting {
		intent, exists, readErr := s.readIntent(ctx, bindingRoot)
		if readErr != nil {
			return CaptureDeleteReceipt{}, readErr
		}
		if exists {
			if err := requireIdentity(intent, identity); err != nil {
				return CaptureDeleteReceipt{}, err
			}
		} else {
			// An opaque-looking providerResourceId is not deletion authority. When
			// the intent has already disappeared, rederive the only admissible
			// identity from the exact binding and the current terminal generation
			// before publishing the irreversible retirement tombstone.
			stopReceipt, stopErr := s.requireCurrentStop(ctx, identity.CaptureBinding)
			if stopErr != nil {
				return CaptureDeleteReceipt{}, stopErr
			}
			expectedProviderResourceID := providerResourceID(
				identity.CaptureBinding,
				stopReceipt.TerminalGeneration,
			)
			if identity.ProviderResourceID != expectedProviderResourceID {
				return CaptureDeleteReceipt{}, fmt.Errorf(
					"%w: absent capture identity does not derive from the current terminal generation",
					ErrConflict,
				)
			}
		}
		deletion = captureDeletion{Version: 1, Identity: identity}
		deletionBytes, marshalErr := json.Marshal(deletion)
		if marshalErr != nil {
			return CaptureDeleteReceipt{}, fmt.Errorf("marshal capture deletion: %w", marshalErr)
		}
		createErr := s.objects.CreatePrivateObject(
			ctx,
			deletionKey(bindingRoot),
			deletionBytes,
			"application/json",
			map[string]string{"contract": "ambit-working-copy-capture-deletion-v2"},
		)
		if createErr != nil {
			winner, winnerExists, readWinnerErr := s.readDeletion(ctx, bindingRoot)
			if readWinnerErr != nil {
				return CaptureDeleteReceipt{}, errors.Join(
					fmt.Errorf("%w: publish capture deletion: %v", ErrOutcomeUnknown, createErr),
					readWinnerErr,
				)
			}
			if !winnerExists {
				return CaptureDeleteReceipt{}, fmt.Errorf("%w: publish capture deletion: %v", ErrOutcomeUnknown, createErr)
			}
			if winner.Identity != identity {
				return CaptureDeleteReceipt{}, fmt.Errorf("%w: deletion publication conflicted", ErrConflict)
			}
			deletion = winner
		}
	}
	present, probeErr := s.operationalObjectsPresent(ctx, identity)
	cleanupErr := s.deleteOperationalObjects(ctx, identity)
	if cleanupErr != nil {
		return CaptureDeleteReceipt{}, errors.Join(probeErr, cleanupErr)
	}
	outcome := "already_absent"
	if present || probeErr != nil {
		outcome = "deleted"
	}
	return CaptureDeleteReceipt{CaptureIdentity: deletion.Identity, Outcome: outcome}, nil
}

func (s *Service) Exists(
	ctx context.Context,
	sandboxID string,
	identity CaptureIdentity,
) (CaptureExistsResponse, error) {
	if _, err := s.validateBinding(sandboxID, identity.CaptureBinding); err != nil {
		return CaptureExistsResponse{}, err
	}
	if err := validateProviderResourceID(identity.ProviderResourceID); err != nil {
		return CaptureExistsResponse{}, err
	}
	bindingRoot := bindingObjectRoot(identity.CaptureBinding)
	release := s.locks.acquire(bindingRoot)
	defer release()
	observation, err := s.observeLocked(ctx, identity.CaptureBinding, &identity)
	if err != nil {
		return CaptureExistsResponse{}, err
	}
	response := CaptureExistsResponse{
		CaptureIdentity: identity,
		Status:          observation.Status,
		Exists:          observation.Status != "absent",
	}
	if observation.Status == "complete" {
		response.Receipt = observation.Receipt
	}
	return response, nil
}

func (s *Service) resumeCapture(
	ctx context.Context,
	zonePath string,
	intent captureIntent,
) (CaptureReceipt, error) {
	currentStop, err := s.requireCurrentStop(ctx, intent.Binding)
	if err != nil {
		return CaptureReceipt{}, err
	}
	if currentStop.TerminalGeneration != intent.Generation {
		return CaptureReceipt{}, fmt.Errorf("%w: stopped generation differs from immutable capture intent", ErrConflict)
	}
	if err := s.ensureNotDeleting(ctx, intent); err != nil {
		return CaptureReceipt{}, err
	}
	if receipt, complete, err := s.readReceipt(ctx, intent); err != nil {
		return CaptureReceipt{}, err
	} else if complete {
		if err := s.verifyContentMetadata(ctx, intent, receipt); err != nil {
			return CaptureReceipt{}, err
		}
		if err := s.ensureNotDeleting(ctx, intent); err != nil {
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
		staged, err = s.captureStableFile(ctx, zonePath, intent)
		if err != nil {
			return CaptureReceipt{}, err
		}
		if err := s.ensureNotDeleting(ctx, intent); err != nil {
			return CaptureReceipt{}, err
		}
		metadata := map[string]string{
			"captured-at":          staged.capturedAt,
			"sha256":               staged.digest,
			"byte-length":          strconv.FormatInt(int64(len(staged.bytes)), 10),
			"provider-resource-id": intent.ProviderResourceID,
			"contract":             "ambit-working-copy-capture-content-v2",
		}
		if err := s.objects.CreatePrivateObject(
			ctx,
			keys.content,
			staged.bytes,
			"application/octet-stream",
			metadata,
		); err != nil {
			winner, winnerExists, readErr := s.readStagedContent(ctx, intent)
			if readErr != nil {
				return CaptureReceipt{}, errors.Join(
					fmt.Errorf("%w: persist capture content: %v", ErrOutcomeUnknown, err),
					readErr,
				)
			}
			if !winnerExists {
				if errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
					return CaptureReceipt{}, fmt.Errorf("%w: capture content disappeared during admission", ErrConflict)
				}
				return CaptureReceipt{}, fmt.Errorf("%w: persist capture content: %v", ErrOutcomeUnknown, err)
			}
			staged = winner
		}
		if err := s.ensureNotDeleting(ctx, intent); err != nil {
			return CaptureReceipt{}, err
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
		map[string]string{"contract": "ambit-working-copy-capture-receipt-v2"},
	); err != nil {
		winner, complete, readErr := s.readReceipt(ctx, intent)
		if readErr != nil {
			return CaptureReceipt{}, errors.Join(
				fmt.Errorf("%w: publish capture receipt: %v", ErrOutcomeUnknown, err),
				readErr,
			)
		}
		if !complete {
			if !errors.Is(err, storage.ErrPrivateObjectAlreadyExists) {
				return CaptureReceipt{}, fmt.Errorf("%w: publish capture receipt: %v", ErrOutcomeUnknown, err)
			}
			return CaptureReceipt{}, fmt.Errorf("%w: capture receipt disappeared during publication", ErrConflict)
		}
		if winner != receipt {
			return CaptureReceipt{}, fmt.Errorf("%w: capture receipt publication conflicted", ErrConflict)
		}
		if err := s.ensureNotDeleting(ctx, intent); err != nil {
			return CaptureReceipt{}, err
		}
		return winner, nil
	}
	if err := s.ensureNotDeleting(ctx, intent); err != nil {
		return CaptureReceipt{}, err
	}
	return receipt, nil
}

func (s *Service) captureStableFile(
	ctx context.Context,
	zonePath string,
	intent captureIntent,
) (capturedFile, error) {
	beforeStop, err := s.requireCurrentStop(ctx, intent.Binding)
	if err != nil {
		return capturedFile{}, err
	}
	if beforeStop.TerminalGeneration != intent.Generation {
		return capturedFile{}, fmt.Errorf("%w: stopped generation changed before capture", ErrConflict)
	}
	containerID := intent.Generation.ContainerID
	before, err := s.statPathChain(ctx, containerID, zonePath)
	if err != nil {
		return capturedFile{}, err
	}
	fileBefore := before[len(before)-1]
	archive, copyStat, err := s.containers.CopyFromContainer(ctx, containerID, zonePath)
	if err != nil {
		return capturedFile{}, dockerReadError("open Docker archive", err)
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
		return capturedFile{}, fmt.Errorf("%w: Docker archive stream failed: %v", ErrUnavailable, err)
	}
	if int64(len(archiveBytes)) > MaximumCaptureBytes+maximumArchiveOverhead {
		return capturedFile{}, invalidf("Docker archive exceeds the bounded single-file envelope")
	}
	content, err := readExactRegularTar(archiveBytes, fileBefore, path.Base(zonePath))
	if err != nil {
		return capturedFile{}, err
	}

	after, err := s.statPathChain(ctx, containerID, zonePath)
	if err != nil {
		return capturedFile{}, err
	}
	if !samePathStatChain(before, after) {
		return capturedFile{}, fmt.Errorf("%w: source path changed during capture", ErrConflict)
	}
	afterStop, err := s.requireCurrentStop(ctx, intent.Binding)
	if err != nil {
		return capturedFile{}, err
	}
	if afterStop.TerminalGeneration != intent.Generation {
		return capturedFile{}, fmt.Errorf("%w: stopped generation changed during capture", ErrConflict)
	}

	return capturedFile{
		bytes:      content,
		digest:     sha256Digest(content),
		capturedAt: s.now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) statPathChain(
	ctx context.Context,
	containerID string,
	zonePath string,
) ([]containertypes.PathStat, error) {
	parts := strings.Split(strings.TrimPrefix(zonePath, "/"), "/")
	stats := make([]containertypes.PathStat, 0, len(parts))
	current := ""
	for index, part := range parts {
		current += "/" + part
		stat, err := s.containers.ContainerStatPath(ctx, containerID, current)
		if err != nil {
			return nil, dockerReadError("stat admitted source path", err)
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
	if err := decodeCanonicalStoredJSON(data, &intent); err != nil || intent.Version != 1 {
		return captureIntent{}, false, fmt.Errorf("%w: capture intent is not canonical", ErrConflict)
	}
	if _, err := s.validateBinding(intent.Binding.Source.ProviderResourceID, intent.Binding); err != nil {
		return captureIntent{}, false, fmt.Errorf("%w: stored capture binding is invalid", ErrConflict)
	}
	if err := validateProviderResourceID(intent.ProviderResourceID); err != nil ||
		intent.ProviderResourceID != providerResourceID(intent.Binding, intent.Generation) ||
		intent.Generation.ContainerID == "" || intent.Generation.ContainerCreatedAt == "" ||
		intent.Generation.ExecutionStartedAt == "" || intent.Generation.ExecutionFinishedAt == "" ||
		intent.Generation.RestartCount < 0 {
		return captureIntent{}, false, fmt.Errorf("%w: capture intent identity is invalid", ErrConflict)
	}
	return intent, true, nil
}

func (s *Service) readDeletion(
	ctx context.Context,
	bindingRoot string,
) (captureDeletion, bool, error) {
	data, err := s.objects.GetPrivateObject(ctx, deletionKey(bindingRoot), maximumDeletionBytes)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return captureDeletion{}, false, nil
	}
	if err != nil {
		return captureDeletion{}, false, objectReadError("read capture deletion", err)
	}
	var deletion captureDeletion
	if err := decodeCanonicalStoredJSON(data, &deletion); err != nil || deletion.Version != 1 {
		return captureDeletion{}, false, fmt.Errorf("%w: capture deletion is not canonical", ErrConflict)
	}
	if _, err := s.validateBinding(
		deletion.Identity.Source.ProviderResourceID,
		deletion.Identity.CaptureBinding,
	); err != nil {
		return captureDeletion{}, false, fmt.Errorf("%w: stored deletion binding is invalid", ErrConflict)
	}
	if err := validateProviderResourceID(deletion.Identity.ProviderResourceID); err != nil {
		return captureDeletion{}, false, fmt.Errorf("%w: stored deletion identity is invalid", ErrConflict)
	}
	if bindingObjectRoot(deletion.Identity.CaptureBinding) != bindingRoot {
		return captureDeletion{}, false, fmt.Errorf("%w: stored deletion root differs", ErrConflict)
	}
	return deletion, true, nil
}

func (s *Service) operationalObjectsPresent(
	ctx context.Context,
	identity CaptureIdentity,
) (bool, error) {
	keys := keysForIdentity(identity)
	present := false
	var failures []error
	for _, key := range []string{keys.receipt, keys.content, keys.intent} {
		exists, err := s.privateObjectExists(ctx, key)
		present = present || exists
		if err != nil {
			failures = append(failures, err)
		}
	}
	return present, errors.Join(failures...)
}

func (s *Service) privateObjectExists(ctx context.Context, key string) (bool, error) {
	_, err := s.objects.StatPrivateObject(ctx, key)
	if errors.Is(err, storage.ErrPrivateObjectNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: stat private capture object: %v", ErrUnavailable, err)
	}
	return true, nil
}

func (s *Service) deleteOperationalObjects(ctx context.Context, identity CaptureIdentity) error {
	keys := keysForIdentity(identity)
	var failures []error
	for _, key := range []string{keys.receipt, keys.content, keys.intent} {
		if err := s.deleteObjectReconciled(ctx, key); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) deleteObjectReconciled(ctx context.Context, key string) error {
	deleteErr := s.objects.DeletePrivateObject(ctx, key)
	_, statErr := s.objects.StatPrivateObject(ctx, key)
	if errors.Is(statErr, storage.ErrPrivateObjectNotFound) {
		return nil
	}
	if statErr == nil {
		if deleteErr != nil {
			return fmt.Errorf("%w: delete private capture object: %v", ErrOutcomeUnknown, deleteErr)
		}
		return fmt.Errorf("%w: deleted private capture object is still present", ErrOutcomeUnknown)
	}
	if deleteErr != nil {
		return errors.Join(
			fmt.Errorf("%w: delete private capture object: %v", ErrOutcomeUnknown, deleteErr),
			fmt.Errorf("%w: verify private capture deletion: %v", ErrUnavailable, statErr),
		)
	}
	return fmt.Errorf("%w: verify private capture deletion: %v", ErrOutcomeUnknown, statErr)
}

func (s *Service) ensureNotDeleting(ctx context.Context, intent captureIntent) error {
	deletion, deleting, err := s.readDeletion(ctx, bindingObjectRoot(intent.Binding))
	if err != nil {
		return err
	}
	if !deleting {
		return nil
	}
	identity := identityFromIntent(intent)
	if deletion.Identity != identity {
		return fmt.Errorf("%w: deletion identity differs", ErrConflict)
	}
	if cleanupErr := s.deleteOperationalObjects(ctx, identity); cleanupErr != nil {
		return errors.Join(fmt.Errorf("%w: capture has been retired", ErrConflict), cleanupErr)
	}
	return fmt.Errorf("%w: capture has been retired", ErrConflict)
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
	if err := decodeCanonicalStoredJSON(data, &receipt); err != nil {
		return CaptureReceipt{}, false, fmt.Errorf("%w: capture receipt is not canonical", ErrConflict)
	}
	if err := requireIdentity(intent, receipt.CaptureIdentity); err != nil ||
		receipt.TotalByteLength < 0 || receipt.TotalByteLength > MaximumCaptureBytes ||
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
		metadata["contract"] != "ambit-working-copy-capture-content-v2" ||
		!isSHA256Digest(metadata["sha256"]) ||
		info.ContentSHA256 != metadata["sha256"] ||
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
	if info.Size != receipt.TotalByteLength ||
		info.ContentSHA256 != receipt.ProviderSHA256Digest ||
		metadata["byte-length"] != strconv.FormatInt(receipt.TotalByteLength, 10) ||
		metadata["sha256"] != receipt.ProviderSHA256Digest ||
		metadata["captured-at"] != receipt.CapturedAt ||
		metadata["provider-resource-id"] != receipt.ProviderResourceID ||
		metadata["contract"] != "ambit-working-copy-capture-content-v2" {
		return fmt.Errorf("%w: completed capture metadata drifted", ErrConflict)
	}
	return nil
}

func (s *Service) requireCurrentStop(
	ctx context.Context,
	binding CaptureBinding,
) (generationstop.Receipt, error) {
	receipt, err := s.stops.RequireCurrentReceipt(
		ctx,
		binding.Source,
		binding.Owner,
		generationstop.Purpose{Kind: generationstop.PurposeWorkingCopyCapture},
		binding.StopAuthority,
	)
	if err == nil {
		return receipt, nil
	}
	switch {
	case errors.Is(err, generationstop.ErrInvalidRequest):
		return generationstop.Receipt{}, fmt.Errorf("%w: stopped-generation authority: %v", ErrInvalidRequest, err)
	case errors.Is(err, generationstop.ErrOutcomeUnknown):
		return generationstop.Receipt{}, fmt.Errorf("%w: stopped-generation authority: %v", ErrOutcomeUnknown, err)
	case errors.Is(err, generationstop.ErrUnavailable):
		return generationstop.Receipt{}, fmt.Errorf("%w: stopped-generation authority: %v", ErrUnavailable, err)
	case errors.Is(err, generationstop.ErrConflict):
		return generationstop.Receipt{}, fmt.Errorf("%w: stopped-generation authority: %v", ErrConflict, err)
	default:
		return generationstop.Receipt{}, fmt.Errorf("%w: stopped-generation authority: %v", ErrUnavailable, err)
	}
}

func (s *Service) validateBinding(sandboxID string, binding CaptureBinding) (string, error) {
	if !boundedRef(binding.ProviderName, 512) {
		return "", invalidf("providerName is invalid")
	}
	if len(binding.RequestFingerprint) != 64 || !isLowerHex(binding.RequestFingerprint) {
		return "", invalidf("requestFingerprint must be 64 lowercase hexadecimal characters")
	}
	if err := validateAuthority(binding.Authority); err != nil {
		return "", err
	}
	if binding.Authority != s.admittedAuthority {
		return "", invalidf("capture authority is not the admitted current lineage")
	}
	if err := generationstop.ValidateBinding(binding.Source, binding.Owner, binding.StopAuthority); err != nil {
		return "", invalidf("stopped-generation binding is invalid: " + err.Error())
	}
	if !boundedRef(sandboxID, 512) || binding.Source.ProviderResourceID != sandboxID {
		return "", invalidf("source providerResourceId does not match the sandbox")
	}
	if binding.Source.ExpectedProfile != "managed-container" ||
		binding.Source.ExpectedRuntimeKind != "full_image_runtime_pack" {
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
		!boundedRef(authority.LineageRef, 512) ||
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
		"ambit.working-copy-capture-authority/v2",
		authority.LineageRef,
	}, "\n")
	return "ambit.working-copy-capture-authority:v2:sha256:" + hashHex(preimage)
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
	tenantDigest := hashHex("ambit-working-copy-capture-tenant/v2\n" + binding.Owner.TenantID)
	bindingDigest := hashHex(strings.Join([]string{
		"ambit-working-copy-capture-binding/v2",
		binding.ProviderName,
		binding.RequestFingerprint,
	}, "\n"))
	return privateRoot + "/" + tenantDigest + "/" + bindingDigest
}

func providerResourceID(binding CaptureBinding, generation generationstop.TerminalGeneration) string {
	bindingBytes, _ := json.Marshal(binding)
	digest := hashHex(strings.Join([]string{
		"ambit-working-copy-capture-generation/v2",
		sha256Digest(bindingBytes),
		generation.ContainerID,
		generation.ContainerCreatedAt,
		generation.ExecutionStartedAt,
		generation.ExecutionFinishedAt,
		strconv.Itoa(generation.RestartCount),
		strconv.Itoa(generation.ExitCode),
		strconv.FormatBool(generation.OOMKilled),
	}, "\n"))
	return "daytona-working-copy-capture:v2:sha256:" + digest
}

func intentKey(bindingRoot string) string {
	return bindingRoot + "/intent.json"
}

func deletionKey(bindingRoot string) string {
	return bindingRoot + "/deletion.json"
}

func keysForIntent(intent captureIntent) objectKeys {
	return keysForIdentity(identityFromIntent(intent))
}

func keysForIdentity(identity CaptureIdentity) objectKeys {
	root := bindingObjectRoot(identity.CaptureBinding)
	generationDigest := strings.TrimPrefix(identity.ProviderResourceID, "daytona-working-copy-capture:v2:sha256:")
	return objectKeys{
		intent:   intentKey(root),
		content:  root + "/" + generationDigest + "/content.bin",
		receipt:  root + "/" + generationDigest + "/receipt.json",
		deletion: deletionKey(root),
	}
}

func identityFromIntent(intent captureIntent) CaptureIdentity {
	return CaptureIdentity{CaptureBinding: intent.Binding, ProviderResourceID: intent.ProviderResourceID}
}

func receiptFromIntent(intent captureIntent, staged capturedFile) CaptureReceipt {
	return CaptureReceipt{
		CaptureIdentity:      identityFromIntent(intent),
		TotalByteLength:      int64(len(staged.bytes)),
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
	const prefix = "daytona-working-copy-capture:v2:sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 || !isLowerHex(strings.TrimPrefix(value, prefix)) {
		return invalidf("providerResourceId is invalid")
	}
	return nil
}

func strictJSON(data []byte, target any) error {
	return generationstop.DecodeExactJSON(data, target)
}

func decodeCanonicalStoredJSON(data []byte, target any) error {
	if err := strictJSON(data, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return fmt.Errorf("marshal canonical durable JSON: %w", err)
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("durable JSON bytes are not canonical")
	}
	return nil
}

// DecodeExactJSON keeps the WorkingCopy API name while delegating schema
// exactness to the shared stopped-generation decoder.
func DecodeExactJSON(data []byte, target any) error {
	return strictJSON(data, target)
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
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, action, err)
}

func dockerReadError(action string, err error) error {
	if errdefs.IsNotFound(err) || errdefs.IsConflict(err) {
		return fmt.Errorf("%w: %s: %v", ErrConflict, action, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, action, err)
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
