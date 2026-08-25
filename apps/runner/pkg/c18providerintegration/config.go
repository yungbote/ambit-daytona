// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/c18preactivation"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	maximumRunConfigBytes = 2 * 1024 * 1024
	maximumInputPathBytes = 4096
)

type PinnedInputFile struct {
	Path       string `json:"path"`
	ByteLength int64  `json:"byteLength"`
	SHA256     string `json:"sha256"`
}

type ProviderLiveExecution struct {
	Facet                string          `json:"facet"`
	Mode                 string          `json:"mode"`
	OperationID          string          `json:"operationId"`
	ArtifactRenderJobRef string          `json:"artifactRenderJobRef"`
	Request              PinnedInputFile `json:"request"`
	Source               PinnedInputFile `json:"source"`
}

type ProviderLiveTimeouts struct {
	ExecuteSeconds                 int `json:"executeSeconds"`
	ObservationSeconds             int `json:"observationSeconds"`
	PollMilliseconds               int `json:"pollMilliseconds"`
	CancelAfterPartialMilliseconds int `json:"cancelAfterPartialMilliseconds"`
}

type ProviderLiveTarget struct {
	ExpectedGeneration         generationstop.ExpectedGeneration `json:"expectedGeneration"`
	Fence                      generationstop.Fence              `json:"fence"`
	ObservedAt                 string                            `json:"observedAt"`
	Owner                      generationstop.ProviderOwner      `json:"owner"`
	Source                     generationstop.Source             `json:"source"`
	WorkspaceExecutionManifest specialistrender.Pin              `json:"workspaceExecutionManifest"`
}

type ProviderLiveRun struct {
	Contract        string                  `json:"contract"`
	SourceRevision  string                  `json:"sourceRevision"`
	SourceTree      string                  `json:"sourceTree"`
	SourceSetDigest string                  `json:"sourceSetDigest"`
	RunnerPolicy    PinnedInputFile         `json:"runnerPolicy"`
	Target          ProviderLiveTarget      `json:"target"`
	Executions      []ProviderLiveExecution `json:"executions"`
	Timeouts        ProviderLiveTimeouts    `json:"timeouts"`
}

type MinIOIntegrationRun struct {
	Contract        string `json:"contract"`
	SourceRevision  string `json:"sourceRevision"`
	SourceTree      string `json:"sourceTree"`
	SourceSetDigest string `json:"sourceSetDigest"`
	RunID           string `json:"runId"`
}

type DaytonaAPIConfig = c18preactivation.HTTPProviderConfig

func ReadProviderLiveRun(path string) (ProviderLiveRun, []byte, error) {
	bytes, err := readCanonicalConfig(path, maximumRunConfigBytes)
	if err != nil {
		return ProviderLiveRun{}, nil, err
	}
	var value ProviderLiveRun
	if err := generationstop.DecodeCanonicalJSON(bytes, &value); err != nil {
		return ProviderLiveRun{}, nil, fmt.Errorf("decode canonical provider live run: %w", err)
	}
	if err := ValidateProviderLiveRun(value); err != nil {
		return ProviderLiveRun{}, nil, err
	}
	return value, bytes, nil
}

func ReadMinIOIntegrationRun(path string) (MinIOIntegrationRun, []byte, error) {
	bytes, err := readCanonicalConfig(path, maximumRunConfigBytes)
	if err != nil {
		return MinIOIntegrationRun{}, nil, err
	}
	var value MinIOIntegrationRun
	if err := generationstop.DecodeCanonicalJSON(bytes, &value); err != nil {
		return MinIOIntegrationRun{}, nil, fmt.Errorf("decode canonical MinIO integration run: %w", err)
	}
	if err := ValidateMinIOIntegrationRun(value); err != nil {
		return MinIOIntegrationRun{}, nil, err
	}
	return value, bytes, nil
}

func ValidateProviderLiveRun(value ProviderLiveRun) error {
	if value.Contract != ProviderLiveRunContract {
		return fmt.Errorf("provider live run contract is invalid")
	}
	if err := validateSourceIdentity(value.SourceRevision, value.SourceTree, value.SourceSetDigest); err != nil {
		return err
	}
	if err := validatePinnedInput(value.RunnerPolicy, 32*1024*1024, "runner policy"); err != nil {
		return err
	}
	if err := generationstop.ValidateSource(value.Target.Source); err != nil {
		return fmt.Errorf("provider target source is invalid: %w", err)
	}
	if err := generationstop.ValidateProviderOwner(value.Target.Owner); err != nil {
		return fmt.Errorf("provider target owner is invalid: %w", err)
	}
	manifestDigest := strings.TrimPrefix(
		value.Target.Fence.WorkspaceExecutionManifestRef,
		"workspace-execution-manifest:",
	)
	if manifestDigest == value.Target.Fence.WorkspaceExecutionManifestRef ||
		!exactDigest(manifestDigest) {
		return fmt.Errorf("provider target fence is invalid")
	}
	if err := generationstop.ValidateExpectedGeneration(value.Target.ExpectedGeneration); err != nil {
		return fmt.Errorf("provider target generation is invalid: %w", err)
	}
	observedAt, err := time.Parse(observationTimeLayout, value.Target.ObservedAt)
	startedAt, startedErr := time.Parse(time.RFC3339Nano, value.Target.ExpectedGeneration.ExecutionStartedAt)
	if err != nil || startedErr != nil || observedAt.Before(startedAt) ||
		value.Target.WorkspaceExecutionManifest.Ref != value.Target.Fence.WorkspaceExecutionManifestRef ||
		!exactDigest(value.Target.WorkspaceExecutionManifest.Digest) {
		return fmt.Errorf("provider target observation or manifest authority is invalid")
	}
	if value.Timeouts.ExecuteSeconds != providerExecuteSeconds ||
		value.Timeouts.ObservationSeconds != providerObservationSeconds ||
		value.Timeouts.PollMilliseconds != providerPollMilliseconds ||
		value.Timeouts.CancelAfterPartialMilliseconds != providerCancelAfterPartialMilli {
		return fmt.Errorf("provider run timeouts are invalid")
	}
	if len(value.Executions) != 12 {
		return fmt.Errorf("provider live run requires exactly twelve executions")
	}
	seenOperations := make(map[string]struct{}, len(value.Executions))
	seenJobs := make(map[string]struct{}, len(value.Executions))
	seenRequestPaths := make(map[string]struct{}, len(value.Executions))
	sourcesByFacet := make(map[string]PinnedInputFile, providerSuccessConcurrency)
	previous := ""
	for index, execution := range value.Executions {
		key := execution.Facet + "\x00" + execution.Mode
		if index > 0 && previous >= key {
			return fmt.Errorf("provider live executions are not sorted and unique")
		}
		previous = key
		if _, exists := facetPacks[execution.Facet]; !exists ||
			(execution.Mode != "cancel" && execution.Mode != "success") {
			return fmt.Errorf("provider live execution facet or mode is invalid")
		}
		parsed, err := uuid.Parse(execution.OperationID)
		if err != nil || parsed == uuid.Nil || parsed.String() != execution.OperationID {
			return fmt.Errorf("provider operation id is invalid")
		}
		jobID := strings.TrimPrefix(execution.ArtifactRenderJobRef, "ambit://artifact-render-jobs/")
		parsedJob, err := uuid.Parse(jobID)
		if !strings.HasPrefix(execution.ArtifactRenderJobRef, "ambit://artifact-render-jobs/") ||
			err != nil || parsedJob == uuid.Nil || parsedJob.String() != jobID || jobID != execution.OperationID {
			return fmt.Errorf("provider artifact-render job ref is invalid")
		}
		if err := validatePinnedInput(execution.Request, specialistrender.MaximumRequestBytes, "provider request"); err != nil {
			return err
		}
		if err := validatePinnedInput(execution.Source, specialistrender.MaximumSourceBytes, "provider source"); err != nil {
			return err
		}
		if source, exists := sourcesByFacet[execution.Facet]; exists && source != execution.Source {
			return fmt.Errorf("provider facet modes use different source authority")
		}
		sourcesByFacet[execution.Facet] = execution.Source
		if _, duplicate := seenOperations[execution.OperationID]; duplicate {
			return fmt.Errorf("provider operation ids are duplicated")
		}
		if _, duplicate := seenJobs[execution.ArtifactRenderJobRef]; duplicate {
			return fmt.Errorf("provider artifact-render job refs are duplicated")
		}
		if _, duplicate := seenRequestPaths[execution.Request.Path]; duplicate {
			return fmt.Errorf("provider request paths are duplicated")
		}
		seenOperations[execution.OperationID] = struct{}{}
		seenJobs[execution.ArtifactRenderJobRef] = struct{}{}
		seenRequestPaths[execution.Request.Path] = struct{}{}
	}
	return nil
}

func ValidateMinIOIntegrationRun(value MinIOIntegrationRun) error {
	if value.Contract != MinIOIntegrationRunContract {
		return fmt.Errorf("MinIO integration run contract is invalid")
	}
	if err := validateSourceIdentity(value.SourceRevision, value.SourceTree, value.SourceSetDigest); err != nil {
		return err
	}
	parsed, err := uuid.Parse(value.RunID)
	if err != nil || parsed == uuid.Nil || parsed.String() != value.RunID {
		return fmt.Errorf("MinIO integration run id is invalid")
	}
	return nil
}

func DaytonaConfigFromEnvironment() (DaytonaAPIConfig, error) {
	return c18preactivation.HTTPProviderConfigFromEnvironment(os.Getenv)
}

func validatePinnedInput(value PinnedInputFile, maximum int64, label string) error {
	if !absoluteCleanPath(value.Path) || value.ByteLength <= 0 || value.ByteLength > maximum || !exactDigest(value.SHA256) {
		return fmt.Errorf("%s pin is invalid", label)
	}
	return nil
}

func readCanonicalConfig(path string, maximum int64) ([]byte, error) {
	if !absoluteCleanPath(path) {
		return nil, fmt.Errorf("configuration path is invalid")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("configuration file is invalid")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("configuration file descriptor is invalid")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum {
		return nil, fmt.Errorf("configuration file is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	if int64(len(data)) != before.Size() {
		return nil, fmt.Errorf("configuration byte length changed while read")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("configuration changed while read")
	}
	return data, nil
}

func absoluteCleanPath(value string) bool {
	return value != "" && len(value) <= maximumInputPathBytes && strings.TrimSpace(value) == value &&
		filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsRune(value, 0)
}

func CanonicalProviderLiveRun(value ProviderLiveRun) ([]byte, error) {
	if err := ValidateProviderLiveRun(value); err != nil {
		return nil, err
	}
	return generationstop.CanonicalJSON(value)
}

func CanonicalMinIOIntegrationRun(value MinIOIntegrationRun) ([]byte, error) {
	if err := ValidateMinIOIntegrationRun(value); err != nil {
		return nil, err
	}
	return generationstop.CanonicalJSON(value)
}
