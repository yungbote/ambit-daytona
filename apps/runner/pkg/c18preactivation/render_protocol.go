// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"golang.org/x/text/unicode/norm"
)

const (
	RenderCommandContractV2  = "ambit.c18-specialist-render-command-request/v2"
	RenderResultContractV2   = "ambit.c18-specialist-render-command-result/v2"
	RenderEvidenceContractV1 = "ambit.c18-specialist-render-check-evidence/v1"

	RenderResultMediaType   = "application/vnd.ambit.c18-specialist-render-command-result+json"
	RenderEvidenceMediaType = "application/vnd.ambit.c18-specialist-render-check-evidence+json"
	RenderPreviewMediaType  = "application/vnd.ambit.c18-specialist-artifact-preview+json"
)

const (
	maximumRenderCommandBytes     = 2 * 1024 * 1024
	maximumRenderEvidenceBytes    = 1024 * 1024
	maximumAggregateEvidenceBytes = 16 * 1024 * 1024
)

var (
	canonicalToken                = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	canonicalMediaType            = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
	canonicalUUID                 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	rendererAuthorityRef          = regexp.MustCompile(`^ambit\.renderer/[a-z0-9][a-z0-9._/-]*@[1-9][0-9]*$`)
	validationAuthorityRef        = regexp.MustCompile(`^ambit\.validation-policy/[a-z0-9][a-z0-9._/-]*@[1-9][0-9]*$`)
	runtimePackAuthorityRef       = regexp.MustCompile(`^ambit\.runtime-pack/[a-z0-9][a-z0-9._/-]*@[1-9][0-9]*$`)
	runtimeProfileAuthorityRef    = regexp.MustCompile(`^ambit\.workspace-runtime/[a-z0-9][a-z0-9._/-]*@[1-9][0-9]*$`)
	workspaceManifestAuthorityRef = regexp.MustCompile(`^workspace-execution-manifest:sha256:[0-9a-f]{64}$`)
)

type RenderCommandV2 struct {
	Contract           string                  `json:"contract"`
	DeadlineAt         string                  `json:"deadlineAt"`
	Digest             string                  `json:"digest"`
	Facet              string                  `json:"facet"`
	JobRef             string                  `json:"jobRef"`
	JobRoot            string                  `json:"jobRoot"`
	Operation          string                  `json:"operation"`
	Output             RenderOutputAuthorityV2 `json:"output"`
	PackRequiredChecks []RenderLabeledCheckV2  `json:"packRequiredChecks"`
	Renderer           RenderRendererV2        `json:"renderer"`
	RequestPath        string                  `json:"requestPath"`
	Runtime            RenderRuntimeV2         `json:"runtime"`
	Source             RenderSourceV2          `json:"source"`
}

type RenderSourceV2 struct {
	ByteLength int64   `json:"byteLength"`
	Digest     string  `json:"digest"`
	MediaType  string  `json:"mediaType"`
	Path       string  `json:"path"`
	Ref        string  `json:"ref"`
	SchemaURI  *string `json:"schemaUri"`
}

type RenderRendererV2 struct {
	ExecutablePath      string `json:"executablePath"`
	RenderMode          string `json:"renderMode"`
	RendererRef         string `json:"rendererRef"`
	Representation      string `json:"representation"`
	ValidationPolicyRef string `json:"validationPolicyRef"`
}

type RenderRuntimeV2 struct {
	PackRevisions              []specialistrender.Pin `json:"packRevisions"`
	ProfileRevision            specialistrender.Pin   `json:"profileRevision"`
	WorkspaceExecutionManifest specialistrender.Pin   `json:"workspaceExecutionManifest"`
}

type RenderLabeledCheckV2 struct {
	Check string `json:"check"`
	Label string `json:"label"`
}

type RenderOutputAuthorityV2 struct {
	JobOutputRoot               string `json:"jobOutputRoot"`
	MaximumAggregateImagePixels int64  `json:"maximumAggregateImagePixels"`
	MaximumImagePixels          int64  `json:"maximumImagePixels"`
	MaximumPreviewBytes         int64  `json:"maximumPreviewBytes"`
	PreviewMediaType            string `json:"previewMediaType"`
	PreviewPath                 string `json:"previewPath"`
	ResultPath                  string `json:"resultPath"`
}

type RenderResultV2 struct {
	Checks    []RenderResultCheckV2 `json:"checks"`
	Contract  string                `json:"contract"`
	Digest    string                `json:"digest"`
	Execution RenderExecutionV2     `json:"execution"`
	Failure   *RenderFailureV2      `json:"failure"`
	Outcome   string                `json:"outcome"`
	Preview   *RenderPreviewV2      `json:"preview"`
	Request   RenderResultRequestV2 `json:"request"`
}

type RenderResultCheckV2 struct {
	Check    string                    `json:"check"`
	Evidence *RenderEvidenceDescriptor `json:"evidence"`
	Outcome  string                    `json:"outcome"`
}

type RenderEvidenceDescriptor struct {
	ByteLength int64  `json:"byteLength"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	Path       string `json:"path"`
}

type RenderExecutionV2 struct {
	CompletedAt      string               `json:"completedAt"`
	ExecutorRevision specialistrender.Pin `json:"executorRevision"`
	StartedAt        string               `json:"startedAt"`
}

type RenderFailureV2 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RenderPreviewV2 struct {
	ByteLength     int64  `json:"byteLength"`
	BytesDigest    string `json:"bytesDigest"`
	EnvelopeDigest string `json:"envelopeDigest"`
	MediaType      string `json:"mediaType"`
	Path           string `json:"path"`
}

type RenderResultRequestV2 struct {
	Digest  string `json:"digest"`
	JobRef  string `json:"jobRef"`
	JobRoot string `json:"jobRoot"`
}

type RenderCheckEvidenceV1 struct {
	Artifacts        []RenderEvidenceDescriptor `json:"artifacts"`
	Check            string                     `json:"check"`
	Contract         string                     `json:"contract"`
	Digest           string                     `json:"digest"`
	ExecutorRevision specialistrender.Pin       `json:"executorRevision"`
	Facts            []RenderEvidenceFactV1     `json:"facts"`
	Outcome          string                     `json:"outcome"`
	Request          RenderEvidenceRequestV1    `json:"request"`
}

type RenderEvidenceFactV1 struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type RenderEvidenceRequestV1 struct {
	Digest       string `json:"digest"`
	JobRef       string `json:"jobRef"`
	SourceDigest string `json:"sourceDigest"`
}

// ParseRenderCommandV2 admits the helper's exact current command bytes and
// rebinds them to the supplied source bytes. Callers must separately compare
// the parsed command to the backend-issued command authority before executing.
func ParseRenderCommandV2(encoded []byte, sourceBytes []byte) (RenderCommandV2, error) {
	if len(encoded) == 0 || len(encoded) > maximumRenderCommandBytes {
		return RenderCommandV2{}, errors.New("C18 render command bytes exceed their bound")
	}
	var command RenderCommandV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &command); err != nil {
		return RenderCommandV2{}, fmt.Errorf("decode C18 render command: %w", err)
	}
	if err := validateRenderCommand(command, sourceBytes); err != nil {
		return RenderCommandV2{}, err
	}
	return command, nil
}

func validateRenderCommand(command RenderCommandV2, sourceBytes []byte) error {
	if command.Contract != RenderCommandContractV2 || command.Operation != "render_validate" {
		return errors.New("C18 render command contract is invalid")
	}
	if err := verifySealedDigest(command, command.Digest); err != nil {
		return err
	}
	policy, foundPolicy := runtimePolicyForCommand(command)
	if !foundPolicy || !rendererMatchesRuntimePolicy(command.Renderer, policy) ||
		!canonicalEqual(command.PackRequiredChecks, policy.CheckLabels) {
		return errors.New("C18 render command differs from the exact runtime policy")
	}
	jobID := strings.TrimPrefix(command.JobRef, "ambit://artifact-render-jobs/")
	if !canonicalUUID.MatchString(jobID) || command.JobRoot != "/workspace/.ambit/render-jobs/"+jobID {
		return errors.New("C18 render command job authority is invalid")
	}
	if command.Runtime.ProfileRevision.Ref == "ambit.workspace-runtime/c18-specialist-conformance@1" {
		return errors.New("C18 preactivation cannot use conformance-only runtime authority")
	}
	if !exactMillisecondInstant(command.DeadlineAt) {
		return errors.New("C18 render command deadline is invalid")
	}
	if len(sourceBytes) == 0 || int64(len(sourceBytes)) != command.Source.ByteLength ||
		sha256Digest(sourceBytes) != command.Source.Digest || command.Source.ByteLength > specialistrender.MaximumSourceBytes ||
		!canonicalMediaTypeValue(command.Source.MediaType) || !validOperationalRef(command.Source.Ref) {
		return errors.New("C18 render command source authority differs from its bytes")
	}
	if !safeZonePath(command.RequestPath, "inputs") || !safeZonePath(command.Source.Path, "inputs") ||
		command.RequestPath == command.Source.Path || !safeZonePath(command.Output.JobOutputRoot, "outputs") ||
		!safeZonePath(command.Output.PreviewPath, "outputs") || !safeZonePath(command.Output.ResultPath, "outputs") ||
		command.Output.PreviewPath == command.Output.ResultPath ||
		!strings.HasPrefix(command.Output.PreviewPath, command.Output.JobOutputRoot+"/") ||
		!strings.HasPrefix(command.Output.ResultPath, command.Output.JobOutputRoot+"/") {
		return errors.New("C18 render command semantic paths are invalid")
	}
	if command.Output.PreviewMediaType != RenderPreviewMediaType || command.Output.MaximumPreviewBytes < 1 ||
		command.Output.MaximumPreviewBytes > 8*1024*1024 || command.Output.MaximumImagePixels < 1 ||
		command.Output.MaximumImagePixels > 8*1024*1024 || command.Output.MaximumAggregateImagePixels < 1 ||
		command.Output.MaximumAggregateImagePixels > 32*1024*1024 ||
		command.Output.MaximumAggregateImagePixels < command.Output.MaximumImagePixels {
		return errors.New("C18 render command output policy is invalid")
	}
	if !rendererAuthorityRef.MatchString(command.Renderer.RendererRef) ||
		!validationAuthorityRef.MatchString(command.Renderer.ValidationPolicyRef) ||
		!canonicalTokenValue(command.Renderer.Representation) || !canonicalTokenValue(command.Renderer.RenderMode) {
		return errors.New("C18 render command renderer policy is invalid")
	}
	if !canonicalEqual(command.Source.SchemaURI, policy.RequiredSchemaURI) {
		return errors.New("C18 render command source schema differs from the runtime policy")
	}
	if command.Source.SchemaURI != nil && !validOperationalRef(*command.Source.SchemaURI) {
		return errors.New("C18 render command source schema authority is invalid")
	}
	if command.PackRequiredChecks == nil || len(command.PackRequiredChecks) == 0 || len(command.PackRequiredChecks) > 256 {
		return errors.New("C18 render command check roster is invalid")
	}
	checkNames := make([]string, len(command.PackRequiredChecks))
	for index, check := range command.PackRequiredChecks {
		if !canonicalTokenValue(check.Check) || !printableBounded(check.Label, 512, 2_048) {
			return errors.New("C18 render command check is invalid")
		}
		checkNames[index] = check.Check
	}
	if !sortedUnique(checkNames) || command.Runtime.PackRevisions == nil ||
		len(command.Runtime.PackRevisions) == 0 || len(command.Runtime.PackRevisions) > 32 ||
		!sortedUniquePinsWithPattern(command.Runtime.PackRevisions, runtimePackAuthorityRef) ||
		!validPinWithPattern(command.Runtime.ProfileRevision, runtimeProfileAuthorityRef) ||
		!validPinWithPattern(command.Runtime.WorkspaceExecutionManifest, workspaceManifestAuthorityRef) {
		return errors.New("C18 render command checks or runtime authority are invalid")
	}
	if !containsPinRef(command.Runtime.PackRevisions, policy.ExecutorPackRevisionRef) {
		return errors.New("C18 render command omits its exact executor pack")
	}
	return nil
}

func ParseRenderResultV2(command RenderCommandV2, encoded []byte) (RenderResultV2, error) {
	if len(encoded) == 0 || len(encoded) > maximumRenderCommandBytes {
		return RenderResultV2{}, errors.New("C18 render result bytes exceed their bound")
	}
	var result RenderResultV2
	if err := generationstop.DecodeCanonicalJSON(encoded, &result); err != nil {
		return RenderResultV2{}, fmt.Errorf("decode C18 render result: %w", err)
	}
	if result.Contract != RenderResultContractV2 || result.Request != (RenderResultRequestV2{
		Digest: command.Digest, JobRef: command.JobRef, JobRoot: command.JobRoot,
	}) {
		return RenderResultV2{}, errors.New("C18 render result changed its request authority")
	}
	if err := verifySealedDigest(result, result.Digest); err != nil {
		return RenderResultV2{}, err
	}
	if result.Checks == nil {
		return RenderResultV2{}, errors.New("C18 render result check roster is null")
	}
	if !validPin(result.Execution.ExecutorRevision.Ref, result.Execution.ExecutorRevision.Digest) ||
		!exactMillisecondInstant(result.Execution.StartedAt) || !exactMillisecondInstant(result.Execution.CompletedAt) ||
		result.Execution.CompletedAt < result.Execution.StartedAt ||
		(result.Outcome == "succeeded" && result.Execution.CompletedAt > command.DeadlineAt) {
		return RenderResultV2{}, errors.New("C18 render result execution authority is invalid")
	}
	requested := renderCheckNames(command)
	observed := make([]string, len(result.Checks))
	for index, check := range result.Checks {
		if !canonicalTokenValue(check.Check) || !containsString(requested, check.Check) ||
			(check.Outcome != "blocked" && check.Outcome != "failed" && check.Outcome != "passed") {
			return RenderResultV2{}, errors.New("C18 render result check is invalid")
		}
		if check.Evidence != nil &&
			(!validEvidenceDescriptor(*check.Evidence) || check.Evidence.ByteLength > maximumRenderEvidenceBytes) {
			return RenderResultV2{}, errors.New("C18 render result evidence descriptor is invalid")
		}
		observed[index] = check.Check
	}
	if !sortedUnique(observed) {
		return RenderResultV2{}, errors.New("C18 render result checks are not sorted and unique")
	}
	evidencePaths := make(map[string]struct{}, len(result.Checks))
	for _, check := range result.Checks {
		if check.Evidence == nil {
			continue
		}
		path := check.Evidence.Path
		if !strings.HasPrefix(path, command.Output.JobOutputRoot+"/") || path == command.Output.PreviewPath ||
			path == command.Output.ResultPath || path == command.Source.Path {
			return RenderResultV2{}, errors.New("C18 render result evidence path is invalid")
		}
		if _, exists := evidencePaths[path]; exists {
			return RenderResultV2{}, errors.New("C18 render result evidence paths are not unique")
		}
		evidencePaths[path] = struct{}{}
	}
	switch result.Outcome {
	case "succeeded":
		if result.Failure != nil || result.Preview == nil || !equalStrings(observed, requested) {
			return RenderResultV2{}, errors.New("successful C18 render result is incomplete")
		}
		for _, check := range result.Checks {
			if check.Outcome != "passed" || check.Evidence == nil {
				return RenderResultV2{}, errors.New("successful C18 render result did not pass every check")
			}
		}
		if !validPreview(*result.Preview, command.Output) {
			return RenderResultV2{}, errors.New("successful C18 render preview is invalid")
		}
	case "failed":
		if result.Failure == nil || result.Preview != nil || !canonicalTokenValue(result.Failure.Code) ||
			!printable(result.Failure.Message, 2_048) {
			return RenderResultV2{}, errors.New("non-success C18 render result relation is invalid")
		}
	default:
		return RenderResultV2{}, errors.New("C18 render result outcome is invalid")
	}
	return result, nil
}

func ParseRenderCheckEvidenceV1(
	command RenderCommandV2,
	expectedExecutor specialistrender.Pin,
	descriptor RenderEvidenceDescriptor,
	encoded []byte,
) (RenderCheckEvidenceV1, error) {
	if !validEvidenceDescriptor(descriptor) || descriptor.MediaType != RenderEvidenceMediaType ||
		descriptor.ByteLength > maximumRenderEvidenceBytes ||
		int64(len(encoded)) != descriptor.ByteLength || sha256Digest(encoded) != descriptor.Digest {
		return RenderCheckEvidenceV1{}, errors.New("C18 check evidence differs from its descriptor")
	}
	var evidence RenderCheckEvidenceV1
	if err := generationstop.DecodeCanonicalJSON(encoded, &evidence); err != nil {
		return RenderCheckEvidenceV1{}, fmt.Errorf("decode C18 check evidence: %w", err)
	}
	if evidence.Contract != RenderEvidenceContractV1 || evidence.ExecutorRevision != expectedExecutor ||
		evidence.Request != (RenderEvidenceRequestV1{
			Digest: command.Digest, JobRef: command.JobRef, SourceDigest: command.Source.Digest,
		}) || !containsString(renderCheckNames(command), evidence.Check) ||
		(evidence.Outcome != "passed" && evidence.Outcome != "failed") {
		return RenderCheckEvidenceV1{}, errors.New("C18 check evidence authority is invalid")
	}
	if err := verifySealedDigest(evidence, evidence.Digest); err != nil {
		return RenderCheckEvidenceV1{}, err
	}
	if evidence.Facts == nil || evidence.Artifacts == nil {
		return RenderCheckEvidenceV1{}, errors.New("C18 check evidence roster is null")
	}
	factKeys := make([]string, len(evidence.Facts))
	for index, fact := range evidence.Facts {
		if !canonicalTokenValue(fact.Key) || !printableBounded(fact.Value, 256, 1_024) {
			return RenderCheckEvidenceV1{}, errors.New("C18 check evidence fact is invalid")
		}
		factKeys[index] = fact.Key
	}
	artifactPaths := make([]string, len(evidence.Artifacts))
	for index, artifact := range evidence.Artifacts {
		if !validEvidenceDescriptor(artifact) || !strings.HasPrefix(artifact.Path, command.Output.JobOutputRoot+"/") ||
			artifact.Path == command.Output.PreviewPath || artifact.Path == command.Output.ResultPath ||
			artifact.Path == command.Source.Path {
			return RenderCheckEvidenceV1{}, errors.New("C18 check evidence artifact is invalid")
		}
		artifactPaths[index] = artifact.Path
	}
	if len(factKeys) > 128 || !sortedUnique(factKeys) || len(artifactPaths) > 64 || !sortedUnique(artifactPaths) {
		return RenderCheckEvidenceV1{}, errors.New("C18 check evidence rosters are invalid")
	}
	return evidence, nil
}

// AdmitRenderExecution closes the helper/provider seam. It accepts a result
// only when every provider-custodied file is exactly owned by the result,
// preview, check evidence, or an evidence artifact and every nested evidence
// document rebinds the command and provider executor.
func AdmitRenderExecution(
	commandBytes []byte,
	sourceBytes []byte,
	expectedRequest specialistrender.Request,
	provider ProviderExecutionResult,
) (RenderResultV2, []RenderCheckEvidenceV1, error) {
	if len(provider.Files) != len(provider.Receipt.Files) {
		return RenderResultV2{}, nil, errors.New("memory provider output roster differs from its receipt")
	}
	for index, file := range provider.Files {
		if file.Descriptor != provider.Receipt.Files[index] ||
			int64(len(file.Bytes)) != file.Descriptor.ByteLength ||
			sha256Digest(file.Bytes) != file.Descriptor.Digest {
			return RenderResultV2{}, nil, errors.New("memory provider output bytes differ from their receipt")
		}
	}
	admitted, err := AdmitRenderCustody(
		commandBytes,
		sourceBytes,
		expectedRequest,
		provider.Receipt,
		memoryProviderOutputReader{files: provider.Files},
	)
	if err != nil {
		return RenderResultV2{}, nil, err
	}
	return admitted.Result, admitted.Evidence, nil
}

func renderCheckNames(command RenderCommandV2) []string {
	result := make([]string, len(command.PackRequiredChecks))
	for index, value := range command.PackRequiredChecks {
		result[index] = value.Check
	}
	return result
}

func validEvidenceDescriptor(value RenderEvidenceDescriptor) bool {
	return value.ByteLength > 0 && value.ByteLength <= specialistrender.MaximumOutputBytes &&
		exactSHA256.MatchString(value.Digest) && canonicalMediaTypeValue(value.MediaType) &&
		safeZonePath(value.Path, "outputs")
}

func validPreview(value RenderPreviewV2, output RenderOutputAuthorityV2) bool {
	return value.Path == output.PreviewPath && value.MediaType == RenderPreviewMediaType && value.ByteLength > 0 &&
		value.ByteLength <= output.MaximumPreviewBytes && exactSHA256.MatchString(value.BytesDigest) &&
		exactSHA256.MatchString(value.EnvelopeDigest)
}

func safeZonePath(value, zone string) bool {
	if value == "" || len(value) > 128 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, `\\:`) ||
		strings.Contains(value, "//") || path.Clean(value) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 || parts[0] != zone {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".sock") {
			return false
		}
		for _, character := range part {
			if !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') &&
				!(character >= '0' && character <= '9') && !strings.ContainsRune("._-", character) {
				return false
			}
		}
	}
	return true
}

func exactMillisecondInstant(value string) bool {
	if len(value) != len("2006-01-02T15:04:05.000Z") || !strings.HasSuffix(value, "Z") {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000Z") == value
}

func printable(value string, maximum int) bool {
	if value == "" || utf16CodeUnits(value) > maximum || value != strings.TrimSpace(value) ||
		!norm.NFC.IsNormalString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Cs) {
			return false
		}
	}
	return true
}

func utf16CodeUnits(value string) int {
	length := 0
	for _, character := range value {
		length += utf16.RuneLen(character)
	}
	return length
}

func sortedUnique(values []string) bool {
	return sort.StringsAreSorted(values) && len(values) == len(uniqueStrings(values))
}

func uniqueStrings(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func sortedUniquePins(values []specialistrender.Pin) bool {
	refs := make([]string, len(values))
	for index, pin := range values {
		if !validPin(pin.Ref, pin.Digest) {
			return false
		}
		refs[index] = pin.Ref
	}
	return sortedUnique(refs)
}

func sortedUniquePinsWithPattern(values []specialistrender.Pin, pattern *regexp.Regexp) bool {
	refs := make([]string, len(values))
	for index, pin := range values {
		if !validPinWithPattern(pin, pattern) {
			return false
		}
		refs[index] = pin.Ref
	}
	return sortedUnique(refs)
}

func validPinWithPattern(pin specialistrender.Pin, pattern *regexp.Regexp) bool {
	return pattern.MatchString(pin.Ref) && exactSHA256.MatchString(pin.Digest)
}

func canonicalTokenValue(value string) bool {
	return len(value) <= 128 && canonicalToken.MatchString(value)
}

func canonicalMediaTypeValue(value string) bool {
	return len(value) <= 128 && canonicalMediaType.MatchString(value)
}

func containsString(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

func equalStrings(left, right []string) bool {
	return bytes.Equal([]byte(strings.Join(left, "\x00")), []byte(strings.Join(right, "\x00")))
}

func containsPinRef(pins []specialistrender.Pin, expected string) bool {
	for _, pin := range pins {
		if pin.Ref == expected {
			return true
		}
	}
	return false
}
