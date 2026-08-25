// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/daytonaio/runner/pkg/generationstop"
)

type CompositionRouting struct {
	Version        int                `json:"version"`
	Kind           string             `json:"kind"`
	ExchangePolicy string             `json:"exchangePolicy"`
	Routes         []CompositionRoute `json:"routes"`
	RoutingRef     string             `json:"routingRef"`
	Digest         string             `json:"digest"`
}

type CompositionRoute struct {
	RouteRef                     string   `json:"routeRef"`
	ExecutorProfileRef           string   `json:"executorProfileRef"`
	ProvidedCapabilityFamilyRefs []string `json:"providedCapabilityFamilyRefs"`
	ProvidedCapabilityRefs       []string `json:"providedCapabilityRefs"`
}

type FullImageComposition struct {
	Version            int                         `json:"version"`
	Kind               string                      `json:"kind"`
	ProfileRevisionRef string                      `json:"profileRevisionRef"`
	DeploymentTarget   CompositionDeploymentTarget `json:"deploymentTarget"`
	Composition        MultiExecutorComposition    `json:"composition"`
	CompositionRef     string                      `json:"compositionRef"`
	Digest             string                      `json:"digest"`
}

type CompositionDeploymentTarget struct {
	TargetRef string              `json:"targetRef"`
	Provider  string              `json:"provider"`
	Platform  CompositionPlatform `json:"platform"`
}

type CompositionPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type MultiExecutorComposition struct {
	Mode               string                `json:"mode"`
	Routing            string                `json:"routing"`
	Executors          []CompositionExecutor `json:"executors"`
	RoutingReceipt     Pin                   `json:"routingReceipt"`
	CompositionReceipt Pin                   `json:"compositionReceipt"`
}

type CompositionExecutor struct {
	ExecutorProfileRef string                     `json:"executorProfileRef"`
	BaseEnvironmentRef string                     `json:"baseEnvironmentRef"`
	PackRevisionRefs   []string                   `json:"packRevisionRefs"`
	Image              CompositionImage           `json:"image"`
	Reproducibility    CompositionReproducibility `json:"reproducibility"`
}

type CompositionImage struct {
	OCIReference           string             `json:"ociReference"`
	IndexDigest            string             `json:"indexDigest"`
	PlatformManifestDigest string             `json:"platformManifestDigest"`
	ConfigDigest           string             `json:"configDigest"`
	SourceIdentity         Pin                `json:"sourceIdentity"`
	OrderedLayers          []CompositionLayer `json:"orderedLayers"`
}

type CompositionLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type CompositionReproducibility struct {
	SourceAdmissionReceipt        Pin    `json:"sourceAdmissionReceipt"`
	BuildReceipt                  Pin    `json:"buildReceipt"`
	PolicyReceipt                 Pin    `json:"policyReceipt"`
	ConformanceReceipt            Pin    `json:"conformanceReceipt"`
	CompleteOCIArchiveDigest      string `json:"completeOciArchiveDigest"`
	BuildCount                    int    `json:"buildCount"`
	ByteIdenticalCompleteArchives bool   `json:"byteIdenticalCompleteOciArchives"`
}

type routingBody struct {
	Version        int                `json:"version"`
	Kind           string             `json:"kind"`
	ExchangePolicy string             `json:"exchangePolicy"`
	Routes         []CompositionRoute `json:"routes"`
}

type compositionBody struct {
	Version            int                         `json:"version"`
	Kind               string                      `json:"kind"`
	ProfileRevisionRef string                      `json:"profileRevisionRef"`
	DeploymentTarget   CompositionDeploymentTarget `json:"deploymentTarget"`
	Composition        MultiExecutorComposition    `json:"composition"`
}

type compositionEvidence struct {
	Mode           string                `json:"mode"`
	Routing        string                `json:"routing"`
	Executors      []CompositionExecutor `json:"executors"`
	RoutingReceipt Pin                   `json:"routingReceipt"`
}

type CompositionAdmission struct {
	Pin       Pin
	Executors map[string]CompositionExecutor
}

func DecodeCompositionAdmission(
	compositionBytes []byte,
	routingBytes []byte,
) (CompositionAdmission, error) {
	if len(compositionBytes) == 0 || len(compositionBytes) > 1024*1024 ||
		len(routingBytes) == 0 || len(routingBytes) > 512*1024 {
		return CompositionAdmission{}, errors.New("composition or routing document exceeds its bound")
	}
	var routing CompositionRouting
	if err := generationstop.DecodeExactJSON(routingBytes, &routing); err != nil {
		return CompositionAdmission{}, fmt.Errorf("decode exact routing document: %w", err)
	}
	var composition FullImageComposition
	if err := generationstop.DecodeExactJSON(compositionBytes, &composition); err != nil {
		return CompositionAdmission{}, fmt.Errorf("decode exact composition document: %w", err)
	}
	if err := validateRouting(routing); err != nil {
		return CompositionAdmission{}, err
	}
	if err := validateComposition(composition, routing); err != nil {
		return CompositionAdmission{}, err
	}
	executors := make(map[string]CompositionExecutor, len(composition.Composition.Executors))
	for _, executor := range composition.Composition.Executors {
		pack, err := exactSpecialistPack(executor.PackRevisionRefs)
		if err != nil {
			return CompositionAdmission{}, err
		}
		if _, exists := executors[pack]; exists {
			return CompositionAdmission{}, errors.New("composition duplicates a specialist pack")
		}
		executors[pack] = executor
	}
	if len(executors) != len(packExecutables) {
		return CompositionAdmission{}, errors.New("composition does not contain the exact specialist pack roster")
	}
	return CompositionAdmission{
		Pin:       Pin{Ref: composition.CompositionRef, Digest: composition.Digest},
		Executors: executors,
	}, nil
}

func validateRouting(value CompositionRouting) error {
	if value.Version != 1 || value.Kind != "runtime_capability_composition_routing" ||
		value.ExchangePolicy != "authorized_immutable_refs_only" ||
		len(value.Routes) < 2 || len(value.Routes) > 64 {
		return errors.New("runtime capability composition routing is invalid")
	}
	routeRefs := make([]string, len(value.Routes))
	executorRefs := make(map[string]struct{}, len(value.Routes))
	for index, route := range value.Routes {
		if !boundedOperationalRef(route.RouteRef, 512) || !boundedOperationalRef(route.ExecutorProfileRef, 512) ||
			!sortedOperationalRefs(route.ProvidedCapabilityFamilyRefs, 1, 256) ||
			!sortedOperationalRefs(route.ProvidedCapabilityRefs, 1, 256) {
			return errors.New("composition route is invalid")
		}
		routeRefs[index] = route.RouteRef
		if _, duplicate := executorRefs[route.ExecutorProfileRef]; duplicate {
			return errors.New("composition route executor is duplicated")
		}
		executorRefs[route.ExecutorProfileRef] = struct{}{}
	}
	if !sortedStrings(routeRefs) {
		return errors.New("composition routes are not sorted and unique")
	}
	digest, err := semanticDigest(routingBody{
		Version: value.Version, Kind: value.Kind,
		ExchangePolicy: value.ExchangePolicy, Routes: value.Routes,
	})
	if err != nil || value.Digest != digest ||
		value.RoutingRef != "runtime-capability-composition-routing:"+digest {
		return errors.New("composition routing identity is invalid")
	}
	return nil
}

func validateComposition(value FullImageComposition, routing CompositionRouting) error {
	multi := value.Composition
	if value.Version != 2 || value.Kind != "runtime_capability_full_image_composition" ||
		!boundedOperationalRef(value.ProfileRevisionRef, 512) ||
		!boundedOperationalRef(value.DeploymentTarget.TargetRef, 512) ||
		value.DeploymentTarget.Provider != "daytona" || value.DeploymentTarget.Platform.OS != "linux" ||
		value.DeploymentTarget.Platform.Architecture != "amd64" ||
		multi.Mode != "explicit_multi_executor" || multi.Routing != "capability_coverage_map" ||
		len(multi.Executors) != len(packExecutables) ||
		multi.RoutingReceipt != (Pin{Ref: routing.RoutingRef, Digest: routing.Digest}) {
		return errors.New("runtime capability full-image composition is invalid")
	}
	profiles := make([]string, len(multi.Executors))
	routed := make(map[string]struct{}, len(routing.Routes))
	packRefs := make(map[string]struct{})
	for _, route := range routing.Routes {
		routed[route.ExecutorProfileRef] = struct{}{}
	}
	for index, executor := range multi.Executors {
		profiles[index] = executor.ExecutorProfileRef
		if !boundedOperationalRef(executor.ExecutorProfileRef, 512) ||
			!boundedOperationalRef(executor.BaseEnvironmentRef, 512) ||
			!sortedOperationalRefs(executor.PackRevisionRefs, 1, 128) {
			return errors.New("composition executor identity is invalid")
		}
		if _, exists := routed[executor.ExecutorProfileRef]; !exists {
			return errors.New("composition executor has no exact route")
		}
		for _, ref := range executor.PackRevisionRefs {
			if _, duplicate := packRefs[ref]; duplicate {
				return errors.New("composition pack revision is assigned to multiple executors")
			}
			packRefs[ref] = struct{}{}
		}
		if err := validateCompositionImage(executor.Image); err != nil {
			return err
		}
		if err := validateReproducibility(executor.Reproducibility); err != nil {
			return err
		}
	}
	if !sortedStrings(profiles) || len(routed) != len(profiles) ||
		!containsString(profiles, value.ProfileRevisionRef) {
		return errors.New("composition executors are not one-to-one with routes")
	}
	evidence := compositionEvidence{
		Mode: multi.Mode, Routing: multi.Routing,
		Executors: multi.Executors, RoutingReceipt: multi.RoutingReceipt,
	}
	receiptDigest, err := semanticDigest(evidence)
	if err != nil || multi.CompositionReceipt.Digest != receiptDigest ||
		multi.CompositionReceipt.Ref != "runtime-full-image-composition-receipt:"+receiptDigest {
		return errors.New("composition receipt is invalid")
	}
	digest, err := semanticDigest(compositionBody{
		Version: value.Version, Kind: value.Kind, ProfileRevisionRef: value.ProfileRevisionRef,
		DeploymentTarget: value.DeploymentTarget, Composition: value.Composition,
	})
	if err != nil || value.Digest != digest ||
		value.CompositionRef != "runtime-full-image-composition:"+digest {
		return errors.New("composition identity is invalid")
	}
	return nil
}

func validateCompositionImage(value CompositionImage) error {
	if !exactDigest(value.IndexDigest) || !exactDigest(value.PlatformManifestDigest) ||
		!exactDigest(value.ConfigDigest) ||
		value.OCIReference == "" || !strings.HasSuffix(value.OCIReference, "@"+value.IndexDigest) ||
		!validPin(value.SourceIdentity) || len(value.OrderedLayers) == 0 || len(value.OrderedLayers) > 256 {
		return errors.New("composition image identity is invalid")
	}
	for _, layer := range value.OrderedLayers {
		if (layer.MediaType != "application/vnd.oci.image.layer.v1.tar+gzip" &&
			layer.MediaType != "application/vnd.oci.image.layer.v1.tar+zstd") ||
			!exactDigest(layer.Digest) || layer.Size <= 0 || layer.Size > 9_007_199_254_740_991 {
			return errors.New("composition image layer is invalid")
		}
	}
	return nil
}

func validateReproducibility(value CompositionReproducibility) error {
	if !validPin(value.SourceAdmissionReceipt) || !validPin(value.BuildReceipt) ||
		!validPin(value.PolicyReceipt) || !validPin(value.ConformanceReceipt) ||
		!exactDigest(value.CompleteOCIArchiveDigest) || value.BuildCount < 2 || value.BuildCount > 64 ||
		!value.ByteIdenticalCompleteArchives {
		return errors.New("composition reproducibility evidence is invalid")
	}
	return nil
}

func exactSpecialistPack(refs []string) (string, error) {
	matches := make([]string, 0, 1)
	for pack := range packExecutables {
		wanted := "ambit.runtime-pack/" + pack + "@1"
		for _, ref := range refs {
			if ref == wanted {
				matches = append(matches, pack)
			}
		}
	}
	if len(matches) != 1 {
		return "", errors.New("composition executor does not bind exactly one specialist pack")
	}
	return matches[0], nil
}

func validPin(value Pin) bool {
	return boundedOperationalRef(value.Ref, 2048) && exactDigest(value.Digest)
}

func sortedOperationalRefs(values []string, minimum int, maximum int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	for _, value := range values {
		if !boundedOperationalRef(value, 2048) {
			return false
		}
	}
	return sortedStrings(values)
}

func sortedStrings(values []string) bool {
	for index, value := range values {
		if index > 0 && compareCanonicalStrings(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}

// compareCanonicalStrings mirrors JavaScript's relational string comparison:
// lexicographic UTF-16 code-unit order, not Go's UTF-8 byte order.
func compareCanonicalStrings(left string, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] < rightUnits[index] {
			return -1
		}
		if leftUnits[index] > rightUnits[index] {
			return 1
		}
	}
	switch {
	case len(leftUnits) < len(rightUnits):
		return -1
	case len(leftUnits) > len(rightUnits):
		return 1
	default:
		return 0
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func semanticDigest(value any) (string, error) {
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func SortedCompositionPacks(value CompositionAdmission) []string {
	packs := make([]string, 0, len(value.Executors))
	for pack := range value.Executors {
		packs = append(packs, pack)
	}
	sort.Strings(packs)
	return packs
}
