// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package specialistrender

import (
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestDecodeCompositionAdmissionBindsExactFourPackRoutingAndImages(t *testing.T) {
	routing, composition := compositionFixture(t)
	routingBytes, _ := generationstop.CanonicalJSON(routing)
	compositionBytes, _ := generationstop.CanonicalJSON(composition)
	admission, err := DecodeCompositionAdmission(compositionBytes, routingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if admission.Pin.Ref != composition.CompositionRef || admission.Pin.Digest != composition.Digest ||
		len(admission.Executors) != 4 ||
		admission.Executors["web-browser"].Image.ConfigDigest != composition.Composition.Executors[3].Image.ConfigDigest {
		t.Fatalf("composition admission differs: %#v", admission)
	}

	composition.Composition.Executors[0].Image.ConfigDigest = digestSeed("f")
	tampered, _ := generationstop.CanonicalJSON(composition)
	if _, err := DecodeCompositionAdmission(tampered, routingBytes); err == nil {
		t.Fatal("composition image substitution was accepted")
	}
}

func TestCanonicalCompositionSortUsesUTF16CodeUnits(t *testing.T) {
	astral := "route:\U00010000"
	bmpPrivateUse := "route:\uE000"
	if !(astral > bmpPrivateUse) {
		t.Fatal("test precondition: Go UTF-8 order no longer differs")
	}
	if !sortedStrings([]string{astral, bmpPrivateUse}) ||
		sortedStrings([]string{bmpPrivateUse, astral}) {
		t.Fatal("composition order does not mirror JavaScript UTF-16 comparison")
	}
}

func compositionFixture(t *testing.T) (CompositionRouting, FullImageComposition) {
	t.Helper()
	packs := []string{"data-research", "office-authoring", "pdf-ocr", "web-browser"}
	routes := make([]CompositionRoute, len(packs))
	executors := make([]CompositionExecutor, len(packs))
	for index, pack := range packs {
		profile := "ambit.workspace-runtime/" + pack + "@1"
		routes[index] = CompositionRoute{
			RouteRef: "route:" + pack, ExecutorProfileRef: profile,
			CapabilityFamilyRefs:   []string{"family:" + pack},
			RequiredCapabilityRefs: []string{"ambit.runtime/" + pack + "@1"},
		}
		indexDigest := digestSeed(string(rune('1' + index)))
		executors[index] = CompositionExecutor{
			ExecutorProfileRef: profile, BaseEnvironmentRef: "ambit.runtime-base/debian@1",
			PackRevisionRefs: []string{"ambit.runtime-pack/" + pack + "@1"},
			Image: CompositionImage{
				OCIReference: "registry.test/ambit/" + pack + "@" + indexDigest,
				IndexDigest:  indexDigest, PlatformManifestDigest: digestSeed("6"),
				ConfigDigest:   digestSeed(string(rune('a' + index))),
				SourceIdentity: Pin{Ref: "ambit.git-source/" + pack + "@1", Digest: digestSeed("7")},
				OrderedLayers:  []CompositionLayer{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestSeed("8"), Size: 1000}},
			},
			Reproducibility: CompositionReproducibility{
				SourceAdmissionReceipt:   Pin{Ref: "ambit.source-admission/" + pack + "@1", Digest: digestSeed("9")},
				BuildReceipt:             Pin{Ref: "ambit.build/" + pack + "@1", Digest: digestSeed("a")},
				PolicyReceipt:            Pin{Ref: "ambit.policy/" + pack + "@1", Digest: digestSeed("b")},
				ConformanceReceipt:       Pin{Ref: "ambit.conformance/" + pack + "@1", Digest: digestSeed("c")},
				CompleteOCIArchiveDigest: digestSeed("d"), BuildCount: 2,
				ByteIdenticalCompleteArchives: true,
			},
		}
	}
	routing := CompositionRouting{
		Version: 1, Kind: "runtime_capability_composition_routing",
		ExchangePolicy: "authorized_immutable_refs_only", Routes: routes,
	}
	routing.Digest, _ = semanticDigest(routingBody{
		Version: routing.Version, Kind: routing.Kind,
		ExchangePolicy: routing.ExchangePolicy, Routes: routing.Routes,
	})
	routing.RoutingRef = "runtime-capability-composition-routing:" + routing.Digest
	multi := MultiExecutorComposition{
		Mode: "explicit_multi_executor", Routing: "capability_family_partition",
		Executors: executors, RoutingReceipt: Pin{Ref: routing.RoutingRef, Digest: routing.Digest},
	}
	receiptDigest, _ := semanticDigest(compositionEvidence{
		Mode: multi.Mode, Routing: multi.Routing, Executors: multi.Executors,
		RoutingReceipt: multi.RoutingReceipt,
	})
	multi.CompositionReceipt = Pin{Ref: "runtime-full-image-composition-receipt:" + receiptDigest, Digest: receiptDigest}
	composition := FullImageComposition{
		Version: 2, Kind: "runtime_capability_full_image_composition",
		ProfileRevisionRef: executors[0].ExecutorProfileRef,
		DeploymentTarget: CompositionDeploymentTarget{
			TargetRef: "ambit.runtime-target/local-daytona@1", Provider: "daytona",
			Platform: CompositionPlatform{OS: "linux", Architecture: "amd64"},
		},
		Composition: multi,
	}
	composition.Digest, _ = semanticDigest(compositionBody{
		Version: composition.Version, Kind: composition.Kind,
		ProfileRevisionRef: composition.ProfileRevisionRef,
		DeploymentTarget:   composition.DeploymentTarget, Composition: composition.Composition,
	})
	composition.CompositionRef = "runtime-full-image-composition:" + composition.Digest
	return routing, composition
}

func digestSeed(seed string) string {
	return "sha256:" + strings.Repeat(seed, 64)
}
