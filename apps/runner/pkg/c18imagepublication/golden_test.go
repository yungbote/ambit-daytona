// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"os"
	"testing"
)

const (
	publicationRequestGoldenSHA256 = "sha256:590a92140f5ec0cbc505ce8c633b5854401acabde8a42bffefeaebcab3f72813"
	publicationReceiptGoldenSHA256 = "sha256:ce3bd42ca26b13e001af795bd1b4930c8232d0f15b537fdd22fa7e281b605f89"
)

func TestCrossLanguagePublicationGoldens(t *testing.T) {
	requestBytes, err := os.ReadFile("testdata/c18-oci-archive-publication-request.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(requestBytes) != publicationRequestGoldenSHA256 {
		t.Fatal("publication request golden raw SHA-256 drifted")
	}
	request, err := ParseRequest(requestBytes)
	if err != nil {
		t.Fatalf("publication request golden is invalid: %v", err)
	}
	if request.ImageTag != request.Source.Revision[:9] || request.UpstreamCertification.Ref == "" {
		t.Fatal("publication request golden lost source or upstream authority")
	}

	receiptBytes, err := os.ReadFile("testdata/c18-oci-archive-publication-receipt.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(receiptBytes) != publicationReceiptGoldenSHA256 {
		t.Fatal("publication receipt golden raw SHA-256 drifted")
	}
	receipt, err := ParseReceipt(receiptBytes)
	if err != nil {
		t.Fatalf("publication receipt golden is invalid: %v", err)
	}
	if receipt.RequestSHA256 != publicationRequestGoldenSHA256 || len(receipt.PublishedArchives) != 4 {
		t.Fatal("publication receipt golden lost its exact request or image roster")
	}
	for _, published := range receipt.PublishedArchives {
		if published.RuntimeImageRef == "" || published.PublicationImageRef == "" ||
			!imageTagState(published.ImageTagState) {
			t.Fatal("publication receipt golden lost digest-only runtime authority")
		}
	}

	receipt.PublishedArchives[0].ImageTagState = "uploaded"
	if _, err := SealReceipt(receipt); err == nil {
		t.Fatal("receipt admitted a tag-mutation disposition")
	}
}
