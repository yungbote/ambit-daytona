// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"fmt"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const ProviderRequestSourceAuthorityContract = "C18ProviderRequestSourceAuthority@1"

type ProviderRequestSourceSelection struct {
	Facet               string `json:"facet"`
	PackID              string `json:"packId"`
	RequestRelativePath string `json:"requestRelativePath"`
	SourceRelativePath  string `json:"sourceRelativePath"`
}

type ProviderRequestSourceAuthority struct {
	Contract   string                           `json:"contract"`
	Selections []ProviderRequestSourceSelection `json:"selections"`
}

var exactProviderRequestSourceSelections = []ProviderRequestSourceSelection{
	{Facet: "data_analysis", PackID: "data-research", RequestRelativePath: "inputs/c18-render-probe/data-analysis-csv/request.json", SourceRelativePath: "inputs/c18-render-probe/data-analysis-csv/source.csv"},
	{Facet: "pdf", PackID: "pdf-ocr", RequestRelativePath: "inputs/c18-render-probe/pdf-document/request.json", SourceRelativePath: "inputs/c18-render-probe/pdf-document/source.pdf"},
	{Facet: "presentation", PackID: "office-authoring", RequestRelativePath: "inputs/c18-render-probe/presentation-pptx/request.json", SourceRelativePath: "inputs/c18-render-probe/presentation-pptx/source.pptx"},
	{Facet: "research", PackID: "data-research", RequestRelativePath: "inputs/c18-render-probe/research-markdown/request.json", SourceRelativePath: "inputs/c18-render-probe/research-markdown/source.md"},
	{Facet: "spreadsheet", PackID: "office-authoring", RequestRelativePath: "inputs/c18-render-probe/spreadsheet-xlsx/request.json", SourceRelativePath: "inputs/c18-render-probe/spreadsheet-xlsx/source.xlsx"},
	{Facet: "web_application", PackID: "web-browser", RequestRelativePath: "inputs/c18-render-probe/web-static-html/request.json", SourceRelativePath: "inputs/c18-render-probe/web-static-html/source.html"},
}

// ParseProviderRequestSourceAuthority admits the source-owned, release-hashed
// choice of one real conformance source per live provider facet. The roster is
// deliberately finite: adding or changing a case requires a source-contract
// revision and a new release, rather than a release operator choosing rows.
func ParseProviderRequestSourceAuthority(data []byte) (ProviderRequestSourceAuthority, error) {
	if len(data) < 2 || data[len(data)-1] != '\n' || bytes.ContainsAny(data[:len(data)-1], "\r\n") {
		return ProviderRequestSourceAuthority{}, fmt.Errorf("provider request source authority framing is invalid")
	}
	data = data[:len(data)-1]
	var value ProviderRequestSourceAuthority
	if err := generationstop.DecodeCanonicalJSON(data, &value); err != nil {
		return ProviderRequestSourceAuthority{}, fmt.Errorf("decode canonical provider request source authority: %w", err)
	}
	if value.Contract != ProviderRequestSourceAuthorityContract || len(value.Selections) != len(exactProviderRequestSourceSelections) {
		return ProviderRequestSourceAuthority{}, fmt.Errorf("provider request source authority identity is invalid")
	}
	actual, err := generationstop.CanonicalJSON(value.Selections)
	if err != nil {
		return ProviderRequestSourceAuthority{}, err
	}
	expected, err := generationstop.CanonicalJSON(exactProviderRequestSourceSelections)
	if err != nil {
		return ProviderRequestSourceAuthority{}, err
	}
	if !bytes.Equal(actual, expected) {
		return ProviderRequestSourceAuthority{}, fmt.Errorf("provider request source authority roster is invalid")
	}
	return value, nil
}
