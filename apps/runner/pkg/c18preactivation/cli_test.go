// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"testing"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func TestDriverCLIRunsExactCanonicalRequestAndObservationLine(t *testing.T) {
	golden, _ := loadPhysicalGolden(t)
	requestBytes, err := generationstop.CanonicalJSON(golden.Request)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeStreamingProvider{execute: func(
		ctx context.Context,
		input ProviderExecutionInput,
		custody ProviderResponseCustody,
	) (ProviderResponseObservation, error) {
		return successfulStageExecution(t, ctx, input, custody)
	}}
	var stdout bytes.Buffer
	if err := RunCLI(
		context.Background(), bytes.NewReader(append(requestBytes, '\n')), &stdout,
		provider, fixedDriverClock("2026-08-24T00:10:00.000Z"),
	); err != nil {
		t.Fatal(err)
	}
	output := stdout.Bytes()
	if len(output) < 3 || output[len(output)-1] != '\n' || bytes.Count(output, []byte{'\n'}) != 1 {
		t.Fatal("driver CLI output framing is invalid")
	}
	if _, err := ParsePhysicalCaseObservationV2(output[:len(output)-1], golden.Request); err != nil {
		t.Fatal(err)
	}
}

func TestDriverCLIRejectsNoncanonicalFramingBeforeProvider(t *testing.T) {
	golden, _ := loadPhysicalGolden(t)
	requestBytes, err := generationstop.CanonicalJSON(golden.Request)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{name: "missing newline", input: requestBytes},
		{name: "CRLF", input: append(append([]byte(nil), requestBytes...), '\r', '\n')},
		{name: "trailing bytes", input: append(append(append([]byte(nil), requestBytes...), '\n'), 'x')},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &fakeStreamingProvider{execute: successfulStageExecutionWithoutTest}
			if err := RunCLI(
				context.Background(), bytes.NewReader(test.input), &bytes.Buffer{}, provider,
				fixedDriverClock("2026-08-24T00:10:00.000Z"),
			); err == nil {
				t.Fatal("invalid driver framing was admitted")
			}
			if provider.calls != 0 {
				t.Fatal("provider was invoked before request framing admission")
			}
		})
	}
}

func successfulStageExecutionWithoutTest(
	context.Context,
	ProviderExecutionInput,
	ProviderResponseCustody,
) (ProviderResponseObservation, error) {
	return ProviderResponseObservation{}, nil
}
