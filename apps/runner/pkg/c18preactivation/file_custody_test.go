// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/daytonaio/runner/pkg/specialistrender"
)

func TestTemporaryProviderResponseCustodyRetainsOnlyUnlinkedDescriptors(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := bytes.Repeat([]byte("file-backed-provider-response-"), 5_000)
	receipt := testProviderReceipt(t, request, payload)
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			}, Cleanup: func() error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	custody, err := NewTemporaryProviderResponseCustody()
	if err != nil {
		t.Fatal(err)
	}
	root := custody.root
	observation, err := ObserveProviderResponseStream(
		context.Background(), bytes.NewReader(encoded.Bytes()), request, custody,
	)
	if err != nil {
		t.Fatal(err)
	}
	if observation.WireSHA256 != sha256Digest(encoded.Bytes()) {
		t.Fatal("temporary custody changed response wire identity")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("temporary custody names remained after commit")
	}
	reader, err := custody.Open(receipt.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	retained, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !bytes.Equal(retained, payload) {
		t.Fatal("unlinked descriptor custody changed provider bytes")
	}
	first, err := custody.Open(receipt.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := custody.Open(receipt.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, firstErr := io.ReadAll(first)
	secondBytes, secondErr := io.ReadAll(second)
	_ = first.Close()
	_ = second.Close()
	if firstErr != nil || secondErr != nil || !bytes.Equal(firstBytes, payload) || !bytes.Equal(secondBytes, payload) {
		t.Fatal("fresh custody readers shared a mutable offset")
	}
	if err := custody.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := custody.Open(receipt.Files[0]); err == nil {
		t.Fatal("cleaned custody reopened a provider object")
	}
}

func TestTemporaryProviderResponseCustodyAbortsAndRemovesInvalidStream(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("result")
	receipt := testProviderReceipt(t, request, payload)
	var encoded bytes.Buffer
	if err := specialistrender.EncodeResponseStream(context.Background(), &encoded, specialistrender.ExecutionResult{
		Receipt: receipt,
		Files: []specialistrender.Payload{{
			File: receipt.Files[0], Open: func(context.Context) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			}, Cleanup: func() error { return nil },
		}},
	}); err != nil {
		t.Fatal(err)
	}
	custody, err := NewTemporaryProviderResponseCustody()
	if err != nil {
		t.Fatal(err)
	}
	root := custody.root
	corrupt := append(append([]byte(nil), encoded.Bytes()...), 'x')
	if _, err := ObserveProviderResponseStream(
		context.Background(), bytes.NewReader(corrupt), request, custody,
	); err == nil {
		t.Fatal("invalid response stream was committed")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("aborted response custody remained on disk")
	}
	if err := custody.Cleanup(); err != nil {
		t.Fatal(err)
	}
}
