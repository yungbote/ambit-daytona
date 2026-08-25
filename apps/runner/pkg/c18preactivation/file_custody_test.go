// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

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
		context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), request, custody,
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
		context.Background(), io.NopCloser(bytes.NewReader(corrupt)), request, custody,
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

func TestTemporaryProviderResponseCustodySurfacesAndRetriesCleanupFailure(t *testing.T) {
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
	cleanupFailure := errors.New("injected cleanup failure")
	custody.removeAll = func(string) error { return cleanupFailure }
	corrupt := append(append([]byte(nil), encoded.Bytes()...), 'x')
	if _, err := ObserveProviderResponseStream(
		context.Background(), io.NopCloser(bytes.NewReader(corrupt)), request, custody,
	); !errors.Is(err, cleanupFailure) {
		t.Fatalf("cleanup failure was not surfaced: %v", err)
	}
	if custody.root == "" {
		t.Fatal("failed cleanup discarded its retry target")
	}
	custody.removeAll = os.RemoveAll
	if err := custody.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryProviderResponseCustodyRehashesStagedFileBeforeCommit(t *testing.T) {
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
	temporary, err := NewTemporaryProviderResponseCustody()
	if err != nil {
		t.Fatal(err)
	}
	custody := &tamperingResponseCustody{TemporaryProviderResponseCustody: temporary}
	if _, err := ObserveProviderResponseStream(
		context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), request, custody,
	); err == nil {
		t.Fatal("same-UID staged-file mutation was admitted")
	}
}

func TestTemporaryProviderResponseCustodyAbortCleansAfterOperationCancellation(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := []byte("cancelled concrete custody")
	receipt := testProviderReceipt(t, request, payload)
	custody, err := NewTemporaryProviderResponseCustody()
	if err != nil {
		t.Fatal(err)
	}
	root := custody.root
	if err := custody.AdmitReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	writer, err := custody.OpenFile(context.Background(), receipt.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if written, err := writer.WriteContext(context.Background(), payload); err != nil || written != len(payload) {
		t.Fatalf("stage concrete custody: written=%d err=%v", written, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := custody.Abort(cancelled); err != nil {
		t.Fatalf("separately bounded abort did not clean cancelled custody: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("cancelled concrete custody root remains: %v", err)
	}
	if err := custody.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryProviderResponseCustodyCancelsDuringConcreteRehash(t *testing.T) {
	request, _, _ := testProviderRequest(t)
	payload := bytes.Repeat([]byte("rehash-cancellation"), 10_000)
	receipt := testProviderReceipt(t, request, payload)
	custody, err := NewTemporaryProviderResponseCustody()
	if err != nil {
		t.Fatal(err)
	}
	root := custody.root
	if err := custody.AdmitReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	writer, err := custody.OpenFile(context.Background(), receipt.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if written, err := writer.WriteContext(context.Background(), payload); err != nil || written != len(payload) {
		t.Fatalf("stage concrete custody: written=%d err=%v", written, err)
	}
	ctx := newStepCancellationContext(5)
	observation := ProviderResponseObservation{Receipt: receipt, WireSHA256: "sha256:" + repeatHex("a")}
	if err := custody.Commit(ctx, observation); !errors.Is(err, context.Canceled) ||
		custody.state == temporaryCustodyCommitted {
		t.Fatalf("concrete rehash ignored cancellation: state=%d err=%v", custody.state, err)
	}
	if err := custody.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := custody.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("cancelled rehash custody root remains: %v", err)
	}
}

type tamperingResponseCustody struct {
	*TemporaryProviderResponseCustody
}

type stepCancellationContext struct {
	mu       sync.Mutex
	calls    int
	cancelAt int
	done     chan struct{}
	once     sync.Once
}

func newStepCancellationContext(cancelAt int) *stepCancellationContext {
	return &stepCancellationContext{cancelAt: cancelAt, done: make(chan struct{})}
}

func (*stepCancellationContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *stepCancellationContext) Done() <-chan struct{}   { return ctx.done }
func (*stepCancellationContext) Value(any) any               { return nil }

func (ctx *stepCancellationContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.calls++
	if ctx.calls < ctx.cancelAt {
		return nil
	}
	ctx.once.Do(func() { close(ctx.done) })
	return context.Canceled
}

func (custody *tamperingResponseCustody) Commit(
	ctx context.Context,
	observation ProviderResponseObservation,
) error {
	if _, err := custody.files[0].file.WriteAt([]byte{'X'}, 0); err != nil {
		return err
	}
	return custody.TemporaryProviderResponseCustody.Commit(ctx, observation)
}
