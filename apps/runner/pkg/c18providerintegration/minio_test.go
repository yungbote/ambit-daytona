// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18providerintegration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daytonaio/runner/pkg/storage"
)

func TestRunMinIOIntegrationExercisesExactProductionStorageSurface(t *testing.T) {
	objects := &memoryObjects{values: make(map[string]memoryObject)}
	times := []time.Time{
		time.Date(2026, 8, 25, 4, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 25, 4, 0, 1, 0, time.UTC),
	}
	index := 0
	receipt, err := RunMinIOIntegration(
		context.Background(),
		MinIOIntegrationRun{
			Contract:        MinIOIntegrationRunContract,
			SourceRevision:  "1" + strings.Repeat("0", 39),
			SourceTree:      "2" + strings.Repeat("0", 39),
			SourceSetDigest: digestSeed(3),
			RunID:           "33333333-3333-4333-8333-333333333333",
		},
		objects,
		func() time.Time {
			value := times[index]
			index++
			return value
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != "passed" || receipt.Observations.ConditionalCreate.ConcurrentWinners != 1 ||
		receipt.Observations.BoundedList.Count != 1 || !receipt.Observations.Delete.AllAbsent {
		t.Fatalf("MinIO integration receipt differs: %#v", receipt)
	}
	if len(objects.values) != 0 {
		t.Fatalf("integration keys remain after exact deletion: %#v", objects.values)
	}
	if objects.creates != 19 || objects.stats < 4 || objects.ranges != 1 ||
		objects.opens != 1 || objects.lists != 1 {
		t.Fatalf("storage operation census differs: %#v", objects)
	}
	encoded, _ := EncodeCanonical(receipt)
	if _, err := ParseMinIOIntegrationReceipt(encoded); err != nil {
		t.Fatal(err)
	}
}

type memoryObject struct {
	bytes    []byte
	metadata map[string]string
}

type memoryObjects struct {
	mu      sync.Mutex
	values  map[string]memoryObject
	creates int
	stats   int
	ranges  int
	opens   int
	lists   int
}

func (objects *memoryObjects) CreatePrivateObject(
	_ context.Context,
	key string,
	data []byte,
	_ string,
	metadata map[string]string,
) error {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.creates++
	if _, exists := objects.values[key]; exists {
		return storage.ErrPrivateObjectAlreadyExists
	}
	objects.values[key] = memoryObject{bytes: append([]byte(nil), data...), metadata: cloneMap(metadata)}
	return nil
}

func (objects *memoryObjects) CreatePrivateObjectStream(
	ctx context.Context,
	key string,
	reader io.Reader,
	size int64,
	contentType string,
	metadata map[string]string,
) error {
	data, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil || int64(len(data)) != size {
		return errors.New("stream differs")
	}
	return objects.CreatePrivateObject(ctx, key, data, contentType, metadata)
}

func (objects *memoryObjects) GetPrivateObject(_ context.Context, key string, maximumBytes int64) ([]byte, error) {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	value, exists := objects.values[key]
	if !exists {
		return nil, storage.ErrPrivateObjectNotFound
	}
	if int64(len(value.bytes)) > maximumBytes {
		return nil, storage.ErrPrivateObjectTooLarge
	}
	return append([]byte(nil), value.bytes...), nil
}

func (objects *memoryObjects) GetPrivateObjectRange(_ context.Context, key string, offset, maximumBytes int64) ([]byte, error) {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.ranges++
	value, exists := objects.values[key]
	if !exists {
		return nil, storage.ErrPrivateObjectNotFound
	}
	if offset < 0 || maximumBytes <= 0 || offset >= int64(len(value.bytes)) {
		return nil, errors.New("invalid range")
	}
	end := offset + maximumBytes
	if end > int64(len(value.bytes)) {
		end = int64(len(value.bytes))
	}
	return append([]byte(nil), value.bytes[offset:end]...), nil
}

func (objects *memoryObjects) StatPrivateObject(_ context.Context, key string) (storage.PrivateObjectInfo, error) {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.stats++
	value, exists := objects.values[key]
	if !exists {
		return storage.PrivateObjectInfo{}, storage.ErrPrivateObjectNotFound
	}
	return storage.PrivateObjectInfo{
		Size: int64(len(value.bytes)), ContentSHA256: digestBytes(value.bytes),
		UserMetadata: cloneMap(value.metadata),
	}, nil
}

func (objects *memoryObjects) OpenPrivateObject(_ context.Context, key string) (io.ReadCloser, storage.PrivateObjectInfo, error) {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.opens++
	value, exists := objects.values[key]
	if !exists {
		return nil, storage.PrivateObjectInfo{}, storage.ErrPrivateObjectNotFound
	}
	data := append([]byte(nil), value.bytes...)
	return io.NopCloser(bytes.NewReader(data)), storage.PrivateObjectInfo{
		Size: int64(len(data)), ContentSHA256: digestBytes(data), UserMetadata: cloneMap(value.metadata),
	}, nil
}

func (objects *memoryObjects) ListPrivateObjects(_ context.Context, prefix string, maximum int) ([]string, error) {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	objects.lists++
	values := make([]string, 0)
	for key := range objects.values {
		if strings.HasPrefix(key, prefix) {
			values = append(values, key)
		}
	}
	sort.Strings(values)
	if len(values) > maximum {
		return nil, storage.ErrPrivateObjectListTooLarge
	}
	return values, nil
}

func (objects *memoryObjects) DeletePrivateObject(_ context.Context, key string) error {
	objects.mu.Lock()
	defer objects.mu.Unlock()
	delete(objects.values, key)
	return nil
}

func cloneMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	target := make(map[string]string, len(source))
	for key, value := range source {
		target[strings.ToLower(key)] = value
	}
	return target
}
