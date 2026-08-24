// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestPrivateObjectMinIOConditionalChecksumRangeAndDelete(t *testing.T) {
	endpoint := os.Getenv("AMBIT_TEST_MINIO_ENDPOINT")
	if endpoint == "" {
		t.Skip("AMBIT_TEST_MINIO_ENDPOINT is not configured")
	}
	accessKey := os.Getenv("AMBIT_TEST_MINIO_ACCESS_KEY")
	secretKey := os.Getenv("AMBIT_TEST_MINIO_SECRET_KEY")
	bucket := os.Getenv("AMBIT_TEST_MINIO_BUCKET")
	if accessKey == "" || secretKey == "" || bucket == "" {
		t.Fatal("private MinIO integration credentials or bucket are incomplete")
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:           credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:          false,
		Region:          "us-east-1",
		TrailingHeaders: true,
	})
	if err != nil {
		t.Fatalf("new MinIO client: %v", err)
	}
	ctx := context.Background()
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		exists, existsErr := client.BucketExists(ctx, bucket)
		if existsErr != nil || !exists {
			t.Fatalf("create integration bucket: %v (exists error: %v)", err, existsErr)
		}
	}
	storage := &minioClient{client: client, bucketName: bucket}
	key := "private/integration/conditional-checksum-range.bin"
	_ = storage.DeletePrivateObject(ctx, key)
	t.Cleanup(func() { _ = storage.DeletePrivateObject(context.Background(), key) })

	payload := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	if err := storage.CreatePrivateObject(
		ctx,
		key,
		payload,
		"application/octet-stream",
		map[string]string{"contract": "ambit-private-object-integration-v1"},
	); err != nil {
		t.Fatalf("create private object: %v", err)
	}
	if err := storage.CreatePrivateObject(ctx, key, []byte("replacement"), "application/octet-stream", nil); !errors.Is(
		err,
		ErrPrivateObjectAlreadyExists,
	) {
		t.Fatalf("conditional replacement was not rejected: %v", err)
	}
	info, err := storage.StatPrivateObject(ctx, key)
	if err != nil {
		t.Fatalf("stat private object: %v", err)
	}
	if info.Size != int64(len(payload)) || info.ContentSHA256 != canonicalTestSHA256(payload) {
		t.Fatalf("provider checksum authority differs: %#v", info)
	}
	rangeBytes, err := storage.GetPrivateObjectRange(ctx, key, 10, 7)
	if err != nil || string(rangeBytes) != string(payload[10:17]) {
		t.Fatalf("ranged read differs: %q, %v", rangeBytes, err)
	}
	if err := storage.DeletePrivateObject(ctx, key); err != nil {
		t.Fatalf("delete private object: %v", err)
	}
	if _, err := storage.StatPrivateObject(ctx, key); !errors.Is(err, ErrPrivateObjectNotFound) {
		t.Fatalf("deleted object is not absent: %v", err)
	}

	streamKey := "private/integration/stream/list/open.bin"
	_ = storage.DeletePrivateObject(ctx, streamKey)
	t.Cleanup(func() { _ = storage.DeletePrivateObject(context.Background(), streamKey) })
	if err := storage.CreatePrivateObjectStream(
		ctx,
		streamKey,
		strings.NewReader(string(payload)),
		int64(len(payload)),
		"application/octet-stream",
		map[string]string{"sha256": canonicalTestSHA256(payload)},
	); err != nil {
		t.Fatalf("create streamed private object: %v", err)
	}
	stream, streamInfo, err := storage.OpenPrivateObject(ctx, streamKey)
	if err != nil {
		t.Fatalf("open streamed private object: %v", err)
	}
	streamed, readErr := io.ReadAll(stream)
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || string(streamed) != string(payload) ||
		streamInfo.Size != int64(len(payload)) || streamInfo.UserMetadata["sha256"] != canonicalTestSHA256(payload) {
		t.Fatalf("streamed private object differs: info=%#v read=%v close=%v", streamInfo, readErr, closeErr)
	}
	listed, err := storage.ListPrivateObjects(ctx, "private/integration/stream/", 8)
	if err != nil || len(listed) != 1 || listed[0] != streamKey {
		t.Fatalf("bounded private object list differs: %#v, %v", listed, err)
	}

	concurrentKey := "private/integration/concurrent-conditional-create.bin"
	_ = storage.DeletePrivateObject(ctx, concurrentKey)
	t.Cleanup(func() { _ = storage.DeletePrivateObject(context.Background(), concurrentKey) })
	var group sync.WaitGroup
	var resultLock sync.Mutex
	successes := 0
	for index := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := storage.CreatePrivateObject(
				ctx,
				concurrentKey,
				[]byte(fmt.Sprintf("candidate-%02d", index)),
				"application/octet-stream",
				nil,
			)
			resultLock.Lock()
			defer resultLock.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrPrivateObjectAlreadyExists):
			default:
				t.Errorf("concurrent conditional create returned unexpected error: %v", err)
			}
		}()
	}
	group.Wait()
	if successes != 1 {
		t.Fatalf("concurrent conditional create admitted %d winners", successes)
	}
	winner, err := storage.GetPrivateObject(ctx, concurrentKey, 64)
	if err != nil || len(winner) != len("candidate-00") {
		t.Fatalf("concurrent immutable winner is unreadable: %q, %v", winner, err)
	}
}

func canonicalTestSHA256(data []byte) string {
	// Keep this test independent from WorkingCopy internals while asserting the
	// exact canonical storage checksum shape.
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}
