// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type multipartPatternReader struct {
	left  int64
	value byte
}

func (r *multipartPatternReader) Read(buffer []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	if int64(len(buffer)) > r.left {
		buffer = buffer[:r.left]
	}
	for i := range buffer {
		buffer[i] = r.value
	}
	r.left -= int64(len(buffer))
	return len(buffer), nil
}

type multipartWitnessTransport struct {
	base        http.RoundTripper
	conditional atomic.Int64
	mu          sync.Mutex
	cancelKey   string
	cancel      context.CancelFunc
}

func (w *multipartWitnessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPost && request.URL.Query().Get("uploadId") != "" && request.Header.Get("If-None-Match") == "*" {
		w.conditional.Add(1)
	}
	response, err := w.base.RoundTrip(request)
	w.mu.Lock()
	if err == nil && response.StatusCode == http.StatusOK && request.Method == http.MethodPut && request.URL.Query().Get("partNumber") == "1" && request.URL.Path == w.cancelKey && w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	w.mu.Unlock()
	return response, err
}

func TestPrivateObjectMultipartConditionalRaceAndCancellation(t *testing.T) {
	endpoint := os.Getenv("AMBIT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("task-owned MinIO endpoint is not configured")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Scheme != "http" {
		t.Fatal("multipart reality test requires task-owned loopback MinIO")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	bucket := "ambit-multipart-" + hex.EncodeToString(nonce)
	transport := &multipartWitnessTransport{base: http.DefaultTransport.(*http.Transport).Clone()}
	client, err := minio.New(parsed.Host, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("AMBIT_TEST_S3_ACCESS_KEY_ID"), os.Getenv("AMBIT_TEST_S3_SECRET_ACCESS_KEY"), ""), Region: "us-east-1", TrailingHeaders: true, Transport: transport})
	if err != nil {
		t.Fatal("task multipart client initialization failed")
	}
	ctx := context.Background()
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		t.Fatal("task multipart bucket creation failed")
	}
	store := &minioClient{client: client, bucketName: bucket}
	// The pinned SDK's physical multipart threshold is 16 MiB; this length
	// exercises multiple parts without allocating the logical file in memory.
	const size int64 = 33 * 1024 * 1024
	digest := func(value byte) string {
		hash := sha256.New()
		_, _ = io.Copy(hash, &multipartPatternReader{left: size, value: value})
		return "sha256:" + hex.EncodeToString(hash.Sum(nil))
	}
	t.Run("conditional completion and independent body checksum", func(t *testing.T) {
		key := "multipart/conditional"
		if err := store.createPrivateMultipart(ctx, key, &multipartPatternReader{left: size, value: 'A'}, size, "application/octet-stream", map[string]string{"sha256": "fixture-metadata-is-not-checksum-nosecret"}); err != nil {
			t.Fatal(err)
		}
		if err := store.createPrivateMultipart(ctx, key, &multipartPatternReader{left: size, value: 'B'}, size, "application/octet-stream", nil); !errors.Is(err, ErrPrivateObjectAlreadyExists) {
			t.Fatalf("multipart replaced immutable content: %v", err)
		}
		body, info, err := store.OpenPrivateObject(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		count, readErr := io.Copy(hash, body)
		closeErr := body.Close()
		if readErr != nil || closeErr != nil || count != size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest('A') {
			t.Fatal("multipart bytes or length differ")
		}
		if info.ContentSHA256 != "" && info.ContentSHA256 != digest('A') {
			t.Fatal("composite or metadata was misreported as a full SHA256")
		}
		t.Logf("multipart fullChecksumAvailable=%t, completionIfNoneMatch=%d", info.ContentSHA256 != "", transport.conditional.Load())
		if transport.conditional.Load() < 1 {
			t.Fatal("multipart completion lacked If-None-Match")
		}
	})
	t.Run("two concurrent immutable publishers have one winner", func(t *testing.T) {
		var group sync.WaitGroup
		results := make(chan error, 2)
		for _, value := range []byte{'A', 'B'} {
			group.Add(1)
			go func(value byte) {
				defer group.Done()
				results <- store.createPrivateMultipart(ctx, "multipart/race", &multipartPatternReader{left: size, value: value}, size, "application/octet-stream", nil)
			}(value)
		}
		group.Wait()
		close(results)
		wins, refused := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else if errors.Is(err, ErrPrivateObjectAlreadyExists) {
				refused++
			} else {
				t.Fatal(err)
			}
		}
		if wins != 1 || refused != 1 {
			t.Fatalf("multipart race: wins=%d refused=%d", wins, refused)
		}
	})
	t.Run("cancel after a real part leaves no object or abandoned upload", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		transport.mu.Lock()
		transport.cancelKey = "/" + bucket + "/multipart/cancel"
		transport.cancel = cancel
		transport.mu.Unlock()
		if err := store.createPrivateMultipart(cancelCtx, "multipart/cancel", &multipartPatternReader{left: size, value: 'C'}, size, "application/octet-stream", nil); err == nil {
			t.Fatal("canceled multipart completed")
		}
		if _, err := store.StatPrivateObject(ctx, "multipart/cancel"); !errors.Is(err, ErrPrivateObjectNotFound) {
			t.Fatal("canceled multipart published content")
		}
		incomplete := 0
		for upload := range client.ListIncompleteUploads(ctx, bucket, "multipart/cancel", true) {
			if upload.Err != nil {
				t.Fatal("multipart cleanup observation failed")
			}
			incomplete++
		}
		if incomplete != 0 {
			t.Fatalf("canceled multipart left %d abandoned uploads", incomplete)
		}
	})
}
