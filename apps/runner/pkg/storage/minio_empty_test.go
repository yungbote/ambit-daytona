// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func emptyDigests() (canonical, encoded string) {
	digest := sha256.Sum256(nil)
	return "sha256:" + hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(digest[:])
}

func transportStorage(t *testing.T, handler http.HandlerFunc) *minioClient {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := minio.New(strings.TrimPrefix(server.URL, "https://"), &minio.Options{
		Creds: credentials.NewStaticV4("test-access", "test-secret", ""), Secure: true,
		Region: "us-east-1", TrailingHeaders: true, Transport: server.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &minioClient{client: client, bucketName: "private-test"}
}

func objectHeaders(w http.ResponseWriter, size int, checksum, version string, metadata map[string]string) {
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`)
	w.Header().Set("Last-Modified", time.Date(2026, 9, 16, 19, 57, 31, 0, time.UTC).Format(http.TimeFormat))
	if checksum != "" {
		w.Header().Set("X-Amz-Checksum-Sha256", checksum)
	}
	if version != "" {
		w.Header().Set("X-Amz-Version-Id", version)
	}
	for key, value := range metadata {
		w.Header().Set("X-Amz-Meta-"+key, value)
	}
}

func TestEmptyPrivateCreatesSendActualProviderChecksumHeader(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		t.Run(fmt.Sprint("streamed=", streamed), func(t *testing.T) {
			canonical, encoded := emptyDigests()
			puts, gets := 0, 0
			storedChecksum := ""
			store := transportStorage(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPut:
					puts++
					storedChecksum = r.Header.Get("X-Amz-Checksum-Sha256")
					if storedChecksum != encoded {
						t.Errorf("empty upload omitted exact provider checksum: %q", storedChecksum)
					}
					if r.Header.Get("If-None-Match") != "*" {
						t.Errorf("conditional create lost: %q", r.Header.Get("If-None-Match"))
					}
					body, err := io.ReadAll(r.Body)
					if err != nil || len(body) != 0 {
						t.Errorf("empty request payload changed: %d %v", len(body), err)
					}
					objectHeaders(w, 0, storedChecksum, "version-1", nil)
				case http.MethodHead:
					objectHeaders(w, 0, storedChecksum, "version-1", nil)
				case http.MethodGet:
					gets++
					t.Error("new checksum-bearing empty object needed recovery read")
					objectHeaders(w, 0, storedChecksum, "version-1", nil)
				default:
					t.Errorf("unexpected storage method %s", r.Method)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			metadata := map[string]string{"contract": "unchanged-input"}
			var err error
			if streamed {
				err = store.CreatePrivateObjectStream(context.Background(), "empty", bytes.NewReader(nil), 0, "application/octet-stream", metadata)
			} else {
				err = store.CreatePrivateObject(context.Background(), "empty", nil, "application/octet-stream", metadata)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(metadata) != 1 {
				t.Fatal("caller metadata was mutated")
			}
			info, err := store.StatPrivateObject(context.Background(), "empty")
			if err != nil || info.Size != 0 || info.ContentSHA256 != canonical || puts != 1 || gets != 0 {
				t.Fatalf("new empty object lost checksum custody: %#v %v", info, err)
			}
		})
	}
}

func TestRetainedEmptyCaptureMetadataRecoversOnlyThroughConditionalEOF(t *testing.T) {
	canonical, _ := emptyDigests()
	// These are the complete immutable-content metadata dimensions of the
	// retained zero-byte receipt that exposed the missing provider checksum.
	metadata := map[string]string{
		"sha256": canonical, "byte-length": "0", "captured-at": "2026-09-16T19:57:31.259Z",
		"provider-resource-id": "daytona-sandbox-file-capture:v1:sha256:23aef57035ee6e9bdb098544e6da43d5aceafb80efe852e769503f61a3df15d6",
		"contract":             "ambit-working-copy-capture-content-v2",
	}
	for _, version := range []string{"", "version-1"} {
		t.Run("version="+version, func(t *testing.T) {
			gets := 0
			store := transportStorage(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					gets++
					if r.Header.Get("If-Match") != `"d41d8cd98f00b204e9800998ecf8427e"` || r.URL.Query().Get("versionId") != version {
						t.Error("recovery did not bind exact HEAD identity")
					}
				} else if r.Method != http.MethodHead {
					t.Errorf("recovery mutated storage with %s", r.Method)
				}
				objectHeaders(w, 0, "", version, metadata)
			})
			info, err := store.StatPrivateObject(context.Background(), "retained-empty")
			if err != nil || info.ContentSHA256 != canonical || info.Size != 0 || gets != 1 {
				t.Fatalf("retained empty read failed: %#v gets=%d err=%v", info, gets, err)
			}
			for key, expected := range metadata {
				if info.UserMetadata[key] != expected {
					t.Fatalf("retained receipt metadata %q changed", key)
				}
			}
			if info.VersionID != version {
				t.Fatal("retained object version changed")
			}
		})
	}
}

func TestEmptyChecksumRecoveryDoesNotNormalizeOtherMissingOrMalformedChecksums(t *testing.T) {
	for _, test := range []struct {
		name     string
		size     int
		checksum string
	}{
		{"nonempty-missing", 1, ""}, {"empty-malformed", 0, "not-base64"}, {"empty-truncated", 0, "YQ=="},
	} {
		t.Run(test.name, func(t *testing.T) {
			gets := 0
			store := transportStorage(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					gets++
				}
				objectHeaders(w, test.size, test.checksum, "version-1", map[string]string{"sha256": "caller-metadata-is-not-authority"})
			})
			info, err := store.StatPrivateObject(context.Background(), "invalid-checksum")
			if err != nil || info.ContentSHA256 != "" || gets != 0 {
				t.Fatalf("missing/malformed checksum was excused: %#v gets=%d err=%v", info, gets, err)
			}
		})
	}
}

func TestRetainedEmptyChecksumRefusesNonEOFOrChangedIdentity(t *testing.T) {
	for _, test := range []string{"bytes", "version", "etag", "metadata", "checksum", "precondition"} {
		t.Run(test, func(t *testing.T) {
			gets := 0
			store := transportStorage(t, func(w http.ResponseWriter, r *http.Request) {
				metadata := map[string]string{"contract": "original"}
				version, checksum, body := "version-1", "", ""
				if r.Method == http.MethodGet {
					gets++
					switch test {
					case "bytes":
						body = "x"
					case "version":
						version = "other-version"
					case "metadata":
						metadata["contract"] = "changed"
					case "checksum":
						checksum = "malformed"
					case "precondition":
						w.Header().Set("Content-Type", "application/xml")
						w.WriteHeader(http.StatusPreconditionFailed)
						_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code><Message>Changed</Message></Error>`)
						return
					}
				}
				objectHeaders(w, len(body), checksum, version, metadata)
				if test == "etag" && r.Method == http.MethodGet {
					w.Header().Set("ETag", `"changed"`)
				}
				if r.Method == http.MethodGet {
					_, _ = io.WriteString(w, body)
				}
			})
			if info, err := store.StatPrivateObject(context.Background(), "retained-empty"); err == nil || info.ContentSHA256 != "" || gets != 1 {
				t.Fatalf("changed empty custody was admitted: %#v gets=%d err=%v", info, gets, err)
			}
		})
	}
}
