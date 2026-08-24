// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package storage

import (
	"context"
	"errors"
)

// ObjectStorageClient defines the interface for object storage operations
type ObjectStorageClient interface {
	GetObject(ctx context.Context, organizationId, hash string) ([]byte, error)
}

var (
	ErrPrivateObjectAlreadyExists = errors.New("private object already exists")
	ErrPrivateObjectNotFound      = errors.New("private object not found")
	ErrPrivateObjectTooLarge      = errors.New("private object exceeds the read limit")
)

// PrivateObjectInfo is the narrow metadata surface needed by provider-owned
// durable effects. Keys remain private to the caller and are never returned
// through a public API.
type PrivateObjectInfo struct {
	Size          int64
	ContentSHA256 string
	ETag          string
	VersionID     string
	UserMetadata  map[string]string
}

// PrivateObjectStorageClient is the runner-owned durable object boundary.
// Create is deliberately conditional: an exact replay must reconcile the
// existing object instead of replacing it.
type PrivateObjectStorageClient interface {
	CreatePrivateObject(
		ctx context.Context,
		key string,
		data []byte,
		contentType string,
		metadata map[string]string,
	) error
	GetPrivateObject(ctx context.Context, key string, maximumBytes int64) ([]byte, error)
	GetPrivateObjectRange(ctx context.Context, key string, offset, maximumBytes int64) ([]byte, error)
	StatPrivateObject(ctx context.Context, key string) (PrivateObjectInfo, error)
	DeletePrivateObject(ctx context.Context, key string) error
}
