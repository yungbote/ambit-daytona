// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/daytonaio/runner/cmd/runner/config"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const CONTEXT_TAR_FILE_NAME = "context.tar"

type minioClient struct {
	client     *minio.Client
	bucketName string
}

var instance ObjectStorageClient

var privateInstance PrivateObjectStorageClient

func GetObjectStorageClient() (ObjectStorageClient, error) {
	if instance != nil {
		return instance, nil
	}

	client, err := newMinioClientFromConfig()
	if err != nil {
		return nil, err
	}
	instance = client
	if privateInstance == nil {
		privateInstance = client
	}
	return instance, nil
}

func GetPrivateObjectStorageClient() (PrivateObjectStorageClient, error) {
	if privateInstance != nil {
		return privateInstance, nil
	}

	client, err := newMinioClientFromConfig()
	if err != nil {
		return nil, err
	}
	privateInstance = client
	if instance == nil {
		instance = client
	}
	return privateInstance, nil
}

func newMinioClientFromConfig() (*minioClient, error) {

	runnerConfig, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	endpoint := runnerConfig.AWSEndpointUrl
	accessKeyId := runnerConfig.AWSAccessKeyId
	secretKey := runnerConfig.AWSSecretAccessKey
	bucketName := runnerConfig.AWSDefaultBucket
	region := runnerConfig.AWSRegion

	useSSL := strings.HasPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	if endpoint == "" || accessKeyId == "" || secretKey == "" || bucketName == "" || region == "" {
		return nil, fmt.Errorf("missing S3 configuration - endpoint, access key, secret key, region, or bucket name not provided")
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyId, secretKey, ""),
		Secure: useSSL,
		Region: region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 client: %w", err)
	}

	return &minioClient{
		client:     client,
		bucketName: bucketName,
	}, nil
}

func (m *minioClient) GetObject(ctx context.Context, organizationId, hash string) ([]byte, error) {
	objectPath := fmt.Sprintf("%s/%s/%s", organizationId, hash, CONTEXT_TAR_FILE_NAME)
	obj, err := m.client.GetObject(ctx, m.bucketName, objectPath, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get object from storage: %w", err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to read object data: %w", err)
	}

	return data, nil
}

func (m *minioClient) CreatePrivateObject(
	ctx context.Context,
	key string,
	data []byte,
	contentType string,
	metadata map[string]string,
) error {
	opts := minio.PutObjectOptions{
		ContentType:  contentType,
		UserMetadata: cloneStringMap(metadata),
	}
	opts.SetMatchETagExcept("*")
	_, err := m.client.PutObject(
		ctx,
		m.bucketName,
		key,
		bytes.NewReader(data),
		int64(len(data)),
		opts,
	)
	if err != nil {
		if isPreconditionFailure(err) {
			return ErrPrivateObjectAlreadyExists
		}
		return fmt.Errorf("create private object: %w", err)
	}
	return nil
}

func (m *minioClient) GetPrivateObject(ctx context.Context, key string, maximumBytes int64) ([]byte, error) {
	if maximumBytes < 0 {
		return nil, fmt.Errorf("private object maximum must be non-negative")
	}
	obj, err := m.client.GetObject(ctx, m.bucketName, key, minio.GetObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrPrivateObjectNotFound
		}
		return nil, fmt.Errorf("open private object: %w", err)
	}
	defer obj.Close()

	data, err := io.ReadAll(io.LimitReader(obj, maximumBytes+1))
	if err != nil {
		if isNotFound(err) {
			return nil, ErrPrivateObjectNotFound
		}
		return nil, fmt.Errorf("read private object: %w", err)
	}
	if int64(len(data)) > maximumBytes {
		return nil, ErrPrivateObjectTooLarge
	}
	return data, nil
}

func (m *minioClient) StatPrivateObject(ctx context.Context, key string) (PrivateObjectInfo, error) {
	info, err := m.client.StatObject(ctx, m.bucketName, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return PrivateObjectInfo{}, ErrPrivateObjectNotFound
		}
		return PrivateObjectInfo{}, fmt.Errorf("stat private object: %w", err)
	}
	return PrivateObjectInfo{
		Size:         info.Size,
		UserMetadata: cloneStringMap(info.UserMetadata),
	}, nil
}

func (m *minioClient) DeletePrivateObject(ctx context.Context, key string) error {
	err := m.client.RemoveObject(ctx, m.bucketName, key, minio.RemoveObjectOptions{})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("delete private object: %w", err)
	}
	return nil
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	response := minio.ToErrorResponse(err)
	return response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.Code == "NotFound"
}

func isPreconditionFailure(err error) bool {
	if errors.Is(err, ErrPrivateObjectAlreadyExists) {
		return true
	}
	response := minio.ToErrorResponse(err)
	return response.Code == "PreconditionFailed" || response.StatusCode == 412
}

func cloneStringMap[T ~string](source map[string]T) map[string]string {
	if len(source) == 0 {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[strings.ToLower(key)] = string(value)
	}
	return clone
}
