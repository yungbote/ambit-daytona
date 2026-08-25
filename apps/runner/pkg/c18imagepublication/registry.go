// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maximumRegistryErrorBytes = 64 * 1024

type transferPolicy struct {
	minimumBytesPerSecond int64
	baseTimeout           time.Duration
	idleTimeout           time.Duration
	maximumTimeout        time.Duration
	cleanupTimeout        time.Duration
}

func defaultProductionTransferPolicy() transferPolicy {
	return transferPolicy{
		minimumBytesPerSecond: 1024 * 1024,
		baseTimeout:           time.Minute,
		idleTimeout:           30 * time.Second,
		maximumTimeout:        40 * time.Minute,
		cleanupTimeout:        10 * time.Second,
	}
}

type registryClient struct {
	origin *url.URL
	client *http.Client
	policy transferPolicy
}

func newRegistryClient(origin string, supplied *http.Client, policy transferPolicy) (*registryClient, error) {
	parsed, err := parsePublicationOrigin(origin)
	if err != nil {
		return nil, err
	}
	if supplied == nil {
		supplied = &http.Client{}
	}
	clientCopy := *supplied
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &registryClient{origin: parsed, client: &clientCopy, policy: policy}, nil
}

func (value *registryClient) ping(ctx context.Context) error {
	operationContext, cancel := context.WithTimeout(ctx, value.policy.baseTimeout)
	defer cancel()
	response, err := value.do(operationContext, http.MethodGet, value.origin.String()+"/v2/", "", nil, 0, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return registryStatusError("registry v2 probe", response)
	}
	return drainBoundedResponse(response, 4*1024)
}

func (value *registryClient) publishArchive(ctx context.Context, archive *inspectedArchive, request Request) (PublishedArchive, error) {
	repository := archive.request.Repository
	tagExists, err := value.requireCompatibleTag(ctx, archive, request.ImageTag)
	if err != nil {
		return PublishedArchive{}, err
	}

	configDisposition := "already_present"
	layerDispositions := make([]string, len(archive.layers))
	for index := range layerDispositions {
		layerDispositions[index] = "already_present"
	}
	manifestDisposition := "already_present"
	if !tagExists {
		configDisposition, err = value.ensureBlob(ctx, repository, archive, archive.config)
		if err != nil {
			return PublishedArchive{}, fmt.Errorf("publish config for %s: %w", archive.request.PackID, err)
		}
		for index, layer := range archive.layers {
			layerDispositions[index], err = value.ensureBlob(ctx, repository, archive, layer)
			if err != nil {
				return PublishedArchive{}, fmt.Errorf("publish layer %d for %s: %w", index, archive.request.PackID, err)
			}
		}
		_, manifestExists, headErr := value.headManifest(ctx, repository, archive.manifest.Digest)
		if headErr != nil {
			return PublishedArchive{}, headErr
		}
		if !manifestExists {
			if err := value.putManifest(ctx, repository, archive.manifest.Digest, archive); err != nil {
				return PublishedArchive{}, err
			}
			manifestDisposition = "uploaded"
		}
		if err := value.verifyManifest(ctx, repository, archive.manifest.Digest, archive); err != nil {
			return PublishedArchive{}, err
		}

	}
	// The build tag is observed, never mutated. Distribution v2 has no
	// compare-and-swap tag operation, so digest-only publication is the only
	// provider-neutral way to avoid overwriting a concurrent foreign value.
	tagExists, err = value.requireCompatibleTag(ctx, archive, request.ImageTag)
	if err != nil {
		return PublishedArchive{}, err
	}
	if err := value.verifyRemoteImage(ctx, repository, request.ImageTag, tagExists, archive); err != nil {
		return PublishedArchive{}, err
	}
	tagState := "absent"
	if tagExists {
		tagState = "present_exact"
	}

	layers := make([]BlobReceipt, len(archive.layers))
	for index, layer := range archive.layers {
		layers[index] = BlobReceipt{
			Digest: layer.Digest, MediaType: layer.MediaType, Size: layer.Size,
			Disposition: layerDispositions[index],
		}
	}
	return PublishedArchive{
		Archive: archive.request, ArchiveByteLength: archive.archiveSize,
		Manifest: ManifestReceipt{Digest: archive.manifest.Digest, MediaType: archive.manifest.MediaType,
			Size: archive.manifest.Size, Disposition: manifestDisposition},
		Config: BlobReceipt{Digest: archive.config.Digest, MediaType: archive.config.MediaType,
			Size: archive.config.Size, Disposition: configDisposition},
		Layers: layers, ImageTagState: tagState,
		PublicationImageRef: value.origin.Host + "/" + repository + "@" + archive.manifest.Digest,
		RuntimeImageRef:     request.Registry.RuntimeAuthority + "/" + repository + "@" + archive.manifest.Digest,
	}, nil
}

func (value *registryClient) requireCompatibleTag(
	ctx context.Context,
	archive *inspectedArchive,
	imageTag string,
) (bool, error) {
	tagDigest, exists, err := value.headManifest(ctx, archive.request.Repository, imageTag)
	if err != nil {
		return false, err
	}
	if exists && tagDigest != archive.manifest.Digest {
		return false, fmt.Errorf("image tag %s/%s already names %s instead of %s",
			archive.request.Repository, imageTag, tagDigest, archive.manifest.Digest)
	}
	return exists, nil
}

func (value *registryClient) preflightImmutableState(ctx context.Context, archive *inspectedArchive) error {
	manifestDigest, exists, err := value.headManifest(ctx, archive.request.Repository, archive.manifest.Digest)
	if err != nil {
		return err
	}
	if exists && manifestDigest != archive.manifest.Digest {
		return errors.New("registry digest endpoint returned a different manifest digest")
	}
	if exists {
		if err := value.verifyManifest(ctx, archive.request.Repository, archive.manifest.Digest, archive); err != nil {
			return err
		}
	}
	configExists, err := value.headBlob(ctx, archive.request.Repository, archive.config.Digest)
	if err != nil {
		return err
	}
	if configExists {
		if err := value.verifyBlob(ctx, archive.request.Repository, archive.config); err != nil {
			return err
		}
	}
	for _, layer := range archive.layers {
		layerExists, err := value.headBlob(ctx, archive.request.Repository, layer.Digest)
		if err != nil {
			return err
		}
		if layerExists {
			if err := value.verifyBlob(ctx, archive.request.Repository, layer); err != nil {
				return err
			}
		}
	}
	return nil
}

func (value *registryClient) ensureBlob(
	ctx context.Context,
	repository string,
	archive *inspectedArchive,
	descriptor ociDescriptor,
) (string, error) {
	exists, err := value.headBlob(ctx, repository, descriptor.Digest)
	if err != nil {
		return "", err
	}
	if exists {
		if err := value.verifyBlob(ctx, repository, descriptor); err != nil {
			return "", err
		}
		return "already_present", nil
	}
	uploadURL, err := value.beginBlobUpload(ctx, repository)
	if err != nil {
		return "", err
	}
	reader, size, err := archive.blobReader(descriptor.Digest)
	if err != nil || size != descriptor.Size {
		return "", errors.New("archive blob reader differs from manifest descriptor")
	}
	nextURL, err := value.patchBlob(ctx, repository, uploadURL, reader, descriptor)
	if err != nil {
		return "", errors.Join(err, value.cancelBlobUpload(uploadURL))
	}
	if err := value.finishBlobUpload(ctx, repository, nextURL, descriptor.Digest); err != nil {
		return "", errors.Join(err, value.cancelBlobUpload(nextURL))
	}
	if err := value.verifyBlob(ctx, repository, descriptor); err != nil {
		return "", err
	}
	return "uploaded", nil
}

func (value *registryClient) cancelBlobUpload(uploadURL *url.URL) error {
	if uploadURL == nil {
		return errors.New("cannot cancel registry upload without its admitted location")
	}
	ctx, cancel := context.WithTimeout(context.Background(), value.policy.cleanupTimeout)
	defer cancel()
	response, err := value.do(ctx, http.MethodDelete, uploadURL.String(), "", nil, 0, nil)
	if err != nil {
		return fmt.Errorf("cancel registry blob upload: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return registryStatusError("cancel registry blob upload", response)
	}
	return drainBoundedResponse(response, 4*1024)
}

func (value *registryClient) headBlob(ctx context.Context, repository, digest string) (bool, error) {
	operationContext, cancel := context.WithTimeout(ctx, value.policy.baseTimeout)
	defer cancel()
	response, err := value.do(operationContext, http.MethodHead, value.blobURL(repository, digest), "", nil, 0, nil)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound:
		return false, drainEmptyResponse(response)
	case http.StatusOK:
		if response.Header.Get("Docker-Content-Digest") != digest {
			return false, errors.New("registry blob HEAD returned a different content digest")
		}
		return true, drainEmptyResponse(response)
	default:
		return false, registryStatusError("registry blob HEAD", response)
	}
}

func (value *registryClient) beginBlobUpload(ctx context.Context, repository string) (*url.URL, error) {
	operationContext, cancel := context.WithTimeout(ctx, value.policy.baseTimeout)
	defer cancel()
	endpoint := value.origin.String() + "/v2/" + escapeRepository(repository) + "/blobs/uploads/"
	response, err := value.do(operationContext, http.MethodPost, endpoint, "", http.NoBody, 0, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return nil, registryStatusError("begin registry blob upload", response)
	}
	if err := drainEmptyResponse(response); err != nil {
		return nil, err
	}
	return value.validateUploadLocation(repository, response.Header.Get("Location"))
}

func (value *registryClient) patchBlob(
	ctx context.Context,
	repository string,
	uploadURL *url.URL,
	reader io.Reader,
	descriptor ociDescriptor,
) (*url.URL, error) {
	transferContext, watch := newTransferWatch(ctx, descriptor.Size, value.policy)
	defer watch.Stop()
	hasher := sha256.New()
	counting := &hashingReader{reader: progressReader{
		reader: contextReader{ctx: transferContext, reader: reader}, watch: watch,
	}, hasher: hasher}
	headers := http.Header{"Content-Type": []string{"application/octet-stream"}}
	response, err := value.do(transferContext, http.MethodPatch, uploadURL.String(), "", counting, descriptor.Size, headers)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return nil, registryStatusError("stream registry blob upload", response)
	}
	if counting.count != descriptor.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != descriptor.Digest {
		return nil, errors.New("archive blob changed while streamed to registry")
	}
	if err := drainEmptyResponse(response); err != nil {
		return nil, err
	}
	return value.validateUploadLocation(repository, response.Header.Get("Location"))
}

func (value *registryClient) finishBlobUpload(ctx context.Context, repository string, uploadURL *url.URL, digest string) error {
	operationContext, cancel := context.WithTimeout(ctx, value.policy.baseTimeout)
	defer cancel()
	query := uploadURL.Query()
	if query.Has("digest") {
		return errors.New("registry upload location unexpectedly contains a digest")
	}
	query.Set("digest", digest)
	uploadURL = cloneURL(uploadURL)
	uploadURL.RawQuery = query.Encode()
	response, err := value.do(operationContext, http.MethodPut, uploadURL.String(), "", http.NoBody, 0, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Docker-Content-Digest") != digest {
		if response.StatusCode != http.StatusCreated {
			return registryStatusError("complete registry blob upload", response)
		}
		return errors.New("completed registry blob upload returned a different digest")
	}
	if err := drainEmptyResponse(response); err != nil {
		return err
	}
	if location := response.Header.Get("Location"); location != "" {
		resolved, err := value.validateSameOriginLocation(location)
		if err != nil || resolved.Path != "/v2/"+repository+"/blobs/"+digest {
			return errors.New("completed registry blob upload returned an invalid location")
		}
	}
	return nil
}

func (value *registryClient) headManifest(ctx context.Context, repository, reference string) (string, bool, error) {
	operationContext, cancel := context.WithTimeout(ctx, value.policy.baseTimeout)
	defer cancel()
	headers := http.Header{"Accept": []string{ociManifestMediaType + ", " + dockerManifestMediaType}}
	response, err := value.do(operationContext, http.MethodHead, value.manifestURL(repository, reference), "", nil, 0, headers)
	if err != nil {
		return "", false, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound:
		return "", false, drainEmptyResponse(response)
	case http.StatusOK:
		digest := response.Header.Get("Docker-Content-Digest")
		if !exactSHA256(digest) {
			return "", false, errors.New("registry manifest HEAD omitted an exact content digest")
		}
		return digest, true, drainEmptyResponse(response)
	default:
		return "", false, registryStatusError("registry manifest HEAD", response)
	}
}

func (value *registryClient) putManifest(
	ctx context.Context,
	repository, reference string,
	archive *inspectedArchive,
) error {
	if reference != archive.manifest.Digest {
		return errors.New("mutable manifest references are forbidden")
	}
	transferContext, watch := newTransferWatch(ctx, archive.manifest.Size, value.policy)
	defer watch.Stop()
	headers := http.Header{"Content-Type": []string{archive.manifest.MediaType}}
	response, err := value.do(transferContext, http.MethodPut, value.manifestURL(repository, reference), "",
		progressReader{reader: bytes.NewReader(archive.manifestBytes), watch: watch},
		int64(len(archive.manifestBytes)), headers)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return registryStatusError("publish registry manifest", response)
	}
	if response.Header.Get("Docker-Content-Digest") != archive.manifest.Digest {
		return errors.New("registry manifest PUT returned a different content digest")
	}
	if err := drainEmptyResponse(response); err != nil {
		return err
	}
	if location := response.Header.Get("Location"); location != "" {
		resolved, err := value.validateSameOriginLocation(location)
		if err != nil || resolved.Path != "/v2/"+repository+"/manifests/"+archive.manifest.Digest {
			return errors.New("registry manifest PUT returned an invalid location")
		}
	}
	return nil
}

func (value *registryClient) verifyRemoteImage(
	ctx context.Context,
	repository, tag string,
	tagExists bool,
	archive *inspectedArchive,
) error {
	if err := value.verifyManifest(ctx, repository, archive.manifest.Digest, archive); err != nil {
		return err
	}
	if tagExists {
		if err := value.verifyManifest(ctx, repository, tag, archive); err != nil {
			return err
		}
	}
	if err := value.verifyBlob(ctx, repository, archive.config); err != nil {
		return err
	}
	for _, layer := range archive.layers {
		if err := value.verifyBlob(ctx, repository, layer); err != nil {
			return err
		}
	}
	return nil
}

func (value *registryClient) verifyManifest(
	ctx context.Context,
	repository, reference string,
	archive *inspectedArchive,
) error {
	transferContext, watch := newTransferWatch(ctx, archive.manifest.Size, value.policy)
	defer watch.Stop()
	headers := http.Header{"Accept": []string{archive.manifest.MediaType}}
	response, err := value.do(transferContext, http.MethodGet, value.manifestURL(repository, reference), "", nil, 0, headers)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return registryStatusError("read back registry manifest", response)
	}
	if response.Header.Get("Docker-Content-Digest") != archive.manifest.Digest {
		return errors.New("registry manifest readback returned a different digest")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != archive.manifest.MediaType {
		return errors.New("registry manifest readback returned a different media type")
	}
	encoded, err := io.ReadAll(io.LimitReader(progressReader{reader: response.Body, watch: watch}, maximumManifestBytes+1))
	if err != nil || !bytes.Equal(encoded, archive.manifestBytes) || digestBytes(encoded) != archive.manifest.Digest {
		return errors.New("registry manifest readback differs from the archive")
	}
	return nil
}

func (value *registryClient) verifyBlob(ctx context.Context, repository string, descriptor ociDescriptor) error {
	transferContext, watch := newTransferWatch(ctx, descriptor.Size, value.policy)
	defer watch.Stop()
	response, err := value.do(transferContext, http.MethodGet, value.blobURL(repository, descriptor.Digest), "", nil, 0, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return registryStatusError("read back registry blob", response)
	}
	if response.Header.Get("Docker-Content-Digest") != descriptor.Digest ||
		(response.ContentLength >= 0 && response.ContentLength != descriptor.Size) {
		return errors.New("registry blob readback metadata differs from the archive")
	}
	hasher := sha256.New()
	count, err := io.CopyBuffer(hasher,
		io.LimitReader(progressReader{reader: response.Body, watch: watch}, descriptor.Size+1), make([]byte, 128*1024))
	if err != nil || count != descriptor.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != descriptor.Digest {
		return errors.New("registry blob readback bytes differ from the archive")
	}
	return nil
}

func (value *registryClient) validateUploadLocation(repository, location string) (*url.URL, error) {
	resolved, err := value.validateSameOriginLocation(location)
	if err != nil {
		return nil, err
	}
	prefix := "/v2/" + repository + "/blobs/uploads/"
	token := strings.TrimPrefix(resolved.Path, prefix)
	if !strings.HasPrefix(resolved.Path, prefix) || token == "" || len(token) > 2048 || strings.Contains(token, "/") {
		return nil, errors.New("registry returned an invalid upload location")
	}
	return resolved, nil
}

func (value *registryClient) validateSameOriginLocation(location string) (*url.URL, error) {
	if location == "" {
		return nil, errors.New("registry response omitted Location")
	}
	reference, err := url.Parse(location)
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.Opaque != "" {
		return nil, errors.New("registry returned an invalid Location")
	}
	resolved := value.origin.ResolveReference(reference)
	if resolved.Scheme != value.origin.Scheme || resolved.Host != value.origin.Host || resolved.User != nil ||
		pathHasNoncanonicalSegments(resolved.Path) {
		return nil, errors.New("registry returned a cross-origin Location")
	}
	return resolved, nil
}

func pathHasNoncanonicalSegments(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || strings.Contains(value, "//") {
		return true
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func (value *registryClient) manifestURL(repository, reference string) string {
	return value.origin.String() + "/v2/" + escapeRepository(repository) + "/manifests/" + url.PathEscape(reference)
}

func (value *registryClient) blobURL(repository, digest string) string {
	return value.origin.String() + "/v2/" + escapeRepository(repository) + "/blobs/" + url.PathEscape(digest)
}

func escapeRepository(repository string) string {
	parts := strings.Split(repository, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func (value *registryClient) do(
	ctx context.Context,
	method, endpoint, contentType string,
	body io.Reader,
	contentLength int64,
	headers http.Header,
) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.ContentLength = contentLength
	request.Header.Set("Accept-Encoding", "identity")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for key, values := range headers {
		for _, headerValue := range values {
			request.Header.Add(key, headerValue)
		}
	}
	response, err := value.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("registry %s %s: %w", method, request.URL.EscapedPath(), err)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		defer response.Body.Close()
		return nil, registryStatusError("registry redirect rejected", response)
	}
	return response, nil
}

func registryStatusError(action string, response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, maximumRegistryErrorBytes+1))
	if len(body) > maximumRegistryErrorBytes {
		body = body[:maximumRegistryErrorBytes]
	}
	message := strings.TrimSpace(string(body))
	if message == "" {
		return fmt.Errorf("%s returned HTTP %d", action, response.StatusCode)
	}
	return fmt.Errorf("%s returned HTTP %d: %s", action, response.StatusCode, message)
}

func drainEmptyResponse(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, 2))
	if err != nil {
		return err
	}
	if len(body) != 0 {
		return errors.New("registry metadata response unexpectedly contained a body")
	}
	return nil
}

func drainBoundedResponse(response *http.Response, maximum int64) error {
	if maximum < 0 {
		return errors.New("registry response bound is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maximum {
		return errors.New("registry response body exceeds its bound")
	}
	return nil
}

type hashingReader struct {
	reader io.Reader
	hasher io.Writer
	count  int64
}

func (value *hashingReader) Read(target []byte) (int, error) {
	count, err := value.reader.Read(target)
	if count > 0 {
		_, _ = value.hasher.Write(target[:count])
		value.count += int64(count)
	}
	return count, err
}

func cloneURL(value *url.URL) *url.URL {
	clone := *value
	return &clone
}

func (value transferPolicy) validate() error {
	if value.minimumBytesPerSecond < 1 || value.baseTimeout <= 0 || value.idleTimeout <= 0 ||
		value.maximumTimeout < value.baseTimeout || value.cleanupTimeout <= 0 {
		return errors.New("registry transfer policy is invalid")
	}
	return nil
}

func (value transferPolicy) timeoutFor(size int64) time.Duration {
	seconds := size / value.minimumBytesPerSecond
	if size%value.minimumBytesPerSecond != 0 {
		seconds++
	}
	timeout := value.baseTimeout + time.Duration(seconds)*time.Second
	if timeout > value.maximumTimeout {
		return value.maximumTimeout
	}
	return timeout
}

type transferWatch struct {
	mutex       sync.Mutex
	timer       *time.Timer
	cancelIdle  context.CancelFunc
	cancelTotal context.CancelFunc
	idleTimeout time.Duration
	stopped     bool
}

func newTransferWatch(parent context.Context, size int64, policy transferPolicy) (context.Context, *transferWatch) {
	totalContext, cancelTotal := context.WithTimeout(parent, policy.timeoutFor(size))
	transferContext, cancelIdle := context.WithCancel(totalContext)
	watch := &transferWatch{
		cancelIdle: cancelIdle, cancelTotal: cancelTotal, idleTimeout: policy.idleTimeout,
	}
	watch.timer = time.AfterFunc(policy.idleTimeout, cancelIdle)
	return transferContext, watch
}

func (value *transferWatch) Progress(count int) {
	if count <= 0 {
		return
	}
	value.mutex.Lock()
	defer value.mutex.Unlock()
	if value.stopped {
		return
	}
	value.timer.Stop()
	value.timer.Reset(value.idleTimeout)
}

func (value *transferWatch) Stop() {
	value.mutex.Lock()
	if value.stopped {
		value.mutex.Unlock()
		return
	}
	value.stopped = true
	value.timer.Stop()
	value.mutex.Unlock()
	value.cancelIdle()
	value.cancelTotal()
}

type progressReader struct {
	reader io.Reader
	watch  *transferWatch
}

func (value progressReader) Read(target []byte) (int, error) {
	count, err := value.reader.Read(target)
	value.watch.Progress(count)
	return count, err
}
