// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package c18imagepublication

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/daytonaio/runner/pkg/generationstop"
	"golang.org/x/sys/unix"
)

const (
	maximumArchiveBytes  = int64(64 * 1024 * 1024 * 1024)
	maximumIndexBytes    = int64(1024 * 1024)
	maximumManifestBytes = int64(4 * 1024 * 1024)
	maximumConfigBytes   = int64(16 * 1024 * 1024)
	maximumLayerBytes    = int64(2 * 1024 * 1024 * 1024)
)

type ociLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type ociPlatform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os.version,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
	Variant      string   `json:"variant,omitempty"`
}

type ociDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Data         []byte            `json:"data,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Platform     *ociPlatform      `json:"platform,omitempty"`
}

type ociIndex struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Manifests     []ociDescriptor   `json:"manifests"`
	Subject       *ociDescriptor    `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type ociManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        ociDescriptor     `json:"config"`
	Layers        []ociDescriptor   `json:"layers"`
	Subject       *ociDescriptor    `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type ociRootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type blobLocation struct {
	Digest string
	Offset int64
	Size   int64
}

type inspectedArchive struct {
	request       ArchiveRequest
	source        SourceAuthority
	imageTag      string
	file          *os.File
	initial       os.FileInfo
	archiveSize   int64
	blobs         map[string]blobLocation
	manifest      ociDescriptor
	manifestBytes []byte
	config        ociDescriptor
	layers        []ociDescriptor
}

func inspectArchive(
	ctx context.Context,
	request ArchiveRequest,
	imageTag string,
	source SourceAuthority,
) (_ *inspectedArchive, resultErr error) {
	if ctx == nil {
		return nil, errors.New("OCI archive inspection context is required")
	}
	if !absoluteNormalizedPath(request.ArchivePath) {
		return nil, errors.New("OCI archive path is invalid")
	}
	parent := filepath.Dir(request.ArchivePath)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return nil, errors.New("OCI archive parent may not contain symlinks")
	}
	descriptor, err := unix.Open(request.ArchivePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open OCI archive: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), request.ArchivePath)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("OCI archive descriptor is invalid")
	}
	archive := &inspectedArchive{request: request, source: source, imageTag: imageTag, file: file}
	failed := true
	defer func() {
		if failed {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	archive.initial, err = file.Stat()
	if err != nil || !archive.initial.Mode().IsRegular() || archive.initial.Size() < 1 ||
		archive.initial.Size() > maximumArchiveBytes {
		return nil, errors.New("OCI archive metadata is invalid")
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(descriptor, &filesystem); err != nil || !localArchiveFilesystem(filesystem.Type) {
		return nil, errors.New("OCI archives must reside on an admitted local filesystem")
	}
	archive.archiveSize = archive.initial.Size()
	if err := archive.verifyArchiveDigest(ctx); err != nil {
		return nil, err
	}
	if err := archive.scanAndValidate(ctx); err != nil {
		return nil, err
	}
	failed = false
	return archive, nil
}

func (value *inspectedArchive) Close() error {
	if value == nil || value.file == nil {
		return nil
	}
	err := value.file.Close()
	value.file = nil
	return err
}

func (value *inspectedArchive) verifyArchiveDigest(ctx context.Context) error {
	if _, err := value.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek OCI archive: %w", err)
	}
	hasher := sha256.New()
	count, err := io.CopyBuffer(hasher,
		io.LimitReader(contextReader{ctx: ctx, reader: value.file}, maximumArchiveBytes+1), make([]byte, 1024*1024))
	if err != nil {
		return fmt.Errorf("read OCI archive exactly: %w", err)
	}
	if count != value.archiveSize {
		return errors.New("OCI archive could not be read exactly")
	}
	observed := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if observed != value.request.ArchiveSHA256 {
		return errors.New("OCI archive SHA-256 differs from the publication request")
	}
	after, err := value.file.Stat()
	if err != nil || !os.SameFile(value.initial, after) || after.Size() != value.initial.Size() ||
		!after.ModTime().Equal(value.initial.ModTime()) {
		return errors.New("OCI archive changed while read")
	}
	if err := value.verifyPathBinding(); err != nil {
		return err
	}
	return nil
}

func (value *inspectedArchive) verifyPathBinding() error {
	parent := filepath.Dir(value.request.ArchivePath)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("OCI archive parent changed after admission")
	}
	literal, err := os.Lstat(value.request.ArchivePath)
	if err != nil || !literal.Mode().IsRegular() || literal.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(value.initial, literal) || literal.Size() != value.initial.Size() ||
		!literal.ModTime().Equal(value.initial.ModTime()) {
		return errors.New("OCI archive path no longer names the admitted inode")
	}
	return nil
}

func (value *inspectedArchive) scanAndValidate(ctx context.Context) error {
	if _, err := value.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	counter := &countingReader{reader: contextReader{ctx: ctx, reader: value.file}}
	reader := tar.NewReader(counter)
	seen := make(map[string]struct{})
	blobs := make(map[string]blobLocation)
	var layoutBytes, indexBytes []byte
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read OCI archive header: %w", err)
		}
		name, isDirectory, err := canonicalTarPath(header)
		if err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("OCI archive contains duplicate entry %q", name)
		}
		seen[name] = struct{}{}
		if isDirectory {
			if name != "blobs" && name != "blobs/sha256" {
				return fmt.Errorf("OCI archive contains unexpected directory %q", name)
			}
			continue
		}
		switch name {
		case "oci-layout":
			layoutBytes, err = readBoundedTarEntry(reader, header.Size, 1024)
		case "index.json":
			indexBytes, err = readBoundedTarEntry(reader, header.Size, maximumIndexBytes)
		default:
			digest, valid := blobDigestFromPath(name)
			if !valid || header.Size < 1 {
				return fmt.Errorf("OCI archive contains unexpected entry %q", name)
			}
			hasher := sha256.New()
			offset := counter.count
			count, copyErr := io.CopyN(hasher, reader, header.Size)
			if copyErr != nil || count != header.Size {
				return fmt.Errorf("read OCI blob %s: %w", digest, copyErr)
			}
			if observed := "sha256:" + hex.EncodeToString(hasher.Sum(nil)); observed != digest {
				return fmt.Errorf("OCI blob %s has invalid content digest", digest)
			}
			blobs[digest] = blobLocation{Digest: digest, Offset: offset, Size: header.Size}
		}
		if err != nil {
			return err
		}
	}
	if err := requireZeroTarTail(contextReader{ctx: ctx, reader: value.file}); err != nil {
		return err
	}
	if len(layoutBytes) == 0 || len(indexBytes) == 0 {
		return errors.New("OCI archive layout or index is missing")
	}
	var layout ociLayout
	if err := generationstop.DecodeExactJSON(layoutBytes, &layout); err != nil || layout.ImageLayoutVersion != "1.0.0" {
		return errors.New("OCI archive layout is invalid")
	}
	var index ociIndex
	if err := generationstop.DecodeExactJSON(indexBytes, &index); err != nil || index.SchemaVersion != 2 ||
		index.MediaType != "application/vnd.oci.image.index.v1+json" || index.ArtifactType != "" ||
		index.Subject != nil || len(index.Manifests) != 1 {
		return errors.New("OCI archive index is invalid")
	}
	manifestDescriptor := index.Manifests[0]
	if err := validateIndexManifestDescriptor(manifestDescriptor); err != nil ||
		manifestDescriptor.Digest != value.request.ManifestDigest || !manifestMediaType(manifestDescriptor.MediaType) ||
		manifestDescriptor.Annotations["org.opencontainers.image.ref.name"] != value.imageTag ||
		manifestDescriptor.Annotations["io.containerd.image.name"] !=
			"docker.io/library/"+value.request.Repository+":"+value.imageTag {
		return errors.New("OCI archive index manifest identity is invalid")
	}
	manifestLocation, exists := blobs[manifestDescriptor.Digest]
	if !exists || manifestLocation.Size != manifestDescriptor.Size || manifestLocation.Size > maximumManifestBytes {
		return errors.New("OCI archive manifest blob is missing or has invalid size")
	}
	manifestBytes, err := value.readBlob(ctx, manifestLocation, maximumManifestBytes)
	if err != nil {
		return err
	}
	var manifest ociManifest
	if err := generationstop.DecodeExactJSON(manifestBytes, &manifest); err != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != manifestDescriptor.MediaType || manifest.ArtifactType != "" || manifest.Subject != nil ||
		len(manifest.Layers) < 1 {
		return errors.New("OCI image manifest is invalid")
	}
	if err := validateDescriptor(manifest.Config, "config"); err != nil ||
		manifest.Config.Digest != value.request.ConfigDigest || !configMediaType(manifest.Config.MediaType) ||
		manifest.Config.Size > maximumConfigBytes {
		return errors.New("OCI image config identity is invalid")
	}
	configLocation, exists := blobs[manifest.Config.Digest]
	if !exists || configLocation.Size != manifest.Config.Size {
		return errors.New("OCI image config blob is missing or has invalid size")
	}
	configBytes, err := value.readBlob(ctx, configLocation, maximumConfigBytes)
	if err != nil {
		return err
	}
	if err := validateConfigIdentity(configBytes, value.request, value.source, len(manifest.Layers)); err != nil {
		return err
	}
	referenced := map[string]struct{}{manifestDescriptor.Digest: {}}
	if err := bindReferencedBlob(blobs, manifest.Config, referenced); err != nil {
		return fmt.Errorf("OCI image config: %w", err)
	}
	for index, layer := range manifest.Layers {
		if err := validateDescriptor(layer, "layer"); err != nil || !layerMediaType(layer.MediaType) ||
			layer.Size > maximumLayerBytes {
			return fmt.Errorf("OCI image layer %d is invalid", index)
		}
		if err := bindReferencedBlob(blobs, layer, referenced); err != nil {
			return fmt.Errorf("OCI image layer %d: %w", index, err)
		}
	}
	if len(referenced) != len(blobs) {
		return errors.New("OCI archive contains an unreferenced blob")
	}
	value.blobs = blobs
	value.manifest = manifestDescriptor
	value.manifestBytes = manifestBytes
	value.config = manifest.Config
	value.layers = append([]ociDescriptor(nil), manifest.Layers...)
	return nil
}

func validateConfigIdentity(
	encoded []byte,
	request ArchiveRequest,
	source SourceAuthority,
	layerCount int,
) error {
	var document map[string]json.RawMessage
	if err := generationstop.DecodeExactJSON(encoded, &document); err != nil {
		return errors.New("OCI image config document is invalid")
	}
	var config map[string]json.RawMessage
	if err := generationstop.DecodeExactJSON(document["config"], &config); err != nil {
		return errors.New("OCI image runtime config is invalid")
	}
	var labels map[string]string
	if err := generationstop.DecodeExactJSON(config["Labels"], &labels); err != nil {
		return errors.New("OCI image config labels are invalid")
	}
	var architecture, operatingSystem string
	var rootFS ociRootFS
	if err := generationstop.DecodeExactJSON(document["architecture"], &architecture); err != nil ||
		architecture != "amd64" {
		return errors.New("OCI image config architecture is invalid")
	}
	if err := generationstop.DecodeExactJSON(document["os"], &operatingSystem); err != nil ||
		operatingSystem != "linux" {
		return errors.New("OCI image config operating system is invalid")
	}
	if err := generationstop.DecodeExactJSON(document["rootfs"], &rootFS); err != nil ||
		rootFS.Type != "layers" || len(rootFS.DiffIDs) != layerCount {
		return errors.New("OCI image config rootfs topology is invalid")
	}
	for _, diffID := range rootFS.DiffIDs {
		if !exactSHA256(diffID) {
			return errors.New("OCI image config rootfs diff ID is invalid")
		}
	}
	expected := map[string]string{
		"org.opencontainers.image.revision": source.Revision,
		"io.ambit.source-tree":              source.Tree,
		"io.ambit.source-set-sha256":        strings.TrimPrefix(source.SourceSetDigest, "sha256:"),
		"io.ambit.runtime-pack":             request.PackRevisionRef,
		"org.opencontainers.image.title":    request.Repository,
	}
	for key, expectedValue := range expected {
		if labels[key] != expectedValue {
			return fmt.Errorf("OCI image config label %s differs from source authority", key)
		}
	}
	return nil
}

func (value *inspectedArchive) readBlob(ctx context.Context, location blobLocation, maximum int64) ([]byte, error) {
	if location.Size < 1 || location.Size > maximum {
		return nil, errors.New("OCI blob exceeds its metadata bound")
	}
	reader := io.NewSectionReader(value.file, location.Offset, location.Size)
	encoded, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: reader}, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read OCI blob exactly: %w", err)
	}
	if int64(len(encoded)) != location.Size || digestBytes(encoded) != location.Digest {
		return nil, errors.New("OCI blob changed after archive validation")
	}
	return encoded, nil
}

func (value *inspectedArchive) blobReader(digest string) (*io.SectionReader, int64, error) {
	location, exists := value.blobs[digest]
	if !exists {
		return nil, 0, errors.New("OCI blob is not present")
	}
	return io.NewSectionReader(value.file, location.Offset, location.Size), location.Size, nil
}

func validateDescriptor(value ociDescriptor, role string) error {
	if !exactSHA256(value.Digest) || value.Size < 1 || value.MediaType == "" || len(value.MediaType) > 256 ||
		len(value.URLs) != 0 || len(value.Data) != 0 || value.ArtifactType != "" || value.Platform != nil {
		return fmt.Errorf("%s descriptor is invalid", role)
	}
	return nil
}

func validateIndexManifestDescriptor(value ociDescriptor) error {
	if !exactSHA256(value.Digest) || value.Size < 1 || !manifestMediaType(value.MediaType) ||
		len(value.URLs) != 0 || len(value.Data) != 0 || value.ArtifactType != "" || value.Platform == nil ||
		value.Platform.Architecture != "amd64" || value.Platform.OS != "linux" ||
		value.Platform.OSVersion != "" || len(value.Platform.OSFeatures) != 0 || value.Platform.Variant != "" {
		return errors.New("manifest descriptor or platform is invalid")
	}
	return nil
}

func bindReferencedBlob(blobs map[string]blobLocation, descriptor ociDescriptor, referenced map[string]struct{}) error {
	if _, duplicate := referenced[descriptor.Digest]; duplicate {
		return errors.New("descriptor digest is duplicated")
	}
	location, exists := blobs[descriptor.Digest]
	if !exists || location.Size != descriptor.Size {
		return errors.New("descriptor blob is missing or has a different size")
	}
	referenced[descriptor.Digest] = struct{}{}
	return nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (value *countingReader) Read(target []byte) (int, error) {
	count, err := value.reader.Read(target)
	value.count += int64(count)
	return count, err
}

func canonicalTarPath(header *tar.Header) (string, bool, error) {
	if header == nil || header.Name == "" || len(header.Name) > 4096 || strings.ContainsRune(header.Name, '\\') ||
		strings.ContainsRune(header.Name, 0) || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return "", false, errors.New("OCI archive contains an invalid tar header")
	}
	isDirectory := header.Typeflag == tar.TypeDir
	if (!isDirectory && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Linkname != "" {
		return "", false, errors.New("OCI archive may contain only regular files and canonical directories")
	}
	name := header.Name
	if isDirectory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == "." ||
		strings.HasPrefix(name, "../") {
		return "", false, errors.New("OCI archive contains a noncanonical or traversing path")
	}
	if isDirectory && header.Size != 0 {
		return "", false, errors.New("OCI archive directory has content")
	}
	return name, isDirectory, nil
}

func blobDigestFromPath(name string) (string, bool) {
	const prefix = "blobs/sha256/"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	hexDigest := strings.TrimPrefix(name, prefix)
	if len(hexDigest) != 64 || !lowerHex(hexDigest) {
		return "", false
	}
	return "sha256:" + hexDigest, true
}

func readBoundedTarEntry(reader io.Reader, size, maximum int64) ([]byte, error) {
	if size < 1 || size > maximum {
		return nil, errors.New("OCI archive metadata document exceeds its bound")
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(encoded)) != size {
		return nil, errors.New("OCI archive metadata document is truncated")
	}
	return encoded, nil
}

func requireZeroTarTail(reader io.Reader) error {
	buffer := make([]byte, 32*1024)
	for {
		count, err := reader.Read(buffer)
		if count > 0 && !bytes.Equal(buffer[:count], make([]byte, count)) {
			return errors.New("OCI archive contains nonzero data after its tar terminator")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read OCI archive tail: %w", err)
		}
	}
}

func absoluteNormalizedPath(value string) bool {
	return value != "" && len(value) <= 4096 && value == strings.TrimSpace(value) &&
		filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" &&
		!strings.ContainsRune(value, 0)
}

func localArchiveFilesystem(filesystemType int64) bool {
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC,
		unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return true
	default:
		return false
	}
}
