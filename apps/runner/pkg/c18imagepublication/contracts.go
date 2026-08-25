// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Package c18imagepublication validates and publishes the four immutable C18
// specialist runtime-pack OCI archives to a private Distribution v2 registry.
package c18imagepublication

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/generationstop"
)

const (
	RequestContract = "C18OciArchivePublicationRequest@1"
	ReceiptContract = "C18OciArchivePublicationReceipt@1"

	ociManifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
)

var (
	expectedPackIDs    = []string{"data-research", "office-authoring", "pdf-ocr", "web-browser"}
	repositoryPart     = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	tagPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	packRefPattern     = regexp.MustCompile(`^ambit\.runtime-pack/([a-z0-9]+(?:-[a-z0-9]+)*)@([1-9][0-9]*)$`)
	upstreamRefPattern = regexp.MustCompile(`^ambit://[a-z0-9][a-z0-9./_-]{0,511}$`)
)

type SourceAuthority struct {
	Revision        string `json:"revision"`
	Tree            string `json:"tree"`
	SourceSetDigest string `json:"sourceSetDigest"`
}

type RegistryAuthority struct {
	PublicationOrigin string `json:"publicationOrigin"`
	RuntimeAuthority  string `json:"runtimeAuthority"`
}

type UpstreamCertification struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

type ArchiveRequest struct {
	PackID          string `json:"packId"`
	PackRevisionRef string `json:"packRevisionRef"`
	ArchivePath     string `json:"archivePath"`
	ArchiveSHA256   string `json:"archiveSha256"`
	Repository      string `json:"repository"`
	ManifestDigest  string `json:"manifestDigest"`
	ConfigDigest    string `json:"configDigest"`
}

type Request struct {
	Contract              string                `json:"contract"`
	Registry              RegistryAuthority     `json:"registry"`
	Source                SourceAuthority       `json:"source"`
	UpstreamCertification UpstreamCertification `json:"upstreamCertification"`
	ImageTag              string                `json:"imageTag"`
	Archives              []ArchiveRequest      `json:"archives"`
}

type BlobReceipt struct {
	Digest      string `json:"digest"`
	MediaType   string `json:"mediaType"`
	Size        int64  `json:"size"`
	Disposition string `json:"disposition"`
}

type ManifestReceipt struct {
	Digest      string `json:"digest"`
	MediaType   string `json:"mediaType"`
	Size        int64  `json:"size"`
	Disposition string `json:"disposition"`
}

type PublishedArchive struct {
	Archive             ArchiveRequest  `json:"archive"`
	ArchiveByteLength   int64           `json:"archiveByteLength"`
	Manifest            ManifestReceipt `json:"manifest"`
	Config              BlobReceipt     `json:"config"`
	Layers              []BlobReceipt   `json:"layers"`
	ImageTagState       string          `json:"imageTagState"`
	PublicationImageRef string          `json:"publicationImageRef"`
	RuntimeImageRef     string          `json:"runtimeImageRef"`
}

type ExecutableAuthority struct {
	SHA256 string `json:"sha256"`
}

type Receipt struct {
	Contract          string              `json:"contract"`
	Digest            string              `json:"digest"`
	RequestSHA256     string              `json:"requestSha256"`
	Request           Request             `json:"request"`
	Executable        ExecutableAuthority `json:"executable"`
	StartedAt         string              `json:"startedAt"`
	CompletedAt       string              `json:"completedAt"`
	PublishedArchives []PublishedArchive  `json:"publishedArchives"`
	Outcome           string              `json:"outcome"`
}

type receiptBody struct {
	Contract          string              `json:"contract"`
	RequestSHA256     string              `json:"requestSha256"`
	Request           Request             `json:"request"`
	Executable        ExecutableAuthority `json:"executable"`
	StartedAt         string              `json:"startedAt"`
	CompletedAt       string              `json:"completedAt"`
	PublishedArchives []PublishedArchive  `json:"publishedArchives"`
	Outcome           string              `json:"outcome"`
}

func ParseRequest(encoded []byte) (Request, error) {
	var value Request
	if err := generationstop.DecodeCanonicalJSON(encoded, &value); err != nil {
		return Request{}, fmt.Errorf("decode canonical publication request: %w", err)
	}
	if err := ValidateRequest(value); err != nil {
		return Request{}, err
	}
	return value, nil
}

func ValidateRequest(value Request) error {
	if value.Contract != RequestContract || !gitObject(value.Source.Revision) ||
		!gitObject(value.Source.Tree) || !exactSHA256(value.Source.SourceSetDigest) ||
		!tagPattern.MatchString(value.ImageTag) || value.ImageTag != value.Source.Revision[:9] ||
		!upstreamRefPattern.MatchString(value.UpstreamCertification.Ref) ||
		!exactSHA256(value.UpstreamCertification.Digest) {
		return errors.New("publication request authority is invalid")
	}
	if _, err := parsePublicationOrigin(value.Registry.PublicationOrigin); err != nil {
		return err
	}
	if !registryAuthority(value.Registry.RuntimeAuthority) ||
		value.Registry.RuntimeAuthority == strings.TrimPrefix(value.Registry.PublicationOrigin, "http://") {
		return errors.New("publication and runtime registry authorities are invalid")
	}
	if len(value.Archives) != len(expectedPackIDs) {
		return errors.New("publication request must contain exactly four archives")
	}
	repositories := make(map[string]struct{}, len(value.Archives))
	manifestDigests := make(map[string]struct{}, len(value.Archives))
	for index, archive := range value.Archives {
		matches := packRefPattern.FindStringSubmatch(archive.PackRevisionRef)
		if archive.PackID != expectedPackIDs[index] || len(matches) != 3 || matches[1] != archive.PackID ||
			!absoluteNormalizedPath(archive.ArchivePath) || !exactSHA256(archive.ArchiveSHA256) ||
			!validRepository(archive.Repository) || !exactSHA256(archive.ManifestDigest) ||
			!exactSHA256(archive.ConfigDigest) {
			return fmt.Errorf("publication archive row %d is invalid", index)
		}
		if _, exists := repositories[archive.Repository]; exists {
			return errors.New("publication repositories must be unique")
		}
		if _, exists := manifestDigests[archive.ManifestDigest]; exists {
			return errors.New("publication manifest digests must be unique")
		}
		repositories[archive.Repository] = struct{}{}
		manifestDigests[archive.ManifestDigest] = struct{}{}
	}
	return nil
}

func SealReceipt(value Receipt) (Receipt, error) {
	value.Contract = ReceiptContract
	value.Digest = ""
	if err := validateReceiptBody(value); err != nil {
		return Receipt{}, err
	}
	body, err := generationstop.CanonicalJSON(projectReceiptBody(value))
	if err != nil {
		return Receipt{}, fmt.Errorf("canonicalize publication receipt body: %w", err)
	}
	value.Digest = digestBytes(body)
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return Receipt{}, fmt.Errorf("canonicalize publication receipt: %w", err)
	}
	return ParseReceipt(encoded)
}

func ParseReceipt(encoded []byte) (Receipt, error) {
	var value Receipt
	if err := generationstop.DecodeCanonicalJSON(encoded, &value); err != nil {
		return Receipt{}, fmt.Errorf("decode canonical publication receipt: %w", err)
	}
	if value.Contract != ReceiptContract {
		return Receipt{}, errors.New("publication receipt contract is invalid")
	}
	if err := validateReceiptBody(value); err != nil {
		return Receipt{}, err
	}
	body, err := generationstop.CanonicalJSON(projectReceiptBody(value))
	if err != nil || value.Digest != digestBytes(body) {
		return Receipt{}, errors.New("publication receipt self-digest is invalid")
	}
	return value, nil
}

func validateReceiptBody(value Receipt) error {
	if value.Contract != ReceiptContract || !exactSHA256(value.RequestSHA256) ||
		!exactSHA256(value.Executable.SHA256) || value.Outcome != "succeeded" ||
		!exactMillisecondInstant(value.StartedAt) || !exactMillisecondInstant(value.CompletedAt) {
		return errors.New("publication receipt body is invalid")
	}
	if err := ValidateRequest(value.Request); err != nil {
		return fmt.Errorf("publication receipt request is invalid: %w", err)
	}
	requestBytes, err := generationstop.CanonicalJSON(value.Request)
	if err != nil || value.RequestSHA256 != digestBytes(requestBytes) {
		return errors.New("publication receipt request digest is invalid")
	}
	started, _ := time.Parse(time.RFC3339Nano, value.StartedAt)
	completed, _ := time.Parse(time.RFC3339Nano, value.CompletedAt)
	if completed.Before(started) || len(value.PublishedArchives) != len(value.Request.Archives) {
		return errors.New("publication receipt chronology or archive roster is invalid")
	}
	origin, _ := parsePublicationOrigin(value.Request.Registry.PublicationOrigin)
	for index, published := range value.PublishedArchives {
		requested := value.Request.Archives[index]
		if published.Archive != requested || published.ArchiveByteLength < 1 ||
			published.Manifest.Digest != requested.ManifestDigest || published.Manifest.Size < 1 ||
			!manifestMediaType(published.Manifest.MediaType) || !disposition(published.Manifest.Disposition) ||
			published.Config.Digest != requested.ConfigDigest || published.Config.Size < 1 ||
			!configMediaType(published.Config.MediaType) || !disposition(published.Config.Disposition) ||
			len(published.Layers) < 1 || !imageTagState(published.ImageTagState) {
			return errors.New("publication receipt image roster is invalid")
		}
		expectedPublicationRef := origin.Host + "/" + requested.Repository + "@" + requested.ManifestDigest
		expectedRuntimeRef := value.Request.Registry.RuntimeAuthority + "/" + requested.Repository + "@" + requested.ManifestDigest
		if published.PublicationImageRef != expectedPublicationRef || published.RuntimeImageRef != expectedRuntimeRef {
			return errors.New("publication receipt endpoint/runtime reference split is invalid")
		}
		seen := map[string]struct{}{published.Config.Digest: {}}
		for _, layer := range published.Layers {
			if !exactSHA256(layer.Digest) || layer.Size < 1 || !layerMediaType(layer.MediaType) ||
				!disposition(layer.Disposition) {
				return errors.New("publication receipt layer roster is invalid")
			}
			if _, exists := seen[layer.Digest]; exists {
				return errors.New("publication receipt blob roster contains a duplicate")
			}
			seen[layer.Digest] = struct{}{}
		}
	}
	return nil
}

func projectReceiptBody(value Receipt) receiptBody {
	return receiptBody{
		Contract: value.Contract, RequestSHA256: value.RequestSHA256, Request: value.Request,
		Executable: value.Executable, StartedAt: value.StartedAt, CompletedAt: value.CompletedAt,
		PublishedArchives: value.PublishedArchives, Outcome: value.Outcome,
	}
}

func CanonicalJSON(value any) ([]byte, error) { return generationstop.CanonicalJSON(value) }

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func exactSHA256(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && lowerHex(value[7:])
}

func gitObject(value string) bool { return len(value) == 40 && lowerHex(value) }

func lowerHex(value string) bool {
	if value == "" || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func exactMillisecondInstant(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000Z") == value
}

func formatInstant(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func parsePublicationOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" ||
		parsed.String() != value {
		return nil, errors.New("publication origin must be a canonical loopback HTTP origin")
	}
	ip := net.ParseIP(parsed.Hostname())
	port, portErr := strconv.Atoi(parsed.Port())
	if ip == nil || !ip.IsLoopback() || portErr != nil || port < 1 || port > 65535 ||
		strconv.Itoa(port) != parsed.Port() {
		return nil, errors.New("publication origin must use a literal loopback address and explicit port")
	}
	return parsed, nil
}

func registryAuthority(value string) bool {
	if value == "" || strings.ToLower(value) != value || strings.ContainsAny(value, "/?#@") {
		return false
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String() == host
	}
	return validHostname(host)
}

func validHostname(value string) bool {
	if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validRepository(value string) bool {
	if value == "" || len(value) > 255 || strings.ToLower(value) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if !repositoryPart.MatchString(part) {
			return false
		}
	}
	return true
}

func disposition(value string) bool { return value == "uploaded" || value == "already_present" }

func imageTagState(value string) bool { return value == "absent" || value == "present_exact" }

func manifestMediaType(value string) bool {
	return value == ociManifestMediaType || value == dockerManifestMediaType
}

func configMediaType(value string) bool {
	return value == "application/vnd.oci.image.config.v1+json" ||
		value == "application/vnd.docker.container.image.v1+json"
}

func layerMediaType(value string) bool {
	switch value {
	case "application/vnd.oci.image.layer.v1.tar",
		"application/vnd.oci.image.layer.v1.tar+gzip",
		"application/vnd.oci.image.layer.v1.tar+zstd",
		"application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		return true
	default:
		return false
	}
}
