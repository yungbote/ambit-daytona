//go:build linux && amd64

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/text/unicode/norm"
)

const (
	maximumBytes       = int64(33_554_432)
	maximumHeaderBytes = uint32(4096)
	maximumDataBytes   = uint32(65_536)
	frameTimeout       = 10 * time.Second
	totalTimeout       = 120 * time.Second
	exitInvalid        = 2
	exitInput          = 3
	exitUnsafe         = 4
	exitIO             = 5
	oTmpfile           = 0x410000
	atEmptyPath        = 0x1000
)

var (
	readyMagic       = []byte("AMATRDY1")
	requestMagic     = []byte("AMATREQ1")
	headerAckMagic   = []byte("AMATHDR1")
	dataMagic        = []byte("AMATDAT1")
	dataAckMagic     = []byte("AMATACK1")
	endMagic         = []byte("AMATEND1")
	resultMagic      = []byte("AMATRES1")
	errorMagic       = []byte("AMATERR1")
	deadlineFailure  = errors.New("frame deadline exceeded")
	existingMismatch = errors.New("existing artifact mismatch")
	linkCountInvalid = errors.New("link count invalid")
	nonRegularFile   = errors.New("non-regular file")
	pathRace         = errors.New("path race")
)

type startupConfiguration struct {
	readyNonce []byte
}

type requestHeader struct {
	ExpectedBytes        int64  `json:"expectedBytes"`
	ExpectedHelperSHA256 string `json:"expectedHelperSha256"`
	ExpectedSHA256       string `json:"expectedSha256"`
	Mode                 uint32 `json:"mode"`
	Operation            string `json:"operation"`
	RelativePath         string `json:"relativePath"`
	Version              int    `json:"version"`
	WorkspaceRoot        string `json:"workspaceRoot"`
}

type materializationConfiguration struct {
	relativePath         string
	components           []string
	expectedSHA256       string
	expectedHelperSHA256 string
	expectedBytes        int64
	mode                 uint32
	operation            string
}

type receiptBody struct {
	Bytes        int64
	HelperSHA256 string
	Kind         string
	Mode         uint32
	Operation    string
	Outcome      string
	RelativePath string
	SHA256       string
	Version      int
}

type receipt struct {
	Bytes        int64
	HelperSHA256 string
	Kind         string
	Mode         uint32
	Operation    string
	Outcome      string
	ReceiptRef   string
	RelativePath string
	SHA256       string
	Version      int
}

type errorReceipt struct {
	Code         string
	Kind         string
	RelativePath *string
	Version      int
}

type operationError struct {
	code         string
	exitCode     int
	relativePath *string
}

type directoryIdentity struct {
	device uint64
	inode  uint64
}

func main() {
	os.Exit(run())
}

func run() int {
	signal.Ignore(syscall.SIGHUP)
	startup, failure := parseStartup(os.Args[1:])
	if failure != nil {
		return emitError(*failure)
	}
	if err := writeAll(os.Stdout, append(append([]byte{}, readyMagic...), startup.readyNonce...)); err != nil {
		return exitIO
	}

	totalDeadline := time.Now().Add(totalTimeout)
	headerBytes, header, failure := readHeader(int(os.Stdin.Fd()), totalDeadline)
	if failure != nil {
		return emitError(*failure)
	}
	config, failure := validateHeader(header, headerBytes)
	if failure != nil {
		return emitError(*failure)
	}
	relativePath := config.relativePath
	helperDigest, err := hashInstalledExecutable()
	if err != nil {
		return emitError(operationError{code: "helper_verification_io_failure", exitCode: exitIO, relativePath: &relativePath})
	}
	if "sha256:"+helperDigest != config.expectedHelperSHA256 {
		return emitError(operationError{code: "unsafe_path", exitCode: exitUnsafe, relativePath: &relativePath})
	}
	headerDigest := sha256.Sum256(headerBytes)
	if err := writeAll(os.Stdout, append(append([]byte{}, headerAckMagic...), headerDigest[:]...)); err != nil {
		return exitIO
	}

	payload, failure := readPayload(int(os.Stdin.Fd()), config, totalDeadline)
	if failure != nil {
		failure.relativePath = &relativePath
		return emitError(*failure)
	}
	outcome, failure := materialize(config, payload)
	if failure != nil {
		failure.relativePath = &relativePath
		return emitError(*failure)
	}
	return emitSuccess(config, helperDigest, outcome)
}

func parseStartup(arguments []string) (startupConfiguration, *operationError) {
	flags := flag.NewFlagSet("ambit-atomic-materialize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var framed bool
	var nonceHex string
	flags.BoolVar(&framed, "framed-stream-v1", false, "")
	flags.StringVar(&nonceHex, "ready-nonce", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !framed || !validDigest(nonceHex) {
		failure := operationError{code: "invalid_invocation", exitCode: exitInvalid}
		return startupConfiguration{}, &failure
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != sha256.Size {
		failure := operationError{code: "invalid_ready_nonce", exitCode: exitInvalid}
		return startupConfiguration{}, &failure
	}
	return startupConfiguration{readyNonce: nonce}, nil
}

func readHeader(fd int, totalDeadline time.Time) ([]byte, requestHeader, *operationError) {
	deadline := boundedDeadline(totalDeadline)
	magic, err := readExact(fd, len(requestMagic), deadline)
	if err != nil {
		failure := framedReadFailure("request_header_truncated", err)
		return nil, requestHeader{}, &failure
	}
	if !bytes.Equal(magic, requestMagic) {
		failure := operationError{code: "invalid_request_magic", exitCode: exitInvalid}
		return nil, requestHeader{}, &failure
	}
	lengthBytes, err := readExact(fd, 4, deadline)
	if err != nil {
		failure := framedReadFailure("request_header_truncated", err)
		return nil, requestHeader{}, &failure
	}
	length := binary.BigEndian.Uint32(lengthBytes)
	if length == 0 || length > maximumHeaderBytes {
		failure := operationError{code: "invalid_header_length", exitCode: exitInvalid}
		return nil, requestHeader{}, &failure
	}
	raw, err := readExact(fd, int(length), deadline)
	if err != nil {
		failure := framedReadFailure("request_header_truncated", err)
		return nil, requestHeader{}, &failure
	}
	var header requestHeader
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		failure := operationError{code: "invalid_header_json", exitCode: exitInvalid}
		return nil, requestHeader{}, &failure
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		failure := operationError{code: "invalid_header_json", exitCode: exitInvalid}
		return nil, requestHeader{}, &failure
	}
	if !bytes.Equal(raw, encodeHeader(header)) {
		failure := operationError{code: "noncanonical_header", exitCode: exitInvalid}
		return nil, requestHeader{}, &failure
	}
	return raw, header, nil
}

func validateHeader(header requestHeader, raw []byte) (materializationConfiguration, *operationError) {
	components, valid := validateRelativePath(header.RelativePath)
	if !valid {
		failure := operationError{code: "invalid_relative_path", exitCode: exitInvalid}
		return materializationConfiguration{}, &failure
	}
	relativePath := header.RelativePath
	if header.Version != 1 || header.WorkspaceRoot != "/workspace" {
		failure := operationError{code: "invalid_header_contract", exitCode: exitInvalid, relativePath: &relativePath}
		return materializationConfiguration{}, &failure
	}
	if len(raw) == 0 || len(raw) > int(maximumHeaderBytes) || !validSHA256Ref(header.ExpectedSHA256) || !validSHA256Ref(header.ExpectedHelperSHA256) {
		failure := operationError{code: "invalid_header_digest", exitCode: exitInvalid, relativePath: &relativePath}
		return materializationConfiguration{}, &failure
	}
	if header.ExpectedBytes < 0 || header.ExpectedBytes > maximumBytes {
		failure := operationError{code: "invalid_expected_bytes", exitCode: exitInvalid, relativePath: &relativePath}
		return materializationConfiguration{}, &failure
	}
	config := materializationConfiguration{
		relativePath:         header.RelativePath,
		components:           components,
		expectedSHA256:       header.ExpectedSHA256,
		expectedHelperSHA256: header.ExpectedHelperSHA256,
		expectedBytes:        header.ExpectedBytes,
		operation:            header.Operation,
	}
	switch header.Mode {
	case 0o444:
		config.mode = 0o444
	case 0o555:
		config.mode = 0o555
	default:
		failure := operationError{code: "invalid_mode", exitCode: exitInvalid, relativePath: &relativePath}
		return materializationConfiguration{}, &failure
	}
	if config.operation != "create_or_verify" && config.operation != "verify_only" {
		failure := operationError{code: "invalid_operation", exitCode: exitInvalid, relativePath: &relativePath}
		return materializationConfiguration{}, &failure
	}
	if len(encodeReceipt(newReceipt(config, config.expectedHelperSHA256, "already_identical"))) > int(maximumHeaderBytes) {
		failure := operationError{code: "response_would_exceed_frame", exitCode: exitInvalid, relativePath: &relativePath}
		return materializationConfiguration{}, &failure
	}
	return config, nil
}

func readPayload(fd int, config materializationConfiguration, totalDeadline time.Time) ([]byte, *operationError) {
	payload := make([]byte, 0, config.expectedBytes)
	digest := sha256.New()
	for {
		deadline := boundedDeadline(totalDeadline)
		magic, err := readExact(fd, len(dataMagic), deadline)
		if err != nil {
			failure := framedReadFailure("payload_frame_truncated", err)
			return nil, &failure
		}
		switch {
		case bytes.Equal(magic, dataMagic):
			lengthBytes, err := readExact(fd, 4, deadline)
			if err != nil {
				failure := framedReadFailure("data_frame_truncated", err)
				return nil, &failure
			}
			length := binary.BigEndian.Uint32(lengthBytes)
			if length == 0 || length > maximumDataBytes || int64(len(payload))+int64(length) > config.expectedBytes {
				failure := operationError{code: "data_frame_length_mismatch", exitCode: exitInput}
				return nil, &failure
			}
			chunk, err := readExact(fd, int(length), deadline)
			if err != nil {
				failure := framedReadFailure("data_frame_truncated", err)
				return nil, &failure
			}
			payload = append(payload, chunk...)
			_, _ = digest.Write(chunk)
			ack := make([]byte, 16)
			copy(ack, dataAckMagic)
			binary.BigEndian.PutUint64(ack[8:], uint64(len(payload)))
			if err := writeAll(os.Stdout, ack); err != nil {
				failure := operationError{code: "ack_write_failure", exitCode: exitIO}
				return nil, &failure
			}
		case bytes.Equal(magic, endMagic):
			end, err := readExact(fd, 40, deadline)
			if err != nil {
				failure := framedReadFailure("end_frame_truncated", err)
				return nil, &failure
			}
			declaredTotal := binary.BigEndian.Uint64(end[:8])
			declaredDigest := end[8:]
			expectedDigest, _ := hex.DecodeString(strings.TrimPrefix(config.expectedSHA256, "sha256:"))
			actualDigest := digest.Sum(nil)
			if declaredTotal != uint64(config.expectedBytes) || int64(len(payload)) != config.expectedBytes || !bytes.Equal(declaredDigest, expectedDigest) || !bytes.Equal(actualDigest, expectedDigest) {
				failure := operationError{code: "payload_end_mismatch", exitCode: exitInput}
				return nil, &failure
			}
			extra, extraErr := queuedInput(fd)
			if extraErr != nil {
				failure := operationError{code: "payload_boundary_io_failure", exitCode: exitIO}
				return nil, &failure
			}
			if extra {
				failure := operationError{code: "payload_trailing_bytes", exitCode: exitInput}
				return nil, &failure
			}
			return payload, nil
		default:
			failure := operationError{code: "out_of_order_frame", exitCode: exitInput}
			return nil, &failure
		}
	}
}

func materialize(config materializationConfiguration, payload []byte) (string, *operationError) {
	relativePath := config.relativePath
	rootFD, err := syscall.Open("/workspace", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		failure := pathFailure("workspace_root_unavailable", err, &relativePath)
		return "", &failure
	}
	directoryFDs := []int{rootFD}
	directoryIdentities := make([]directoryIdentity, 0, len(config.components))
	rootIdentity, err := descriptorIdentity(rootFD)
	if err != nil {
		closeDescriptors(directoryFDs)
		failure := operationError{code: "workspace_root_identity_failure", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}
	directoryIdentities = append(directoryIdentities, rootIdentity)
	defer func() {
		closeDescriptors(directoryFDs)
	}()

	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)
	allowCreate := config.operation == "create_or_verify"
	for _, component := range config.components[:len(config.components)-1] {
		parentFD := directoryFDs[len(directoryFDs)-1]
		nextFD, openErr := syscall.Openat(parentFD, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil && errors.Is(openErr, syscall.ENOENT) && allowCreate {
			mkdirErr := syscall.Mkdirat(parentFD, component, 0o755)
			if mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				failure := pathFailure("parent_creation_failed", mkdirErr, &relativePath)
				return "", &failure
			}
			if mkdirErr == nil {
				if err := syscall.Fsync(parentFD); err != nil {
					failure := operationError{code: "parent_durability_failure", exitCode: exitIO, relativePath: &relativePath}
					return "", &failure
				}
			}
			nextFD, openErr = syscall.Openat(parentFD, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		if openErr != nil {
			failure := pathFailure("unsafe_parent", openErr, &relativePath)
			return "", &failure
		}
		directoryFDs = append(directoryFDs, nextFD)
		identity, identityErr := descriptorIdentity(nextFD)
		if identityErr != nil {
			failure := operationError{code: "parent_identity_failure", exitCode: exitIO, relativePath: &relativePath}
			return "", &failure
		}
		directoryIdentities = append(directoryIdentities, identity)
	}

	parentFD := directoryFDs[len(directoryFDs)-1]
	leaf := config.components[len(config.components)-1]
	if config.operation == "verify_only" {
		existingStat, verifyErr := verifyExisting(parentFD, leaf, payload, config.mode)
		if verifyErr != nil {
			failure := operationError{code: publicConflictCode(verifyErr), exitCode: exitUnsafe, relativePath: &relativePath}
			return "", &failure
		}
		if verifyReachableArtifact(config.components[:len(config.components)-1], directoryIdentities, leaf, payload, config.mode, existingStat) != nil {
			failure := operationError{code: "path_race", exitCode: exitUnsafe, relativePath: &relativePath}
			return "", &failure
		}
		return "already_identical", nil
	}

	existingStat, existingErr := verifyExisting(parentFD, leaf, payload, config.mode)
	if existingErr == nil {
		if verifyReachableArtifact(config.components[:len(config.components)-1], directoryIdentities, leaf, payload, config.mode, existingStat) != nil {
			failure := operationError{code: "path_race", exitCode: exitUnsafe, relativePath: &relativePath}
			return "", &failure
		}
		return "already_identical", nil
	}
	if !errors.Is(existingErr, syscall.ENOENT) {
		failure := operationError{code: publicConflictCode(existingErr), exitCode: exitUnsafe, relativePath: &relativePath}
		return "", &failure
	}

	temporaryFD, err := syscall.Openat(parentFD, ".", oTmpfile|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		failure := operationError{code: "anonymous_file_unavailable", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}
	temporary := os.NewFile(uintptr(temporaryFD), "ambit-atomic-materialize")
	if temporary == nil {
		syscall.Close(temporaryFD)
		failure := operationError{code: "anonymous_file_unavailable", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}
	defer temporary.Close()
	if err := writeAll(temporary, payload); err != nil {
		failure := operationError{code: "artifact_write_failure", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}
	if err := syscall.Fchmod(temporaryFD, config.mode); err != nil {
		failure := operationError{code: "artifact_mode_failure", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}
	if err := syscall.Fsync(temporaryFD); err != nil {
		failure := operationError{code: "artifact_durability_failure", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}
	var temporaryStat syscall.Stat_t
	if err := syscall.Fstat(temporaryFD, &temporaryStat); err != nil {
		failure := operationError{code: "artifact_identity_failure", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}

	linkErr := linkAnonymousFile(temporaryFD, parentFD, leaf)
	if linkErr != nil {
		if errors.Is(linkErr, syscall.EEXIST) {
			existingStat, verifyErr := verifyExisting(parentFD, leaf, payload, config.mode)
			if verifyErr == nil && verifyReachableArtifact(config.components[:len(config.components)-1], directoryIdentities, leaf, payload, config.mode, existingStat) == nil {
				return "already_identical", nil
			}
			code := "path_race"
			if verifyErr != nil {
				code = publicConflictCode(verifyErr)
			}
			failure := operationError{code: code, exitCode: exitUnsafe, relativePath: &relativePath}
			return "", &failure
		}
		if errors.Is(linkErr, syscall.ENOENT) || errors.Is(linkErr, syscall.ELOOP) || errors.Is(linkErr, syscall.ENOTDIR) || errors.Is(linkErr, syscall.ESTALE) || errors.Is(linkErr, syscall.EBUSY) {
			failure := operationError{code: "path_race", exitCode: exitUnsafe, relativePath: &relativePath}
			return "", &failure
		}
		failure := operationError{code: "publish_io_failure", exitCode: exitIO, relativePath: &relativePath}
		return "", &failure
	}

	if verifyReachableArtifact(config.components[:len(config.components)-1], directoryIdentities, leaf, payload, config.mode, temporaryStat) != nil {
		removePublished(parentFD, leaf)
		failure := operationError{code: "path_race", exitCode: exitUnsafe, relativePath: &relativePath}
		return "", &failure
	}
	for index := len(directoryFDs) - 1; index >= 0; index-- {
		if err := syscall.Fsync(directoryFDs[index]); err != nil {
			removePublished(parentFD, leaf)
			failure := operationError{code: "directory_durability_failure", exitCode: exitIO, relativePath: &relativePath}
			return "", &failure
		}
	}
	return "created", nil
}

func validateRelativePath(value string) ([]string, bool) {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) || norm.NFC.String(value) != value {
		return nil, false
	}
	for _, character := range value {
		if character <= 0x1f || (character >= 0x7f && character <= 0x9f) {
			return nil, false
		}
	}
	components := strings.Split(value, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return nil, false
		}
	}
	return components, true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validSHA256Ref(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validDigest(strings.TrimPrefix(value, "sha256:"))
}

func hashInstalledExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	fd, err := syscall.Open(executable, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "ambit-atomic-materialize-self")
	if file == nil {
		syscall.Close(fd)
		return "", syscall.EIO
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 {
		return "", syscall.EPERM
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func verifyExisting(parentFD int, leaf string, expected []byte, expectedMode uint32) (syscall.Stat_t, error) {
	fd, err := syscall.Openat(parentFD, leaf, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return syscall.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), "ambit-existing-artifact")
	if file == nil {
		syscall.Close(fd)
		return syscall.Stat_t{}, syscall.EIO
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return syscall.Stat_t{}, err
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return syscall.Stat_t{}, nonRegularFile
	}
	if before.Nlink != 1 {
		return syscall.Stat_t{}, linkCountInvalid
	}
	if before.Size != int64(len(expected)) || before.Mode&0o777 != expectedMode {
		return syscall.Stat_t{}, existingMismatch
	}
	digest := sha256.New()
	readBytes, err := io.Copy(digest, file)
	if err != nil || readBytes != int64(len(expected)) {
		return syscall.Stat_t{}, syscall.EIO
	}
	expectedDigest := sha256.Sum256(expected)
	if !bytes.Equal(digest.Sum(nil), expectedDigest[:]) {
		return syscall.Stat_t{}, existingMismatch
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return syscall.Stat_t{}, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return syscall.Stat_t{}, pathRace
	}
	return after, nil
}

func linkAnonymousFile(sourceFD, parentFD int, leaf string) error {
	empty, _ := syscall.BytePtrFromString("")
	target, err := syscall.BytePtrFromString(leaf)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(sourceFD), uintptr(unsafe.Pointer(empty)), uintptr(parentFD), uintptr(unsafe.Pointer(target)), uintptr(atEmptyPath), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func descriptorIdentity(fd int) (directoryIdentity, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return directoryIdentity{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return directoryIdentity{}, syscall.ENOTDIR
	}
	return directoryIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func verifyReachableArtifact(components []string, expectedDirectories []directoryIdentity, leaf string, payload []byte, mode uint32, expectedArtifact syscall.Stat_t) error {
	rootFD, err := syscall.Open("/workspace", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	descriptors := []int{rootFD}
	defer func() {
		closeDescriptors(descriptors)
	}()
	identity, err := descriptorIdentity(rootFD)
	if err != nil || identity != expectedDirectories[0] {
		return pathRace
	}
	for index, component := range components {
		fd, openErr := syscall.Openat(descriptors[len(descriptors)-1], component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			return openErr
		}
		descriptors = append(descriptors, fd)
		identity, identityErr := descriptorIdentity(fd)
		if identityErr != nil || identity != expectedDirectories[index+1] {
			return pathRace
		}
	}
	actualArtifact, err := verifyExisting(descriptors[len(descriptors)-1], leaf, payload, mode)
	if err != nil || actualArtifact.Dev != expectedArtifact.Dev || actualArtifact.Ino != expectedArtifact.Ino {
		return pathRace
	}
	return nil
}

func removePublished(parentFD int, leaf string) {
	_ = syscall.Unlinkat(parentFD, leaf)
	_ = syscall.Fsync(parentFD)
}

func queuedInput(fd int) (bool, error) {
	if err := syscall.SetNonblock(fd, true); err != nil {
		return false, err
	}
	defer syscall.SetNonblock(fd, false)
	buffer := []byte{0}
	for {
		count, err := syscall.Read(fd, buffer)
		if count > 0 {
			return true, nil
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, io.EOF) {
			return false, nil
		}
		if errors.Is(err, syscall.EIO) {
			return false, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return false, err
	}
}

func boundedDeadline(total time.Time) time.Time {
	frame := time.Now().Add(frameTimeout)
	if total.Before(frame) {
		return total
	}
	return frame
}

func readExact(fd, length int, deadline time.Time) ([]byte, error) {
	result := make([]byte, length)
	offset := 0
	for offset < length {
		if err := waitReadable(fd, deadline); err != nil {
			return nil, err
		}
		count, err := syscall.Read(fd, result[offset:])
		if count > 0 {
			offset += count
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, io.ErrUnexpectedEOF
		}
	}
	return result, nil
}

func waitReadable(fd int, deadline time.Time) error {
	word := fd / 64
	if word < 0 || word >= len((syscall.FdSet{}).Bits) {
		return syscall.EINVAL
	}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return deadlineFailure
		}
		var descriptors syscall.FdSet
		descriptors.Bits[word] |= int64(1) << uint(fd%64)
		timeout := syscall.NsecToTimeval(remaining.Nanoseconds())
		ready, err := syscall.Select(fd+1, &descriptors, nil, nil, &timeout)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			return deadlineFailure
		}
		return nil
	}
}

func framedReadFailure(code string, err error) operationError {
	if errors.Is(err, deadlineFailure) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.EIO) {
		return operationError{code: code, exitCode: exitInput}
	}
	return operationError{code: code, exitCode: exitIO}
}

func newReceipt(config materializationConfiguration, helperDigestRef, outcome string) receipt {
	body := receiptBody{
		Bytes:        config.expectedBytes,
		HelperSHA256: helperDigestRef,
		Kind:         "ambit_atomic_materialization_receipt",
		Mode:         config.mode,
		Operation:    config.operation,
		Outcome:      outcome,
		RelativePath: config.relativePath,
		SHA256:       config.expectedSHA256,
		Version:      1,
	}
	canonicalBody := encodeReceiptBody(body)
	receiptDigest := sha256.Sum256(canonicalBody)
	return receipt{
		Bytes:        body.Bytes,
		HelperSHA256: body.HelperSHA256,
		Kind:         body.Kind,
		Mode:         body.Mode,
		Operation:    body.Operation,
		Outcome:      body.Outcome,
		ReceiptRef:   fmt.Sprintf("atomic-materialization-receipt:sha256:%x", receiptDigest),
		RelativePath: body.RelativePath,
		SHA256:       body.SHA256,
		Version:      body.Version,
	}
}

func emitSuccess(config materializationConfiguration, helperDigest, outcome string) int {
	encoded := encodeReceipt(newReceipt(config, "sha256:"+helperDigest, outcome))
	if len(encoded) == 0 || len(encoded) > int(maximumHeaderBytes) {
		return emitError(operationError{code: "response_frame_overflow", exitCode: exitIO, relativePath: &config.relativePath})
	}
	return emitResponse(resultMagic, encoded, 0)
}

func emitError(failure operationError) int {
	encoded := encodeErrorReceipt(errorReceipt{Code: failure.code, Kind: "ambit_atomic_materialization_error", RelativePath: failure.relativePath, Version: 1})
	if len(encoded) == 0 || len(encoded) > int(maximumHeaderBytes) {
		encoded = []byte(`{"code":"error_frame_overflow","kind":"ambit_atomic_materialization_error","relativePath":null,"version":1}`)
	}
	return emitResponse(errorMagic, encoded, failure.exitCode)
}

func emitResponse(magic, encoded []byte, exitCode int) int {
	frame := make([]byte, 12+len(encoded))
	copy(frame, magic)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(encoded)))
	copy(frame[12:], encoded)
	if err := writeAll(os.Stdout, frame); err != nil {
		if exitCode != 0 {
			return exitCode
		}
		return exitIO
	}
	return exitCode
}

func encodeHeader(value requestHeader) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"expectedBytes":`)
	buffer.WriteString(strconv.FormatInt(value.ExpectedBytes, 10))
	buffer.WriteString(`,"expectedHelperSha256":`)
	writeJSONString(&buffer, value.ExpectedHelperSHA256)
	buffer.WriteString(`,"expectedSha256":`)
	writeJSONString(&buffer, value.ExpectedSHA256)
	buffer.WriteString(`,"mode":`)
	buffer.WriteString(strconv.FormatUint(uint64(value.Mode), 10))
	buffer.WriteString(`,"operation":`)
	writeJSONString(&buffer, value.Operation)
	buffer.WriteString(`,"relativePath":`)
	writeJSONString(&buffer, value.RelativePath)
	buffer.WriteString(`,"version":`)
	buffer.WriteString(strconv.Itoa(value.Version))
	buffer.WriteString(`,"workspaceRoot":`)
	writeJSONString(&buffer, value.WorkspaceRoot)
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func encodeReceiptBody(value receiptBody) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"bytes":`)
	buffer.WriteString(strconv.FormatInt(value.Bytes, 10))
	buffer.WriteString(`,"helperSha256":`)
	writeJSONString(&buffer, value.HelperSHA256)
	buffer.WriteString(`,"kind":`)
	writeJSONString(&buffer, value.Kind)
	buffer.WriteString(`,"mode":`)
	buffer.WriteString(strconv.FormatUint(uint64(value.Mode), 10))
	buffer.WriteString(`,"operation":`)
	writeJSONString(&buffer, value.Operation)
	buffer.WriteString(`,"outcome":`)
	writeJSONString(&buffer, value.Outcome)
	buffer.WriteString(`,"relativePath":`)
	writeJSONString(&buffer, value.RelativePath)
	buffer.WriteString(`,"sha256":`)
	writeJSONString(&buffer, value.SHA256)
	buffer.WriteString(`,"version":`)
	buffer.WriteString(strconv.Itoa(value.Version))
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func encodeReceipt(value receipt) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"bytes":`)
	buffer.WriteString(strconv.FormatInt(value.Bytes, 10))
	buffer.WriteString(`,"helperSha256":`)
	writeJSONString(&buffer, value.HelperSHA256)
	buffer.WriteString(`,"kind":`)
	writeJSONString(&buffer, value.Kind)
	buffer.WriteString(`,"mode":`)
	buffer.WriteString(strconv.FormatUint(uint64(value.Mode), 10))
	buffer.WriteString(`,"operation":`)
	writeJSONString(&buffer, value.Operation)
	buffer.WriteString(`,"outcome":`)
	writeJSONString(&buffer, value.Outcome)
	buffer.WriteString(`,"receiptRef":`)
	writeJSONString(&buffer, value.ReceiptRef)
	buffer.WriteString(`,"relativePath":`)
	writeJSONString(&buffer, value.RelativePath)
	buffer.WriteString(`,"sha256":`)
	writeJSONString(&buffer, value.SHA256)
	buffer.WriteString(`,"version":`)
	buffer.WriteString(strconv.Itoa(value.Version))
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func encodeErrorReceipt(value errorReceipt) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"code":`)
	writeJSONString(&buffer, value.Code)
	buffer.WriteString(`,"kind":`)
	writeJSONString(&buffer, value.Kind)
	buffer.WriteString(`,"relativePath":`)
	if value.RelativePath == nil {
		buffer.WriteString("null")
	} else {
		writeJSONString(&buffer, *value.RelativePath)
	}
	buffer.WriteString(`,"version":`)
	buffer.WriteString(strconv.Itoa(value.Version))
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func writeJSONString(buffer *bytes.Buffer, value string) {
	const hexadecimal = "0123456789abcdef"
	buffer.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			buffer.WriteByte('\\')
			buffer.WriteRune(character)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		default:
			if character < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(hexadecimal[byte(character)>>4])
				buffer.WriteByte(hexadecimal[byte(character)&0x0f])
			} else {
				buffer.WriteRune(character)
			}
		}
	}
	buffer.WriteByte('"')
}

func writeAll(file *os.File, payload []byte) error {
	for len(payload) > 0 {
		written, err := file.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func pathFailure(code string, err error, relativePath *string) operationError {
	if errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EMLINK) {
		return operationError{code: "unsafe_path", exitCode: exitUnsafe, relativePath: relativePath}
	}
	return operationError{code: code, exitCode: exitIO, relativePath: relativePath}
}

func publicConflictCode(err error) string {
	switch {
	case errors.Is(err, linkCountInvalid):
		return "link_count_invalid"
	case errors.Is(err, nonRegularFile):
		return "non_regular_file"
	case errors.Is(err, pathRace):
		return "path_race"
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.ENOENT):
		return "unsafe_path"
	default:
		return "existing_mismatch"
	}
}

func closeDescriptors(descriptors []int) {
	for index := len(descriptors) - 1; index >= 0; index-- {
		_ = syscall.Close(descriptors[index])
	}
}
