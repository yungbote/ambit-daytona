// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daytonaio/runner/pkg/c18oci"
	"github.com/daytonaio/runner/pkg/generationstop"
	"github.com/daytonaio/runner/pkg/specialistrender"
	"golang.org/x/sys/unix"
)

const (
	policyGenerationReceiptContract = "C18RunnerPolicyGenerationReceipt@1"
	runtimeAuthorityRoot            = "/opt/ambit/c18-authority"
	runtimeSeccompPath              = runtimeAuthorityRoot + "/specialist-seccomp-v1.json"
	policyFileName                  = "runner-policy.json"
	policyReceiptFileName           = "runner-policy-generation-receipt.json"
	seccompFileName                 = "specialist-seccomp-v1.json"
)

var authorityFileRoster = []string{policyReceiptFileName, policyFileName, seccompFileName}

type policyReceiptSource struct {
	Revision                  string `json:"revision"`
	Tree                      string `json:"tree"`
	SourceSetDigest           string `json:"sourceSetDigest"`
	SourceContractsFileSHA256 string `json:"sourceContractsFileSha256"`
}

type policyReceiptGenerator struct {
	ExecutableSHA256 string `json:"executableSha256"`
}

type policyReceiptRegistry struct {
	InspectAuthority string `json:"inspectAuthority"`
	RuntimeAuthority string `json:"runtimeAuthority"`
}

type policyReceiptInputs struct {
	CompositionFileSHA256   string `json:"compositionFileSha256"`
	RoutingFileSHA256       string `json:"routingFileSha256"`
	SeccompSourceFileSHA256 string `json:"seccompSourceFileSha256"`
	SeccompCopiedFileSHA256 string `json:"seccompCopiedFileSha256"`
	SeccompRuntimePath      string `json:"seccompRuntimePath"`
}

type policyReceiptImage struct {
	PackID          string `json:"packId"`
	RuntimeImageRef string `json:"runtimeImageRef"`
	InspectImageRef string `json:"inspectImageRef"`
	ManifestDigest  string `json:"manifestDigest"`
	ConfigDigest    string `json:"configDigest"`
}

type policyReceiptPolicy struct {
	Schema     string `json:"schema"`
	RowCount   int    `json:"rowCount"`
	FileSHA256 string `json:"fileSha256"`
}

type policyGenerationReceipt struct {
	Contract   string                 `json:"contract"`
	Digest     string                 `json:"digest"`
	ObservedAt string                 `json:"observedAt"`
	Source     policyReceiptSource    `json:"source"`
	Generator  policyReceiptGenerator `json:"generator"`
	Registry   policyReceiptRegistry  `json:"registry"`
	Inputs     policyReceiptInputs    `json:"inputs"`
	Images     []policyReceiptImage   `json:"images"`
	Policy     policyReceiptPolicy    `json:"policy"`
}

type policyGenerationReceiptBody struct {
	Contract   string                 `json:"contract"`
	ObservedAt string                 `json:"observedAt"`
	Source     policyReceiptSource    `json:"source"`
	Generator  policyReceiptGenerator `json:"generator"`
	Registry   policyReceiptRegistry  `json:"registry"`
	Inputs     policyReceiptInputs    `json:"inputs"`
	Images     []policyReceiptImage   `json:"images"`
	Policy     policyReceiptPolicy    `json:"policy"`
}

func sealPolicyGenerationReceipt(value policyGenerationReceipt) (policyGenerationReceipt, error) {
	value.Contract = policyGenerationReceiptContract
	value.Digest = ""
	if err := validatePolicyGenerationReceiptBody(value); err != nil {
		return policyGenerationReceipt{}, err
	}
	body, err := generationstop.CanonicalJSON(policyReceiptBody(value))
	if err != nil {
		return policyGenerationReceipt{}, fmt.Errorf("canonicalize policy generation receipt: %w", err)
	}
	value.Digest = digestBytes(body)
	encoded, err := generationstop.CanonicalJSON(value)
	if err != nil {
		return policyGenerationReceipt{}, err
	}
	return parsePolicyGenerationReceipt(encoded)
}

func parsePolicyGenerationReceipt(encoded []byte) (policyGenerationReceipt, error) {
	var value policyGenerationReceipt
	if err := generationstop.DecodeCanonicalJSON(encoded, &value); err != nil {
		return policyGenerationReceipt{}, fmt.Errorf("decode canonical policy generation receipt: %w", err)
	}
	if value.Contract != policyGenerationReceiptContract {
		return policyGenerationReceipt{}, errors.New("policy generation receipt contract is invalid")
	}
	if err := validatePolicyGenerationReceiptBody(value); err != nil {
		return policyGenerationReceipt{}, err
	}
	body, err := generationstop.CanonicalJSON(policyReceiptBody(value))
	if err != nil || value.Digest != digestBytes(body) {
		return policyGenerationReceipt{}, errors.New("policy generation receipt digest is invalid")
	}
	return value, nil
}

func validatePolicyGenerationReceiptBody(value policyGenerationReceipt) error {
	if !gitObject(value.Source.Revision) || !gitObject(value.Source.Tree) ||
		!exactSHA256(value.Source.SourceSetDigest) ||
		value.Source.SourceContractsFileSHA256 != value.Source.SourceSetDigest ||
		!exactSHA256(value.Generator.ExecutableSHA256) ||
		!exactSHA256(value.Inputs.CompositionFileSHA256) ||
		!exactSHA256(value.Inputs.RoutingFileSHA256) ||
		!exactSHA256(value.Inputs.SeccompSourceFileSHA256) ||
		value.Inputs.SeccompSourceFileSHA256 != specialistrender.SpecialistSeccompDigest ||
		value.Inputs.SeccompCopiedFileSHA256 != value.Inputs.SeccompSourceFileSHA256 ||
		value.Inputs.SeccompRuntimePath != runtimeSeccompPath ||
		!c18oci.ValidRegistryAuthority(value.Registry.InspectAuthority, true, true) ||
		!c18oci.ValidRegistryAuthority(value.Registry.RuntimeAuthority, true, false) ||
		value.Policy.Schema != specialistrender.PolicySetSchema || value.Policy.RowCount != 4 ||
		!exactSHA256(value.Policy.FileSHA256) || !exactMillisecondInstant(value.ObservedAt) {
		return errors.New("policy generation receipt body is invalid")
	}
	expectedPacks := []string{"data-research", "office-authoring", "pdf-ocr", "web-browser"}
	if len(value.Images) != len(expectedPacks) {
		return errors.New("policy generation receipt image roster is invalid")
	}
	for index, image := range value.Images {
		inspectRef, runtimeAuthority, manifestDigest, err := rewriteRegistryAuthority(
			image.RuntimeImageRef, value.Registry.InspectAuthority,
		)
		if err != nil || image.PackID != expectedPacks[index] ||
			runtimeAuthority != value.Registry.RuntimeAuthority || image.InspectImageRef != inspectRef ||
			image.ManifestDigest != manifestDigest || !exactSHA256(image.ConfigDigest) {
			return errors.New("policy generation receipt image identity is invalid")
		}
	}
	return nil
}

func policyReceiptBody(value policyGenerationReceipt) policyGenerationReceiptBody {
	return policyGenerationReceiptBody{
		Contract: value.Contract, ObservedAt: value.ObservedAt, Source: value.Source,
		Generator: value.Generator, Registry: value.Registry, Inputs: value.Inputs,
		Images: value.Images, Policy: value.Policy,
	}
}

func publishAuthorityDirectory(
	outputRoot string,
	policyBytes []byte,
	receiptBytes []byte,
	seccompBytes []byte,
) error {
	if err := preflightAuthorityOutputRoot(outputRoot); err != nil {
		return err
	}
	parent := filepath.Dir(outputRoot)
	receipt, err := parsePolicyGenerationReceipt(receiptBytes)
	if err != nil {
		return err
	}
	if receipt.Policy.FileSHA256 != digestBytes(policyBytes) ||
		receipt.Inputs.SeccompCopiedFileSHA256 != digestBytes(seccompBytes) {
		return errors.New("authority output bytes differ from the generation receipt")
	}
	var policy specialistrender.PolicySet
	if err := generationstop.DecodeCanonicalJSON(policyBytes, &policy); err != nil ||
		policy.Schema != specialistrender.PolicySetSchema || len(policy.Policies) != 4 {
		return errors.New("authority policy output is invalid")
	}
	for index, row := range policy.Policies {
		image := receipt.Images[index]
		if row.Image.PackID != image.PackID || row.Image.Ref != image.RuntimeImageRef ||
			row.Image.ConfigDigest != image.ConfigDigest || row.SeccompPath != runtimeSeccompPath ||
			row.SeccompDigest != receipt.Inputs.SeccompCopiedFileSHA256 {
			return errors.New("authority policy rows differ from the generation receipt")
		}
	}

	staging, err := os.MkdirTemp(parent, ".c18-authority-staging-*")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.Chmod(staging, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		policyFileName: policyBytes, policyReceiptFileName: receiptBytes, seccompFileName: seccompBytes,
	}
	for _, name := range authorityFileRoster {
		if err := writePrivateFile(filepath.Join(staging, name), files[name]); err != nil {
			return err
		}
	}
	if err := validateAuthorityDirectory(staging, receipt); err != nil {
		return err
	}
	stagingHandle, err := os.Open(staging)
	if err != nil {
		return err
	}
	if err := stagingHandle.Sync(); err != nil {
		_ = stagingHandle.Close()
		return err
	}
	if err := stagingHandle.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, outputRoot, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("authority output root already exists")
		}
		return err
	}
	committed = true
	parentHandle, err := os.Open(parent)
	if err != nil {
		return rollbackPublishedAuthority(outputRoot, err)
	}
	syncErr := parentHandle.Sync()
	closeErr := parentHandle.Close()
	if syncErr != nil || closeErr != nil {
		return rollbackPublishedAuthority(outputRoot, errors.Join(syncErr, closeErr))
	}
	return nil
}

func preflightAuthorityOutputRoot(outputRoot string) error {
	if !absoluteNormalizedPath(outputRoot) || filepath.Base(outputRoot) == "." || filepath.Base(outputRoot) == ".." {
		return errors.New("authority output root is invalid")
	}
	if _, err := os.Lstat(outputRoot); err == nil {
		return errors.New("authority output root already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(outputRoot)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("authority output parent is invalid")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return errors.New("authority output parent may not contain symlinks")
	}
	return nil
}

func validateAuthorityDirectory(root string, receipt policyGenerationReceipt) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("authority directory metadata is invalid")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(authorityFileRoster) {
		return errors.New("authority directory roster is invalid")
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
		entryInfo, infoErr := entry.Info()
		if infoErr != nil || !entryInfo.Mode().IsRegular() || entryInfo.Mode().Perm() != 0o600 {
			return errors.New("authority file metadata is invalid")
		}
	}
	sort.Strings(names)
	if strings.Join(names, "\n") != strings.Join(authorityFileRoster, "\n") {
		return errors.New("authority directory contains an unexpected file")
	}
	policyBytes, err := readRegularFileSnapshot(filepath.Join(root, policyFileName), 32*1024*1024)
	if err != nil || digestBytes(policyBytes) != receipt.Policy.FileSHA256 {
		return errors.New("published policy differs from its receipt")
	}
	seccompBytes, err := readRegularFileSnapshot(filepath.Join(root, seccompFileName), 4*1024*1024)
	if err != nil || digestBytes(seccompBytes) != receipt.Inputs.SeccompCopiedFileSHA256 {
		return errors.New("published seccomp differs from its receipt")
	}
	receiptBytes, err := readRegularFileSnapshot(filepath.Join(root, policyReceiptFileName), 4*1024*1024)
	if err != nil {
		return err
	}
	parsed, err := parsePolicyGenerationReceipt(receiptBytes)
	if err != nil || parsed.Digest != receipt.Digest {
		return errors.New("published generation receipt differs")
	}
	return nil
}

func rollbackPublishedAuthority(root string, cause error) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(cause, errors.New("cannot safely roll back authority directory"))
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(authorityFileRoster) {
		return errors.Join(cause, errors.New("authority directory changed before rollback"))
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
		entryInfo, infoErr := entry.Info()
		if infoErr != nil || !entryInfo.Mode().IsRegular() || entryInfo.Mode().Perm() != 0o600 {
			return errors.Join(cause, errors.New("authority files changed before rollback"))
		}
	}
	sort.Strings(names)
	if strings.Join(names, "\n") != strings.Join(authorityFileRoster, "\n") {
		return errors.Join(cause, errors.New("authority roster changed before rollback"))
	}
	for _, name := range names {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			return errors.Join(cause, err)
		}
	}
	if err := os.Remove(root); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func writePrivateFile(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readRegularFileSnapshot(path string, maximum int64) ([]byte, error) {
	if !absoluteNormalizedPath(path) || maximum < 1 {
		return nil, errors.New("input file path or bound is invalid")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("input file descriptor is invalid")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("input file metadata is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.Size() {
		return nil, errors.New("input file bytes are invalid")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("input file changed while read")
	}
	return data, nil
}

func readExecutableSnapshot() ([]byte, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 512*1024*1024 {
		return nil, errors.New("generator executable metadata is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, 512*1024*1024+1))
	if err != nil || int64(len(data)) != before.Size() {
		return nil, errors.New("generator executable bytes are invalid")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("generator executable changed while read")
	}
	return data, nil
}

func absoluteNormalizedPath(value string) bool {
	return value != "" && len(value) <= 4096 && value == strings.TrimSpace(value) &&
		filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" &&
		!strings.ContainsRune(value, 0)
}

func exactSHA256(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") &&
		strings.ToLower(value) == value && lowerHex(strings.TrimPrefix(value, "sha256:"))
}

func gitObject(value string) bool {
	return len(value) == 40 && strings.ToLower(value) == value && lowerHex(value)
}

func lowerHex(value string) bool {
	if value == "" {
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

func rewriteRegistryAuthority(runtimeReference, inspectAuthority string) (string, string, string, error) {
	if !c18oci.ValidRegistryAuthority(inspectAuthority, true, true) || strings.Count(runtimeReference, "@") != 1 {
		return "", "", "", errors.New("registry image authority is invalid")
	}
	name, manifestDigest, found := strings.Cut(runtimeReference, "@")
	slash := strings.IndexByte(name, '/')
	if !found || slash < 1 || slash == len(name)-1 || !exactSHA256(manifestDigest) {
		return "", "", "", errors.New("runtime image reference is invalid")
	}
	runtimeAuthority := name[:slash]
	repositoryPath := name[slash+1:]
	if !c18oci.ValidRegistryAuthority(runtimeAuthority, true, false) || !registryRepositoryPath(repositoryPath) {
		return "", "", "", errors.New("runtime image reference is invalid")
	}
	return inspectAuthority + "/" + repositoryPath + "@" + manifestDigest,
		runtimeAuthority, manifestDigest, nil
}

func registryRepositoryPath(value string) bool {
	if value == "" || len(value) > 2048 || value != strings.ToLower(value) {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." ||
			!lowerAlphaNumeric(component[0]) || !lowerAlphaNumeric(component[len(component)-1]) {
			return false
		}
		for _, character := range component {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				character != '.' && character != '_' && character != '-' {
				return false
			}
		}
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
