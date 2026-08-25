// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package c18oci owns the single Go admission grammar for immutable C18 image
// references shared by provider requests and preactivation authority.
package c18oci

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var repositoryComponent = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
var registryLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var bracketedIPv6Authority = regexp.MustCompile(`^\[([0-9a-f:]+)\](?::([1-9][0-9]{0,4}))?$`)

func ValidImmutableReference(value string) bool {
	return validImmutableReference(value, false)
}

func ValidImmutableSourceReference(value string) bool {
	return validImmutableReference(value, true)
}

func validImmutableReference(value string, allowLoopback bool) bool {
	if value == "" || len([]byte(value)) > 512 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zs, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	pieces := strings.Split(value, "@")
	if len(pieces) != 2 || !exactSHA256(pieces[1]) {
		return false
	}
	location := strings.Split(pieces[0], "/")
	if len(location) < 2 || !ValidRegistryAuthority(location[0], false, allowLoopback) {
		return false
	}
	for _, component := range location[1:] {
		if !repositoryComponent.MatchString(component) {
			return false
		}
	}
	return true
}

func ValidRegistryAuthority(value string, requirePort, allowLoopback bool) bool {
	if match := bracketedIPv6Authority.FindStringSubmatch(value); match != nil {
		address := net.ParseIP(match[1])
		return address != nil && address.To4() == nil && strings.Contains(match[1], ":") &&
			address.String() == match[1] && validPort(match[2]) && (!requirePort || match[2] != "") &&
			(allowLoopback || !address.IsLoopback())
	}
	if strings.Count(value, ":") > 1 {
		return false
	}
	host, port, hasPort := strings.Cut(value, ":")
	if hasPort && (port == "" || !validPort(port)) {
		return false
	}
	if requirePort && !hasPort {
		return false
	}
	if address := net.ParseIP(host); address != nil {
		return address.To4() != nil && address.String() == host && (allowLoopback || !address.IsLoopback())
	}
	if legacyNumericHost(host) {
		return false
	}
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !registryLabel.MatchString(label) {
			return false
		}
	}
	return allowLoopback || host != "localhost"
}

func legacyNumericHost(value string) bool {
	components := strings.Split(value, ".")
	if len(components) == 0 {
		return false
	}
	for _, component := range components {
		if component == "" {
			return false
		}
		if strings.HasPrefix(component, "0x") {
			if len(component) == 2 {
				return false
			}
			for _, character := range strings.TrimPrefix(component, "0x") {
				if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
					return false
				}
			}
			continue
		}
		for _, character := range component {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validPort(value string) bool {
	if value == "" {
		return true
	}
	if value[0] == '0' || len(value) > 5 {
		return false
	}
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65_535 && strconv.Itoa(port) == value
}

func exactSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
