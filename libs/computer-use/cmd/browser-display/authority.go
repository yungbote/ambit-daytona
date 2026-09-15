// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"encoding/binary"
	"os"
	"strings"
)

// xgb may try an unauthenticated setup when its authority reader fails. Refuse
// before connecting unless its first matching local record is the explicit
// MIT cookie for this display. The driver still owns and starts the private
// authenticated Xvfb server; this is not a replacement display authority.
func explicitAuthority(path, displayName string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.Size() > 65536 {
		return false
	}
	data := make([]byte, stat.Size())
	if _, err = file.ReadAt(data, 0); err != nil {
		return false
	}
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	return matchingAuthority(data, displayName, hostname)
}
func matchingAuthority(data []byte, displayName, hostname string) bool {
	number := strings.SplitN(strings.TrimPrefix(displayName, ":"), ".", 2)[0]
	read := func() ([]byte, bool) {
		if len(data) < 2 {
			return nil, false
		}
		size := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		// Match xgb's actual authority-reader bound so its reader cannot fail
		// and silently retry without credentials after this validation.
		if size > 256 || len(data) < size {
			return nil, false
		}
		value := data[:size]
		data = data[size:]
		return value, true
	}
	for len(data) > 0 {
		if len(data) < 2 {
			return false
		}
		family := binary.BigEndian.Uint16(data)
		data = data[2:]
		address, ok := read()
		if !ok {
			return false
		}
		display, ok := read()
		if !ok {
			return false
		}
		name, ok := read()
		if !ok {
			return false
		}
		cookie, ok := read()
		if !ok {
			return false
		}
		if (family == 65535 || (family == 256 && string(address) == hostname)) && (len(display) == 0 || string(display) == number) {
			return string(name) == "MIT-MAGIC-COOKIE-1" && len(cookie) == 16
		}
	}
	return false
}
