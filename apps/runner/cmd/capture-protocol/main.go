// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// capture-protocol writes exact source-owned interface bytes for qualification.
// It does not observe a running Runner or issue a conformance receipt.
package main

import (
	"fmt"
	"os"

	"github.com/daytonaio/runner/pkg/api/docs"
)

func main() {
	protocol, err := docs.CaptureProtocol()
	if err == nil {
		_, err = os.Stdout.Write(protocol)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
