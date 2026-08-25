// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/daytonaio/runner/pkg/c18preactivation"
)

func main() {
	if len(os.Args) != 1 {
		fail()
		return
	}
	config, err := c18preactivation.HTTPProviderConfigFromEnvironment(os.Getenv)
	if err != nil {
		fail()
		return
	}
	provider, err := c18preactivation.NewHTTPProvider(config, &http.Client{})
	if err != nil {
		fail()
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c18preactivation.RunCLI(ctx, os.Stdin, os.Stdout, provider, nil); err != nil {
		fail()
	}
}

func fail() {
	_, _ = os.Stderr.WriteString("C18 preactivation physical driver failed.\n")
	os.Exit(1)
}
