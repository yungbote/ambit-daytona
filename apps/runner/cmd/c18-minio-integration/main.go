// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daytonaio/runner/pkg/c18providerintegration"
	"github.com/daytonaio/runner/pkg/storage"
)

func main() {
	os.Exit(run())
}

func run() int {
	requestPath := flag.String("request", "", "absolute canonical C18 MinIO integration request")
	outputPath := flag.String("output", "", "absolute new canonical MinIO receipt output")
	flag.Parse()
	if flag.NArg() != 0 || *requestPath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: c18-minio-integration --request ABSOLUTE_JSON --output ABSOLUTE_NEW_JSON")
		return 64
	}
	runRequest, _, err := c18providerintegration.ReadMinIOIntegrationRun(*requestPath)
	if err != nil {
		return fail(err)
	}
	privateObjects, err := storage.GetPrivateObjectStorageClient()
	if err != nil {
		return fail(fmt.Errorf("private object storage is unavailable: %w", err))
	}
	streaming, ok := privateObjects.(storage.PrivateObjectStreamStorageClient)
	if !ok {
		return fail(fmt.Errorf("streaming private object storage is unavailable"))
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	receipt, err := c18providerintegration.RunMinIOIntegration(ctx, runRequest, streaming, nil)
	if err != nil {
		return fail(err)
	}
	if err := c18providerintegration.WriteCanonicalExclusive(*outputPath, receipt); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "c18-minio-integration: %v\n", err)
	return 1
}
