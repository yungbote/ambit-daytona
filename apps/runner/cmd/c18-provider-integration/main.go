// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/daytonaio/runner/pkg/c18providerintegration"
)

func main() {
	os.Exit(run())
}

func run() int {
	requestPath := flag.String("request", "", "absolute canonical C18 provider live-run request")
	outputPath := flag.String("output", "", "absolute new canonical collection output")
	journalPath := flag.String("journal", "", "absolute private crash-recovery journal")
	flag.Parse()
	if flag.NArg() != 0 || *requestPath == "" || *outputPath == "" || *journalPath == "" {
		fmt.Fprintln(os.Stderr, "usage: c18-provider-integration --request ABSOLUTE_JSON --journal ABSOLUTE_PRIVATE_JSON --output ABSOLUTE_NEW_JSON")
		return 64
	}
	runRequest, _, err := c18providerintegration.ReadProviderLiveRun(*requestPath)
	if err != nil {
		return fail(err)
	}
	api, err := c18providerintegration.DaytonaConfigFromEnvironment()
	if err != nil {
		return fail(err)
	}
	collector, err := c18providerintegration.NewCollector(api, nil)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	collection, err := collector.CollectWithJournal(ctx, runRequest, *journalPath)
	if err != nil {
		return fail(err)
	}
	if err := c18providerintegration.WriteCanonicalExclusive(*outputPath, collection); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "c18-provider-integration: %v\n", err)
	if errors.Is(err, c18providerintegration.ErrProviderCollectionAbandoned) {
		return 75
	}
	return 1
}
