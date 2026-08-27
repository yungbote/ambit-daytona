// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

// Command c18-image-publication validates and publishes the four pinned C18
// OCI archives to one request-authorized loopback Distribution v2 endpoint.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daytonaio/runner/pkg/c18imagepublication"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("c18-image-publication", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", "", "absolute canonical publication request path")
	requestSHA256 := flags.String("request-sha256", "", "exact sha256: digest of the request bytes")
	outputPath := flags.String("output", "", "absolute new canonical receipt output path")
	if err := flags.Parse(arguments); err != nil {
		return 64
	}
	if flags.NArg() != 0 || *requestPath == "" || *requestSHA256 == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "usage: c18-image-publication --request ABSOLUTE_JSON --request-sha256 sha256:HEX --output ABSOLUTE_NEW_JSON")
		return 64
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, 2*time.Hour)
	defer cancel()
	output, err := c18imagepublication.OpenReceiptOutput(*outputPath)
	if err != nil {
		return fail(stderr, err)
	}
	failAfterOutput := func(cause error) int {
		return fail(stderr, errors.Join(cause, output.Close()))
	}
	request, _, err := c18imagepublication.ReadRequest(ctx, *requestPath, *requestSHA256)
	if err != nil {
		return failAfterOutput(err)
	}
	executableSHA256, err := c18imagepublication.ExecutableSHA256(ctx)
	if err != nil {
		return failAfterOutput(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	// No flat ResponseHeaderTimeout: a whole-layer PATCH only answers after
	// its body has streamed, which legitimately takes minutes over a
	// kubectl port-forward. The registry client already bounds every
	// request by context (base timeout for small operations; a progress
	// watchdog plus a size-scaled total timeout for transfers), and the
	// client's overall Timeout caps the whole publication.
	client := &http.Client{Transport: transport, Timeout: 45 * time.Minute}
	publisher, err := c18imagepublication.NewPublisher(client, time.Now, executableSHA256)
	if err != nil {
		return failAfterOutput(err)
	}
	receipt, err := publisher.Publish(ctx, request, *requestSHA256)
	if err != nil {
		return failAfterOutput(err)
	}
	if err := context.Cause(ctx); err != nil {
		return failAfterOutput(err)
	}
	if err := output.CommitAndClose(receipt); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "c18-image-publication: %v\n", err)
	return 1
}
