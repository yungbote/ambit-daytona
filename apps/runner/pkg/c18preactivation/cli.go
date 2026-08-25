// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package c18preactivation

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/daytonaio/runner/pkg/generationstop"
)

func RunCLI(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	provider StreamingSpecialistRenderProvider,
	clock DriverClock,
) error {
	if stdin == nil || stdout == nil {
		return errors.New("C18 physical driver stdio is unavailable")
	}
	requestBytes, err := readCanonicalDriverLine(stdin, maximumPhysicalRequestBytes)
	if err != nil {
		return err
	}
	request, err := ParsePhysicalCaseRequestV2(requestBytes)
	if err != nil {
		return err
	}
	driver, err := NewPhysicalDriver(provider, clock)
	if err != nil {
		return err
	}
	observation, err := driver.Evaluate(ctx, request)
	if err != nil {
		return err
	}
	encoded, err := generationstop.CanonicalJSON(observation)
	if err != nil || len(encoded) < 2 || len(encoded) > maximumPhysicalResponseBytes {
		return errors.New("C18 physical observation encoding is invalid")
	}
	if _, err := ParsePhysicalCaseObservationV2(encoded, request); err != nil {
		return err
	}
	framed := append(encoded, '\n')
	written, err := stdout.Write(framed)
	if err != nil {
		return fmt.Errorf("write C18 physical observation: %w", err)
	}
	if written != len(framed) {
		return io.ErrShortWrite
	}
	return nil
}

func readCanonicalDriverLine(reader io.Reader, maximum int) ([]byte, error) {
	buffered := bufio.NewReaderSize(reader, maximum+2)
	line, err := buffered.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maximum+1 {
		return nil, errors.New("C18 physical request line exceeds its bound")
	}
	if err != nil || len(line) < 3 || line[len(line)-1] != '\n' ||
		bytes.IndexByte(line[:len(line)-1], '\r') >= 0 || bytes.IndexByte(line[:len(line)-1], '\n') >= 0 {
		return nil, errors.New("C18 physical request framing is invalid")
	}
	if trailing, err := buffered.ReadByte(); err == nil {
		return nil, fmt.Errorf("C18 physical request contains trailing byte %#x", trailing)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read C18 physical request tail: %w", err)
	}
	return append([]byte(nil), line[:len(line)-1]...), nil
}
