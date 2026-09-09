// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//go:build !linux

package session

import (
	"os/exec"
	"time"
)

// The daemon's existing release target is Linux. Keep other builds explicit;
// they must not pretend process-group enumeration proves descendant custody.
func RunSupervisor(args []string) (int, bool) { return 0, false }

func supervisorCommand(grace, interval time.Duration, shell string) *exec.Cmd { return nil }
