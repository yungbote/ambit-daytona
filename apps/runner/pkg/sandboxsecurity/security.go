// Copyright 2026 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

// Package sandboxsecurity shares Linux security facts and exact seccomp bytes.
// Workspace and specialist owners retain their separate admission policies.
package sandboxsecurity

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const RootlessSeccompDigest = "sha256:9de0b08286e0c0ba068eb8f6bf9e2aa49860327b654b8f0b20bcabc4fdc796f2"

//go:embed rootless-seccomp-v1.json
var rootlessSeccomp string

func RootlessSeccomp() string { return rootlessSeccomp }

func ValidateRootlessSeccomp(value []byte) error {
	if fmt.Sprintf("sha256:%x", sha256.Sum256(value)) != RootlessSeccompDigest {
		return fmt.Errorf("rootless seccomp bytes do not match the qualified profile")
	}
	return nil
}

type ProcessSecurity struct {
	StartTicks              string
	NoNewPrivileges         bool
	SeccompMode             int
	EffectiveCapabilities   string
	PermittedCapabilities   string
	BoundingCapabilities    string
	InheritableCapabilities string
	AmbientCapabilities     string
}

func ObserveProcess(pid int) (ProcessSecurity, error) {
	if pid <= 0 {
		return ProcessSecurity{}, fmt.Errorf("process identity is absent")
	}
	before, err := ProcessStartTicks(pid)
	if err != nil {
		return ProcessSecurity{}, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ProcessSecurity{}, err
	}
	observed, err := ParseProcessStatus(status)
	if err != nil {
		return ProcessSecurity{}, err
	}
	after, err := ProcessStartTicks(pid)
	if err != nil || before != after {
		return ProcessSecurity{}, fmt.Errorf("process generation changed while observing security")
	}
	observed.StartTicks = before
	return observed, nil
}

// ProcessStartTicks is the existing Linux process-generation witness shared
// with specialist rendering. A numeric PID alone is not a stable identity.
func ProcessStartTicks(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("process identity is absent")
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	return parseProcessStartTicks(stat)
}

func parseProcessStartTicks(stat []byte) (string, error) {
	closeIndex := strings.LastIndexByte(string(stat), ')')
	if closeIndex < 0 {
		return "", fmt.Errorf("process stat command terminator is absent")
	}
	fields := strings.Fields(string(stat[closeIndex+1:]))
	if len(fields) <= 19 {
		return "", fmt.Errorf("process stat is incomplete")
	}
	if value, err := strconv.ParseUint(fields[19], 10, 64); err != nil || value == 0 {
		return "", fmt.Errorf("process start ticks are invalid")
	}
	return fields[19], nil
}

func ParseProcessStatus(status []byte) (ProcessSecurity, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			values[strings.TrimSuffix(fields[0], ":")] = fields[1]
		}
	}
	seccomp, err := strconv.Atoi(values["Seccomp"])
	if err != nil || seccomp < 0 || seccomp > 2 ||
		(values["NoNewPrivs"] != "0" && values["NoNewPrivs"] != "1") {
		return ProcessSecurity{}, fmt.Errorf("process security status is incomplete")
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
		values[key] = strings.ToLower(values[key])
		if _, err := strconv.ParseUint(values[key], 16, 64); err != nil || len(values[key]) != 16 {
			return ProcessSecurity{}, fmt.Errorf("process capability mask is invalid")
		}
	}
	return ProcessSecurity{
		NoNewPrivileges: values["NoNewPrivs"] == "1", SeccompMode: seccomp,
		EffectiveCapabilities: values["CapEff"], PermittedCapabilities: values["CapPrm"],
		BoundingCapabilities: values["CapBnd"], InheritableCapabilities: values["CapInh"],
		AmbientCapabilities: values["CapAmb"],
	}, nil
}
