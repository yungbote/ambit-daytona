// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"maps"
	"testing"
)

func TestSandboxUsesSecrets(t *testing.T) {
	if sandboxUsesSecrets(map[string]string{"FOO": "bar", "BAZ": "qux"}) {
		t.Fatal("env with no placeholder should report no secrets")
	}
	if !sandboxUsesSecrets(map[string]string{"ANTHROPIC_API_KEY": "dtn_secret_abc123"}) {
		t.Fatal("env with a placeholder should report secrets")
	}
	if sandboxUsesSecrets(nil) {
		t.Fatal("nil env should report no secrets")
	}
}

func TestFirstHostIP(t *testing.T) {
	cases := map[string]string{
		"172.20.0.0/16":  "172.20.0.1",
		"10.0.0.0/8":     "10.0.0.1",
		"192.168.5.0/24": "192.168.5.1",
		"not-a-cidr":     "",
	}
	for cidr, want := range cases {
		if got := firstHostIP(cidr); got != want {
			t.Errorf("firstHostIP(%q) = %q, want %q", cidr, got, want)
		}
	}
}

func TestEnvSliceToMap(t *testing.T) {
	m := envSliceToMap([]string{"A=1", "B=two=2", "MALFORMED", "=novalue"})
	if m["A"] != "1" {
		t.Errorf("A = %q, want 1", m["A"])
	}
	if m["B"] != "two=2" {
		t.Errorf("B = %q, want two=2", m["B"])
	}
	if _, ok := m["MALFORMED"]; ok {
		t.Error("entry without '=' should be skipped")
	}
	if _, ok := m[""]; ok {
		t.Error("entry with empty key should be skipped")
	}
}

func TestProxyWiringEnvVars(t *testing.T) {
	secretEnv := map[string]string{"KEY": "dtn_secret_x"}
	plainEnv := map[string]string{"KEY": "plain"}
	const proxyAddr = "172.20.0.1:18080"

	tests := []struct {
		name            string
		client          *DockerClient
		env             map[string]string
		domainAllowList string
		wantWiring      bool
	}{
		{
			name:       "proxy unavailable",
			client:     &DockerClient{},
			env:        secretEnv,
			wantWiring: false,
		},
		{
			name:       "plain sandbox",
			client:     &DockerClient{secretProxyAddr: proxyAddr},
			env:        plainEnv,
			wantWiring: false,
		},
		{
			name:            "domain policy without enforcement",
			client:          &DockerClient{secretProxyAddr: proxyAddr},
			env:             plainEnv,
			domainAllowList: "example.com",
			wantWiring:      false,
		},
		{
			name: "domain policy with enforcement",
			client: &DockerClient{
				secretProxyAddr:         proxyAddr,
				proxyEnforcementEnabled: true,
			},
			env:             plainEnv,
			domainAllowList: "example.com",
			wantWiring:      true,
		},
		{
			name:       "secret sandbox",
			client:     &DockerClient{secretProxyAddr: proxyAddr},
			env:        secretEnv,
			wantWiring: true,
		},
	}

	proxyURL := "http://" + proxyAddr
	want := map[string]string{
		"HTTP_PROXY":          proxyURL,
		"HTTPS_PROXY":         proxyURL,
		"http_proxy":          proxyURL,
		"https_proxy":         proxyURL,
		"NO_PROXY":            "localhost,127.0.0.1,::1",
		"no_proxy":            "localhost,127.0.0.1,::1",
		"SSL_CERT_FILE":       secretCAContainerPath,
		"NODE_EXTRA_CA_CERTS": secretCAContainerPath,
		"REQUESTS_CA_BUNDLE":  secretCAContainerPath,
		"CURL_CA_BUNDLE":      secretCAContainerPath,
		"DENO_CERT":           secretCAContainerPath,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.client.proxyWiringEnvVars(tt.env, tt.domainAllowList)
			if !tt.wantWiring {
				if got != nil {
					t.Fatalf("proxyWiringEnvVars() = %v, want nil", got)
				}
				return
			}

			gotMap := envSliceToMap(got)
			if len(got) != len(want) {
				t.Fatalf("proxyWiringEnvVars() returned %d entries, want %d: %v", len(got), len(want), got)
			}
			if !maps.Equal(gotMap, want) {
				t.Errorf("proxyWiringEnvVars() = %v, want %v", gotMap, want)
			}
		})
	}
}

func TestProxyCABind(t *testing.T) {
	secretEnv := map[string]string{"KEY": "dtn_secret_x"}
	plainEnv := map[string]string{"KEY": "plain"}
	const caPath = "/var/lib/netleash/ca.crt"
	wantBind := caPath + ":" + secretCAContainerPath + ":ro"

	tests := []struct {
		name            string
		client          *DockerClient
		env             map[string]string
		domainAllowList string
		want            string
	}{
		{
			name:   "CA unavailable",
			client: &DockerClient{},
			env:    secretEnv,
		},
		{
			name:   "plain sandbox",
			client: &DockerClient{secretProxyCACert: caPath},
			env:    plainEnv,
		},
		{
			name:            "domain policy without enforcement",
			client:          &DockerClient{secretProxyCACert: caPath},
			env:             plainEnv,
			domainAllowList: "example.com",
		},
		{
			name: "domain policy with enforcement",
			client: &DockerClient{
				secretProxyCACert:       caPath,
				proxyEnforcementEnabled: true,
			},
			env:             plainEnv,
			domainAllowList: "example.com",
			want:            wantBind,
		},
		{
			name:   "secret sandbox",
			client: &DockerClient{secretProxyCACert: caPath},
			env:    secretEnv,
			want:   wantBind,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.client.proxyCABind(tt.env, tt.domainAllowList); got != tt.want {
				t.Errorf("proxyCABind() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSandboxNetworkName_RunnerBridge(t *testing.T) {
	d := &DockerClient{interSandboxNetworkEnabled: false}
	if got := d.sandboxNetworkName(); got != RUNNER_BRIDGE_NETWORK_NAME {
		t.Errorf("sandboxNetworkName = %q, want %q", got, RUNNER_BRIDGE_NETWORK_NAME)
	}
}
