//go:build linux

package session

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func runConfigurationEnvironmentFixture() {
	fmt.Printf("ordinary=%q,%q,%q;secret=%x\n", os.Getenv("feature.enabled"), os.Getenv("feature.limit"), os.Getenv("feature.label"), sha256.Sum256([]byte(os.Getenv("api_key"))))
}

func TestConfigurationEnvironmentDeliverExactNativeNames(t *testing.T) {
	svc := newStdinTestService(t)
	openSession(t, svc, "configuration")
	// nosecret: fresh synthetic material, never a provider credential.
	secret := "nosecret-" + uuid.NewString()
	lease := &EnvironmentLease{Version: 2, ID: uuid.NewString(), ExpiresAt: time.Now().Add(5 * time.Second), Values: map[string]string{
		"api_key": secret, "feature.enabled": "false", "feature.limit": "0", "feature.label": "",
	}}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := shellFixtureQuote(executable) + " --custody-fixture configuration-env unused"
	result, err := svc.ExecuteEnvironmentLease("configuration", command, false, true, true, true, lease)
	if err != nil || result.ExitCode == nil || *result.ExitCode != 0 || result.Output == nil {
		t.Fatal("native configuration recipient did not execute", err)
	}
	expected := fmt.Sprintf("ordinary=%q,%q,%q;secret=%x", "false", "0", "", sha256.Sum256([]byte(secret)))
	if !strings.Contains(*result.Output, expected) {
		t.Fatal("native configuration names or values changed")
	}
	observed, err := svc.Get("configuration")
	if err != nil || observed.EnvironmentLeaseVersion != 2 || observed.EnvironmentLeaseID != lease.ID || !observed.InputClosed {
		t.Fatal("configuration acceptance lost its native capability/custody")
	}
	owned, _ := svc.sessions.Get("configuration")
	assertNoStoredEnvironment(t, owned.Dir(svc.configDir), secret)
}

func TestConfigurationEnvironmentNameBoundary(t *testing.T) {
	for _, name := range []string{"feature.limit", "hyphen-name", " space ", "数字"} {
		if _, err := environmentValues(map[string]string{name: "0"}); err != nil {
			t.Fatalf("valid native name %q was rejected", name)
		}
	}
	for _, name := range []string{"", "a=b", "a\x00b"} {
		if _, err := environmentValues(map[string]string{name: "0"}); err == nil {
			t.Fatal("invalid native name was accepted")
		}
	}
}
