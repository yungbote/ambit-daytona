package sandboxsecurity

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedPolicyMatchesExistingQualifiedSource(t *testing.T) {
	if err := ValidateRootlessSeccomp([]byte(RootlessSeccomp())); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("../../../../images/ambit-agent-workspace/capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json")
	if err != nil || string(source) != RootlessSeccomp() {
		t.Fatalf("shared policy drifted from qualified source: %v", err)
	}
	if ValidateRootlessSeccomp(append(source, '\n')) == nil {
		t.Fatal("altered policy was accepted")
	}
}

func TestProcessSecurityRequiresEveryCapabilitySet(t *testing.T) {
	valid := "NoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapBnd:\t0000000000000000\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n"
	observed, err := ParseProcessStatus([]byte(valid))
	if err != nil || !observed.NoNewPrivileges || observed.SeccompMode != 2 || observed.BoundingCapabilities != "0000000000000000" {
		t.Fatalf("valid status rejected: %+v, %v", observed, err)
	}
	for _, malformed := range []string{
		strings.Replace(valid, "CapBnd:\t0000000000000000\n", "", 1),
		strings.Replace(valid, "CapEff:\t0000000000000000", "CapEff:\tzzzzzzzzzzzzzzzz", 1),
		strings.Replace(valid, "NoNewPrivs:\t1", "NoNewPrivs:\tunknown", 1),
		strings.Replace(valid, "Seccomp:\t2", "Seccomp:\t3", 1),
	} {
		if _, err := ParseProcessStatus([]byte(malformed)); err == nil {
			t.Fatal("incomplete/malformed status accepted")
		}
	}
}

func TestProcessStartTicksHandlesCommandParenthesesAndRejectsMalformedStat(t *testing.T) {
	fields := strings.Fields("S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 20")
	stat := "42 (command with ) spaces) " + strings.Join(fields, " ")
	if ticks, err := parseProcessStartTicks([]byte(stat)); err != nil || ticks != "123456" {
		t.Fatalf("incorrect start ticks: %q, %v", ticks, err)
	}
	for _, bad := range []string{"42 command", "42 (command) S 1", strings.Replace(stat, "123456", "invalid", 1)} {
		if _, err := parseProcessStartTicks([]byte(bad)); err == nil {
			t.Fatal("malformed process identity accepted")
		}
	}
	before, err := ProcessStartTicks(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := ObserveProcess(os.Getpid())
	if err != nil || observed.StartTicks != before {
		t.Fatalf("security observation lost its process generation: %+v, %v", observed, err)
	}
}
