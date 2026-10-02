package manager

import (
	"strings"
	"testing"
)

// ConfigureInterface must reject a TC-mode attach with no interface name (a
// kata sandbox whose host veth couldn't be resolved), rather than silently
// attaching nothing — except when the call is just clearing the allow list.
// An open-network policy (no domains, proxy enforced) attaches a filter too, so
// it needs the interface as much as an allow list does.
func TestConfigureInterface_RequiresInterface(t *testing.T) {
	m := quietManager()

	requiresInterface := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "requires an interface name")
	}
	if err := m.ConfigureInterface("wl-1", "", true, []string{"example.com"}, false); !requiresInterface(err) {
		t.Fatalf("an allow list without an interface must be refused for the missing interface, got: %v", err)
	}
	if err := m.ConfigureInterface("wl-1", "", true, nil, true); !requiresInterface(err) {
		t.Fatalf("proxy enforcement without an interface must be refused for the missing interface, got: %v", err)
	}

	// Empty domains without enforcement is a clear/remove; it must not require an
	// interface and must not error for an unmanaged workload.
	if err := m.ConfigureInterface("wl-1", "", true, nil, false); err != nil {
		t.Fatalf("clearing with empty interface should be a no-op, got: %v", err)
	}
	if m.IsManaged("wl-1") {
		t.Fatal("workload should not be managed after a clear")
	}
}
