package session

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if code, handled := RunSupervisor(os.Args[1:]); handled {
		os.Exit(code)
	}
	if runCustodyFixture(os.Args[1:]) {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
