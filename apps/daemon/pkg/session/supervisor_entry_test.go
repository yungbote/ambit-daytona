package session

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Race-instrumented self-reexecuted fixtures otherwise sleep for one second
	// after reporting real kernel settlement. Keep every caller option and only
	// remove that artificial delay from future subprocesses; this process's
	// race runtime has already read its original options during startup.
	if err := os.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0"); err != nil {
		panic(err)
	}
	if code, handled := RunSupervisor(os.Args[1:]); handled {
		os.Exit(code)
	}
	if runCustodyFixture(os.Args[1:]) {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
