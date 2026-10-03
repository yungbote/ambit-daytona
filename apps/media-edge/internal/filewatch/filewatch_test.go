// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package filewatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWatchAppliesChangesAndKeepsTheLastGoodContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var applied []string
	reports := 0
	apply := func(content []byte) error {
		if string(content) == "bad" {
			return errors.New("invalid")
		}
		mu.Lock()
		defer mu.Unlock()
		applied = append(applied, string(content))
		return nil
	}
	report := func(error) { mu.Lock(); reports++; mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Watch(ctx, path, 5*time.Millisecond, apply, report); err != nil {
		t.Fatal(err)
	}
	await := func(what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			mu.Lock()
			ok := done()
			mu.Unlock()
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s (applied %v, reports %d)", what, applied, reports)
			}
			time.Sleep(time.Millisecond)
		}
	}
	_ = os.WriteFile(path, []byte("bad"), 0o600)
	await("the invalid content reported", func() bool { return reports == 1 })
	time.Sleep(30 * time.Millisecond)
	_ = os.WriteFile(path, []byte("two"), 0o600)
	await("the next good content", func() bool { return len(applied) == 2 && applied[1] == "two" })
	mu.Lock()
	defer mu.Unlock()
	if reports != 1 {
		t.Fatalf("an invalid content is reported once, got %d", reports)
	}

	if Watch(ctx, filepath.Join(t.TempDir(), "missing"), time.Second, apply, report) == nil {
		t.Fatal("a missing file refuses to start")
	}
	if Watch(ctx, path, time.Second, func([]byte) error { return errors.New("no") }, report) == nil {
		t.Fatal("an invalid file refuses to start")
	}
}
