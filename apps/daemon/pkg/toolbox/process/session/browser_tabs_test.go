// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func tabRoster(t *testing.T, tabs []any) (map[string]any, []byte) {
	t.Helper()
	message, _ := json.Marshal(map[string]any{"type": "tabs", "tabs": tabs, "controllerId": "private-controller"})
	projected, valid := browserTabRecords(message)
	if !valid {
		t.Fatal("valid native tab snapshot was rejected")
	}
	lines := bytes.Split(projected, []byte{'\n'})
	var roster map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &roster); err != nil {
		t.Fatal(err)
	}
	if roster["type"] != "tabs" || len(lines[len(lines)-1]) > browserTabRosterLimit {
		t.Fatal("invalid roster framing or size")
	}
	if bytes.Contains(projected, []byte("private-controller")) || bytes.Contains(projected, []byte("private-target")) {
		t.Fatal("tab stream included private driver data")
	}
	return roster, projected
}

func TestBrowserTabsProjectExactFieldsWithActiveFirst(t *testing.T) {
	roster, records := tabRoster(t, []any{
		map[string]any{"tabId": "t1", "title": "First", "url": "https://one.test/", "active": false, "targetId": "private-target"},
		map[string]any{"tabId": "t2", "title": "Second", "url": "https://two.test/", "active": true, "targetId": "private-target"},
	})
	if roster["complete"] != true {
		t.Fatal("complete browser roster became partial")
	}
	tabs := roster["tabs"].([]any)
	if len(tabs) != 2 || tabs[0].(map[string]any)["id"] != "t2" || len(tabs[0].(map[string]any)) != 4 {
		t.Fatalf("invalid public tabs: %v", tabs)
	}
	if !bytes.HasPrefix(records, []byte(`{"type":"url","url":"https://two.test/"`)) {
		t.Fatal("roster lost compatible current URL")
	}
}

func TestBrowserTabsBoundCountWithoutInferringMissingTabs(t *testing.T) {
	tabs := make([]any, 300)
	for index := range tabs {
		tabs[index] = map[string]any{"tabId": fmt.Sprintf("t%d", index+1), "title": "Tab", "url": "about:blank", "active": index == 299}
	}
	roster, _ := tabRoster(t, tabs)
	projected := roster["tabs"].([]any)
	if roster["complete"] != false || len(projected) != browserTabCountLimit || projected[0].(map[string]any)["id"] != "t300" {
		t.Fatal("count bound lost the active tab or claimed completeness")
	}
}

func TestBrowserTabsOmitOversizedOrAmbiguousRowsWithoutTruncatingText(t *testing.T) {
	roster, _ := tabRoster(t, []any{
		map[string]any{"tabId": "t1", "title": "Current", "url": "about:blank", "active": true},
		map[string]any{"tabId": "t2", "title": strings.Repeat("<", browserTabRosterLimit), "url": "about:blank", "active": false},
		map[string]any{"tabId": "t3", "title": "Duplicate", "url": "about:blank", "active": false},
		map[string]any{"tabId": "t3", "title": "Other duplicate", "url": "about:blank", "active": false},
	})
	if roster["complete"] != false || len(roster["tabs"].([]any)) != 1 {
		t.Fatal("oversized or duplicate rows were treated as exact")
	}
	empty, _ := tabRoster(t, []any{})
	if empty["complete"] != true || len(empty["tabs"].([]any)) != 0 {
		t.Fatal("empty native roster was not preserved")
	}
	for _, id := range []string{"t0", "t01", "1", "t4294967296", "../t1"} {
		if validBrowserTabID(id) {
			t.Fatalf("invalid native tab id accepted: %s", id)
		}
	}
}
