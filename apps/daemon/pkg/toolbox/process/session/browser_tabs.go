// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

const browserTabCountLimit = 256
const browserTabRosterLimit = 512 << 10

type browserTab struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

// A native tab snapshot yields a compatible current URL and one bounded roster.
// Every record is complete JSON on its own line. Missing rows are explicit and
// never authorize a client to infer that a native tab has closed.
func browserTabRecords(message []byte) ([]byte, bool) {
	var snapshot struct {
		Tabs []json.RawMessage `json:"tabs"`
	}
	if json.Unmarshal(message, &snapshot) != nil || snapshot.Tabs == nil {
		return nil, false
	}
	complete := true
	tabs := make([]browserTab, 0, len(snapshot.Tabs))
	counts := make(map[string]int)
	var location []byte
	activeCount := 0
	for _, raw := range snapshot.Tabs {
		var item struct {
			ID           *string `json:"tabId"`
			Title        *string `json:"title"`
			URL          *string `json:"url"`
			Active       *bool   `json:"active"`
			CanGoBack    *bool   `json:"canGoBack"`
			CanGoForward *bool   `json:"canGoForward"`
		}
		if json.Unmarshal(raw, &item) != nil {
			complete = false
			continue
		}
		if item.Active != nil && *item.Active {
			activeCount++
			if item.URL != nil && *item.URL != "" {
				location, _ = json.Marshal(struct {
					Type         string  `json:"type"`
					URL          string  `json:"url"`
					Title        *string `json:"title,omitempty"`
					CanGoBack    *bool   `json:"canGoBack,omitempty"`
					CanGoForward *bool   `json:"canGoForward,omitempty"`
				}{"url", *item.URL, item.Title, item.CanGoBack, item.CanGoForward})
			}
		}
		if item.ID == nil || !validBrowserTabID(*item.ID) || item.Title == nil || item.URL == nil || item.Active == nil {
			complete = false
			continue
		}
		tabs = append(tabs, browserTab{*item.ID, *item.Title, *item.URL, *item.Active})
		counts[*item.ID]++
	}
	if activeCount > 1 {
		return nil, false
	}
	if len(snapshot.Tabs) > 0 && activeCount != 1 {
		complete = false
	}
	ordered := make([]browserTab, 0, len(tabs))
	for _, active := range []bool{true, false} {
		for _, tab := range tabs {
			if tab.Active == active {
				ordered = append(ordered, tab)
			}
		}
	}
	var roster struct {
		Type     string       `json:"type"`
		Tabs     []browserTab `json:"tabs"`
		Complete bool         `json:"complete"`
	}
	roster.Type = "tabs"
	roster.Tabs = []browserTab{}
	base, _ := json.Marshal(roster)
	size := len(base)
	for _, tab := range ordered {
		encoded, _ := json.Marshal(tab)
		cost := len(encoded)
		if len(roster.Tabs) > 0 {
			cost++
		}
		if counts[tab.ID] != 1 || len(roster.Tabs) >= browserTabCountLimit || size+cost > browserTabRosterLimit {
			complete = false
			continue
		}
		roster.Tabs = append(roster.Tabs, tab)
		size += cost
	}
	roster.Complete = complete
	body, _ := json.Marshal(roster)
	if location == nil {
		return body, true
	}
	return bytes.Join([][]byte{location, body}, []byte{'\n'}), true
}

func validBrowserTabID(id string) bool {
	if !strings.HasPrefix(id, "t") {
		return false
	}
	number, err := strconv.ParseUint(id[1:], 10, 32)
	return err == nil && number > 0 && id == "t"+strconv.FormatUint(number, 10)
}
