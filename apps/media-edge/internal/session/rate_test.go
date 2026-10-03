// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

package session

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRateRequiresNegotiatedPipeAndIsOrderedAfterItsSubscription(t *testing.T) {
	for _, pipe := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "pipe"}[pipe], func(t *testing.T) {
			route := newFakeRoute()
			route.rateInput = pipe
			edge := testEdge(&fakeUpstream{route: route})
			admission := admit(t, edge, "grant="+token(t, nil)+"&frames=binary&patches=1&video=av1&width=320&height=240")
			s, err := edge.Open(context.Background(), admission, "fake")
			if err != nil {
				t.Fatal(err)
			}
			viewer := newFakeCarrier()
			done := make(chan struct{})
			go func() { s.Run(viewer); close(done) }()
			defer func() { viewer.Close(0, ""); <-done }()
			route.out <- inbound{true, []byte(`{"type":"video","state":"available","codec":"av1"}`)}
			await(t, "video offer", func() bool { return len(viewer.delivered()) > 0 })
			viewer.send(`{"type":"video","enabled":true,"generation":1}`)
			await(t, "subscription", func() bool { return len(route.messages()) > 0 })
			if pipe {
				await(t, "generation-bound rate", func() bool { return len(route.messages()) > 1 })
			}
			messages := route.messages()
			if !pipe && len(messages) != 1 {
				t.Fatalf("legacy route received unsupported rate: %v", messages)
			}
			if pipe {
				var video, rate struct {
					Type       string
					Generation uint64
				}
				_ = json.Unmarshal([]byte(messages[0]), &video)
				_ = json.Unmarshal([]byte(messages[1]), &rate)
				if video.Type != "video" || rate.Type != "rate" || video.Generation != rate.Generation {
					t.Fatalf("wrong rate order/generation: %v", messages)
				}
			}
		})
	}
}
