// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build !linux

package websocket

import "github.com/daytonaio/media-edge/internal/rate"

func (c *carrier) Network() rate.Network { return rate.Network{ProxyHop: true} }
