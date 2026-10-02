// Copyright 2026 Ambit
// SPDX-License-Identifier: AGPL-3.0

//go:build linux

package websocket

import (
	"net"
	"time"

	"github.com/daytonaio/media-edge/internal/rate"
	"golang.org/x/sys/unix"
)

// TCP_INFO describes this socket's peer. In the supported deployment that
// peer is ingress, so its capacity never overrides end-to-end paint feedback.
func (c *carrier) Network() rate.Network {
	connection := c.conn.UnderlyingConn()
	for {
		wrapped, ok := connection.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		connection = wrapped.NetConn()
	}
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		return rate.Network{ProxyHop: true}
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return rate.Network{ProxyHop: true}
	}
	var info *unix.TCPInfo
	var socketErr error
	if err := raw.Control(func(fd uintptr) { info, socketErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil || socketErr != nil || info == nil {
		return rate.Network{ProxyHop: true}
	}
	return rate.Network{Known: true, ProxyHop: true, AckedBytes: info.Bytes_acked, DeliveryBytesPerSecond: float64(info.Delivery_rate), RTT: time.Duration(info.Rtt) * time.Microsecond, MinimumRTT: time.Duration(info.Min_rtt) * time.Microsecond, WindowBytes: uint64(info.Snd_cwnd) * uint64(info.Snd_mss), InFlightBytes: uint64(info.Unacked) * uint64(info.Snd_mss), ApplicationLimited: info.Notsent_bytes == 0, Shares: 1}
}
