// Copyright Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"github.com/robotn/xgb"
	"github.com/robotn/xgb/shm"
	"golang.org/x/sys/unix"
)

// sharedImage is the retained framebuffer in a System V shared-memory segment
// the X server also maps (MIT-SHM). A fetch then asks the server to copy the
// damaged rows straight into the retained framebuffer, instead of sending them
// over the socket to be copied again. The helper and its private Xvfb share
// one IPC namespace and user; anything else falls back to GetImage for the
// life of the helper, with the same pixels.
//
// The segment is private (0600) and marked for removal as soon as the server
// has attached it, so it disappears when both processes detach or exit.
type sharedImage struct {
	segment shm.Seg
	memory  []byte
	failed  bool
}

// openSharedImage prepares the extension on the frame connection, where
// shm.Init has already registered it. A server without it answers nil, which
// every method treats as unavailable.
func openSharedImage(c *xgb.Conn) *sharedImage {
	if _, err := shm.QueryVersion(c).Reply(); err != nil {
		return nil
	}
	segment, err := shm.NewSegId(c)
	if err != nil {
		return nil
	}
	return &sharedImage{segment: segment}
}

// buffer answers size bytes of shared memory for the retained framebuffer, or
// current when shared memory is unavailable. Growing replaces the segment;
// the caller re-fetches every band after any size change.
func (s *sharedImage) buffer(c *xgb.Conn, size int, current []byte) []byte {
	if s == nil || s.failed || size <= 0 {
		return current
	}
	if len(s.memory) >= size {
		return s.memory[:size]
	}
	if s.holds(current) {
		// The old segment's pixels are stale after a size change anyway;
		// never hand back memory that is about to be unmapped.
		current = nil
	}
	s.detach(c)
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, size, unix.IPC_CREAT|0o600)
	if err != nil {
		s.failed = true
		return current
	}
	memory, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		_, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil)
		s.failed = true
		return current
	}
	attached := shm.AttachChecked(c, s.segment, uint32(id), false).Check()
	_, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil)
	if attached != nil {
		_ = unix.SysvShmDetach(memory)
		s.failed = true
		return current
	}
	s.memory = memory
	return s.memory[:size]
}

// holds reports whether fetches may target the shared segment: it is live and
// retained is its memory.
func (s *sharedImage) holds(retained []byte) bool {
	return s != nil && !s.failed && len(retained) > 0 && len(s.memory) >= len(retained) && &retained[0] == &s.memory[0]
}

// disable falls back to GetImage for the rest of the helper's life. The
// segment stays mapped because retained pixels may still live in it.
func (s *sharedImage) disable() {
	if s != nil {
		s.failed = true
	}
}

func (s *sharedImage) detach(c *xgb.Conn) {
	if s == nil || s.memory == nil {
		return
	}
	_ = shm.DetachChecked(c, s.segment).Check()
	_ = unix.SysvShmDetach(s.memory)
	s.memory = nil
}

func (s *sharedImage) release(c *xgb.Conn) { s.detach(c) }
