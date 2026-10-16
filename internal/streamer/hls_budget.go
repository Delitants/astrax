// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrHLSCapacity        = errors.New("stage_c_hls_capacity")
	ErrHLSSegmentNotFound = errors.New("stage_c_hls_segment_not_found")
)

const (
	hlsSegmentBytes int64 = 4 * 1024 * 1024
	hlsStreamBytes  int64 = 32 * 1024 * 1024
	hlsProcessBytes int64 = 128 * 1024 * 1024
)

type hlsBudget struct {
	mu   sync.Mutex
	used int64
}

// Generations retain one stream owner; its counter and the process counter
// are updated atomically under budget.mu until detached response pins leave.
type hlsStreamBudget struct {
	budget *hlsBudget
	used   int64
}
type hlsSlab struct {
	data []byte
	refs int
}
type boundedHLSSegment struct {
	index         int
	duration      time.Duration
	slab          *hlsSlab
	discontinuity bool
}
type boundedHLSState struct {
	budget                *hlsBudget
	owner                 *hlsStreamBudget
	now                   func() time.Time
	used                  int64
	active                *hlsSlab
	completed             []boundedHLSSegment
	closed                bool
	discard               bool
	pendingDiscontinuity  bool
	activeDiscontinuity   bool
	discontinuitySequence uint64
	capacityErr           error
}
type hlsSegmentLease struct {
	mu       sync.Mutex
	h        *hlsBuffer
	slab     *hlsSlab
	bytes    []byte
	once     sync.Once
	released atomic.Bool
}

func newHLSBudget() *hlsBudget { return &hlsBudget{} }
func (b *hlsBudget) Used() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}
func (b *hlsBudget) reserveSlab(owner *hlsStreamBudget, minimum int) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	size := min(hlsSegmentBytes/188*188, hlsStreamBytes-owner.used, hlsProcessBytes-b.used)
	size = size / 188 * 188
	if size < int64(minimum) {
		return 0, ErrHLSCapacity
	}
	b.used += size
	owner.used += size
	return int(size), nil
}
func (b *hlsBudget) release(owner *hlsStreamBudget, bytes int64) {
	b.mu.Lock()
	b.used -= bytes
	owner.used -= bytes
	b.mu.Unlock()
}
func (b *hlsBudget) reserveExact(owner *hlsStreamBudget, bytes int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bytes < 0 || bytes > hlsStreamBytes-owner.used || bytes > hlsProcessBytes-b.used {
		return ErrHLSCapacity
	}
	b.used += bytes
	owner.used += bytes
	return nil
}
func newBoundedHLSBuffer(budget *hlsBudget, now func() time.Time) (*hlsBuffer, error) {
	return newBoundedHLSBufferWithOwner(budget, now, nil)
}
func newBoundedHLSBufferWithOwner(budget *hlsBudget, now func() time.Time, owner *hlsStreamBudget) (*hlsBuffer, error) {
	if budget == nil {
		return nil, ErrStageCSinksUnavailable
	}
	if now == nil {
		now = time.Now
	}
	if owner == nil {
		owner = &hlsStreamBudget{budget: budget}
	} else if owner.budget != budget {
		return nil, ErrStageCSinksUnavailable
	}
	return &hlsBuffer{startTime: now(), bounded: &boundedHLSState{budget: budget, owner: owner, now: now}}, nil
}
func (h *hlsBuffer) releaseSlabLocked(slab *hlsSlab) {
	if slab == nil {
		return
	}
	slab.refs--
	if slab.refs == 0 {
		bytes := int64(cap(slab.data))
		h.bounded.used -= bytes
		h.bounded.budget.release(h.bounded.owner, bytes)
		slab.data = nil
	}
}
func (h *hlsBuffer) discardLocked() error {
	b := h.bounded
	h.releaseSlabLocked(b.active)
	b.active = nil
	b.discard = true
	b.activeDiscontinuity = false
	b.pendingDiscontinuity = true
	b.capacityErr = ErrHLSCapacity
	h.index++
	return ErrHLSCapacity
}
func (h *hlsBuffer) WritePacketChecked(packet []byte) error {
	if h == nil || h.bounded == nil {
		return ErrStageCSinksUnavailable
	}
	if len(packet) != 188 {
		return ErrInvalidRegistration
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.bounded
	if b.closed {
		return ErrStreamerClosed
	}
	now := b.now()
	if b.discard {
		if now.Sub(h.startTime) < hlsSegmentDuration {
			return ErrHLSCapacity
		}
		b.discard = false
		b.capacityErr = nil
		h.startTime = now
	}
	if b.active != nil && len(b.active.data) > 0 && now.Sub(h.startTime) >= hlsSegmentDuration {
		// Transfer the same immutable slab to the window: no finalize copy,
		// no temporarily uncharged second segment at a pinned-byte ceiling.
		b.completed = append(b.completed, boundedHLSSegment{index: h.index, duration: now.Sub(h.startTime), slab: b.active, discontinuity: b.activeDiscontinuity})
		b.active = nil
		b.activeDiscontinuity = false
		h.index++
		h.startTime = now
		if len(b.completed) > hlsWindowSize {
			if b.completed[0].discontinuity {
				b.discontinuitySequence++
			}
			h.releaseSlabLocked(b.completed[0].slab)
			copy(b.completed, b.completed[1:])
			b.completed[len(b.completed)-1] = boundedHLSSegment{}
			b.completed = b.completed[:len(b.completed)-1]
		}
	}
	length := 0
	if b.active != nil {
		length = len(b.active.data)
	}
	if int64(length+len(packet)) > hlsSegmentBytes {
		return h.discardLocked()
	}
	if b.active == nil || length+len(packet) > cap(b.active.data) {
		// Reserve physical backing capacity before allocation. Slabs generally
		// use a whole packet-aligned segment; tight budgets admit smaller slabs.
		// A later growth copy reserves both old and new storage until transfer.
		size, err := b.budget.reserveSlab(b.owner, length+len(packet))
		if err != nil {
			return h.discardLocked()
		}
		b.used += int64(size)
		slab := &hlsSlab{data: make([]byte, length, size), refs: 1}
		if b.active != nil {
			copy(slab.data, b.active.data)
			h.releaseSlabLocked(b.active)
		} else {
			b.activeDiscontinuity = b.pendingDiscontinuity
			b.pendingDiscontinuity = false
		}
		b.active = slab
	}
	// Existing prefixes are never overwritten, including an active response's
	// length-capped view. Appending a new suffix cannot mutate an older view.
	b.active.data = append(b.active.data, packet...)
	return nil
}
func (h *hlsBuffer) AcquireSegment(index int) (*hlsSegmentLease, error) {
	if h == nil || h.bounded == nil {
		return nil, ErrStageCSinksUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.bounded
	if b.closed {
		return nil, ErrHLSSegmentNotFound
	}
	var slab *hlsSlab
	for _, segment := range b.completed {
		if segment.index == index {
			slab = segment.slab
			break
		}
	}
	if slab == nil && h.index == index && !b.discard {
		slab = b.active
	}
	if slab == nil || len(slab.data) == 0 {
		return nil, ErrHLSSegmentNotFound
	}
	slab.refs++
	view := slab.data[:len(slab.data):len(slab.data)]
	return &hlsSegmentLease{h: h, slab: slab, bytes: view}, nil
}
func (h *hlsBuffer) acquirePlaylist(baseURL string) (*hlsSegmentLease, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.bounded
	if b == nil || b.closed {
		return nil, ErrStageCSinksUnavailable
	}
	// At most seven entries; reserve fixed backing capacity before rendering
	// so response-pinned playlist storage is charged just like segment storage.
	entries := len(b.completed) + 1
	if len(baseURL) > int(hlsStreamBytes)/entries-128 {
		return nil, ErrHLSCapacity
	}
	capacity := 128 + entries*(len(baseURL)+128)
	if err := b.budget.reserveExact(b.owner, int64(capacity)); err != nil {
		return nil, err
	}
	b.used += int64(capacity)
	slab := &hlsSlab{data: h.boundedPlaylistLocked(make([]byte, 0, capacity), baseURL), refs: 1}
	return &hlsSegmentLease{h: h, slab: slab, bytes: slab.data[:len(slab.data):len(slab.data)]}, nil
}
func (h *hlsBuffer) CapacityError() error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.bounded == nil {
		return nil
	}
	return h.bounded.capacityErr
}
func (h *hlsBuffer) Used() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.bounded == nil {
		return 0
	}
	return h.bounded.used
}
func (h *hlsBuffer) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.bounded
	if b == nil || b.closed {
		return nil
	}
	b.closed = true
	h.releaseSlabLocked(b.active)
	b.active = nil
	for _, segment := range b.completed {
		h.releaseSlabLocked(segment.slab)
	}
	b.completed = nil
	return nil
}

// Bytes is a read-only view owned until Release; callers must not mutate it.
func (l *hlsSegmentLease) Bytes() []byte {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released.Load() {
		return nil
	}
	return l.bytes
}
func (l *hlsSegmentLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.released.Store(true)
		l.mu.Lock()
		l.bytes = nil
		l.mu.Unlock()
		l.h.mu.Lock()
		defer l.h.mu.Unlock()
		l.h.releaseSlabLocked(l.slab)
	})
}
