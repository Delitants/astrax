// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"errors"
	"sync"

	"astrax/internal/model"
	"astrax/internal/packetbudget"
)

var (
	ErrStageCSinksUnavailable = errors.New("stage_c_sinks_unavailable")
	ErrViewerCapacity         = errors.New("stage_c_viewer_capacity")
)

type viewerKind uint8

const (
	viewerTS viewerKind = iota
	viewerHLS
)

type viewerLimiter struct {
	mu      sync.Mutex
	process int
	streams map[string][2]int
}
type viewerLease struct {
	limiter  *viewerLimiter
	streamID string
	kind     viewerKind
	once     sync.Once
}

func newViewerLimiter() *viewerLimiter { return &viewerLimiter{streams: make(map[string][2]int)} }
func (l *viewerLimiter) Acquire(id string, kind viewerKind) (*viewerLease, error) {
	if l == nil || id == "" || kind > viewerHLS {
		return nil, ErrStageCSinksUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	counts := l.streams[id]
	if l.process >= 4096 || counts[kind] >= 128 {
		return nil, ErrViewerCapacity
	}
	if l.streams == nil {
		l.streams = make(map[string][2]int)
	}
	counts[kind]++
	l.streams[id] = counts
	l.process++
	return &viewerLease{limiter: l, streamID: id, kind: kind}, nil
}
func (l *viewerLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		owner := l.limiter
		owner.mu.Lock()
		defer owner.mu.Unlock()
		counts := owner.streams[l.streamID]
		counts[l.kind]--
		owner.process--
		if counts == [2]int{} {
			delete(owner.streams, l.streamID)
		} else {
			owner.streams[l.streamID] = counts
		}
	})
}

// One caller-owned instance is shared by every Streamer in the process.
// Resource-aware constructors never manufacture a second packet budget.
type StageCResources struct {
	PacketBudget *packetbudget.Budget
	Viewers      *viewerLimiter
	HLS          *hlsBudget
}

func (r *StageCResources) available() bool {
	return r != nil && r.PacketBudget != nil && r.Viewers != nil && r.HLS != nil
}
func NewStageCResources(budget *packetbudget.Budget) (*StageCResources, error) {
	if budget == nil {
		return nil, ErrStageCSinksUnavailable
	}
	return &StageCResources{PacketBudget: budget, Viewers: newViewerLimiter(), HLS: newHLSBudget()}, nil
}
func NewWithStageCResources(settings model.Settings, resources *StageCResources) (*Streamer, error) {
	if !resources.available() {
		return nil, ErrStageCSinksUnavailable
	}
	st := New(settings)
	st.stageCResources = resources
	return st, nil
}

// Immutable resource identity lets runtime wiring reject split packet budgets.
// This is not an admission or descrambling capability.
func (st *Streamer) StageCPacketBudget() *packetbudget.Budget {
	if st == nil || !st.stageCResources.available() {
		return nil
	}
	return st.stageCResources.PacketBudget
}
func stageCEnabled(cfg model.Stream) bool {
	return cfg.DVBDescrambling != nil && cfg.DVBDescrambling.Enabled
}
