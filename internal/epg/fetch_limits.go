// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"errors"
	"time"
)

// FetchLimits bounds each source, including decompressed XML and body reads.
type FetchLimits struct {
	MaxSourceBytes int64
	Timeout        time.Duration
	MaxProgrammes  int
}

func DefaultFetchLimits() FetchLimits {
	return FetchLimits{MaxSourceBytes: 64 * 1024 * 1024, Timeout: 30 * time.Second, MaxProgrammes: 500000}
}

// SetFetchLimits updates policy without fetching, remerging, or writing output.
func (a *Aggregator) SetFetchLimits(limits FetchLimits) error {
	if limits.MaxSourceBytes < 1 || limits.MaxSourceBytes > 256*1024*1024 {
		return errors.New("EPG source bytes must be between 1 and 268435456")
	}
	if limits.Timeout < time.Second || limits.Timeout > 120*time.Second {
		return errors.New("EPG fetch timeout must be between 1 and 120 seconds")
	}
	if limits.MaxProgrammes < 1 || limits.MaxProgrammes > 1000000 {
		return errors.New("EPG source programmes must be between 1 and 1000000")
	}
	a.mu.Lock()
	a.cancelFetchLocked()
	a.fetchLimits = limits
	a.settingsRevision++
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) cancelFetchLocked() {
	if a.fetchCancel != nil {
		a.fetchCancel()
		a.fetchCancel = nil
	}
}
