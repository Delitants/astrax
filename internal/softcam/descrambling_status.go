// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import "time"

type descramblingStatusSample struct {
	status DescramblingStatusSnapshot
	at     time.Time
}

type DescramblingStatusSnapshot struct {
	DescramblingPipelineStatus
	SampleAgeMS int64
}

func closedDescramblingStatus() DescramblingStatusSnapshot {
	return DescramblingStatusSnapshot{DescramblingPipelineStatus: DescramblingPipelineStatus{State: "closed"}}
}

func (p *DescramblingPipeline) metadataStateLocked() string {
	state := p.state
	if state == "cipher_failed" || state == "closed" {
		return state
	}
	if state == "payload_processed" && p.processed == 0 {
		state = "waiting_keys"
	}
	needed := uint8(p.needed.Load())
	if needed == 0 {
		return state
	}
	valid, received := uint8(0), false
	if hints := p.hints.Load(); hints != nil {
		now := p.now()
		for i, info := range hints {
			if needed&(1<<uint(i)) == 0 {
				continue
			}
			received = received || !info.ReceivedAt.IsZero()
			if info.ValidMask&(1<<uint(i)) != 0 && !now.Before(info.ReceivedAt) && now.Before(info.ExpiresAt) {
				valid |= 1 << uint(i)
			}
		}
	}
	if valid == needed {
		return state
	}
	if valid != 0 && p.processed > 0 {
		return "partial_clear"
	}
	if valid == 0 && received {
		return "key_expired"
	}
	return "waiting_keys"
}

func cachedDescramblingStatus(sample *descramblingStatusSample) DescramblingStatusSnapshot {
	if sample == nil {
		return DescramblingStatusSnapshot{DescramblingPipelineStatus: DescramblingPipelineStatus{State: "waiting_keys"}}
	}
	status := sample.status
	status.SampleAgeMS = max(0, time.Since(sample.at).Milliseconds())
	return status
}

// Metadata reads never wait on the mutex that encloses a native cipher call.
// A busy pipeline returns its last owned scalar sample, explicitly marked stale.
func (p *DescramblingPipeline) SnapshotStatus() (DescramblingStatusSnapshot, bool) {
	if p.closing.Load() {
		return closedDescramblingStatus(), true
	}
	if !p.mu.TryLock() {
		return cachedDescramblingStatus(p.statusCache.Load()), false
	}
	defer p.mu.Unlock()
	status := DescramblingStatusSnapshot{DescramblingPipelineStatus: DescramblingPipelineStatus{State: p.metadataStateLocked(), Queued: p.size, OutputQueued: p.output, Processed: p.processed, Dropped: p.dropped + p.rejected.Load()}}
	if p.closing.Load() {
		status = closedDescramblingStatus()
	}
	p.statusCache.Store(&descramblingStatusSample{status, time.Now()})
	return status, true
}

func (o *DescramblingOutput) SnapshotStatus() (DescramblingStatusSnapshot, bool) {
	p := o.parent
	if o.closing.Load() || p.closing.Load() {
		return closedDescramblingStatus(), true
	}
	if !p.mu.TryLock() {
		return cachedDescramblingStatus(o.statusCache.Load()), false
	}
	defer p.mu.Unlock()
	status := DescramblingStatusSnapshot{DescramblingPipelineStatus: DescramblingPipelineStatus{State: p.metadataStateLocked(), Queued: p.size, OutputQueued: o.output, Processed: p.processed, Dropped: o.dropped + p.dropped + p.rejected.Load()}}
	if o.closing.Load() || p.closing.Load() {
		status = closedDescramblingStatus()
	}
	o.statusCache.Store(&descramblingStatusSample{status, time.Now()})
	return status, true
}

func (out *descramblingRegistrySource) DescramblingStatus() (DescramblingStatusSnapshot, bool) {
	if out.closed.Load() || out.owner.Revoked() {
		return closedDescramblingStatus(), true
	}
	return out.source.SnapshotStatus()
}
