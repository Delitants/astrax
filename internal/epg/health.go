// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"errors"
	"time"
)

// Health describes the served generation and its inputs without exposing URLs
// or filesystem paths. Zero timestamps mean that no such event has occurred.
type Health struct {
	Enabled        bool           `json:"enabled"`
	Available      bool           `json:"available"`
	SnapshotAt     time.Time      `json:"snapshot_at"`
	LastMerge      time.Time      `json:"last_merge"`
	Bytes          int            `json:"bytes"`
	ChannelCount   int            `json:"channel_count"`
	ProgrammeCount int            `json:"programme_count"`
	RetentionHours int            `json:"retention_hours"`
	Sources        []SourceHealth `json:"sources"`
	Output         OutputHealth   `json:"output"`
}

type SourceHealth struct {
	Index           int       `json:"index"`
	Status          string    `json:"status"`
	ErrorCode       string    `json:"error_code"`
	LastAttempt     time.Time `json:"last_attempt"`
	LastSuccess     time.Time `json:"last_success"`
	CacheAgeSeconds int64     `json:"cache_age_seconds"`
	ChannelCount    int       `json:"channel_count"`
	ProgrammeCount  int       `json:"programme_count"`
	Cached          bool      `json:"cached"`
	Retained        bool      `json:"retained"`
}

type OutputHealth struct {
	Configured  bool      `json:"configured"`
	Status      string    `json:"status"`
	ErrorCode   string    `json:"error_code"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
}

type sourceAttempt struct {
	lastAttempt   time.Time
	lastSuccess   time.Time
	errorCode     string
	unfinished    bool
	fetchRevision uint64
}

type outputAttempt struct {
	lastAttempt  time.Time
	lastSuccess  time.Time
	errorCode    string
	dataRevision uint64
}

// Health only observes: expiry is reported without pruning or remerging. The
// merged counts remain those of the actual applied bytes until a mutation.
func (a *Aggregator) Health() Health {
	a.mu.RLock()
	defer a.mu.RUnlock()
	now := a.now().UTC()
	h := Health{
		Enabled: a.enabled, Available: a.enabled && len(a.data) > 0,
		SnapshotAt: now, LastMerge: a.lastFetch, Bytes: len(a.data),
		ChannelCount: a.mergedChannels, ProgrammeCount: a.mergedProgrammes,
		RetentionHours: int(a.retention / time.Hour),
		Sources:        make([]SourceHealth, 0, len(a.sources)),
	}
	for i, src := range a.sources {
		attempt := a.sourceAttempts[src]
		value, cached := a.sourceCache[src]
		x := SourceHealth{
			Index: i + 1, Status: "never_fetched", Cached: cached,
			CacheAgeSeconds: -1,
			LastAttempt:     attempt.lastAttempt, LastSuccess: attempt.lastSuccess,
			ErrorCode: attempt.errorCode,
		}
		if !x.LastSuccess.IsZero() {
			x.CacheAgeSeconds = int64(now.Sub(x.LastSuccess) / time.Second)
			if x.CacheAgeSeconds < 0 {
				x.CacheAgeSeconds = 0
			}
		}
		if cached {
			x.ChannelCount, x.ProgrammeCount = len(value.tv.Channels), len(value.tv.Programmes)
			x.Retained = a.enabled && now.Sub(value.fetchedAt) < a.retention
		}
		switch {
		case !a.enabled || src == "":
			x.Status, x.Retained = "disabled", false
		case !x.LastSuccess.IsZero() && !x.Retained:
			x.Status = "expired"
		case x.Retained && attempt.unfinished:
			x.Status = "stale"
		case x.Retained && x.ErrorCode != "":
			x.Status = "retained"
		case x.Retained:
			x.Status = "healthy"
		case x.ErrorCode != "":
			x.Status = "error"
		}
		h.Sources = append(h.Sources, x)
	}
	h.Output = OutputHealth{
		Configured: a.localPath != "", Status: "unconfigured",
		LastAttempt: a.outputAttempt.lastAttempt, LastSuccess: a.outputAttempt.lastSuccess,
		ErrorCode: a.outputAttempt.errorCode,
	}
	if h.Output.Configured {
		switch {
		case h.Output.ErrorCode != "":
			h.Output.Status = "error"
		case h.Output.LastSuccess.IsZero():
			h.Output.Status = "pending"
		case a.enabled && a.dataRevision == a.revision && a.outputAttempt.dataRevision == a.dataRevision:
			h.Output.Status = "current"
		default:
			h.Output.Status = "stale"
		}
	}
	return h
}

// SetRetentionHours changes only cache policy and the in-memory merged feed.
// Purging before expansion prevents already expired data from being revived.
func (a *Aggregator) SetRetentionHours(hours int) error {
	if hours < 1 || hours > 168 {
		return errors.New("EPG retention hours must be between 1 and 168")
	}
	a.mu.Lock()
	a.cancelFetchLocked()
	a.pruneSourceCacheLocked()
	a.retention = time.Duration(hours) * time.Hour
	a.settingsRevision++
	a.pruneSourceCacheLocked()
	a.external = a.mergeSourceCacheLocked()
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	return a.applySnapshot(snapshot)
}

func (a *Aggregator) pruneSourceAttemptsLocked() {
	configured := make(map[string]bool, len(a.sources))
	for _, src := range a.sources {
		configured[src] = true
	}
	for src := range a.sourceAttempts {
		if !configured[src] {
			delete(a.sourceAttempts, src)
		}
	}
}
