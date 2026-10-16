// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import "astrax/internal/epg"

// EPGHealthSnapshot is a control-plane snapshot, never a refresh request.
type EPGHealthSnapshot struct {
	epg.Health
	RuntimeAvailable bool `json:"runtime_available"`
}

func (s *Store) EPGHealth() EPGHealthSnapshot {
	if s.epg != nil {
		return EPGHealthSnapshot{Health: s.epg.Health(), RuntimeAvailable: true}
	}
	// Disabled-runtime fixtures and failed/uninitialized runtime must not imply
	// that saved configuration has produced a feed or a successful fetch.
	settings := s.Settings()
	hours := settings.EPGSourceRetentionHours
	if hours == 0 {
		hours = 24
	}
	h := epg.Health{Enabled: settings.EPGEnabled, SnapshotAt: s.now().UTC(), RetentionHours: hours,
		Sources: make([]epg.SourceHealth, 0, len(settings.EPGSourceURLs)),
		Output:  epg.OutputHealth{Configured: settings.EPGLocalPath != "", Status: "unconfigured"}}
	if h.Output.Configured {
		h.Output.Status = "pending"
	}
	for i := range settings.EPGSourceURLs {
		status := "never_fetched"
		if !settings.EPGEnabled {
			status = "disabled"
		}
		h.Sources = append(h.Sources, epg.SourceHealth{Index: i + 1, Status: status, CacheAgeSeconds: -1})
	}
	return EPGHealthSnapshot{Health: h}
}
