// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import "time"

const sourceRetention = 24 * time.Hour

type sourceSnapshot struct {
	tv        TV
	fetchedAt time.Time
}

func (a *Aggregator) pruneSourceCacheLocked() {
	configured := make(map[string]bool, len(a.sources))
	if a.enabled {
		for _, src := range a.sources {
			configured[src] = true
		}
	}
	now := a.now().UTC()
	for src, value := range a.sourceCache {
		if !configured[src] || now.Sub(value.fetchedAt) >= a.retention {
			delete(a.sourceCache, src)
		}
	}
}

func (a *Aggregator) mergeSourceCacheLocked() TV {
	var tv TV
	for _, src := range a.sources {
		if value, ok := a.sourceCache[src]; ok {
			tv.Channels = append(tv.Channels, value.tv.Channels...)
			tv.Programmes = append(tv.Programmes, value.tv.Programmes...)
		}
	}
	return tv
}
