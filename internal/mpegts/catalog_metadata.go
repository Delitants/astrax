// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import "time"

func (c *Catalog) Metadata(sid uint16, now time.Time) (Service, string) {
	service, _, state := c.MetadataSnapshot(sid, now)
	return service, state
}

// MetadataSnapshot reads joined, current metadata without rebuilding the input
// catalog or changing PID interests. The stamp fences a later status sample.
func (c *Catalog) MetadataSnapshot(sid uint16, now time.Time) (Service, CatalogStamp, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Service{}, CatalogStamp{}, "closed"
	}
	if now.After(c.now) {
		c.now = now
		c.wallAnchor = time.Now()
	}
	pmt := c.pmts[sid]
	if c.pat == nil || c.sdt == nil || pmt == nil {
		return Service{}, CatalogStamp{}, "missing"
	}
	for _, table := range []*validatedTable{&c.pat.table, &c.sdt.table, &pmt.table} {
		if c.now.Sub(table.updated) >= catalogLifetime {
			return Service{}, CatalogStamp{}, "stale"
		}
		if !table.valid {
			return Service{}, CatalogStamp{}, "missing"
		}
	}
	if service, ok := c.services[sid]; ok {
		return cloneService(service), CatalogStamp{c, sid, c.stamps[sid]}, "ready"
	}
	return Service{}, CatalogStamp{}, "missing"
}
