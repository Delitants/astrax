// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import "time"

type catalogServiceGeneration struct{ marker byte }

// CatalogStamp is opaque metadata identity, not a packet/key publication grant.
// A nonzero-sized token cannot alias a replacement while an old reader holds it.
type CatalogStamp struct {
	owner      *Catalog
	sid        uint16
	generation *catalogServiceGeneration
}

func (c *Catalog) Snapshot(sid uint16, now time.Time) (Service, CatalogStamp, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Service{}, CatalogStamp{}, false
	}
	c.advance(now)
	s, ok := c.services[sid]
	if !ok {
		return Service{}, CatalogStamp{}, false
	}
	return cloneService(s), CatalogStamp{c, sid, c.stamps[sid]}, true
}

// Current is an allocation-free guard for ingress and output dequeue. It checks
// exact table expiry without cloning service metadata or rebuilding the catalog.
func (c *Catalog) Current(stamp CatalogStamp, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || stamp.owner != c || stamp.generation == nil || c.stamps[stamp.sid] != stamp.generation {
		return false
	}
	if now.After(c.now) {
		c.now = now
		c.wallAnchor = time.Now()
	}
	p := c.pmts[stamp.sid]
	if c.pat == nil || c.sdt == nil || p == nil {
		return false
	}
	for _, t := range []*validatedTable{&c.pat.table, &c.sdt.table, &p.table} {
		if !t.valid || c.now.Sub(t.updated) >= catalogLifetime {
			return false
		}
	}
	return true
}
