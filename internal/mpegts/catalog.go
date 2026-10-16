// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import (
	"crypto/sha256"
	"reflect"
	"sort"
	"sync"
	"time"
)

const catalogLifetime = 5 * time.Second

type storageSpan struct{ offset, size, used int }
type freeSpan struct{ offset, size int }
type packetState struct {
	last          Packet
	haveCC        bool
	cc            byte
	partial       *storageSpan
	partialAt     time.Time
	skipRemaining int
}

func (s *packetState) hasPartial() bool { return s.partial != nil || s.skipRemaining > 0 }

type tableCandidate struct {
	header   sectionHeader
	sections map[byte]*storageSpan
	updated  time.Time
	invalid  bool
}
type validatedTable struct {
	header  sectionHeader
	digests map[byte][32]byte
	updated time.Time
	valid   bool
	blocked bool
}
type patTable struct {
	table    validatedTable
	programs map[uint16]uint16
}
type sdtTable struct {
	table    validatedTable
	metadata map[uint16]serviceMetadata
}
type pmtTable struct {
	table   validatedTable
	service Service
	tsid    uint16
}

// Catalog owns one input. The fixed arena contains every retained section/partial
// byte; validated metadata and fingerprints are bounded by the service/table caps.
type Catalog struct {
	mu         sync.Mutex
	closed     bool
	now        time.Time
	wallAnchor time.Time
	arena      [maxAssemblerBytes]byte
	free       []freeSpan
	spans      map[*storageSpan]struct{}
	used       int
	states     map[uint16]*packetState
	candidates map[tableKey]*tableCandidate
	pat        *patTable
	sdt        *sdtTable
	pmts       map[uint16]*pmtTable
	services   map[uint16]Service
	stamps     map[uint16]*catalogServiceGeneration
	pids       map[uint16]bool
	delivered  uint64
}

// CatalogStats is bounded metadata only, with no payload, handles, or secrets.
// AssemblerBytes counts all retained candidate sections and partial section bytes.
// RegisteredPIDs counts the same memberships returned by Interests; DeliveredSections
// counts accepted section deliveries (duplicates must not increment it).
// Partial reservations count their full bounded wire size, including unfilled bytes.
// Reads use a monotonic input clock; Interests advances it by elapsed wall time
// since the last explicit Push/Service/Stats timestamp, not by an unrelated epoch.
type CatalogStats struct {
	Candidates        int
	AssemblerBytes    int
	Services          int
	RegisteredPIDs    int
	DeliveredSections uint64
}

func NewCatalog() *Catalog {
	return &Catalog{free: []freeSpan{{size: maxAssemblerBytes}}, spans: make(map[*storageSpan]struct{}),
		states: make(map[uint16]*packetState), candidates: make(map[tableKey]*tableCandidate),
		pmts: make(map[uint16]*pmtTable), services: make(map[uint16]Service), pids: map[uint16]bool{0: true, 17: true}}
}

func (c *Catalog) allocate(size int) *storageSpan {
	if size <= 0 || size > maxWireSection || c.used+size > maxAssemblerBytes {
		return nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		for n, f := range c.free {
			if f.size < size {
				continue
			}
			span := &storageSpan{offset: f.offset, size: size}
			c.free[n].offset += size
			c.free[n].size -= size
			if c.free[n].size == 0 {
				c.free = append(c.free[:n], c.free[n+1:]...)
			}
			c.spans[span] = struct{}{}
			c.used += size
			return span
		}
		// Compact only arena bytes, updating owned spans; no active table is evicted.
		spans := make([]*storageSpan, 0, len(c.spans))
		for s := range c.spans {
			spans = append(spans, s)
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i].offset < spans[j].offset })
		pos := 0
		for _, s := range spans {
			copy(c.arena[pos:pos+s.size], c.arena[s.offset:s.offset+s.size])
			s.offset = pos
			pos += s.size
		}
		c.free = []freeSpan{{offset: pos, size: maxAssemblerBytes - pos}}
	}
	return nil
}

func (c *Catalog) release(s *storageSpan) {
	if s == nil {
		return
	}
	if _, ok := c.spans[s]; !ok {
		return
	}
	delete(c.spans, s)
	c.used -= s.size
	c.free = append(c.free, freeSpan{offset: s.offset, size: s.size})
	sort.Slice(c.free, func(i, j int) bool { return c.free[i].offset < c.free[j].offset })
	out := c.free[:0]
	for _, f := range c.free {
		if len(out) > 0 && out[len(out)-1].offset+out[len(out)-1].size == f.offset {
			out[len(out)-1].size += f.size
		} else {
			out = append(out, f)
		}
	}
	c.free = out
}

func (c *Catalog) spanBytes(s *storageSpan) []byte { return c.arena[s.offset : s.offset+s.used] }
func (c *Catalog) resetPartial(s *packetState) {
	c.release(s.partial)
	s.partial = nil
	s.skipRemaining = 0
}
func (c *Catalog) dropCandidate(key tableKey) {
	if candidate := c.candidates[key]; candidate != nil {
		for _, s := range candidate.sections {
			c.release(s)
		}
		delete(c.candidates, key)
	}
}

func (c *Catalog) advance(now time.Time) {
	if c.now.IsZero() || now.After(c.now) {
		c.now = now
	}
	c.wallAnchor = time.Now()
	for key, candidate := range c.candidates {
		if c.now.Sub(candidate.updated) >= catalogLifetime {
			c.dropCandidate(key)
		}
	}
	for _, state := range c.states {
		if state.hasPartial() && c.now.Sub(state.partialAt) >= catalogLifetime {
			c.resetPartial(state)
		}
	}
	expire := func(t *validatedTable) {
		if c.now.Sub(t.updated) >= catalogLifetime {
			t.valid = false
			t.blocked = false
			t.digests = nil
		}
	}
	if c.pat != nil {
		expire(&c.pat.table)
	}
	if c.sdt != nil {
		expire(&c.sdt.table)
	}
	for _, p := range c.pmts {
		expire(&p.table)
	}
	c.rebuild()
}

func joinedServices(pat *patTable, sdt *sdtTable, pmts map[uint16]*pmtTable) map[uint16]Service {
	out := make(map[uint16]Service)
	if pat == nil || sdt == nil || !pat.table.valid || !sdt.table.valid || pat.table.header.key.ext != sdt.table.header.key.ext {
		return out
	}
	for sid, pid := range pat.programs {
		p := pmts[sid]
		meta, hasMeta := sdt.metadata[sid]
		if p == nil || !p.table.valid || !hasMeta || p.service.PMTPID != pid || p.tsid != pat.table.header.key.ext {
			continue
		}
		s := p.service
		s.TSID, s.ONID = pat.table.header.key.ext, sdt.table.header.onid
		s.Name, s.ProviderName = meta.name, meta.provider
		out[sid] = s
	}
	return out
}

func registeredPIDs(pat *patTable, services map[uint16]Service) map[uint16]bool {
	out := map[uint16]bool{0: true, 17: true}
	// Keep bounded PMT monitoring after identity expiry so valid refresh is possible.
	// ECM interests require a current, completely joined service, never stale metadata.
	if pat != nil {
		for _, pid := range pat.programs {
			out[pid] = true
		}
	}
	for _, s := range services {
		for _, ca := range s.CADescriptors {
			out[ca.ECMPID] = true
		}
	}
	return out
}

func (c *Catalog) rebuild() {
	services := joinedServices(c.pat, c.sdt, c.pmts)
	stamps := make(map[uint16]*catalogServiceGeneration, len(services))
	for sid, service := range services {
		stamp := c.stamps[sid]
		if stamp == nil || !reflect.DeepEqual(c.services[sid], service) {
			stamp = &catalogServiceGeneration{}
		}
		stamps[sid] = stamp
	}
	c.services, c.stamps = services, stamps
	c.pids = registeredPIDs(c.pat, c.services)
	for pid, state := range c.states {
		if !c.isPSIPID(pid) {
			c.resetPartial(state)
			delete(c.states, pid)
		}
	}
}

func (c *Catalog) isPSIPID(pid uint16) bool {
	if pid == 0 || pid == 17 {
		return true
	}
	if c.pat != nil {
		for _, p := range c.pat.programs {
			if p == pid {
				return true
			}
		}
	}
	return false
}

func (c *Catalog) Push(p Packet, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrInvalidPSI
	}
	c.advance(now)
	info, err := inspectPacket(&p)
	if err != nil {
		pid := uint16(p[1]&31)<<8 | uint16(p[2])
		if state := c.states[pid]; state != nil {
			c.resetPartial(state)
			state.haveCC = false
		}
		return err
	}
	if !c.isPSIPID(info.pid) {
		return nil
	}
	state := c.states[info.pid]
	if state == nil {
		if len(c.states) >= maxRegisteredPIDs {
			return ErrCapacity
		}
		state = &packetState{}
		c.states[info.pid] = state
	}
	if info.scrambled {
		c.resetPartial(state)
		return ErrInvalidPSI
	}
	// A repeated packet with a discontinuity indicator is still a duplicate.
	if len(info.payload) > 0 && state.haveCC && info.cc == state.cc && p == state.last {
		return nil
	}
	if info.discontinuity {
		c.resetPartial(state)
		state.haveCC = false
	}
	if len(info.payload) == 0 {
		return nil
	}
	if state.haveCC {
		if info.cc == state.cc {
			if p == state.last {
				return nil
			}
			c.resetPartial(state)
			state.haveCC = false
			return ErrInvalidPacket
		}
		if info.cc != (state.cc+1)&15 {
			c.resetPartial(state)
		}
	}
	state.last, state.cc, state.haveCC = p, info.cc, true
	data := info.payload
	if info.pusi {
		if int(data[0]) >= len(data)-1 {
			c.resetPartial(state)
			return ErrInvalidPacket
		}
		pointer := int(data[0])
		data = data[1:]
		if state.hasPartial() {
			used, err := c.continueSection(info.pid, state, data[:pointer])
			if err != nil {
				c.resetPartial(state)
				return err
			}
			if state.hasPartial() || !stuffing(data[used:pointer]) {
				c.resetPartial(state)
				return ErrInvalidPacket
			}
		}
		return c.startSections(info.pid, state, data[pointer:])
	}
	if !state.hasPartial() {
		return nil
	}
	used, err := c.continueSection(info.pid, state, data)
	if err != nil {
		c.resetPartial(state)
		return err
	}
	if !state.hasPartial() && !stuffing(data[used:]) {
		return ErrInvalidPSI
	}
	return nil
}

func stuffing(raw []byte) bool {
	for _, b := range raw {
		if b != 0xFF {
			return false
		}
	}
	return true
}

func (c *Catalog) sectionDomain(pid uint16, tid byte) (bool, error) {
	switch tid {
	case 0:
		if pid != 0 {
			return false, ErrInvalidPSI
		}
	case 0x42:
		if pid != 17 {
			return false, ErrInvalidPSI
		}
	case 2:
		if pid == 0 || pid == 17 {
			return false, ErrInvalidPSI
		}
	default:
		return false, nil
	}
	return true, nil
}

func sectionSize(raw []byte) (int, error) {
	size := 3 + int(word(raw[1:3])&0x0FFF)
	flags := byte(0xB0)
	minimum := 12
	if raw[0] == 0x42 {
		flags, minimum = 0xF0, 15
	}
	if raw[0] == 2 {
		minimum = 16
	}
	if raw[1]&0xF0 != flags || size < minimum || size > maxWireSection {
		return 0, ErrInvalidPSI
	}
	return size, nil
}

func ignoredSectionSize(raw []byte) (int, error) {
	// Other ignored domains supply only a 12-bit skip envelope, not a validated table.
	size := 3 + int(word(raw[1:3])&0x0FFF)
	// SDT other shares actual SDT's wire envelope, but never its catalog identity.
	if raw[0] == 0x46 && (raw[1]&0xF0 != 0xF0 || size < 15 || size > maxWireSection) {
		return 0, ErrInvalidPSI
	}
	return size, nil
}

func (c *Catalog) skipIgnored(state *packetState, data []byte) int {
	n := state.skipRemaining
	if n > len(data) {
		n = len(data)
	}
	state.skipRemaining -= n
	if n > 0 {
		state.partialAt = c.now
	}
	return n
}

func (c *Catalog) startSections(pid uint16, state *packetState, data []byte) error {
	for len(data) > 0 {
		if data[0] == 0xFF {
			if !stuffing(data) {
				return ErrInvalidPSI
			}
			return nil
		}
		known, err := c.sectionDomain(pid, data[0])
		if err != nil {
			return err
		}
		size := 3
		if len(data) >= 3 {
			if known {
				size, err = sectionSize(data)
			} else {
				size, err = ignoredSectionSize(data)
			}
			if err != nil {
				return err
			}
			if !known {
				// Retain only a bounded remaining-byte count, not ignored payloads.
				state.skipRemaining, state.partialAt = size-3, c.now
				used := 3 + c.skipIgnored(state, data[3:])
				data = data[used:]
				if state.hasPartial() {
					return nil
				}
				continue
			}
			if len(data) >= size {
				if err := c.acceptSection(pid, data[:size], nil); err != nil {
					return err
				}
				data = data[size:]
				continue
			}
		}
		span := c.allocate(size)
		if span == nil {
			return ErrCapacity
		}
		span.used = copy(c.arena[span.offset:span.offset+span.size], data)
		state.partial, state.partialAt = span, c.now
		return nil
	}
	return nil
}

func (c *Catalog) continueSection(pid uint16, state *packetState, data []byte) (int, error) {
	if state.skipRemaining > 0 {
		return c.skipIgnored(state, data), nil
	}
	used := 0
	for state.partial != nil && len(data) > 0 {
		s := state.partial
		n := s.size - s.used
		if n > len(data) {
			n = len(data)
		}
		copy(c.arena[s.offset+s.used:s.offset+s.used+n], data[:n])
		s.used += n
		used += n
		data = data[n:]
		state.partialAt = c.now
		if s.used < s.size {
			break
		}
		if s.size == 3 {
			var header [3]byte
			copy(header[:], c.spanBytes(s))
			known, err := c.sectionDomain(pid, header[0])
			size := 0
			if err == nil {
				if known {
					size, err = sectionSize(header[:])
				} else {
					size, err = ignoredSectionSize(header[:])
				}
			}
			c.resetPartial(state)
			if err != nil {
				return used, err
			}
			if !known {
				state.skipRemaining, state.partialAt = size-3, c.now
				return used + c.skipIgnored(state, data), nil
			}
			grown := c.allocate(size)
			if grown == nil {
				return used, ErrCapacity
			}
			copy(c.arena[grown.offset:grown.offset+3], header[:])
			grown.used = 3
			state.partial = grown
			continue
		}
		state.partial = nil
		return used, c.acceptSection(pid, c.spanBytes(s), s)
	}
	return used, nil
}

func (c *Catalog) currentTable(key tableKey) *validatedTable {
	switch key.tid {
	case 0:
		if c.pat != nil && c.pat.table.header.key == key {
			return &c.pat.table
		}
	case 0x42:
		if c.sdt != nil && c.sdt.table.header.key == key {
			return &c.sdt.table
		}
	case 2:
		if p := c.pmts[key.ext]; p != nil && p.table.header.key == key {
			return &p.table
		}
	}
	return nil
}

func (c *Catalog) poison(candidate *tableCandidate) {
	for _, s := range candidate.sections {
		c.release(s)
	}
	candidate.sections = nil
	candidate.invalid = true
	// Do not turn rejected-version churn into a progress/expiry refresh.
}

func (c *Catalog) acceptSection(pid uint16, raw []byte, owner *storageSpan) error {
	taken := false
	defer func() {
		if !taken {
			c.release(owner)
		}
	}()
	h, err := parseSectionHeader(pid, raw)
	if err != nil {
		return err
	}
	// Validate full nested structure before storage, including next tables.
	switch h.key.tid {
	case 0:
		_, err = parsePAT(raw)
	case 0x42:
		_, err = parseSDT(raw)
	case 2:
		if c.pat == nil || c.pat.programs[h.key.ext] != pid {
			return ErrInvalidPSI
		}
		_, err = parsePMT(raw, pid)
	}
	if err != nil {
		return err
	}
	if !h.current {
		return nil
	}
	digest := sha256.Sum256(raw)
	if current := c.currentTable(h.key); current != nil {
		if current.blocked {
			return nil
		}
		if len(current.digests) > 0 {
			sum, exists := current.digests[h.number]
			if !exists || sum != digest || current.header.last != h.last || current.header.onid != h.onid {
				current.valid, current.blocked = false, true
				c.dropCandidate(h.key)
				c.rebuild()
				return ErrInvalidPSI
			}
		}
	}
	candidate := c.candidates[h.key]
	if candidate != nil {
		if candidate.invalid {
			return nil
		}
		if candidate.header.last != h.last || candidate.header.onid != h.onid {
			c.poison(candidate)
			return ErrInvalidPSI
		}
		if old := candidate.sections[h.number]; old != nil {
			if sha256.Sum256(c.spanBytes(old)) != digest {
				c.poison(candidate)
				return ErrInvalidPSI
			}
			c.delivered++
			return nil
		}
	} else if len(c.candidates) >= maxCandidates {
		return ErrCapacity
	}
	if owner == nil {
		owner = c.allocate(len(raw))
		if owner == nil {
			return ErrCapacity
		}
		owner.used = copy(c.arena[owner.offset:owner.offset+owner.size], raw)
	}
	if candidate == nil {
		candidate = &tableCandidate{header: h, sections: make(map[byte]*storageSpan), updated: c.now}
		c.candidates[h.key] = candidate
	}
	candidate.sections[h.number] = owner
	taken = true
	candidate.updated = c.now
	if len(candidate.sections) == int(h.last)+1 {
		if err := c.commit(candidate); err != nil {
			c.dropCandidate(h.key)
			return err
		}
	}
	c.delivered++
	return nil
}

func (c *Catalog) commit(candidate *tableCandidate) error {
	h := candidate.header
	table := validatedTable{header: h, valid: true, updated: c.now, digests: make(map[byte][32]byte)}
	for n, s := range candidate.sections {
		table.digests[n] = sha256.Sum256(c.spanBytes(s))
	}
	pat, sdt := c.pat, c.sdt
	identityChanged := false
	pmts := make(map[uint16]*pmtTable, len(c.pmts)+1)
	for sid, p := range c.pmts {
		pmts[sid] = p
	}
	switch h.key.tid {
	case 0:
		programs := make(map[uint16]uint16)
		for n := 0; n <= int(h.last); n++ {
			part, err := parsePAT(c.spanBytes(candidate.sections[byte(n)]))
			if err != nil {
				return err
			}
			for sid, pid := range part {
				if _, exists := programs[sid]; exists {
					return ErrInvalidPSI
				}
				programs[sid] = pid
				if len(programs) > maxServices {
					return ErrCapacity
				}
			}
		}
		pat = &patTable{table: table, programs: programs}
		if c.pat != nil && c.pat.table.header.key.ext != h.key.ext {
			sdt = nil
			identityChanged = true
		}
		for sid, p := range pmts {
			if p.tsid != h.key.ext || programs[sid] != p.service.PMTPID {
				delete(pmts, sid)
			}
		}
	case 0x42:
		metadata := make(map[uint16]serviceMetadata)
		for n := 0; n <= int(h.last); n++ {
			part, err := parseSDT(c.spanBytes(candidate.sections[byte(n)]))
			if err != nil {
				return err
			}
			for sid, meta := range part {
				if _, exists := metadata[sid]; exists {
					return ErrInvalidPSI
				}
				metadata[sid] = meta
				if len(metadata) > maxServices {
					return ErrCapacity
				}
			}
		}
		if pat != nil && pat.table.header.key.ext != h.key.ext {
			c.dropCandidate(h.key)
			return nil
		}
		if sdt != nil && sdt.table.header.key.ext == h.key.ext && sdt.table.header.onid != h.onid {
			identityChanged = true
			for sid, p := range pmts {
				if p.tsid == h.key.ext {
					delete(pmts, sid)
				}
			}
		}
		sdt = &sdtTable{table: table, metadata: metadata}
	case 2:
		service, err := parsePMT(c.spanBytes(candidate.sections[0]), h.key.pid)
		if err != nil {
			return err
		}
		pmts[h.key.ext] = &pmtTable{table: table, service: service, tsid: pat.table.header.key.ext}
		if len(pmts) > maxServices {
			return ErrCapacity
		}
	}
	services := joinedServices(pat, sdt, pmts)
	pids := registeredPIDs(pat, services)
	if len(services) > maxServices || len(pids) > maxRegisteredPIDs {
		return ErrCapacity
	}
	// Publish the entire validated join and its membership set together under mu.
	c.pat, c.sdt, c.pmts, c.pids = pat, sdt, pmts, pids
	if identityChanged {
		// A PMT assembled across two TSID/ONID epochs cannot validate the new join.
		for _, state := range c.states {
			c.resetPartial(state)
		}
	}
	for key := range c.candidates {
		if identityChanged || (key.pid == h.key.pid && key.tid == h.key.tid && key.ext == h.key.ext) {
			c.dropCandidate(key)
		}
	}
	c.rebuild()
	return nil
}

func (c *Catalog) Service(sid uint16, now time.Time) (Service, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Service{}, false
	}
	c.advance(now)
	s, ok := c.services[sid]
	if !ok {
		return Service{}, false
	}
	return cloneService(s), true
}

func (c *Catalog) Interests() []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if !c.wallAnchor.IsZero() {
		c.advance(c.now.Add(time.Since(c.wallAnchor)))
	}
	ids := make([]uint16, 0, len(c.pids))
	for pid := range c.pids {
		ids = append(ids, pid)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *Catalog) Stats(now time.Time) CatalogStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return CatalogStats{}
	}
	c.advance(now)
	return CatalogStats{Candidates: len(c.candidates), AssemblerBytes: c.used,
		Services: len(c.services), RegisteredPIDs: len(c.pids), DeliveredSections: c.delivered}
}

func (c *Catalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.arena = [maxAssemblerBytes]byte{}
	c.free, c.spans, c.states, c.candidates = nil, nil, nil, nil
	c.pat, c.sdt, c.pmts, c.services, c.pids = nil, nil, nil, nil, nil
	c.stamps = nil
	c.used, c.delivered = 0, 0
}
