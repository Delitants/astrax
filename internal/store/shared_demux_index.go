// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"sync"
	"time"
	"unsafe"

	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
)

const (
	sharedDemuxInputMembershipLimit   = 8192
	sharedDemuxProcessMembershipLimit = 65536
	sharedDemuxPacketLimit            = 134217728
	sharedDemuxCatalogArenaBytes      = 262144
	sharedDemuxQueueCapacity          = 256
)

var errSharedDemuxMembershipCapacity = errors.New("shared demux membership capacity exceeded")
var errSharedDemuxStreamMissing = errors.New("shared demux stream is not registered")

// Only retained memberships, not arbitrary Go heap overhead, are counted here.
type sharedDemuxMembershipBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func newSharedDemuxMembershipBudget(limit int) *sharedDemuxMembershipBudget {
	return &sharedDemuxMembershipBudget{limit: limit}
}
func (b *sharedDemuxMembershipBudget) reserve(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.limit-b.used {
		return false
	}
	b.used += n
	return true
}
func (b *sharedDemuxMembershipBudget) release(n int) {
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
}
func (b *sharedDemuxMembershipBudget) Used() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

type sharedDemuxDependencies struct {
	packets     *packetbudget.Budget
	memberships *sharedDemuxMembershipBudget
}

var processSharedDemuxDependencies = &sharedDemuxDependencies{
	packets:     packetbudget.New(sharedDemuxPacketLimit),
	memberships: newSharedDemuxMembershipBudget(sharedDemuxProcessMembershipLimit),
}

// Nodes are allocated before publication. Removed nodes retain their next link
// for an in-progress traversal; they are never recycled into a different row.
type sharedDemuxListener struct {
	stream     *streamPacketSource
	generation uint64
	pid        uint16
	wildcard   bool
	active     bool
	prev, next *sharedDemuxListener
}

type sharedDemuxAdmission struct {
	id                 string
	old                *streamPacketSource
	oldCount, newCount int
	oldRemoved         bool
	done               chan struct{}
}

// Admission tickets serialize a single ID without holding ownership locks over
// allocation. A closing old source leaves its membership credits pinned to the
// ticket until commit/rollback; equal-sized replacement never double charges.
func (sd *sharedDemux) beginAdmission(id string, count int, requireOld bool) (*sharedDemuxAdmission, error) {
	ticket := &sharedDemuxAdmission{id: id, newCount: count, done: make(chan struct{})}
	for {
		sd.mu.Lock()
		if sd.closed {
			err := sd.unavailableErrorLocked()
			sd.mu.Unlock()
			return nil, err
		}
		if pending := sd.pending[id]; pending != nil {
			done := pending.done
			sd.mu.Unlock()
			<-done
			continue
		}
		ticket.old = sd.streams[id]
		if requireOld && ticket.old == nil {
			sd.mu.Unlock()
			return nil, errSharedDemuxStreamMissing
		}
		if ticket.old != nil {
			ticket.oldCount = len(ticket.old.nodes)
		}
		delta := count - ticket.oldCount
		if delta > 0 {
			if err := sd.changeMembersLocked(delta); err != nil {
				sd.mu.Unlock()
				return nil, err
			}
		}
		sd.pending[id] = ticket
		sd.work.Add(1)
		sd.mu.Unlock()
		return ticket, nil
	}
}

func (sd *sharedDemux) changeMembersLocked(delta int) error {
	if delta > 0 {
		if delta > sharedDemuxInputMembershipLimit-sd.membershipCount || !sd.dependencies.memberships.reserve(delta) {
			return errSharedDemuxMembershipCapacity
		}
	} else if delta < 0 {
		sd.dependencies.memberships.release(-delta)
	}
	sd.membershipCount += delta
	return nil
}

func (sd *sharedDemux) finishAdmissionLocked(ticket *sharedDemuxAdmission, commit bool) {
	if commit {
		if delta := ticket.newCount - ticket.oldCount; delta < 0 {
			_ = sd.changeMembersLocked(delta)
		}
	} else {
		if delta := ticket.newCount - ticket.oldCount; delta > 0 {
			_ = sd.changeMembersLocked(-delta)
		}
		if ticket.oldRemoved {
			_ = sd.changeMembersLocked(-ticket.oldCount)
		}
	}
	delete(sd.pending, ticket.id)
	close(ticket.done)
}

func (sd *sharedDemux) abortAdmission(ticket *sharedDemuxAdmission) {
	sd.mu.Lock()
	sd.finishAdmissionLocked(ticket, false)
	sd.mu.Unlock()
}

func sharedDemuxNodes(allowed map[uint16]struct{}, wildcard bool) []sharedDemuxListener {
	if wildcard {
		return []sharedDemuxListener{{wildcard: true}}
	}
	nodes := make([]sharedDemuxListener, len(allowed))
	n := 0
	for pid := range allowed {
		nodes[n].pid = pid
		n++
	}
	return nodes
}

func (sd *sharedDemux) linkStreamLocked(stream *streamPacketSource) {
	for i := range stream.nodes {
		node := &stream.nodes[i]
		node.stream = stream
		node.generation = stream.generation
		node.active = true
		head := &sd.listeners[node.pid]
		if node.wildcard {
			head = &sd.wildcards
		}
		node.next = *head
		if node.next != nil {
			node.next.prev = node
		}
		*head = node
	}
	stream.indexed = true
}
func (sd *sharedDemux) unlinkStreamLocked(stream *streamPacketSource) {
	if !stream.indexed {
		return
	}
	for i := range stream.nodes {
		node := &stream.nodes[i]
		head := &sd.listeners[node.pid]
		if node.wildcard {
			head = &sd.wildcards
		}
		if node.prev == nil {
			*head = node.next
		} else {
			node.prev.next = node.next
		}
		if node.next != nil {
			node.next.prev = node.prev
		}
		node.active = false
	}
	stream.indexed = false
}

func newSharedDemuxWithDependencies(inner model.PacketSource, deps *sharedDemuxDependencies) (*sharedDemux, error) {
	return newSharedDemuxInternal(inner, deps)
}

func (sd *sharedDemux) ReplaceInterests(id string, pids []int) error {
	allowed, err := validateSharedDemuxRegistration(id, pids)
	if err != nil {
		return err
	}
	ticket, err := sd.beginAdmission(id, len(allowed), true)
	if err != nil {
		return err
	}
	defer sd.work.Done()
	// Avoid rebuilding the retained index at all for an equal PID set.
	sd.mu.Lock()
	equal := !sd.closed && !ticket.oldRemoved && !ticket.old.wildcard && len(ticket.old.pids) == len(allowed)
	if equal {
		for pid := range allowed {
			if _, ok := ticket.old.pids[pid]; !ok {
				equal = false
				break
			}
		}
	}
	if equal {
		ticket.old.mu.Lock()
		equal = !ticket.old.closed
		ticket.old.mu.Unlock()
	}
	if equal {
		sd.finishAdmissionLocked(ticket, true)
		sd.mu.Unlock()
		return nil
	}
	sd.mu.Unlock()
	nodes := sharedDemuxNodes(allowed, false)
	sd.mu.Lock()
	stream := ticket.old
	stream.mu.Lock()
	if sd.closed || ticket.oldRemoved || stream.closed {
		err := errStreamPacketSourceClosed
		if sd.closed {
			err = sd.unavailableErrorLocked()
		}
		sd.finishAdmissionLocked(ticket, false)
		stream.mu.Unlock()
		sd.mu.Unlock()
		return err
	}
	sd.unlinkStreamLocked(stream)
	stream.generation++
	stream.pids = allowed
	stream.wildcard = false
	stream.nodes = nodes
	sd.linkStreamLocked(stream)
	sd.finishAdmissionLocked(ticket, true)
	stream.mu.Unlock()
	sd.mu.Unlock()
	return nil
}

func (sd *sharedDemux) RegisterWildcard(id string) (model.PacketSource, error) {
	// Reuse the existing ID validation without reinterpreting nil/empty PIDs.
	if _, err := validateSharedDemuxRegistration(id, []int{0}); err != nil {
		return nil, err
	}
	return sd.register(id, nil, true)
}

// Queue charge covers the actual source/owner-slot backing and channel slice
// descriptors, plus a conservative 128-byte header allowance for each channel.
// Caller-retained closed handles and transferred packet slices are not Go RSS.
func sharedDemuxQueueBytes() int64 {
	return int64(unsafe.Sizeof(streamPacketSource{})) +
		sharedDemuxQueueCapacity*int64(unsafe.Sizeof([]byte(nil))) + 256
}

func (sd *sharedDemux) register(id string, allowed map[uint16]struct{}, wildcard bool) (model.PacketSource, error) {
	count := len(allowed)
	if wildcard {
		count = 1
	}
	ticket, err := sd.beginAdmission(id, count, false)
	if err != nil {
		return nil, err
	}
	defer sd.work.Done()
	nodes := sharedDemuxNodes(allowed, wildcard)
	bytes := sharedDemuxQueueBytes()
	hold, err := sd.dependencies.packets.Reserve(bytes)
	if err != nil {
		sd.abortAdmission(ticket)
		return nil, err
	}
	sd.mu.Lock()
	if sd.closed {
		err := sd.unavailableErrorLocked()
		sd.finishAdmissionLocked(ticket, false)
		sd.mu.Unlock()
		hold.Release()
		return nil, err
	}
	sd.queueBytes += bytes
	sd.mu.Unlock()
	sd.recordAllocation("queue", bytes, false)
	stream := &streamPacketSource{
		sd: sd, id: id, pids: allowed, wildcard: wildcard, nodes: nodes, generation: 1,
		ch: make(chan []byte, sharedDemuxQueueCapacity), done: make(chan struct{}),
		queueReservation: hold, queueBytes: bytes,
	}
	sd.mu.Lock()
	if sd.closed {
		err := sd.unavailableErrorLocked()
		sd.queueBytes -= bytes
		sd.finishAdmissionLocked(ticket, false)
		sd.mu.Unlock()
		hold.Release()
		return nil, err
	}
	if ticket.old != nil {
		sd.unlinkStreamLocked(ticket.old)
	}
	sd.streams[id] = stream
	sd.linkStreamLocked(stream)
	sd.finishAdmissionLocked(ticket, true)
	sd.mu.Unlock()
	if ticket.old != nil {
		ticket.old.closeWithError(errStreamPacketSourceReplaced)
	}
	return stream, nil
}

func (sd *sharedDemux) dispatch(pid uint16, pkt []byte) {
	sd.mu.Lock()
	sd.indexStats.DispatchPackets++
	sd.indexStats.LastListenerVisits = 0
	head, wild := sd.listeners[pid], sd.wildcards
	sd.mu.Unlock()
	for _, first := range [2]*sharedDemuxListener{head, wild} {
		for node := first; node != nil; {
			sd.mu.Lock()
			next, active, stream, generation := node.next, node.active, node.stream, node.generation
			sd.indexStats.LastListenerVisits++
			sd.indexStats.ListenerVisits++
			sd.mu.Unlock()
			if active {
				stream.trySend(pkt, generation)
			}
			node = next
		}
	}
}

// Task3 retains one last Packet in each PSI state in addition to its arena.
// Reserve those distinct retained bytes and two working Packet values before
// ParsePacket/Push, rather than treating them as uncharged heap metadata.
func (sd *sharedDemux) feedCatalog(pid uint16, raw []byte) {
	sd.catalogMu.Lock()
	defer sd.catalogMu.Unlock()
	sd.mu.Lock()
	if sd.closed || !sd.catalogPIDs[pid] {
		sd.mu.Unlock()
		return
	}
	sd.work.Add(1)
	catalog := sd.catalog
	sd.mu.Unlock()
	defer sd.work.Done()
	working, err := sd.dependencies.packets.Reserve(376)
	if err != nil {
		return
	}
	defer working.Release()
	sd.mu.Lock()
	sd.catalogWorkingBytes += 376
	haveState := sd.catalogStateReservations[pid] != nil
	sd.mu.Unlock()
	defer func() { sd.mu.Lock(); sd.catalogWorkingBytes -= 376; sd.mu.Unlock() }()
	if !haveState {
		state, err := sd.dependencies.packets.Reserve(188)
		if err != nil {
			return
		}
		sd.mu.Lock()
		if len(sd.catalogStateReservations) >= 256 {
			sd.mu.Unlock()
			state.Release()
			return
		}
		sd.catalogStateReservations[pid] = state
		sd.catalogStateBytes += 188
		sd.mu.Unlock()
	}
	packet, err := mpegts.ParsePacket(raw)
	if err == nil {
		sd.mu.Lock()
		sd.indexStats.CatalogPackets++
		sd.mu.Unlock()
		// The transaction remains locked through Push, expiry and reconciliation.
		sd.catalogRevision++
		_ = catalog.Push(packet, time.Now())
	}
	sd.reconcileCatalogInterestsLocked(sd.snapshotCatalogInterestsLocked())
}

func (sd *sharedDemux) refreshCatalogInterests() {
	sd.catalogMu.Lock()
	defer sd.catalogMu.Unlock()
	sd.reconcileCatalogInterestsLocked(sd.snapshotCatalogInterestsLocked())
}

// Snapshot metadata is a fresh PID list bounded by Task3's 256-PID cap;
// it contains no catalog, packet, or reservation owner handles.
type sharedDemuxCatalogInterestSnapshot struct {
	pids     []uint16
	revision uint64
}

func (sd *sharedDemux) snapshotCatalogInterests() sharedDemuxCatalogInterestSnapshot {
	sd.catalogMu.Lock()
	defer sd.catalogMu.Unlock()
	return sd.snapshotCatalogInterestsLocked()
}

// Caller holds catalogMu, not sd.mu/sps.mu. Interests advances expiry and may
// remove parser states, so even snapshots invalidate earlier ownership decisions.
func (sd *sharedDemux) snapshotCatalogInterestsLocked() sharedDemuxCatalogInterestSnapshot {
	sd.mu.Lock()
	if sd.closed {
		sd.mu.Unlock()
		return sharedDemuxCatalogInterestSnapshot{}
	}
	catalog := sd.catalog
	sd.mu.Unlock()
	sd.catalogRevision++
	return sharedDemuxCatalogInterestSnapshot{pids: catalog.Interests(), revision: sd.catalogRevision}
}

func (sd *sharedDemux) reconcileCatalogInterests(snapshot sharedDemuxCatalogInterestSnapshot) {
	sd.catalogMu.Lock()
	defer sd.catalogMu.Unlock()
	sd.reconcileCatalogInterestsLocked(snapshot)
}

// Caller holds catalogMu across revision validation and every state-credit
// release. Push and expiry cannot invalidate this decision while it is applied.
func (sd *sharedDemux) reconcileCatalogInterestsLocked(snapshot sharedDemuxCatalogInterestSnapshot) {
	if snapshot.revision != sd.catalogRevision {
		return
	}
	wanted := snapshot.pids
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if sd.closed {
		return
	}
	// Interest slices and state maps are bounded by Task3's 256-PID cap.
	for pid, hold := range sd.catalogStateReservations {
		keep := false
		for _, candidate := range wanted {
			if candidate == pid {
				keep = true
				break
			}
		}
		if !keep {
			delete(sd.catalogStateReservations, pid)
			sd.catalogStateBytes -= 188
			hold.Release()
		}
	}
	delta := len(wanted) - len(sd.catalogInterests)
	// Capacity failure keeps the old admitted input row. A later catalog
	// packet or listener removal retries; never evict a sibling to make room.
	if err := sd.changeMembersLocked(delta); err != nil {
		sd.indexStats.CatalogAdmissionFailures++
		return
	}
	for _, pid := range sd.catalogInterests {
		sd.catalogPIDs[pid] = false
	}
	for _, pid := range wanted {
		sd.catalogPIDs[pid] = true
	}
	sd.catalogInterests = wanted
}

type sharedDemuxIndexStats struct {
	DispatchPackets          uint64
	ListenerVisits           uint64
	LastListenerVisits       int
	Memberships              int
	WildcardListeners        int
	QueuedPackets            int
	QueueBytes               int64
	PacketBytes              int64
	ScratchBytes             int64
	CatalogConsumers         int
	CatalogPackets           uint64
	CatalogAdmissionFailures uint64
	sharedDemuxAllocationStats
}

type sharedDemuxAllocationStats struct {
	QueueAllocations               uint64
	CopyAllocations                uint64
	CatalogAllocations             uint64
	LastQueueReserved              int64
	LastCopyReserved               int64
	LastCatalogReserved            int64
	LastQueueAllocationBytes       int64
	LastCopyAllocationBytes        int64
	LastCatalogAllocationBytes     int64
	AllocationsUnderOwnershipLocks uint64
}

func (sd *sharedDemux) recordAllocation(kind string, bytes int64, ownershipLocked bool) {
	reserved := sd.dependencies.packets.Used()
	sd.diagnosticsMu.Lock()
	defer sd.diagnosticsMu.Unlock()
	if ownershipLocked {
		sd.allocationStats.AllocationsUnderOwnershipLocks++
	}
	switch kind {
	case "queue":
		sd.allocationStats.QueueAllocations++
		sd.allocationStats.LastQueueReserved = reserved
		sd.allocationStats.LastQueueAllocationBytes = bytes
	case "packet":
		sd.allocationStats.CopyAllocations++
		sd.allocationStats.LastCopyReserved = reserved
		sd.allocationStats.LastCopyAllocationBytes = bytes
	case "catalog":
		sd.allocationStats.CatalogAllocations++
		sd.allocationStats.LastCatalogReserved = reserved
		sd.allocationStats.LastCatalogAllocationBytes = bytes
	}
}

// Scalar metadata only. Lifecycle counters include staged allocations and
// detached/replaced sources until their ownership has actually been released.
func (sd *sharedDemux) Stats() sharedDemuxIndexStats {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	out := sd.indexStats
	out.Memberships = sd.membershipCount
	out.QueuedPackets = sd.queuedPackets
	out.QueueBytes = sd.queueBytes
	out.PacketBytes = sd.packetBytes
	out.ScratchBytes = sd.catalogArenaBytes + sd.catalogStateBytes + sd.catalogWorkingBytes
	if sd.catalogArenaReservation != nil {
		out.CatalogConsumers = 1
	}
	for node := sd.wildcards; node != nil; node = node.next {
		out.WildcardListeners++
	}
	sd.diagnosticsMu.Lock()
	out.sharedDemuxAllocationStats = sd.allocationStats
	sd.diagnosticsMu.Unlock()
	return out
}
