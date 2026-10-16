// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"sync"
	"sync/atomic"
	"time"

	"astrax/internal/mpegts"
)

type ECMPacket struct {
	Data   mpegts.Packet
	Parity uint8
}

type ECMPacketProof struct {
	Even, Odd *ECMResult
}

func (ECMPacketProof) String() string               { return "ECMPacketProof[redacted]" }
func (ECMPacketProof) GoString() string             { return "ECMPacketProof[redacted]" }
func (ECMPacketProof) MarshalJSON() ([]byte, error) { return []byte(`"ECMPacketProof[redacted]"`), nil }

type ecmPacketSlot struct {
	packet ECMPacket
	proof  ECMPacketProof
}

type ECMPacketGate struct {
	mu         sync.Mutex
	client     *ECMClient
	route      ECMRoute
	generation uint64
	closed     bool
	slots      [64]ecmPacketSlot
	head, size int
}

func (*ECMPacketGate) String() string               { return "ECMPacketGate[redacted]" }
func (*ECMPacketGate) GoString() string             { return "ECMPacketGate[redacted]" }
func (*ECMPacketGate) MarshalJSON() ([]byte, error) { return []byte(`"ECMPacketGate[redacted]"`), nil }

func (c *ECMClient) NewPacketGate(route ECMRoute, generation uint64, capacity int) (*ECMPacketGate, error) {
	if capacity != 64 {
		return nil, ecmInvalidRequestError
	}
	if _, err := ecmClientBroker(c); err != nil {
		return nil, err
	}
	// The only queue allocation is outside every ownership/native lock. The
	// constructor then validates real broker and native capabilities, not flags.
	g := &ECMPacketGate{client: c, route: route, generation: generation}
	b, fence, err := g.lockPublication(generation)
	if err != nil {
		return nil, err
	}
	g.unlockPublication(b, fence)
	return g, nil
}

// Success returns with the full gate -> owner -> quota -> broker -> native
// chain held. Failure unlocks everything and cannot expose queued data.
func (g *ECMPacketGate) lockPublication(generation uint64) (*ecmBroker, ecmPublicationFence, error) {
	g.mu.Lock()
	if g.closed || generation != g.generation {
		g.mu.Unlock()
		return nil, nil, ecmStaleError
	}
	b, err := ecmClientBroker(g.client)
	if err != nil {
		g.clearLocked()
		g.mu.Unlock()
		return nil, nil, err
	}
	b.lock()
	fence, session, ok := ecmPublicationFences(b.transport)
	if !ok {
		g.clearLocked()
		g.unlockPublication(b, nil)
		return nil, nil, ecmUnsupportedError
	}
	fence.lockECMResults()
	if !b.clientScopeLocked(g.client) {
		err = ecmStaleError
	} else if err = session.validateECMSessionLocked(g.client.sessionEpoch); err == nil {
		err = fence.validateECMRouteLocked(g.route)
	}
	if err != nil {
		g.clearLocked()
		g.unlockPublication(b, fence)
		return nil, nil, err
	}
	return b, fence, nil
}

// Like broker.unlock, but waiters/notices must also be outside the gate lock.
// There is no broker registry of gates and no upward gate acquisition.
func (g *ECMPacketGate) unlockPublication(b *ecmBroker, fence ecmPublicationFence) {
	if fence != nil {
		fence.unlockECMResults()
	}
	signals := b.signals
	b.signals = nil
	b.mu.Unlock()
	b.quota.mu.Unlock()
	b.owner.guard.RUnlock()
	g.mu.Unlock()
	for _, w := range signals {
		close(w.done)
	}
	b.notify()
}

func (g *ECMPacketGate) clearLocked() {
	clear(g.slots[:])
	g.head, g.size = 0, 0
}

// This transient bounded set contains handles only, never backing/key material.
// Unioning all queued batches prevents result refresh from creating a cache of
// more than the same two opaque owners while older packets remain queued.
type ecmGateOwners struct {
	handles [2]*ECMResult
	masks   [2]uint8
}

func (owners *ecmGateOwners) add(r *ECMResult, mask uint8) bool {
	if r == nil {
		return true
	}
	for i, present := range owners.handles {
		if present == r {
			owners.masks[i] |= mask
			return true
		}
	}
	for i, present := range owners.handles {
		if present == nil {
			owners.handles[i], owners.masks[i] = r, mask
			return true
		}
	}
	return false
}
func (owners *ecmGateOwners) addProof(proof ECMPacketProof) bool {
	return owners.add(proof.Even, 1) && owners.add(proof.Odd, 2)
}

func (g *ECMPacketGate) queueOwnersLocked(owners *ecmGateOwners) bool {
	for i := 0; i < g.size; i++ {
		slot := &g.slots[(g.head+i)%len(g.slots)]
		if (slot.packet.Parity == 2 && slot.proof.Even == nil) ||
			(slot.packet.Parity == 3 && slot.proof.Odd == nil) || !owners.addProof(slot.proof) {
			return false
		}
	}
	return true
}

func (g *ECMPacketGate) validateOwnersLocked(b *ecmBroker, fence ecmPublicationFence, owners *ecmGateOwners) error {
	var expires [2]time.Time
	for i, r := range owners.handles {
		if r == nil {
			continue
		}
		k, err := b.leaseBackingLocked(g.client, r, b.clock.Now(), fence)
		if err != nil {
			return err
		}
		if k.token.route != g.route {
			return ecmNoRouteError
		}
		if k.keys.validMask&owners.masks[i] != owners.masks[i] {
			return ecmStaleError
		}
		expires[i] = k.expires
	}
	// Recheck both after all native validations: an odd check must not let an
	// earlier even check's receipt expire before the indivisible commit/dequeue.
	now := b.clock.Now()
	valid := true
	for i, r := range owners.handles {
		if r != nil && !now.Before(expires[i]) {
			b.dropResultLocked(r.ownerID)
			valid = false
		}
	}
	if !valid {
		return ecmStaleError
	}
	return nil
}

func (g *ECMPacketGate) Publish(generation uint64, proof ECMPacketProof, packets []ECMPacket) error {
	return g.publishUntil(generation, proof, packets, time.Time{}, nil)
}

// Pipeline publication additionally checks packet residence and close intent
// after native-lock contention. No caller clock or callback runs in this chain.
func (g *ECMPacketGate) publishUntil(generation uint64, proof ECMPacketProof, packets []ECMPacket, deadline time.Time, closing *atomic.Bool) error {
	if g == nil {
		return ecmStaleError
	}
	if len(packets) == 0 {
		return ecmInvalidRequestError
	}
	if len(packets) > 64 {
		return ecmCapacityError
	}
	// Copy/parse before locking. Even if the parser's escape behavior changes,
	// it cannot allocate or invoke code beneath the publication chain.
	var batch [64]ECMPacket
	copy(batch[:], packets)
	var needed uint8
	for i := 0; i < len(packets); i++ {
		p := &batch[i]
		switch p.Parity {
		case 0:
		case 2:
			needed |= 1
		case 3:
			needed |= 2
		default:
			return ecmInvalidRequestError
		}
		if p.Data[3]&0xc0 != 0 {
			return ecmInvalidRequestError
		}
		if _, err := mpegts.ParsePacket(p.Data[:]); err != nil {
			return ecmInvalidRequestError
		}
	}
	if needed&1 == 0 {
		proof.Even = nil
	}
	if needed&2 == 0 {
		proof.Odd = nil
	}
	b, fence, err := g.lockPublication(generation)
	if err != nil {
		return err
	}
	defer g.unlockPublication(b, fence)
	var owners ecmGateOwners
	if !g.queueOwnersLocked(&owners) {
		g.clearLocked()
		return ecmStaleError
	}
	if err := g.validateOwnersLocked(b, fence, &owners); err != nil {
		g.clearLocked()
		return err
	}
	if (needed&1 != 0 && proof.Even == nil) || (needed&2 != 0 && proof.Odd == nil) {
		return ecmStaleError
	}
	if !owners.addProof(proof) {
		return ecmCapacityError
	}
	if err := g.validateOwnersLocked(b, fence, &owners); err != nil {
		g.clearLocked()
		return err
	}
	if len(packets) > len(g.slots)-g.size {
		return ecmCapacityError
	}
	if closing != nil && closing.Load() {
		g.clearLocked()
		return ecmStaleError
	}
	if !deadline.IsZero() && !b.clock.Now().Before(deadline) {
		return ecmStaleError
	}
	for i := 0; i < len(packets); i++ {
		g.slots[(g.head+g.size)%len(g.slots)] = ecmPacketSlot{packet: batch[i], proof: proof}
		g.size++
	}
	return nil
}

func (g *ECMPacketGate) Take(generation uint64) (mpegts.Packet, error) {
	if g == nil {
		return mpegts.Packet{}, ecmStaleError
	}
	b, fence, err := g.lockPublication(generation)
	if err != nil {
		return mpegts.Packet{}, err
	}
	defer g.unlockPublication(b, fence)
	if g.size == 0 {
		return mpegts.Packet{}, ecmStaleError
	}
	var owners ecmGateOwners
	if !g.queueOwnersLocked(&owners) {
		g.clearLocked()
		return mpegts.Packet{}, ecmStaleError
	}
	if err := g.validateOwnersLocked(b, fence, &owners); err != nil {
		g.clearLocked()
		return mpegts.Packet{}, err
	}
	p := g.slots[g.head].packet.Data
	g.slots[g.head] = ecmPacketSlot{}
	g.head = (g.head + 1) % len(g.slots)
	g.size--
	if g.size == 0 {
		g.head = 0
	}
	return p, nil
}

// Revalidate existing queues independently of an incoming result. A rejected
// unrelated lease must not revoke still-authorized sibling output.
func (g *ECMPacketGate) revalidate(generation uint64) (int, error) {
	b, fence, err := g.lockPublication(generation)
	if err != nil {
		return 0, err
	}
	defer g.unlockPublication(b, fence)
	var owners ecmGateOwners
	if !g.queueOwnersLocked(&owners) {
		g.clearLocked()
		return 0, ecmStaleError
	}
	if err := g.validateOwnersLocked(b, fence, &owners); err != nil {
		g.clearLocked()
		return 0, err
	}
	return g.size, nil
}

func (g *ECMPacketGate) Revoke(generation uint64) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if generation == g.generation {
		g.closed = true
		g.clearLocked()
		g.client = nil
	}
	g.mu.Unlock()
}
func (g *ECMPacketGate) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closed = true
	g.clearLocked()
	g.client = nil
	g.mu.Unlock()
}
