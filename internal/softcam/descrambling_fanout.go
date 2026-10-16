// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"io"
	"strings"
	"sync/atomic"
	"time"

	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
)

const pipelineOutputReservation = 64 * 1024

// Outputs share their service's cipher and two key owners. Only SPTS state and
// the guarded 64-packet queue are output-specific; no output starts a goroutine.
type DescramblingOutput struct {
	parent      *DescramblingPipeline
	id          string
	builder     *mpegts.SPTS
	gate        *ECMPacketGate
	reservation *packetbudget.Reservation
	closing     atomic.Bool
	closed      bool
	published   bool
	output      int
	dropped     uint64
	selected    [8192]bool
	statusCache atomic.Pointer[descramblingStatusSample]
}

func (*DescramblingOutput) String() string   { return "DescramblingOutput[redacted]" }
func (*DescramblingOutput) GoString() string { return "DescramblingOutput[redacted]" }
func (*DescramblingOutput) MarshalJSON() ([]byte, error) {
	return []byte(`"DescramblingOutput[redacted]"`), nil
}

func (p *DescramblingPipeline) Subscribe(id string, selection mpegts.Selection) (*DescramblingOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.shared || p.closing.Load() {
		return nil, ecmStaleError
	}
	if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || strings.ContainsRune(id, 0) || p.outputs[id] != nil {
		return nil, ecmInvalidRequestError
	}
	if len(p.outputs) >= 64 {
		return nil, ecmCapacityError
	}
	r, err := p.budget.Reserve(pipelineOutputReservation)
	if err != nil {
		return nil, err
	}
	builder, err := mpegts.NewSPTS(p.service, selection)
	if err != nil {
		r.Release()
		return nil, err
	}
	gate, err := p.client.NewPacketGate(p.route, p.generation, 64)
	if err != nil {
		r.Release()
		return nil, err
	}
	out := &DescramblingOutput{parent: p, id: id, builder: builder, gate: gate, reservation: r}
	for _, pid := range selection.PIDs {
		out.selected[pid] = true
	}
	if selection.PCRPID != 8191 {
		out.selected[selection.PCRPID] = true
	}
	p.outputs[id] = out
	return out, nil
}

func (o *DescramblingOutput) clearLocked() {
	o.gate.mu.Lock()
	o.gate.clearLocked()
	o.gate.mu.Unlock()
	o.output = 0
}

func (o *DescramblingOutput) recoveryLocked() {
	if o.published {
		o.builder.Discontinuity()
	}
}

func (o *DescramblingOutput) closeLocked() {
	if o.closed {
		return
	}
	o.closing.Store(true)
	o.closed = true
	o.gate.Close()
	o.output = 0
	o.reservation.Release()
	o.parent.ready.Broadcast()
}

func (o *DescramblingOutput) Close() error {
	if o == nil {
		return nil
	}
	o.closing.Store(true)
	o.gate.Close()
	p := o.parent
	p.mu.Lock()
	defer p.mu.Unlock()
	o.closeLocked()
	if p.outputs[o.id] == o {
		delete(p.outputs, o.id)
	}
	return nil
}

func (o *DescramblingOutput) ReadPacket() ([]byte, error) {
	p := o.parent
	p.mu.Lock()
	defer p.mu.Unlock()
	for o.output == 0 && !o.closing.Load() && !p.closing.Load() {
		p.ready.Wait()
	}
	if o.closing.Load() || p.closing.Load() {
		return nil, io.EOF
	}
	packet, err := o.gate.Take(p.generation)
	if o.closing.Load() || p.closing.Load() {
		clear(packet[:])
		o.clearLocked()
		return nil, io.EOF
	}
	if err != nil {
		o.output = 0
		o.recoveryLocked()
		return nil, err
	}
	o.output--
	return packet[:], nil
}

func (o *DescramblingOutput) Status() DescramblingPipelineStatus {
	p := o.parent
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.state
	if o.closing.Load() {
		state = "closed"
	}
	return DescramblingPipelineStatus{State: state, OutputQueued: o.output, Processed: p.processed, Dropped: o.dropped}
}

func (p *DescramblingPipeline) fanoutLocked(packets []mpegts.Packet, parities []uint8, consumed int, deadline time.Time, leases [2]bool) error {
	accepted := false
	var failure error
	for _, out := range p.outputs {
		if p.closing.Load() {
			failure = io.EOF
			break
		}
		if out.closing.Load() {
			continue
		}
		retained := false
		for _, packet := range packets {
			pid := uint16(packet[1]&31)<<8 | uint16(packet[2])
			if out.selected[pid] {
				retained = true
				break
			}
		}
		if !retained {
			continue
		}
		if out.output == 64 {
			out.dropped += uint64(len(packets))
			out.recoveryLocked()
			continue
		}
		proposal, err := out.builder.Prepare(packets, p.now(), false, 64-out.output)
		if err != nil {
			out.dropped += uint64(len(packets))
			out.recoveryLocked()
			failure = err
			continue
		}
		if len(proposal.Packets) == 0 {
			out.builder.Discard(proposal)
			continue
		}
		var batch [64]ECMPacket
		for i, packet := range proposal.Packets {
			batch[i].Data = packet
			if origin := proposal.Origins[i]; origin >= 0 {
				batch[i].Parity = parities[origin]
			}
		}
		err = out.gate.publishUntil(p.generation, ECMPacketProof{Even: p.keys[0], Odd: p.keys[1]}, batch[:len(proposal.Packets)], deadline, &p.closing)
		clear(batch[:])
		if err == nil && (out.closing.Load() || p.closing.Load()) {
			out.clearLocked()
			err = io.EOF
		}
		if err != nil {
			out.gate.mu.Lock()
			out.output = out.gate.size
			out.gate.mu.Unlock()
			out.builder.Discard(proposal)
			out.recoveryLocked()
			out.dropped += uint64(len(packets))
			failure = err
			continue
		}
		if err = out.builder.Commit(proposal); err != nil {
			out.clearLocked()
			out.dropped += uint64(len(packets))
			failure = err
			continue
		}
		out.output += len(proposal.Packets)
		out.published = true
		if proposal.Consumed < len(packets) {
			out.dropped += uint64(len(packets) - proposal.Consumed)
			out.builder.Discontinuity()
		}
		accepted = true
	}
	if accepted {
		for _, parity := range parities {
			if parity != 0 {
				p.processed++
			}
		}
		p.published = true
		p.state = "payload_processed"
	} else {
		p.dropped += uint64(consumed)
	}
	p.removeLocked(consumed, false)
	p.pruneLocked(p.now(), leases)
	p.ready.Broadcast()
	if !accepted {
		return failure
	}
	return nil
}
