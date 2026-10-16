// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"errors"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"astrax/internal/csa"
	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
)

const pipelineReservation = 256 * 1024

var errPipelineCipher = errors.New("descrambling_cipher_failed")

type DescramblingPipelineConfig struct {
	Client     *ECMClient
	Backend    csa.Backend
	Budget     *packetbudget.Budget
	Service    mpegts.Service
	Policy     model.DVBDescramblingConfig
	Selection  mpegts.Selection
	Generation uint64
	Now        func() time.Time
	Shared     bool
}

type DescramblingPipelineStatus struct {
	State                string
	Queued, OutputQueued int
	Processed, Dropped   uint64
}

type pipelinePacket struct {
	data mpegts.Packet
	at   time.Time
}

// DescramblingPipeline owns bounded packet storage and installed result handles.
// Client and Backend are borrowed: close the pipeline before releasing either.
// It starts no workers or network operations. The service coordinator submits
// sections returned by Push and invokes Flush from its bounded worker pool.
type DescramblingPipeline struct {
	mu                        sync.Mutex
	ready                     *sync.Cond
	closing                   atomic.Bool
	once                      sync.Once
	client                    *ECMClient
	backend                   csa.Backend
	reservation               *packetbudget.Reservation
	builder                   *mpegts.SPTS
	assembler                 *mpegts.ECMAssembler
	gate                      *ECMPacketGate
	route                     ECMRoute
	ecmPID                    uint16
	generation                uint64
	now                       func() time.Time
	selected                  [8192]bool
	keys                      [2]*ECMResult
	input                     [256]pipelinePacket
	head, size, output, batch int
	state                     string
	processed, dropped        uint64
	published                 bool
	shared                    bool
	service                   mpegts.Service
	budget                    *packetbudget.Budget
	outputs                   map[string]*DescramblingOutput
	needed                    atomic.Uint32
	pending                   atomic.Int32
	rejected                  atomic.Uint64
	gap                       atomic.Bool
	ecmGap                    atomic.Bool
	hints                     atomic.Pointer[[2]ECMLeaseInfo]
	statusCache               atomic.Pointer[descramblingStatusSample]
}

// Formatting never walks the borrowed broker, key owners or packet buffers.
func (*DescramblingPipeline) String() string   { return "DescramblingPipeline[redacted]" }
func (*DescramblingPipeline) GoString() string { return "DescramblingPipeline[redacted]" }
func (*DescramblingPipeline) MarshalJSON() ([]byte, error) {
	return []byte(`"DescramblingPipeline[redacted]"`), nil
}

func NewDescramblingPipeline(cfg DescramblingPipelineConfig) (*DescramblingPipeline, error) {
	if cfg.Client == nil || cfg.Backend == nil || cfg.Budget == nil || cfg.Generation == 0 {
		return nil, ecmInvalidRequestError
	}
	v := reflect.ValueOf(cfg.Backend)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, ecmInvalidRequestError
	}
	batch := cfg.Backend.BatchSize()
	if batch < 1 || batch > 128 {
		return nil, ecmInvalidRequestError
	}
	binding, err := cfg.Client.BindingInfo()
	if err != nil {
		return nil, err
	}
	id := binding.Identity
	if id.ONID != cfg.Service.ONID || id.TSID != cfg.Service.TSID || id.ServiceID != cfg.Service.SID {
		return nil, ecmInvalidRequestError
	}
	// Charge packet/scratch retention before constructing queues or table buffers.
	r, err := cfg.Budget.Reserve(pipelineReservation)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			r.Release()
		}
	}()
	route, err := mpegts.ResolveRoute(cfg.Service, cfg.Policy)
	if err != nil {
		return nil, err
	}
	builder, err := mpegts.NewSPTS(cfg.Service, cfg.Selection)
	if err != nil {
		return nil, err
	}
	assembler, err := mpegts.NewECMAssembler(route.ECMPID)
	if err != nil {
		return nil, err
	}
	er := ECMRoute{CAID: route.CAID, Provider: route.Provider}
	gate, err := cfg.Client.NewPacketGate(er, cfg.Generation, 64)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	p := &DescramblingPipeline{client: cfg.Client, backend: cfg.Backend,
		reservation: r, builder: builder, assembler: assembler, gate: gate,
		route: er, ecmPID: route.ECMPID, generation: cfg.Generation,
		now: now, batch: min(64, batch), state: "waiting_keys"}
	for _, pid := range cfg.Selection.PIDs {
		p.selected[pid] = true
	}
	if cfg.Shared {
		for _, es := range cfg.Service.ElementaryStreams {
			p.selected[es.PID] = true
		}
	}
	if cfg.Selection.PCRPID != 8191 {
		p.selected[cfg.Selection.PCRPID] = true
	}
	p.ready = sync.NewCond(&p.mu)
	p.shared, p.service, p.budget = cfg.Shared, cfg.Service.Clone(), cfg.Budget
	if cfg.Shared {
		p.outputs = make(map[string]*DescramblingOutput, 64)
	}
	ok = true
	return p, nil
}

func (p *DescramblingPipeline) Push(packet mpegts.Packet, arrived time.Time) ([][]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pushLocked(packet, arrived)
}

// TryPush keeps the input dispatcher independent of a cipher/native-lock wait.
func (p *DescramblingPipeline) TryPush(packet mpegts.Packet, arrived time.Time) ([][]byte, error) {
	if p.closing.Load() {
		return nil, io.EOF
	}
	pid := uint16(packet[1]&31)<<8 | uint16(packet[2])
	if pid != p.ecmPID && !p.selected[pid] {
		return nil, nil
	}
	if !p.mu.TryLock() {
		p.rejected.Add(1)
		if pid == p.ecmPID {
			p.ecmGap.Store(true)
		} else {
			p.gap.Store(true)
		}
		return nil, ecmCapacityError
	}
	defer p.mu.Unlock()
	return p.pushLocked(packet, arrived)
}

func (p *DescramblingPipeline) pushLocked(packet mpegts.Packet, arrived time.Time) ([][]byte, error) {
	if p.closing.Load() {
		return nil, io.EOF
	}
	pid := uint16(packet[1]&31)<<8 | uint16(packet[2])
	if pid == p.ecmPID {
		if p.ecmGap.Swap(false) {
			p.assembler.Reset()
		}
		return p.assembler.Push(packet)
	}
	if !p.selected[pid] {
		return nil, nil
	}
	payload, parity, err := packet.Payload()
	if err != nil {
		return nil, err
	}
	if len(payload) > 0 && parity >= 2 {
		p.needed.Or(1 << uint(parity-2))
	}
	now := p.now()
	if arrived.IsZero() || arrived.After(now) || now.Sub(arrived) >= 100*time.Millisecond {
		p.dropped++
		p.recoveryLocked()
		return nil, ecmStaleError
	}
	if p.size == len(p.input) {
		p.dropped++
		p.recoveryLocked()
		return nil, ecmCapacityError
	}
	p.input[(p.head+p.size)%len(p.input)] = pipelinePacket{data: packet, at: arrived}
	p.size++
	p.pending.Store(int32(p.size))
	return nil, nil
}

// InstallResult consumes ownership, including on rejection. It never refreshes
// the receipt timestamp. A handle carrying both parities is retained only once.
func (p *DescramblingPipeline) InstallResult(result *ECMResult) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.installResultLocked(result)
}

// A control worker must not wait for a media actor's bounded native call.
// Capacity rejection consumes the incoming owner, without caching a third CW.
func (p *DescramblingPipeline) TryInstallResult(result *ECMResult) error {
	if result == nil {
		return ecmInvalidRequestError
	}
	if p.closing.Load() {
		_ = result.Release()
		return io.EOF
	}
	if !p.mu.TryLock() {
		_ = result.Release()
		return ecmCapacityError
	}
	defer p.mu.Unlock()
	return p.installResultLocked(result)
}

func (p *DescramblingPipeline) installResultLocked(result *ECMResult) error {
	if result == nil {
		return ecmInvalidRequestError
	}
	if p.closing.Load() {
		_ = result.Release()
		return io.EOF
	}
	b, fence, err := p.gate.lockPublication(p.generation)
	var mask uint8
	var info ECMLeaseInfo
	if err == nil {
		k, leaseErr := b.leaseBackingLocked(p.client, result, b.clock.Now(), fence)
		err = leaseErr
		if err == nil {
			if k.token.route != p.route {
				err = ecmNoRouteError
			} else {
				mask = k.keys.validMask
				info = ECMLeaseInfo{ReceivedAt: k.responseAt, ExpiresAt: k.expires, ValidMask: mask}
			}
		}
		p.gate.unlockPublication(b, fence)
	}
	if err != nil {
		actual, _ := p.gate.revalidate(p.generation)
		if actual < p.output {
			p.output = actual
			p.recoveryLocked()
		}
		for _, out := range p.outputs {
			queued, _ := out.gate.revalidate(p.generation)
			if queued < out.output {
				out.output = queued
				out.recoveryLocked()
			}
		}
		_ = result.Release()
		return err
	}
	old := p.keys
	var metadata [2]ECMLeaseInfo
	if previous := p.hints.Load(); previous != nil {
		metadata = *previous
	}
	for i, key := range old {
		if key != nil && mask&(1<<i) != 0 && info.ReceivedAt.Before(metadata[i].ReceivedAt) {
			if result != old[0] && result != old[1] {
				_ = result.Release()
			}
			return ecmStaleError
		}
	}
	replaced := false
	for i := range p.keys {
		if mask&(1<<i) != 0 {
			replaced = replaced || (p.keys[i] != nil && p.keys[i] != result)
			p.keys[i] = result
			metadata[i] = info
		}
	}
	if replaced {
		p.clearOutputLocked()
		p.recoveryLocked()
	}
	for i, r := range old {
		if r != nil && r != p.keys[0] && r != p.keys[1] && (i == 0 || r != old[0]) {
			_ = r.Release()
		}
	}
	p.state = "keys_ready"
	p.hints.Store(&metadata)
	return nil
}

func (p *DescramblingPipeline) clearOutputLocked() {
	p.gate.mu.Lock()
	p.gate.clearLocked()
	p.gate.mu.Unlock()
	p.output = 0
	for _, out := range p.outputs {
		out.clearLocked()
		out.recoveryLocked()
	}
}

func (p *DescramblingPipeline) recoveryLocked() {
	if p.published {
		p.builder.Discontinuity()
		for _, out := range p.outputs {
			out.recoveryLocked()
		}
	}
}

func (p *DescramblingPipeline) removeLocked(n int, dropped bool) {
	for range n {
		p.input[p.head] = pipelinePacket{}
		p.head = (p.head + 1) % len(p.input)
		p.size--
	}
	if dropped {
		p.dropped += uint64(n)
		p.recoveryLocked()
	}
	if p.size == 0 {
		p.head = 0
	}
	p.pending.Store(int32(p.size))
}

func (p *DescramblingPipeline) eligibleLocked(entry *pipelinePacket, now time.Time, leases [2]bool) bool {
	if entry.at.After(now) || now.Sub(entry.at) >= 100*time.Millisecond {
		return false
	}
	payload, parity, err := entry.data.Payload()
	if err != nil {
		return false
	}
	if parity == 0 {
		return true
	}
	// With no scrambled payload there is no successful transform authorizing a
	// flag change. Clear adaptation-only/PCR packets still pass without a key.
	if len(payload) == 0 {
		return false
	}
	if !leases[parity-2] {
		if p.keys[parity-2] == nil {
			p.state = "waiting_keys"
		} else {
			p.state = "key_expired"
		}
		return false
	}
	return true
}

func (p *DescramblingPipeline) pruneLocked(now time.Time, leases [2]bool) {
	for p.size > 0 && !p.eligibleLocked(&p.input[p.head], now, leases) {
		p.removeLocked(1, true)
	}
}

// Flush copies a bounded prefix, decrypts outside the native ownership chain,
// then performs Prepare -> guarded Publish -> Commit. Neither CGo nor table
// allocation runs beneath broker/native locks. Failed batches stay private.
func (p *DescramblingPipeline) Flush(force bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing.Load() {
		return io.EOF
	}
	now := p.now()
	if p.gap.Swap(false) {
		p.recoveryLocked()
	}
	var leases [2]bool
	for slot, key := range p.keys {
		if key != nil {
			_, err := p.client.LeaseInfo(key)
			leases[slot] = err == nil
		}
	}
	p.pruneLocked(now, leases)
	if p.size == 0 {
		return nil
	}
	if !force && p.size < p.batch && now.Sub(p.input[p.head].at) < 2*time.Millisecond {
		return nil
	}
	if !p.shared && p.output == 64 {
		return ecmCapacityError
	}
	n := min(p.size, p.batch)
	if p.shared && len(p.outputs) == 0 {
		p.removeLocked(n, true)
		return nil
	}
	var packets [64]mpegts.Packet
	var parities [64]uint8
	var source [64]int
	var payloads [2][64][]byte
	var counts [2]int
	valid := 0
	var deadline time.Time
	for i := 0; i < n; i++ {
		entry := &p.input[(p.head+i)%len(p.input)]
		// End a valid FIFO prefix at a gap. Its successor cannot be prepared
		// until pruning records recovery; never mark a gap after publication.
		if !p.eligibleLocked(entry, now, leases) {
			n = i
			break
		}
		packet := entry.data
		payload, parity, _ := packet.Payload()
		d := entry.at.Add(100 * time.Millisecond)
		if deadline.IsZero() || d.Before(deadline) {
			deadline = d
		}
		packets[valid], parities[valid], source[valid] = packet, parity, i
		if parity != 0 && len(payload) > 0 {
			owned, _, _ := packets[valid].Payload()
			slot := parity - 2
			payloads[slot][counts[slot]] = owned
			counts[slot]++
		} else {
			parities[valid] = 0
		}
		valid++
	}
	if valid == 0 {
		p.removeLocked(n, true)
		return nil
	}
	for slot, count := range counts {
		if count == 0 {
			continue
		}
		even, odd, mask, err := p.client.CopyKeys(p.keys[slot])
		if err == nil && mask&(1<<slot) == 0 {
			err = ecmStaleError
		}
		if err == nil {
			if slot == 0 {
				err = p.backend.Decrypt(even, payloads[slot][:count])
			} else {
				err = p.backend.Decrypt(odd, payloads[slot][:count])
			}
		}
		clear(even[:])
		clear(odd[:])
		if err != nil {
			clear(packets[:])
			p.removeLocked(n, true)
			p.state = "cipher_failed"
			return errPipelineCipher
		}
	}
	defer clear(packets[:])
	if p.closing.Load() {
		p.removeLocked(n, true)
		return io.EOF
	}
	// Recheck residence after the cipher too, not merely before borrowing it.
	if !p.now().Before(deadline) {
		p.removeLocked(n, true)
		return ecmStaleError
	}
	for i := 0; i < valid; i++ {
		packets[i][3] &= 0x3f
	}
	if p.shared {
		return p.fanoutLocked(packets[:valid], parities[:valid], n, deadline, leases)
	}
	prepared, err := p.builder.Prepare(packets[:valid], p.now(), false, 64-p.output)
	if err != nil {
		if !errors.Is(err, mpegts.ErrCapacity) {
			p.removeLocked(n, true)
		}
		return err
	}
	defer p.builder.Discard(prepared)
	var batch [64]ECMPacket
	for i, packet := range prepared.Packets {
		batch[i].Data = packet
		if origin := prepared.Origins[i]; origin >= 0 {
			batch[i].Parity = parities[origin]
		}
	}
	if len(prepared.Packets) == 0 {
		return nil
	}
	err = p.gate.publishUntil(p.generation, ECMPacketProof{Even: p.keys[0], Odd: p.keys[1]}, batch[:len(prepared.Packets)], deadline, &p.closing)
	clear(batch[:])
	if err != nil {
		// Publish may clear an already stale output queue. Read its actual size.
		p.gate.mu.Lock()
		p.output = p.gate.size
		p.gate.mu.Unlock()
		p.removeLocked(n, true)
		p.state = "key_expired"
		return err
	}
	if p.closing.Load() {
		p.clearOutputLocked()
		p.removeLocked(n, true)
		return io.EOF
	}
	if err = p.builder.Commit(prepared); err != nil {
		p.clearOutputLocked()
		p.removeLocked(n, true)
		return err
	}
	consumed := n
	if prepared.Consumed < valid {
		consumed = source[prepared.Consumed]
	}
	for i := 0; i < prepared.Consumed; i++ {
		if parities[i] != 0 {
			p.processed++
		}
	}
	p.removeLocked(consumed, false)
	p.output += len(prepared.Packets)
	p.published = true
	p.state = "payload_processed"
	p.pruneLocked(p.now(), leases)
	p.ready.Broadcast()
	return nil
}

func (p *DescramblingPipeline) ReadPacket() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.shared {
		return nil, ecmInvalidRequestError
	}
	for p.output == 0 && !p.closing.Load() {
		p.ready.Wait()
	}
	if p.closing.Load() {
		return nil, io.EOF
	}
	packet, err := p.gate.Take(p.generation)
	if p.closing.Load() {
		clear(packet[:])
		p.clearOutputLocked()
		return nil, io.EOF
	}
	if err != nil {
		p.output = 0
		p.state = "key_expired"
		p.recoveryLocked()
		return nil, err
	}
	p.output--
	return packet[:], nil
}

func (p *DescramblingPipeline) Close() error {
	if p == nil {
		return nil
	}
	// Intent fences the batch even while Close waits for its in-flight cipher.
	p.closing.Store(true)
	p.once.Do(func() {
		p.gate.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for i, r := range p.keys {
			if r != nil && (i == 0 || r != p.keys[0]) {
				_ = r.Release()
			}
		}
		clear(p.keys[:])
		p.needed.Store(0)
		p.pending.Store(0)
		p.hints.Store(nil)
		for id, out := range p.outputs {
			out.closeLocked()
			delete(p.outputs, id)
		}
		clear(p.input[:])
		p.assembler.Reset()
		p.head, p.size, p.output, p.state = 0, 0, 0, "closed"
		p.reservation.Release()
		p.ready.Broadcast()
	})
	return nil
}

func (p *DescramblingPipeline) Status() DescramblingPipelineStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return DescramblingPipelineStatus{State: p.state, Queued: p.size, OutputQueued: p.output, Processed: p.processed, Dropped: p.dropped + p.rejected.Load()}
}

type ECMRefreshHints struct {
	Needed uint8
	Leases [2]ECMLeaseInfo
}

// Refresh hints are scheduling metadata, not authority to decrypt or publish.
func (p *DescramblingPipeline) RefreshHints() ECMRefreshHints {
	var h ECMRefreshHints
	if p.closing.Load() {
		return h
	}
	h.Needed = uint8(p.needed.Load())
	if snapshot := p.hints.Load(); snapshot != nil {
		h.Leases = *snapshot
	}
	return h
}

func (p *DescramblingPipeline) HasPackets() bool { return !p.closing.Load() && p.pending.Load() > 0 }
