// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
	"astrax/internal/softcam"
)

const sharedDemuxRetryDelay = 50 * time.Millisecond

var (
	errSharedDemuxClosed          = errors.New("shared demux closed")
	errStreamPacketSourceClosed   = errors.New("stream packet source closed")
	errStreamPacketSourceReplaced = errors.New("stream packet source replaced")
)

// sharedDemux wraps one full-TS source and fans packets out by PID.
type sharedDemux struct {
	transformMu     sync.Mutex
	transforms      map[softcam.DescramblingServiceKey]*descramblingTap
	transformIndex  map[uint16][]*descramblingTap
	transformPMTs   map[uint16]int
	transformCount  atomic.Int32
	dependencies    *sharedDemuxDependencies
	indexStats      sharedDemuxIndexStats
	diagnosticsMu   sync.Mutex
	allocationStats sharedDemuxAllocationStats
	// Catalog transactions precede sd.mu; never acquire this while holding
	// sd.mu/sps.mu, or wait for worker retirement while holding it.
	catalogMu       sync.Mutex
	catalogRevision uint64
	// Identity is immutable; terminal Close clears catalog storage, not this
	// pointer, which scheduler ownership snapshots may still legitimately hold.
	catalog                                                   *mpegts.Catalog
	catalogArenaReservation                                   *packetbudget.Reservation
	catalogArenaBytes, catalogStateBytes, catalogWorkingBytes int64
	catalogStateReservations                                  map[uint16]*packetbudget.Reservation
	catalogInterests                                          []uint16
	catalogPIDs                                               [8192]bool
	listeners                                                 [8192]*sharedDemuxListener
	wildcards                                                 *sharedDemuxListener
	pending                                                   map[string]*sharedDemuxAdmission
	membershipCount                                           int
	queueBytes, packetBytes                                   int64
	queuedPackets                                             int
	work                                                      sync.WaitGroup
	retireOnce                                                sync.Once

	inner          model.PacketSource
	streams        map[string]*streamPacketSource
	mu             sync.Mutex
	closed         bool
	terminalErr    error
	innerCloseErr  error
	cancel         context.CancelFunc
	done           chan struct{}
	innerCloseOnce sync.Once
	resultOnce     sync.Once
	resultErr      error
}

type sharedDemuxPacketOwner struct {
	packet      []byte
	reservation *packetbudget.Reservation
	bytes       int
	pending     bool
}

type streamPacketSource struct {
	sd               *sharedDemux
	id               string
	ch               chan []byte
	done             chan struct{}
	pids             map[uint16]struct{}
	wildcard         bool
	nodes            []sharedDemuxListener
	indexed          bool
	generation       uint64
	owners           [sharedDemuxQueueCapacity]sharedDemuxPacketOwner
	queueReservation *packetbudget.Reservation
	queueBytes       int64
	work             sync.WaitGroup
	mu               sync.Mutex
	closed           bool
	closeErr         error
	closeOnce        sync.Once
}

func newSharedDemux(inner model.PacketSource) (*sharedDemux, error) {
	return newSharedDemuxInternal(inner, processSharedDemuxDependencies)
}

func newSharedDemuxInternal(inner model.PacketSource, deps *sharedDemuxDependencies) (*sharedDemux, error) {
	if nilPacketSource(inner) {
		return nil, fmt.Errorf("shared demux inner source is nil")
	}
	if deps == nil {
		deps = processSharedDemuxDependencies
	}
	if deps.packets == nil || deps.memberships == nil {
		return nil, fmt.Errorf("shared demux dependencies are incomplete")
	}
	arena, err := deps.packets.Reserve(sharedDemuxCatalogArenaBytes)
	if err != nil {
		return nil, err
	}
	if !deps.memberships.reserve(2) {
		arena.Release()
		return nil, errSharedDemuxMembershipCapacity
	}
	ctx, cancel := context.WithCancel(context.Background())
	sd := &sharedDemux{
		dependencies: deps, inner: inner,
		streams:                  make(map[string]*streamPacketSource, sharedDemuxInputMembershipLimit),
		pending:                  make(map[string]*sharedDemuxAdmission, sharedDemuxInputMembershipLimit),
		catalogStateReservations: make(map[uint16]*packetbudget.Reservation, 256),
		catalogInterests:         []uint16{0, 17}, membershipCount: 2,
		catalogArenaReservation: arena, catalogArenaBytes: sharedDemuxCatalogArenaBytes,
		cancel: cancel, done: make(chan struct{}),
	}
	sd.catalogPIDs[0], sd.catalogPIDs[17] = true, true
	sd.recordAllocation("catalog", sharedDemuxCatalogArenaBytes, false)
	sd.catalog = mpegts.NewCatalog()
	go sd.run(ctx)
	return sd, nil
}

func nilPacketSource(source model.PacketSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (sd *sharedDemux) run(ctx context.Context) {
	defer close(sd.done)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pkt, err := sd.inner.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			delay, retry := sharedDemuxRetry(err)
			if !retry {
				sd.fail(err)
				return
			}
			if !waitSharedDemuxRetry(ctx, delay) {
				return
			}
			continue
		}
		if len(pkt) < 3 {
			continue
		}

		pid := uint16(pkt[1]&0x1f)<<8 | uint16(pkt[2])

		sd.feedCatalog(pid, pkt)
		sd.pushDescrambling(pid, pkt)
		sd.dispatch(pid, pkt)
	}
}

func sharedDemuxRetry(err error) (time.Duration, bool) {
	if errors.Is(err, syscall.EINTR) {
		return 0, true
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return sharedDemuxRetryDelay, true
	}
	return 0, false
}

func waitSharedDemuxRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (sd *sharedDemux) RegisterStream(id string, pids []int) (model.PacketSource, error) {
	allowed, err := validateSharedDemuxRegistration(id, pids)
	if err != nil {
		return nil, err
	}
	return sd.register(id, allowed, false)
}

func validateSharedDemuxRegistration(id string, pids []int) (map[uint16]struct{}, error) {
	if id == "" {
		return nil, fmt.Errorf("shared demux stream ID is required")
	}
	if strings.TrimSpace(id) != id {
		return nil, fmt.Errorf("shared demux stream ID %q must be trimmed", id)
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("shared demux stream %q requires at least one PID", id)
	}
	capacity := len(pids)
	if capacity > 8192 {
		capacity = 8192
	}
	allowed := make(map[uint16]struct{}, capacity)
	for _, pid := range pids {
		if pid < 0 || pid > 0x1fff {
			return nil, fmt.Errorf("shared demux stream %q PID %d must be between 0 and 8191", id, pid)
		}
		allowed[uint16(pid)] = struct{}{}
	}
	return allowed, nil
}

func (sd *sharedDemux) unavailableErrorLocked() error {
	if sd.terminalErr != nil {
		return fmt.Errorf("%w after terminal source failure: %w", errSharedDemuxClosed, sd.terminalErr)
	}
	return errSharedDemuxClosed
}

func (sd *sharedDemux) removeStream(stream *streamPacketSource) {
	sd.mu.Lock()
	if stream.indexed {
		count := len(stream.nodes)
		sd.unlinkStreamLocked(stream)
		if ticket := sd.pending[stream.id]; ticket != nil && ticket.old == stream {
			ticket.oldRemoved = true
		} else {
			_ = sd.changeMembersLocked(-count)
		}
	}
	if sd.streams[stream.id] == stream {
		delete(sd.streams, stream.id)
	}
	stream.nodes = nil
	stream.pids = nil
	sd.mu.Unlock()
	sd.refreshCatalogInterests()
}

func (sd *sharedDemux) fail(err error) { sd.shutdown(err) }

// All callers join retirement; no Close returns while another caller still
// owns detached queues, staged admissions or packet copies. The run goroutine
// never waits for its own done channel.
func (sd *sharedDemux) shutdown(terminalErr error) {
	sd.mu.Lock()
	if terminalErr != nil && sd.terminalErr == nil {
		sd.terminalErr = terminalErr
	}
	sd.closed = true
	closeErr := errSharedDemuxClosed
	if sd.terminalErr != nil {
		closeErr = sd.terminalErr
	}
	sd.mu.Unlock()
	sd.cancel()
	sd.revokeDescrambling()
	sd.retireOnce.Do(func() {
		sd.mu.Lock()
		streams := sd.streams
		sd.streams = nil
		sd.mu.Unlock()
		for _, stream := range streams {
			stream.closeWithError(closeErr)
		}
		sd.closeInner()
		sd.work.Wait()
		sd.catalogMu.Lock()
		sd.catalog.Close()
		sd.mu.Lock()
		_ = sd.changeMembersLocked(-len(sd.catalogInterests))
		sd.catalogInterests = nil
		sd.catalogPIDs = [8192]bool{}
		for pid, hold := range sd.catalogStateReservations {
			hold.Release()
			delete(sd.catalogStateReservations, pid)
		}
		sd.catalogStateBytes = 0
		sd.catalogStateReservations = nil
		sd.pending = nil
		sd.catalogArenaReservation.Release()
		sd.catalogArenaReservation = nil
		sd.catalogArenaBytes = 0
		sd.mu.Unlock()
		sd.catalogMu.Unlock()
	})
}

func (sd *sharedDemux) closeInner() error {
	sd.innerCloseOnce.Do(func() {
		err := sd.inner.Close()
		sd.mu.Lock()
		sd.innerCloseErr = err
		sd.mu.Unlock()
	})
	sd.mu.Lock()
	err := sd.innerCloseErr
	sd.mu.Unlock()
	return err
}

func (sd *sharedDemux) Close() error {
	sd.shutdown(nil)
	<-sd.done

	sd.resultOnce.Do(func() {
		sd.mu.Lock()
		terminalErr := sd.terminalErr
		innerCloseErr := sd.innerCloseErr
		sd.mu.Unlock()
		sd.resultErr = joinSharedDemuxErrors(terminalErr, innerCloseErr)
	})
	return sd.resultErr
}

func joinSharedDemuxErrors(terminalErr, innerCloseErr error) error {
	if terminalErr == nil {
		return innerCloseErr
	}
	if innerCloseErr == nil || errors.Is(terminalErr, innerCloseErr) {
		return terminalErr
	}
	return errors.Join(terminalErr, innerCloseErr)
}

func (sps *streamPacketSource) ReadPacket() ([]byte, error) {
	select {
	case <-sps.done:
		return nil, sps.readError()
	default:
	}

	select {
	case <-sps.done:
		return nil, sps.readError()
	case pkt := <-sps.ch:
		// Release at the legacy caller transfer boundary, not when the caller
		// eventually drops the slice. Sibling copies have separate reservations.
		sps.sd.mu.Lock()
		sps.mu.Lock()
		for i := range sps.owners {
			owner := &sps.owners[i]
			if len(owner.packet) > 0 && &owner.packet[0] == &pkt[0] {
				sps.releaseOwnerLocked(i)
				break
			}
		}
		sps.mu.Unlock()
		sps.sd.mu.Unlock()
		if err := sps.readError(); err != nil {
			return nil, err
		}
		return pkt, nil
	}
}

func (sps *streamPacketSource) Close() error {
	sps.closeWithError(errStreamPacketSourceClosed)
	return nil
}

func (sps *streamPacketSource) closeWithError(err error) {
	if err == nil {
		err = errStreamPacketSourceClosed
	}
	sps.closeOnce.Do(func() {
		sps.mu.Lock()
		sps.closed, sps.closeErr = true, err
		close(sps.done)
		sps.mu.Unlock()
		sps.sd.removeStream(sps)
		sps.work.Wait()
		sps.sd.mu.Lock()
		sps.mu.Lock()
		for i := range sps.owners {
			sps.releaseOwnerLocked(i)
		}
		for draining := true; draining; {
			select {
			case <-sps.ch:
			default:
				draining = false
			}
		}
		sps.queueReservation.Release()
		sps.queueReservation = nil
		sps.sd.queueBytes -= sps.queueBytes
		sps.queueBytes = 0
		sps.mu.Unlock()
		sps.sd.mu.Unlock()
	})
}

// Caller holds sd.mu then sps.mu; Release allocates no owned storage.
func (sps *streamPacketSource) releaseOwnerLocked(slot int) {
	owner := &sps.owners[slot]
	if owner.reservation != nil {
		sps.sd.packetBytes -= int64(owner.bytes)
		owner.reservation.Release()
	}
	if len(owner.packet) > 0 {
		sps.sd.queuedPackets--
	}
	*owner = sharedDemuxPacketOwner{}
}

func (sps *streamPacketSource) readError() error {
	sps.mu.Lock()
	closed := sps.closed
	err := sps.closeErr
	sps.mu.Unlock()
	if !closed {
		return nil
	}
	if errors.Is(err, errSharedDemuxClosed) {
		sps.sd.mu.Lock()
		terminalErr := sps.sd.terminalErr
		sps.sd.mu.Unlock()
		if terminalErr != nil {
			return terminalErr
		}
	}
	if err == nil {
		return errStreamPacketSourceClosed
	}
	return err
}

// Eligibility is rechecked after allocation so a close, replacement or PID
// update cannot commit a stale snapshot to an old owner. All backing allocation
// happens with neither sd.mu nor sps.mu held.
func (sps *streamPacketSource) eligibleLocked(pid uint16) bool {
	if sps.closed || sps.sd.closed || sps.sd.streams[sps.id] != sps {
		return false
	}
	if sps.wildcard {
		return true
	}
	_, ok := sps.pids[pid]
	return ok
}

func (sps *streamPacketSource) trySend(pkt []byte, generation uint64) {
	pid := uint16(pkt[1]&0x1f)<<8 | uint16(pkt[2])
	sd := sps.sd
	sd.mu.Lock()
	sps.mu.Lock()
	slot := -1
	if sps.generation == generation && sps.eligibleLocked(pid) {
		for i := range sps.owners {
			if !sps.owners[i].pending && sps.owners[i].reservation == nil {
				slot = i
				break
			}
		}
	}
	if slot < 0 {
		sps.mu.Unlock()
		sd.mu.Unlock()
		return
	}
	sps.owners[slot].pending = true
	sd.work.Add(1)
	sps.work.Add(1)
	sps.mu.Unlock()
	sd.mu.Unlock()
	defer sd.work.Done()
	defer sps.work.Done()
	hold, err := sd.dependencies.packets.Reserve(int64(len(pkt)))
	sd.mu.Lock()
	sps.mu.Lock()
	if err != nil || sps.generation != generation || !sps.eligibleLocked(pid) {
		sps.owners[slot] = sharedDemuxPacketOwner{}
		sps.mu.Unlock()
		sd.mu.Unlock()
		hold.Release()
		return
	}
	sps.owners[slot].reservation = hold
	sps.owners[slot].bytes = len(pkt)
	sd.packetBytes += int64(len(pkt))
	sps.mu.Unlock()
	sd.mu.Unlock()
	sd.recordAllocation("packet", int64(len(pkt)), false)
	packet := make([]byte, len(pkt))
	copy(packet, pkt)
	sd.mu.Lock()
	sps.mu.Lock()
	if sps.generation != generation || !sps.eligibleLocked(pid) {
		sps.releaseOwnerLocked(slot)
	} else {
		owner := &sps.owners[slot]
		owner.pending = false
		owner.packet = packet
		// Only this input's bounded producer commits to this consumer queue.
		select {
		case sps.ch <- packet:
			sd.queuedPackets++
		default:
			owner.packet = nil
			owner.pending = true
			sps.releaseOwnerLocked(slot)
		}
	}
	sps.mu.Unlock()
	sd.mu.Unlock()
}
