// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"astrax/internal/model"
)

type cccamProbe struct {
	deadline time.Time
}

type cccamOutbound struct {
	frame    cccamFrame
	deadline time.Time
	complete chan error
}

type cccamSession struct {
	ctx           context.Context
	wire          *cccamWire
	mu            sync.Mutex
	cards         map[uint32]cccamCard
	cardRevisions map[uint32]uint64
	cardRevision  uint64
	ecmEpoch      uint64
	ecmRetiring   bool
	ecmPending    *cccamECMTransaction
	ecmWake       chan struct{}
	authenticated bool
	closed        bool
	err           error
	probe         *cccamProbe
	lastPeerReply time.Time
	outbound      chan cccamOutbound
	done          chan struct{}
	shutdownOnce  sync.Once
	cleanupOnce   sync.Once
	loops         sync.WaitGroup
}

var _ caidSession = (*cccamSession)(nil)
var _ sessionStatusProvider = (*cccamSession)(nil)

func openCCcamSessionContext(ctx context.Context, profile model.Softcam) (session, time.Duration, error) {
	return openCCcamSessionWithOptions(ctx, profile, defaultCCcamOptions())
}

func openCCcamSessionWithOptions(ctx context.Context, profile model.Softcam, opts cccamOptions) (session, time.Duration, error) {
	w, latency, err := loginCCcam(ctx, profile, opts)
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		w.Close()
		return nil, 0, protocolError("cancelled", err)
	}
	s := newCCcamSession(ctx, w)
	if err := ctx.Err(); err != nil {
		s.Close()
		return nil, 0, protocolError("cancelled", err)
	}
	return s, latency, nil
}

// Called exactly once after login releases I/O. Pre-ack frames are already
// decrypted. Handled early peer probes carry suppression, never new liveness.
func newCCcamSession(ctx context.Context, w *cccamWire) *cccamSession {
	s := &cccamSession{ctx: ctx, wire: w, cards: make(map[uint32]cccamCard), cardRevisions: make(map[uint32]uint64), ecmWake: make(chan struct{}, 1), authenticated: ctx.Err() == nil, outbound: make(chan cccamOutbound, cccamControlQueue), done: make(chan struct{})}
	pending := w.pending[:0]
	for _, f := range w.pending {
		if f.Command == 6 {
			s.lastPeerReply = time.Now()
			continue
		}
		pending = append(pending, f)
	}
	clear(w.pending[len(pending):])
	w.pending = pending
	s.loops.Add(2)
	go s.readLoop()
	go s.writeLoop()
	return s
}

func (s *cccamSession) stateErrorLocked() error {
	if s.ctx.Err() != nil {
		return protocolError("cancelled", s.ctx.Err())
	}
	if s.closed {
		return s.err
	}
	if s.ecmRetiring {
		return protocolError("session_closed", nil)
	}
	return nil
}

func (s *cccamSession) SessionStatus() SessionStatus {
	status, _ := s.sessionState()
	return status
}

func (s *cccamSession) sessionState() (SessionStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stateErrorLocked(); err != nil {
		return SessionStatus{}, err
	}
	return SessionStatus{Authenticated: s.authenticated, CardsObserved: len(s.cards)}, nil
}

func (s *cccamSession) addCard(card cccamCard) error {
	s.mu.Lock()
	if err := s.stateErrorLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	if len(card.Providers) > cccamMaxProviders {
		s.mu.Unlock()
		return protocolError("invalid_frame", nil)
	}
	if _, found := s.cards[card.ID]; !found && len(s.cards) >= cccamMaxCards {
		s.mu.Unlock()
		return protocolError("inventory_limit", nil)
	}
	if s.cardRevision == math.MaxUint64 {
		s.mu.Unlock()
		s.abortECM(ecmError("ecm_stale", nil))
		return protocolError("inventory_limit", nil)
	}
	s.cardRevision++
	card.Providers = append([]uint32(nil), card.Providers...)
	s.cards[card.ID] = card
	s.cardRevisions[card.ID] = s.cardRevision
	ambiguous := s.invalidateECMCardLocked(card.ID)
	s.mu.Unlock()
	if ambiguous {
		s.abortECM(ecmError("ecm_stale", nil))
	}
	return nil
}

func (s *cccamSession) cardSnapshot() []cccamCard {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErrorLocked() != nil {
		return nil
	}
	result := make([]cccamCard, 0, len(s.cards))
	for _, c := range s.cards {
		c.Providers = append([]uint32(nil), c.Providers...)
		result = append(result, c)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (s *cccamSession) GetCAIDs() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stateErrorLocked(); err != nil {
		return nil, err
	}
	unique := make(map[uint16]struct{})
	for _, c := range s.cards {
		unique[c.CAID] = struct{}{}
	}
	caids := make([]string, 0, len(unique))
	for caid := range unique {
		caids = append(caids, fmt.Sprintf("%04X", caid))
	}
	sort.Strings(caids)
	return caids, nil
}

// Signal shutdown without joining: either owned loop may report its own failure.
func (s *cccamSession) shutdown(err error) {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		if s.ctx.Err() != nil {
			err = protocolError("cancelled", s.ctx.Err())
		}
		if err == nil {
			err = protocolError("session_closed", nil)
		}
		s.closed = true
		s.authenticated = false
		s.err = err
		clear(s.cards)
		clear(s.cardRevisions)
		if tx := s.ecmPending; tx != nil {
			if tx.err == nil {
				tx.err = ecmError("ecm_session_unavailable", err)
			}
			tx.keys = ecmKeys{}
			tx.notifyLocked()
		}
		close(s.done)
		s.mu.Unlock()
		s.wire.Close()
	})
}

func (s *cccamSession) Close() error {
	s.shutdown(nil)
	s.loops.Wait()
	s.cleanupOnce.Do(func() {
		clear(s.wire.pending)
		s.wire.pending = nil
		clear(s.wire.clientIdentity[:])
		s.wire.identityRetained = false
		for {
			select {
			case op := <-s.outbound:
				op.complete <- s.closedError()
			default:
				return
			}
		}
	})
	return s.wire.Close()
}

func (s *cccamSession) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stateErrorLocked(); err != nil {
		return err
	}
	return protocolError("session_closed", nil)
}

func cccamOperationError(err error) error {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return protocolError("keepalive_timeout", err)
	}
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return err
	}
	return protocolError("invalid_frame", err)
}

func (s *cccamSession) enqueue(op cccamOutbound) error {
	s.mu.Lock()
	err := s.stateErrorLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	remaining := time.Until(op.deadline)
	if remaining <= 0 {
		err = protocolError("keepalive_timeout", context.DeadlineExceeded)
		s.shutdown(err)
		return err
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-s.done:
		return s.closedError()
	case <-timer.C:
		err = protocolError("keepalive_timeout", context.DeadlineExceeded)
		s.shutdown(err)
		return err
	case s.outbound <- op:
		return nil
	}
}

func (s *cccamSession) send(op cccamOutbound) error {
	op.frame.Payload = append([]byte(nil), op.frame.Payload...)
	op.complete = make(chan error, 1)
	if err := s.enqueue(op); err != nil {
		return err
	}
	timer := time.NewTimer(max(time.Until(op.deadline), 0))
	defer timer.Stop()
	select {
	case <-s.done:
		return s.closedError()
	case err := <-op.complete:
		return err
	case <-timer.C:
		err := protocolError("keepalive_timeout", context.DeadlineExceeded)
		s.shutdown(err)
		return err
	}
}

func (s *cccamSession) writeLoop() {
	defer s.loops.Done()
	for {
		var op cccamOutbound
		// Control gets first refusal at every writer turn. The serial ECM
		// slot never occupies any of the 32 control queue entries.
		select {
		case <-s.done:
			return
		case op = <-s.outbound:
		default:
			s.mu.Lock()
			tx := s.ecmPending
			if tx != nil && !tx.selected && tx.err == nil {
				tx.selected = true
			} else {
				tx = nil
			}
			s.mu.Unlock()
			if tx != nil {
				s.writeECM(tx)
				continue
			}
			select {
			case <-s.done:
				return
			case op = <-s.outbound:
			case <-s.ecmWake:
				continue
			}
		}
		s.mu.Lock()
		err := s.stateErrorLocked()
		if err == nil && !time.Now().Before(op.deadline) {
			err = protocolError("keepalive_timeout", context.DeadlineExceeded)
		}
		s.mu.Unlock()
		if err == nil {
			err = s.wire.conn.SetWriteDeadline(op.deadline)
		}
		if err == nil {
			s.mu.Lock()
			err = s.stateErrorLocked()
			s.mu.Unlock()
		}
		if err == nil {
			err = s.wire.writeFrame(op.frame)
		}
		if err == nil && !time.Now().Before(op.deadline) {
			err = protocolError("keepalive_timeout", context.DeadlineExceeded)
		}
		if err != nil {
			err = cccamOperationError(err)
			s.shutdown(err)
		}
		op.complete <- err
		if err != nil {
			return
		}
	}
}

func (s *cccamSession) operationDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	deadline := time.Now().Add(cccamLivenessBudget)
	if s.probe != nil && s.probe.deadline.Before(deadline) {
		deadline = s.probe.deadline
	}
	if d, ok := s.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

func (s *cccamSession) readLoop() {
	defer s.loops.Done()
	var control cccamControl
	for {
		frame, err := s.wire.readFrame()
		if err == nil {
			err = s.handleFrame(&control, frame)
		}
		if err != nil {
			s.shutdown(cccamOperationError(err))
			return
		}
		select {
		case <-s.done:
			return
		default:
		}
	}
}

func (s *cccamSession) handleFrame(control *cccamControl, frame cccamFrame) error {
	if frame.Command == 1 || frame.Command == 0xfe || frame.Command == 0xff {
		return s.handleECMResponse(frame)
	}
	if frame.Flags != 0 {
		return protocolError("unsupported_protocol", nil)
	}
	switch frame.Command {
	case 7, 15:
		card, err := parseCCcamCard(frame.Payload, frame.Command == 15)
		if err != nil {
			return err
		}
		return s.addCard(card)
	case 4:
		id, err := parseCCcamRemoval(frame.Payload)
		if err != nil {
			return err
		}
		return s.removeECMCard(id)
	case 6:
		if len(frame.Payload) != 0 {
			return protocolError("unsupported_protocol", nil)
		}
		now := time.Now()
		s.mu.Lock()
		if s.probe != nil {
			// Empty frames cannot acknowledge a specific local write. Avoid
			// queuing another response behind the already-pending keepalive.
			s.mu.Unlock()
			return nil
		}
		if now.Sub(s.lastPeerReply) < cccamLivenessBudget {
			s.mu.Unlock()
			return nil
		}
		s.lastPeerReply = now
		s.mu.Unlock()
		if err := s.send(cccamOutbound{frame: cccamFrame{Command: 6}, deadline: s.operationDeadline()}); err != nil {
			return err
		}
		s.mu.Lock()
		// Backpressure must not consume the post-response echo suppression window.
		s.lastPeerReply = time.Now()
		s.mu.Unlock()
		return nil
	default:
		if frame.Command == 5 {
			s.mu.Lock()
			s.authenticated = false
			s.mu.Unlock()
		}
		reply, err := control.interpret(frame)
		if err != nil {
			return err
		}
		if reply != nil {
			if err := s.send(cccamOutbound{frame: *reply, deadline: s.operationDeadline()}); err != nil {
				return err
			}
			s.mu.Lock()
			if s.stateErrorLocked() == nil {
				s.authenticated = true
			}
			s.mu.Unlock()
		}
		return nil
	}
}

// CCcam keepalives need not be echoed. This bounds the native write, not peer
// responsiveness; the reader and ECM deadlines independently report failures.
func (s *cccamSession) KeepAlive(timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	if timeout > cccamLivenessBudget {
		timeout = cccamLivenessBudget
	}
	p := &cccamProbe{deadline: start.Add(timeout)}
	s.mu.Lock()
	if err := s.stateErrorLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	if s.probe != nil {
		s.mu.Unlock()
		return 0, protocolError("probe_busy", nil)
	}
	s.probe = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.probe == p {
			s.probe = nil
		}
		s.mu.Unlock()
	}()
	if err := s.send(cccamOutbound{frame: cccamFrame{Command: 6}, deadline: p.deadline}); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stateErrorLocked(); err != nil {
		return 0, err
	}
	s.lastPeerReply = time.Now()
	return 0, nil
}
