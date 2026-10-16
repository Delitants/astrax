// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"errors"
	"time"
)

// The broker owns the immutable admitted section until claim. Only the native
// writer makes its private wire copy, after the forward-order ownership fence.
type newcamdECMTransaction struct {
	session                                                *newcamdSession
	token                                                  ecmToken
	ctx                                                    context.Context
	deadline                                               time.Time
	claim                                                  ecmWriterClaim
	section                                                []byte
	changed                                                chan struct{}
	selected, writerOwned, issued, writeDone, responseDone bool
	id                                                     uint16
	command                                                byte
	keys                                                   ecmKeys
	err, responseErr                                       error
}

var _ ecmTransport = (*newcamdSession)(nil)
var _ ecmResultFence = (*newcamdSession)(nil)
var _ ecmNativeTransaction = (*newcamdECMTransaction)(nil)
var _ ecmPublicationFence = (*newcamdSession)(nil)
var _ ecmSessionFence = (*newcamdSession)(nil)

func (s *newcamdSession) validateECMSessionLocked(epoch uint64) error {
	if s.ctx == nil || s.ctx.Err() != nil || s.closed || s.ecmRetiring || !s.authenticated || s.ecmEpoch == 0 {
		return ecmSessionUnavailableError
	}
	if epoch != s.ecmEpoch {
		return ecmStaleError
	}
	return nil
}

func (s *newcamdSession) validateECMRouteLocked(route ECMRoute) error {
	if err := s.validateECMSessionLocked(s.ecmEpoch); err != nil {
		return err
	}
	if s.card == nil || s.cardID != 1 || s.cardRevision != 1 ||
		route.Provider > ecmMaxProvider || route.CAID != s.card.CAID {
		return ecmNoRouteError
	}
	for _, provider := range s.card.Providers {
		if provider == route.Provider {
			return nil
		}
	}
	return ecmNoRouteError
}

func (tx *newcamdECMTransaction) Lock()   { tx.session.mu.Lock() }
func (tx *newcamdECMTransaction) Unlock() { tx.session.mu.Unlock() }
func (tx *newcamdECMTransaction) ValidateLocked(token ecmToken, now time.Time) error {
	if tx.session.ecmPending != tx || tx.err != nil || tx.writerOwned || token != tx.token {
		return ecmError("ecm_stale", nil)
	}
	return tx.validateLocked(now)
}
func (tx *newcamdECMTransaction) validateLocked(now time.Time) error {
	if e := tx.session.validateECMTokenLocked(tx.token); e != nil {
		return e
	}
	if e := tx.ctx.Err(); e != nil {
		return nativeECMContextError(e)
	}
	if !now.Before(tx.deadline) {
		return ecmError("ecm_timeout", context.DeadlineExceeded)
	}
	return nil
}
func (tx *newcamdECMTransaction) MarkWriterOwnedLocked() {
	if tx.session.ecmPending == tx && tx.err == nil {
		tx.writerOwned = true
	}
}
func (tx *newcamdECMTransaction) notifyLocked() {
	select {
	case tx.changed <- struct{}{}:
	default:
	}
}
func (s *newcamdSession) bindECMSession(epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErrorLocked() != nil || !s.authenticated || s.ecmRetiring {
		return ecmError("ecm_session_unavailable", nil)
	}
	if epoch == 0 || s.ecmEpoch != 0 {
		return ecmError("ecm_stale", nil)
	}
	s.ecmEpoch = epoch
	return nil
}
func (s *newcamdSession) ecmInventory() []ecmCardRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErrorLocked() != nil || !s.authenticated || s.ecmRetiring || s.ecmEpoch == 0 || s.card == nil {
		return nil
	}
	return []ecmCardRef{{ID: s.cardID, Revision: s.cardRevision, CAID: s.card.CAID, Providers: append([]uint32(nil), s.card.Providers...)}}
}
func (s *newcamdSession) validateECMTokenLocked(t ecmToken) error {
	if e := s.stateErrorLocked(); e != nil {
		return ecmError("ecm_session_unavailable", e)
	}
	if !s.authenticated || s.ecmRetiring || s.ecmEpoch == 0 {
		return ecmError("ecm_session_unavailable", nil)
	}
	if t.sessionEpoch != s.ecmEpoch || t.operationID == 0 || t.cardID != 1 || t.cardRevision != 1 || s.card == nil || s.cardID != t.cardID || s.cardRevision != t.cardRevision {
		return ecmError("ecm_stale", nil)
	}
	if e := validateECMIdentity(t.profileID, t.identity); e != nil {
		return e
	}
	if t.route.CAID != s.card.CAID || t.route.Provider > ecmMaxProvider {
		return ecmError("ecm_no_route", nil)
	}
	for _, p := range s.card.Providers {
		if p == t.route.Provider {
			return nil
		}
	}
	return ecmError("ecm_no_route", nil)
}
func (s *newcamdSession) lockECMResults()   { s.mu.Lock() }
func (s *newcamdSession) unlockECMResults() { s.mu.Unlock() }
func (s *newcamdSession) validateECMResultLocked(t ecmToken) error {
	if err := s.validateECMSessionLocked(t.sessionEpoch); err != nil {
		return err
	}
	if t.operationID == 0 || t.cardID != 1 || t.cardRevision != 1 ||
		s.card == nil || s.cardID != t.cardID || s.cardRevision != t.cardRevision {
		return ecmStaleError
	}
	if len(t.profileID) > ecmMaxIDBytes || len(t.identity.InputID) > ecmMaxIDBytes {
		return ecmInvalidRequestError
	}
	if t.route.Provider > ecmMaxProvider || t.route.CAID != s.card.CAID {
		return ecmNoRouteError
	}
	for _, provider := range s.card.Providers {
		if provider == t.route.Provider {
			return nil
		}
	}
	return ecmNoRouteError
}
func (s *newcamdSession) finishECMLocked(tx *newcamdECMTransaction) {
	if s.ecmPending == tx {
		s.ecmPending = nil
	}
	tx.section = nil
	tx.keys = ecmKeys{}
}
func (s *newcamdSession) exchangeECM(ctx context.Context, q ecmWireRequest, claim ecmWriterClaim) (ecmKeys, error) {
	if ctx == nil || claim == nil {
		return ecmKeys{}, ecmError("ecm_invalid_request", nil)
	}
	if e := ctx.Err(); e != nil {
		return ecmKeys{}, nativeECMContextError(e)
	}
	if e := validateECMRequest(q.section, q.token.route); e != nil {
		return ecmKeys{}, e
	}
	now := time.Now()
	deadline := q.deadline
	if limit := now.Add(ecmOperationLifetime); limit.Before(deadline) {
		deadline = limit
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if d, ok := s.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if !now.Before(deadline) {
		return ecmKeys{}, ecmError("ecm_timeout", context.DeadlineExceeded)
	}
	s.mu.Lock()
	if e := s.validateECMTokenLocked(q.token); e != nil {
		s.mu.Unlock()
		return ecmKeys{}, e
	}
	if s.ecmPending != nil {
		s.mu.Unlock()
		return ecmKeys{}, ecmError("ecm_capacity", nil)
	}
	tx := &newcamdECMTransaction{session: s, token: q.token, ctx: ctx, deadline: deadline, claim: claim, section: q.section, command: q.section[0], changed: make(chan struct{}, 1)}
	s.ecmPending = tx
	s.mu.Unlock()
	s.wakeWriter()
	timer := time.NewTimer(max(time.Until(deadline), 0))
	defer timer.Stop()
	for {
		s.mu.Lock()
		now = time.Now()
		terminal := tx.err
		ready := tx.writeDone && tx.responseDone
		wakeDeadline := deadline
		if terminal == nil {
			if e := ctx.Err(); e != nil {
				terminal = nativeECMContextError(e)
			} else if !now.Before(deadline) {
				terminal = ecmError("ecm_timeout", context.DeadlineExceeded)
			} else {
				terminal = s.validateECMTokenLocked(tx.token)
			}
			if terminal == nil && !tx.keys.receivedAt.IsZero() {
				expires := tx.keys.receivedAt.Add(ecmResultLifetime)
				if !now.Before(expires) {
					terminal = ecmError("ecm_stale", nil)
				}
				if expires.Before(wakeDeadline) {
					wakeDeadline = expires
				}
			}
		}
		if terminal != nil {
			tx.err = terminal
			tx.keys = ecmKeys{}
			owned := tx.writerOwned
			alreadyRetiring := s.ecmRetiring
			if owned {
				s.ecmRetiring = true
			}
			// Socket retirement can precede Write's return. Preserve that completion
			// gate for a late write error, but never wait past caller/receipt expiry.
			var ee *ECMError
			waitWriter := owned && !tx.writeDone && ctx.Err() == nil && now.Before(wakeDeadline) && errors.As(terminal, &ee) && (ee.Code == "ecm_session_unavailable" || ee.Code == "ecm_invalid_response")
			if !waitWriter {
				s.finishECMLocked(tx)
			}
			s.mu.Unlock()
			if owned && !alreadyRetiring {
				s.abortECM(terminal)
			}
			if !waitWriter {
				return ecmKeys{}, terminal
			}
		} else if ready {
			keys, e := tx.keys, tx.responseErr
			s.finishECMLocked(tx)
			s.mu.Unlock()
			return keys, e
		} else {
			s.mu.Unlock()
		}
		s.mu.Lock()
		done := s.done
		if s.closed {
			done = nil
		}
		s.mu.Unlock()
		timer.Reset(max(time.Until(wakeDeadline), 0))
		select {
		case <-tx.changed:
		case <-done:
		case <-ctx.Done():
		case <-timer.C:
		}
	}
}
func (s *newcamdSession) abortECM(cause error) { s.shutdown(newcamdError("session_closed", cause)) }
func (s *newcamdSession) writeECM(tx *newcamdECMTransaction) {
	e := tx.claim.BeginWrite(tx)
	s.mu.Lock()
	owned := tx.writerOwned
	if e == nil && (!owned || s.ecmPending != tx || tx.err != nil) {
		e = ecmError("ecm_stale", nil)
	}
	if e == nil {
		e = tx.validateLocked(time.Now())
	}
	var frame newcamdFrame
	if e == nil {
		tx.id, e = s.nextIDLocked()
	}
	if e == nil {
		frame = newcamdFrame{MessageID: tx.id, ServiceID: tx.token.identity.ServiceID, Payload: append([]byte(nil), tx.section...)}
		tx.section = nil
	}
	s.mu.Unlock()
	if e == nil {
		e = s.writeFrame(frame, tx.deadline)
	}
	clear(frame.Payload)
	s.mu.Lock()
	tx.writeDone = true
	if e != nil {
		var ee *ECMError
		if !errors.As(e, &ee) {
			e = ecmError("ecm_session_unavailable", e)
		}
		var prior *ECMError
		if tx.err == nil || (errors.As(tx.err, &prior) && prior.Code == "ecm_session_unavailable") {
			tx.err = e
		}
		tx.keys = ecmKeys{}
		if owned {
			s.ecmRetiring = true
		}
	}
	tx.notifyLocked()
	s.mu.Unlock()
	if e != nil && owned {
		s.abortECM(e)
	}
}
func (s *newcamdSession) handleECMResponse(f newcamdFrame) error {
	defer clear(f.Payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx := s.ecmPending
	fail := func(code string) error {
		s.ecmRetiring = true
		if tx != nil {
			tx.err = ecmError("ecm_invalid_response", nil)
			tx.keys = ecmKeys{}
			tx.notifyLocked()
		}
		return newcamdError(code, nil)
	}
	if s.ecmEpoch == 0 {
		return fail("unsupported_protocol")
	}
	if f.Reserved != ([6]byte{}) {
		return fail("unsupported_protocol")
	}
	if s.stateErrorLocked() != nil || tx == nil || !tx.writerOwned || !tx.issued || tx.responseDone || tx.err != nil || f.MessageID != tx.id || len(f.Payload) < 3 || f.Payload[0] != tx.command {
		return fail("invalid_frame")
	}
	if len(f.Payload) != 3 && len(f.Payload) != 19 {
		return fail("invalid_frame")
	}
	if e := tx.validateLocked(time.Now()); e != nil {
		tx.err = e
		tx.notifyLocked()
		s.ecmRetiring = true
		return newcamdError("session_closed", e)
	}
	if len(f.Payload) == 19 {
		copy(tx.keys.material[:], f.Payload[3:])
		for _, b := range tx.keys.material[:8] {
			if b != 0 {
				tx.keys.validMask |= 1
				break
			}
		}
		for _, b := range tx.keys.material[8:] {
			if b != 0 {
				tx.keys.validMask |= 2
				break
			}
		}
		if tx.keys.validMask != 0 {
			tx.keys.receivedAt = time.Now()
		}
	}
	if tx.keys.validMask == 0 {
		tx.keys = ecmKeys{}
		tx.responseErr = ecmError("ecm_rejected", nil)
	}
	tx.responseDone = true
	tx.notifyLocked()
	return nil
}
