// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"
)

// All fields are protected by the existing session mutex. The slot is separate
// from control admission; selected is not writer ownership and advances no cipher.
type cccamECMTransaction struct {
	session                                        *cccamSession
	token                                          ecmToken
	deadline                                       time.Time
	ctx                                            context.Context
	claim                                          ecmWriterClaim
	payload                                        []byte
	changed                                        chan struct{}
	selected, writerOwned, writeDone, responseDone bool
	keys                                           ecmKeys
	err                                            error
	responseErr                                    error
}

var _ ecmTransport = (*cccamSession)(nil)
var _ ecmNativeTransaction = (*cccamECMTransaction)(nil)

func (tx *cccamECMTransaction) Lock()   { tx.session.mu.Lock() }
func (tx *cccamECMTransaction) Unlock() { tx.session.mu.Unlock() }
func (tx *cccamECMTransaction) ValidateLocked(token ecmToken, now time.Time) error {
	s := tx.session
	if s.ecmPending != tx || tx.err != nil || tx.writerOwned || token != tx.token {
		return ecmError("ecm_stale", nil)
	}
	if err := s.validateECMTokenLocked(token); err != nil {
		return err
	}
	if err := tx.ctx.Err(); err != nil {
		return nativeECMContextError(err)
	}
	if !now.Before(tx.deadline) {
		return ecmError("ecm_timeout", context.DeadlineExceeded)
	}
	return nil
}
func (tx *cccamECMTransaction) MarkWriterOwnedLocked() {
	if tx.session.ecmPending == tx && tx.err == nil {
		tx.writerOwned = true
	}
}
func (tx *cccamECMTransaction) notifyLocked() {
	select {
	case tx.changed <- struct{}{}:
	default:
	}
}
func nativeECMContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ecmError("ecm_timeout", err)
	}
	return ecmError("ecm_cancelled", err)
}
func (s *cccamSession) bindECMSession(epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErrorLocked() != nil || !s.authenticated || !s.wire.identityRetained {
		return ecmError("ecm_session_unavailable", nil)
	}
	if epoch == 0 || s.ecmEpoch != 0 {
		return ecmError("ecm_stale", nil)
	}
	s.ecmEpoch = epoch
	return nil
}
func (s *cccamSession) ecmInventory() []ecmCardRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stateErrorLocked() != nil || !s.authenticated || s.ecmEpoch == 0 {
		return nil
	}
	result := make([]ecmCardRef, 0, len(s.cards))
	for id, c := range s.cards {
		result = append(result, ecmCardRef{ID: id, Revision: s.cardRevisions[id], CAID: c.CAID, Providers: append([]uint32(nil), c.Providers...)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
func (s *cccamSession) validateECMTokenLocked(token ecmToken) error {
	if err := s.stateErrorLocked(); err != nil {
		return ecmError("ecm_session_unavailable", err)
	}
	if !s.authenticated || !s.wire.identityRetained || s.ecmEpoch == 0 {
		return ecmError("ecm_session_unavailable", nil)
	}
	if token.sessionEpoch != s.ecmEpoch || token.cardRevision == 0 || token.operationID == 0 {
		return ecmError("ecm_stale", nil)
	}
	if err := validateECMIdentity(token.profileID, token.identity); err != nil {
		return err
	}
	card, ok := s.cards[token.cardID]
	if !ok || s.cardRevisions[token.cardID] != token.cardRevision {
		return ecmError("ecm_stale", nil)
	}
	if token.route.CAID != card.CAID || token.route.Provider > ecmMaxProvider {
		return ecmError("ecm_no_route", nil)
	}
	for _, provider := range card.Providers {
		if provider == token.route.Provider {
			return nil
		}
	}
	return ecmError("ecm_no_route", nil)
}
func (s *cccamSession) wakeECMWriter() {
	select {
	case s.ecmWake <- struct{}{}:
	default:
	}
}
func (s *cccamSession) finishECMLocked(tx *cccamECMTransaction) {
	if s.ecmPending == tx {
		s.ecmPending = nil
	}
	clear(tx.payload)
	tx.payload = nil
	tx.keys = ecmKeys{}
}

func (s *cccamSession) exchangeECM(ctx context.Context, request ecmWireRequest, claim ecmWriterClaim) (ecmKeys, error) {
	if ctx == nil || claim == nil {
		return ecmKeys{}, ecmError("ecm_invalid_request", nil)
	}
	if err := ctx.Err(); err != nil {
		return ecmKeys{}, nativeECMContextError(err)
	}
	if err := validateECMRequest(request.section, request.token.route); err != nil {
		return ecmKeys{}, err
	}
	now := time.Now()
	deadline := request.deadline
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
	if err := s.validateECMTokenLocked(request.token); err != nil {
		s.mu.Unlock()
		return ecmKeys{}, err
	}
	if s.ecmPending != nil {
		s.mu.Unlock()
		return ecmKeys{}, ecmError("ecm_capacity", nil)
	}
	// The one bounded payload copy is owned before admission; caller bytes are
	// never retained or used by the asynchronous writer.
	payload, err := encodeCCcamECM(request.token.route, request.token.cardID, request.token.identity.ServiceID, request.section)
	if err != nil {
		s.mu.Unlock()
		return ecmKeys{}, err
	}
	tx := &cccamECMTransaction{session: s, token: request.token, deadline: deadline, ctx: ctx, claim: claim, payload: payload, changed: make(chan struct{}, 1)}
	s.ecmPending = tx
	s.mu.Unlock()
	s.wakeECMWriter()
	timer := time.NewTimer(max(time.Until(deadline), 0))
	defer timer.Stop()
	for {
		s.mu.Lock()
		terminal := tx.err
		ready := tx.responseDone && tx.writeDone
		if terminal == nil {
			if err := s.stateErrorLocked(); err != nil {
				terminal = ecmError("ecm_session_unavailable", err)
			} else if err := ctx.Err(); err != nil {
				terminal = nativeECMContextError(err)
			} else if !time.Now().Before(deadline) {
				terminal = ecmError("ecm_timeout", context.DeadlineExceeded)
			} else if !tx.responseDone || tx.responseErr == nil {
				terminal = s.validateECMTokenLocked(tx.token)
			}
		}
		if terminal != nil {
			tx.err = terminal
			ambiguous := tx.writerOwned && !ready
			alreadyRetiring := s.ecmRetiring
			if ambiguous {
				s.ecmRetiring = true
			}
			// A socket/control fault can precede the actual Write return. Retain
			// the slot until its writer reports, so a late write fault wins. An
			// explicit cancellation/deadline still has a bounded terminal fence.
			waitWriter := tx.writerOwned && !tx.writeDone && ctx.Err() == nil && time.Now().Before(deadline)
			if !waitWriter {
				s.finishECMLocked(tx)
			}
			s.mu.Unlock()
			if ambiguous && !alreadyRetiring {
				s.abortECM(terminal)
			}
			if !waitWriter {
				return ecmKeys{}, terminal
			}
		} else if ready {
			keys, err := tx.keys, tx.responseErr
			s.finishECMLocked(tx)
			s.mu.Unlock()
			return keys, err
		} else {
			s.mu.Unlock()
		}
		// Once shutdown is observed, a closed done channel must not spin while
		// the writer unwinds. Its own notification remains the completion gate.
		s.mu.Lock()
		done := s.done
		if s.closed {
			done = nil
		}
		s.mu.Unlock()
		select {
		case <-tx.changed:
		case <-done:
		case <-ctx.Done():
		case <-timer.C:
		}
	}
}

// Never join from a reader, writer or broker retirement callback. Stage A's
// terminal projection is deliberately retained; raw ECM causes stay private.
func (s *cccamSession) abortECM(cause error) { s.shutdown(protocolError("session_closed", cause)) }

func (s *cccamSession) writeECM(tx *cccamECMTransaction) {
	// BeginWrite locks in the forward owner/quota/broker/native order. No native
	// lock is held at this call, and no deadlines or cipher bytes have changed.
	err := tx.claim.BeginWrite(tx)
	s.mu.Lock()
	owned := tx.writerOwned
	if err == nil && (!owned || s.ecmPending != tx || s.closed || tx.err != nil) {
		err = ecmError("ecm_stale", nil)
	}
	payload := tx.payload
	if err == nil {
		tx.payload = nil
	} else {
		payload = nil
	}
	s.mu.Unlock()
	if err == nil {
		err = s.wire.conn.SetWriteDeadline(tx.deadline)
	}
	if err == nil {
		err = s.wire.writeFrame(cccamFrame{Command: 1, Payload: payload})
	}
	clear(payload)
	if err == nil && !time.Now().Before(tx.deadline) {
		err = ecmError("ecm_timeout", context.DeadlineExceeded)
	}
	s.mu.Lock()
	tx.writeDone = true
	if err != nil {
		var ee *ECMError
		if !errors.As(err, &ee) {
			err = ecmError("ecm_session_unavailable", err)
		}
		// A late write fault wins even if the reader already retained a CW/NOK.
		// The socket close inside writeFrame may also wake the reader first;
		// its generic unavailable error must not replace the actual write cause.
		var prior *ECMError
		if tx.err == nil || tx.responseDone || (errors.As(tx.err, &prior) && prior.Code == "ecm_session_unavailable") {
			tx.err = err
		}
		tx.keys = ecmKeys{}
	}
	if err != nil && owned {
		s.ecmRetiring = true
	}
	tx.notifyLocked()
	s.mu.Unlock()
	if err != nil && owned {
		s.abortECM(err)
	}
}

func (s *cccamSession) handleECMResponse(frame cccamFrame) error {
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
		return protocolError(code, nil)
	}
	// Metadata-only Stage A sessions never negotiated an ECM owner. Preserve
	// their existing unsupported-control projection, rather than relabeling it
	// as a failed ECM transaction merely because a response command arrived.
	if s.ecmEpoch == 0 {
		return fail("unsupported_protocol")
	}
	if frame.Flags != 0 {
		return fail("unsupported_protocol")
	}
	if tx == nil || !tx.writerOwned || tx.responseDone {
		return fail("invalid_frame")
	}
	if frame.Command == 1 {
		if len(frame.Payload) != 16 {
			return fail("invalid_frame")
		}
		// Decode independent material first; approved extra ENCRYPT advancement uses
		// the retained ENCODED pre-transform payload, NOT the decoded keys.
		encoded := append([]byte(nil), frame.Payload...)
		keys, err := decodeCCcamCW(s.wire.clientIdentity, tx.token.cardID, frame.Payload)
		s.wire.receive.encrypt(encoded)
		clear(encoded)
		clear(frame.Payload)
		if err != nil {
			return fail("invalid_frame")
		}
		if keys.validMask != 0 {
			keys.receivedAt = time.Now()
		}
		tx.keys = keys
		if keys.validMask == 0 {
			tx.responseErr = ecmError("ecm_rejected", nil)
		}
	} else {
		if len(frame.Payload) != 0 {
			return fail("unsupported_protocol")
		}
		if frame.Command == 0xfe {
			if s.cardRevision == math.MaxUint64 {
				return fail("inventory_limit")
			}
			s.cardRevision++
			delete(s.cards, tx.token.cardID)
			delete(s.cardRevisions, tx.token.cardID)
		}
		tx.responseErr = ecmError("ecm_rejected", nil)
	}
	tx.responseDone = true
	tx.notifyLocked()
	return nil
}

// Returns whether the untagged issued slot became ambiguous. Caller shuts down
// only AFTER releasing the native lock; no upward callbacks or I/O here.
func (s *cccamSession) invalidateECMCardLocked(id uint32) bool {
	tx := s.ecmPending
	if tx == nil || tx.token.cardID != id {
		return false
	}
	tx.err = ecmError("ecm_stale", nil)
	tx.keys = ecmKeys{}
	tx.notifyLocked()
	ambiguous := tx.writerOwned && !(tx.writeDone && tx.responseDone)
	if ambiguous {
		s.ecmRetiring = true
	}
	return ambiguous
}
func (s *cccamSession) removeECMCard(id uint32) error {
	s.mu.Lock()
	if err := s.stateErrorLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	if _, ok := s.cards[id]; !ok {
		s.mu.Unlock()
		return nil
	}
	if s.cardRevision == math.MaxUint64 {
		s.mu.Unlock()
		s.abortECM(ecmError("ecm_stale", nil))
		return protocolError("inventory_limit", nil)
	}
	s.cardRevision++
	delete(s.cards, id)
	delete(s.cardRevisions, id)
	ambiguous := s.invalidateECMCardLocked(id)
	s.mu.Unlock()
	if ambiguous {
		s.abortECM(ecmError("ecm_stale", nil))
	}
	return nil
}
