// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/streamer"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

type dvbReconcileAction string

const (
	dvbReconcileStart   dvbReconcileAction = "start"
	dvbReconcileRefresh dvbReconcileAction = "refresh"
	dvbReconcileStop    dvbReconcileAction = "stop"
	dvbReconcileNoop    dvbReconcileAction = "noop"
	dvbReconcileError   dvbReconcileAction = "error"
)

type dvbReconcileResult struct {
	StreamID   string
	InputIndex int
	Action     dvbReconcileAction
	OnDemand   *dvbOnDemandResult
	Err        error
}
type dvbOnDemandState string

const (
	dvbOnDemandAbsent      dvbOnDemandState = "absent"
	dvbOnDemandPlaceholder dvbOnDemandState = "placeholder"
	dvbOnDemandActive      dvbOnDemandState = "active"
)

type dvbOnDemandResult struct {
	State       dvbOnDemandState
	Placeholder *sinkRegistrationToken
}

func prepareDVBStream(input model.Stream) (model.Stream, error) {
	return prepareDVBStreamChecked(input, false)
}
func prepareDVBStreamChecked(input model.Stream, descramblingHookup bool) (model.Stream, error) {
	st := cloneStream(input)
	if err := validStreamID(st.ID); err != nil {
		return st, err
	}
	if st.DVB == nil {
		return st, errors.New("structured DVB configuration is required")
	}
	if err := descramblingRuntimeGate(st); err != nil && !descramblingHookup {
		return st, err
	}
	st.DVB.Normalize()
	if err := dvb.ValidateStreamForLinux(*st.DVB); err != nil {
		return st, err
	}
	if _, err := servicePIDs(st); err != nil {
		return st, err
	}
	if strings.TrimSpace(st.OutputURL) == "" {
		return st, errors.New("output URL is required")
	}
	if _, err := streamer.ValidateOutputPath(st.OutputURL); err != nil {
		return st, err
	}
	return st, nil
}
func placementPolicy(st model.Stream) model.DVBAdapterPolicy {
	p := st.DVB.Adapter
	if p.Mode == "auto" {
		p.DeviceKey = ""
		p.LastAddress = ""
	}
	if p.Mode == "fixed" && p.DeviceKey != "" && !strings.HasPrefix(p.DeviceKey, "address:") {
		p.LastAddress = ""
	}
	if strings.HasPrefix(p.DeviceKey, "address:") {
		p.LastAddress = strings.TrimPrefix(p.DeviceKey, "address:")
		p.DeviceKey = ""
	}
	return p
}
func pipelineFingerprint(st model.Stream) tuningKey {
	pids, _ := servicePIDs(st)
	var set [1024]byte
	for _, pid := range pids {
		set[pid/8] |= 1 << uint(pid%8)
	}
	value := struct {
		ServiceID                        int
		PIDs                             [1024]byte
		Output, Protocol, Softcam, XMLTV string
		Scrambled, OnDemand              bool
		CAIDs                            []int
		Timeout                          int
		Descrambling                     *model.DVBDescramblingConfig `json:",omitempty"`
	}{st.DVB.ServiceID, set, strings.TrimSpace(st.OutputURL), strings.ToLower(strings.TrimSpace(st.Protocol)),
		st.SoftcamID, st.XMLTVChannelID, st.Scrambled, st.OnDemand, st.CAIDs, st.OnDemandTimeoutSec, st.DVBDescrambling}
	encoded, _ := json.Marshal(value)
	return sha256.Sum256(encoded)
}
func absentOnDemand() dvbOnDemandResult { return dvbOnDemandResult{State: dvbOnDemandAbsent} }
func placeholderOnDemand(token *sinkRegistrationToken) dvbOnDemandResult {
	if token == nil {
		return absentOnDemand()
	}
	copy := *token
	return dvbOnDemandResult{State: dvbOnDemandPlaceholder, Placeholder: &copy}
}
func (s *dvbScheduler) stateLocked(id string, placeholder *sinkRegistrationToken) dvbOnDemandResult {
	if s.attachments[id] != nil {
		return dvbOnDemandResult{State: dvbOnDemandActive}
	}
	return placeholderOnDemand(placeholder)
}
func (s *dvbScheduler) startCheckLocked(id string) error {
	if s.descramblingPreparing {
		return schedulerError(ErrDVBSchedulerOwnership, "descrambling resources are being installed")
	}
	if s.health != nil {
		return s.health
	}
	if s.isClosing() {
		return ErrDVBSchedulerClosed
	}
	if a := s.attachments[id]; a != nil {
		if !s.attachmentCoherentLocked(a) {
			return s.latchCorruptLocked(errors.New("requested attachment indexes disagree"))
		}
		return schedulerError(ErrDVBSchedulerOwnership, "stream already has an active attachment")
	}
	if s.streamSessions[id] != "" {
		return s.latchCorruptLocked(errors.New("requested stream reverse index has no attachment"))
	}
	return nil
}
func (s *dvbScheduler) Start(input model.Stream) error {
	end, err := s.begin(input.ID)
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	err = s.startCheckLocked(input.ID)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if input.OnDemand {
		return schedulerError(ErrDVBSchedulerOwnership, "use StartOnDemand with an exact placeholder")
	}
	st, err := s.prepareStream(input)
	if err != nil {
		return err
	}
	_, err = s.startPrepared(st, nil, nil)
	return err
}

// StartOnDemand requires Store's exact current, reservation-bound placeholder.
// A failed conforming call echoes that token; a stale-token error is not a query
// for a newer unknown sink generation and never authorizes ID-only removal.
func (s *dvbScheduler) StartOnDemand(input model.Stream, token sinkRegistrationToken) (dvbOnDemandResult, error) {
	result := absentOnDemand()
	if input.OnDemand && token.StreamID == input.ID && token.Generation != 0 {
		result = placeholderOnDemand(&token)
	}
	end, err := s.begin(input.ID)
	if err != nil {
		return s.resultingState(input.ID, result.Placeholder), err
	}
	defer end()
	s.mu.Lock()
	result = s.stateLocked(input.ID, result.Placeholder)
	err = s.startCheckLocked(input.ID)
	s.mu.Unlock()
	if err != nil {
		return result, err
	}
	if !input.OnDemand || token.StreamID != input.ID || token.Generation == 0 {
		return absentOnDemand(), schedulerError(ErrDVBSchedulerOwnership, "exact on-demand placeholder token required")
	}
	st, err := s.prepareStream(input)
	if err != nil {
		return result, err
	}
	return s.startPrepared(st, &token, nil)
}
func (s *dvbScheduler) sessionValidLocked(session *tuningSession) bool {
	if session == nil || session.runtime == nil {
		return false
	}
	r := session.runtime
	card, ok := s.cards[session.cardID]
	physical, present := canonicalPhysicalFrontendKey(card)
	return r.inputGeneration != 0 && r.inputGeneration == r.generation &&
		ok && present && physical == r.physical && s.cardRevisions[session.cardID] == r.cardRevision &&
		s.ownedSessions[session.id] == session && s.physicalReservations[r.physical] == session && !r.closing
}
func (s *dvbScheduler) operationValidLocked(session *tuningSession, id string, generation uint64) error {
	if s.health != nil {
		return s.health
	}
	if s.isClosing() {
		return ErrDVBSchedulerClosed
	}
	reservation := s.streamReservations[id]
	if lease := reservation.recoveryLease; lease != nil {
		if lease.admissionEpoch != reservation.recoveryEpoch || s.cardOperationCurrentLocked(lease) != nil {
			return ErrDVBSchedulerSuperseded
		}
	}
	_, epoch := s.desiredCardLocked(session.cardID)
	if reservation.admissionEpoch != epoch || s.cardAdmissionReasonLocked(session.card) != "" {
		return ErrDVBSchedulerSuperseded
	}
	if reservation.generation != generation || reservation.session != session || !s.sessionValidLocked(session) {
		return ErrDVBSchedulerSuperseded
	}
	return nil
}

func (s *dvbScheduler) newStreamReservationLocked(session *tuningSession, id string, generation uint64) dvbStreamReservation {
	_, epoch := s.desiredCardLocked(session.cardID)
	reservation := dvbStreamReservation{session: session, generation: generation, admissionEpoch: epoch}
	// Gate-held permissions are retired before Store stream-gate handoff, so
	// only the executing restart can authorize this stream, not a predecessor.
	for _, lease := range s.cardOperations {
		_, relocating := lease.relocations[id]
		if lease.recovery[id] || relocating {
			reservation.recoveryLease = lease
			reservation.recoveryEpoch = lease.admissionEpoch
			break
		}
	}
	return reservation
}
func (s *dvbScheduler) wakeSessionLocked(session *tuningSession) {
	r := session.runtime
	close(r.changed)
	r.changed = make(chan struct{})
}
func (s *dvbScheduler) waitingSessionLocked(st model.Stream) *tuningSession {
	ids := s.cardOrder
	if st.DVB.Adapter.Mode == "fixed" {
		card, err := s.fixedTargetLocked(st.DVB.Adapter)
		if err != nil {
			return nil
		}
		ids = []string{card.ID}
	}
	for _, id := range ids {
		if s.counters != nil {
			s.counters.CardCandidates++
		}
		card := s.cards[id]
		physical, ok := canonicalPhysicalFrontendKey(card)
		if !ok || s.cardOperationBlockedLocked(card, st.ID) {
			continue
		}
		session := s.physicalReservations[physical]
		if session == nil {
			continue
		}
		r := session.runtime
		if r == nil {
			continue
		}
		resolved, err := resolveTune(st, card)
		if err == nil && canonicalTuningKey(resolved) == session.key && (r.retiring || r.closing || !r.ready || r.cardRevision != s.cardRevisions[id]) {
			return session
		}
	}
	return nil
}
func (s *dvbScheduler) reserveSession(st model.Stream) (*tuningSession, uint64, bool, error) {
	for {
		s.mu.Lock()
		if err := s.startCheckLocked(st.ID); err != nil {
			s.mu.Unlock()
			return nil, 0, false, err
		}
		choice, err := s.selectCardLocked(st, tuningKey{})
		if err != nil || !choice.shared {
			if pending := s.waitingSessionLocked(st); pending != nil {
				wake := pending.runtime.changed
				s.mu.Unlock()
				select {
				case <-wake:
					continue
				case <-s.lifecycle.stopping:
					return nil, 0, false, ErrDVBSchedulerClosed
				}
			}
		}
		if err != nil {
			s.mu.Unlock()
			return nil, 0, false, err
		}
		if s.generation == ^uint64(0) {
			s.mu.Unlock()
			return nil, 0, false, schedulerError(ErrDVBSchedulerOwnership, "generation space exhausted")
		}
		s.generation++
		generation := s.generation
		if choice.shared {
			session := s.sessions[choice.sessionID]
			if !s.sessionValidLocked(session) {
				delete(s.streamReservations, st.ID)
				s.mu.Unlock()
				return nil, 0, false, ErrDVBSchedulerSuperseded
			}
			session.runtime.pending++
			s.streamReservations[st.ID] = s.newStreamReservationLocked(session, st.ID, generation)
			s.mu.Unlock()
			return session, generation, false, nil
		}
		physical, _ := canonicalPhysicalFrontendKey(choice.card)
		if s.physicalReservations[physical] != nil {
			delete(s.streamReservations, st.ID)
			s.mu.Unlock()
			return nil, 0, false, ErrDVBSchedulerSuperseded
		}
		ctx, cancel := context.WithCancel(context.Background())
		r := &dvbSessionRuntime{generation: generation, inputGeneration: generation, cardRevision: s.cardRevisions[choice.card.ID], physical: physical, pending: 1,
			attachments: make(map[string]*streamAttachment), changed: make(chan struct{}), ctx: ctx, cancel: cancel, transport: cloneDVBStreamConfig(st.DVB)}
		r.workCond = sync.NewCond(&r.workMu)
		session := &tuningSession{id: fmt.Sprintf("dvb-session-%d", generation), key: choice.key, cardID: choice.card.ID, card: cloneDVBCard(choice.card),
			config: choice.config, streamIDs: make(map[string]struct{}), runtime: r}
		s.streamReservations[st.ID] = s.newStreamReservationLocked(session, st.ID, generation)
		s.ownedSessions[session.id] = session
		s.physicalReservations[physical] = session
		s.reservations[choice.card.ID] = cardReservation{key: choice.key, generation: generation}
		if s.counters != nil {
			s.counters.TargetedMutations++
		}
		s.mu.Unlock()
		return session, generation, true, nil
	}
}
func (s *dvbScheduler) publishSessionLocked(session *tuningSession) {
	r := session.runtime
	r.ready = true
	session.healthy = true
	s.sessions[session.id] = session
	s.sessionByCard[session.cardID] = session.id
	s.sessionByPhysical[r.physical] = session
	if s.sessionsByKey[session.key] == nil {
		s.sessionsByKey[session.key] = make(map[string]struct{})
	}
	s.sessionsByKey[session.key][session.id] = struct{}{}
	ids := s.sessionOrderByKey[session.key]
	at := len(ids)
	for i, id := range ids {
		if s.counters != nil {
			s.counters.ExactBucketVisits++
			s.counters.Comparisons++
		}
		if compareDVBCardDefault(session.card, s.sessions[id].card) < 0 {
			at = i
			break
		}
	}
	ids = append(ids, "")
	copy(ids[at+1:], ids[at:])
	ids[at] = session.id
	s.sessionOrderByKey[session.key] = ids
	if reservation, ok := s.reservations[session.cardID]; ok && reservation.generation == r.generation {
		delete(s.reservations, session.cardID)
	}
	s.wakeSessionLocked(session)
}
func (s *dvbScheduler) openReserved(session *tuningSession, id string, generation uint64) error {
	if s.opener == nil || s.sink == nil {
		return schedulerError(ErrDVBSchedulerBackend, "runtime dependencies are unavailable")
	}
	s.lockStreamPublication(session, id, generation)
	err := s.operationValidLocked(session, id, generation)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	frontend, err := s.opener.OpenSession(session.config)
	if nilDVBSession(frontend) {
		frontend = nil
	}
	s.lockStreamPublication(session, id, generation)
	session.runtime.frontend = frontend
	valid := s.operationValidLocked(session, id, generation)
	s.mu.Unlock()
	if err != nil {
		return schedulerWrap(ErrDVBSchedulerBackend, err)
	}
	if frontend == nil {
		return schedulerError(ErrDVBSchedulerBackend, "opener returned nil session")
	}
	if valid != nil {
		return valid
	}
	inner, err := frontend.OpenDemux(0, 0, 0)
	if err != nil {
		var cleanupErr error
		if !nilPacketSource(inner) {
			cleanupErr = s.closeTemporaryDemux(inner)
		}
		return errors.Join(schedulerWrap(ErrDVBSchedulerBackend, err), cleanupErr)
	}
	if nilPacketSource(inner) {
		return schedulerError(ErrDVBSchedulerBackend, "OpenDemux returned nil")
	}
	s.lockStreamPublication(session, id, generation)
	valid = s.operationValidLocked(session, id, generation)
	s.mu.Unlock()
	if valid != nil {
		return errors.Join(valid, s.closeTemporaryDemux(inner))
	}
	deps := processSharedDemuxDependencies
	if s.packetBudget != nil {
		deps = &sharedDemuxDependencies{packets: s.packetBudget, memberships: deps.memberships}
	}
	demux, err := newSharedDemuxInternal(inner, deps)
	if err != nil {
		return errors.Join(schedulerWrap(ErrDVBSchedulerBackend, err), s.closeTemporaryDemux(inner))
	}
	s.lockStreamPublication(session, id, generation)
	session.runtime.demux = demux
	session.runtime.catalog = demux.catalog
	valid = s.operationValidLocked(session, id, generation)
	if valid == nil {
		s.publishSessionLocked(session)
	}
	s.mu.Unlock()
	return valid
}

// This reader never entered the owned shared demux. Consume it before the
// admitted setup returns, and let concurrent Close observe terminal errors only.
func (s *dvbScheduler) closeTemporaryDemux(inner dvb.DemuxReader) error {
	err := schedulerWrap(ErrDVBSchedulerBackend, inner.Close())
	s.mu.Lock()
	s.recordClosingCleanupLocked(err)
	s.mu.Unlock()
	return err
}
func (s *dvbScheduler) startPrepared(st model.Stream, expected *sinkRegistrationToken, held *tuningSession) (dvbOnDemandResult, error) {
	result := placeholderOnDemand(expected)
	if err := s.descramblingAdmissionError(st); err != nil {
		if held != nil {
			err = errors.Join(err, s.releasePending(held, st.ID, 0))
		}
		return result, err
	}
	var session *tuningSession
	var generation uint64
	var created bool
	var err error
	if held == nil {
		session, generation, created, err = s.reserveSession(st)
	} else {
		session = held
		s.mu.Lock()
		reservation := s.streamReservations[st.ID]
		generation = reservation.generation
		if reservation.session != held || generation == 0 {
			s.mu.Unlock()
			return result, errors.Join(ErrDVBSchedulerSuperseded, s.releasePending(held, st.ID, 0))
		}
		s.mu.Unlock()
	}
	if err != nil {
		return result, err
	}
	finish := func(cause error) (dvbOnDemandResult, error) {
		return result, errors.Join(cause, s.releasePending(session, st.ID, generation))
	}
	if created {
		if err := s.openReserved(session, st.ID, generation); err != nil {
			return finish(err)
		}
	}
	s.lockStreamPublication(session, st.ID, generation)
	err = s.operationValidLocked(session, st.ID, generation)
	s.mu.Unlock()
	if err != nil {
		return finish(err)
	}
	pids, err := servicePIDs(st)
	if err != nil {
		return finish(err)
	}
	subscription := fmt.Sprintf("%s@%d", st.ID, generation)
	source, err := session.runtime.demux.RegisterStream(subscription, pids)
	if err != nil {
		return finish(schedulerWrap(ErrDVBSchedulerBackend, err))
	}
	base, ok := source.(*streamPacketSource)
	if !ok || base == nil {
		return finish(errors.Join(ErrDVBSchedulerOwnership, source.Close()))
	}
	output := source
	if descramblingEnabled(st) {
		output, err = s.newDescramblingSource(session, base, st)
		if err != nil {
			return finish(errors.Join(err, base.Close()))
		}
	}
	s.lockStreamPublication(session, st.ID, generation)
	err = s.operationValidLocked(session, st.ID, generation)
	s.mu.Unlock()
	if err != nil {
		return finish(errors.Join(err, output.Close()))
	}
	token, err := s.sink.RegisterStream(st, output, expected)
	if err != nil {
		return finish(errors.Join(schedulerWrap(ErrDVBSchedulerSink, err), output.Close()))
	}
	s.lockStreamPublication(session, st.ID, generation)
	err = s.operationValidLocked(session, st.ID, generation)
	if token.StreamID != st.ID || token.Generation == 0 {
		err = s.latchCorruptLocked(errors.New("sink returned invalid active token"))
	}
	if err == nil {
		a := &streamAttachment{id: st.ID, generation: generation, session: session, stream: cloneStream(st), pipeline: pipelineFingerprint(st),
			policy: placementPolicy(st), subscription: subscription, sinkToken: token, source: source, baseSource: base, outputSource: output}
		s.attachments[st.ID] = a
		s.streamSessions[st.ID] = session.id
		session.streamIDs[st.ID] = struct{}{}
		session.runtime.attachments[st.ID] = a
		s.subscriptions[subscription] = a
		s.sinkTokens[token] = a
		session.runtime.pending--
		session.runtime.retiring = false
		session.healthy = true
		delete(s.streamReservations, st.ID)
		s.wakeSessionLocked(session)
		if s.counters != nil {
			s.counters.TargetedMutations++
		}
		s.mu.Unlock()
		return dvbOnDemandResult{State: dvbOnDemandActive}, nil
	}
	s.mu.Unlock()
	// Successful checked registration transferred the source; only the exact token may roll back.
	mode := sinkDetachRemove
	if expected != nil {
		mode = sinkDetachPreservePlaceholder
	}
	next, detachErr := s.detachSink(token, mode)
	result = placeholderOnDemand(next)
	s.mu.Lock()
	s.recordClosingCleanupLocked(detachErr)
	s.mu.Unlock()
	return finish(errors.Join(err, detachErr))
}

// With exact owned tokens, valid modes and the required sink lifetime, checked
// cleanup consumes the active pipeline even on post-transition errors. Preserve
// allocation can fail before transition; exact Remove needs no new generation.
// A nonnil returned token is authoritative even with a cleanup error. Arbitrary
// pre-transition lifetime/token failures do not establish any discoverable state.
func (s *dvbScheduler) detachSink(token sinkRegistrationToken, mode sinkDetachMode) (*sinkRegistrationToken, error) {
	next, err := s.sink.UnregisterStream(token, mode)
	if err != nil && next == nil {
		err = errors.Join(err, s.sink.RemoveStream(token))
	}
	return next, schedulerWrap(ErrDVBSchedulerSink, err)
}
func (s *dvbScheduler) recordClosingCleanupLocked(err error) {
	if err != nil && s.isClosing() {
		s.closingCleanupErrors = append(s.closingCleanupErrors, err)
	}
}
func (s *dvbScheduler) claimCloseLocked(session *tuningSession) bool {
	r := session.runtime
	if r.closing || r.pending != 0 || len(r.attachments) != 0 {
		return false
	}
	r.closing = true
	r.publicationRefs++
	r.retiring = true
	session.healthy = false
	s.wakeSessionLocked(session)
	return true
}
func (s *dvbScheduler) releasePending(session *tuningSession, id string, generation uint64) error {
	s.mu.Lock()
	r := session.runtime
	r.pending--
	reservation := s.streamReservations[id]
	if reservation.session == session && (generation == 0 || reservation.generation == generation) {
		delete(s.streamReservations, id)
	}
	closeOwned := s.claimCloseLocked(session)
	s.mu.Unlock()
	if closeOwned {
		return s.closeOwnedSession(session, nil)
	}
	return nil
}
func (s *dvbScheduler) eraseAttachmentLocked(a *streamAttachment) {
	session := a.session
	r := session.runtime
	if s.attachments[a.id] == a {
		delete(s.attachments, a.id)
	}
	if s.streamSessions[a.id] == session.id {
		delete(s.streamSessions, a.id)
	}
	if r.attachments[a.id] == a {
		delete(r.attachments, a.id)
		delete(session.streamIDs, a.id)
	}
	if s.subscriptions[a.subscription] == a {
		delete(s.subscriptions, a.subscription)
	}
	if s.sinkTokens[a.sinkToken] == a {
		delete(s.sinkTokens, a.sinkToken)
	}
	if s.counters != nil {
		s.counters.TargetedMutations++
		s.counters.AttachmentVisits++
	}
}
func (s *dvbScheduler) detach(id string, mode sinkDetachMode) (dvbOnDemandResult, error) {
	s.mu.Lock()
	a := s.attachments[id]
	if a == nil {
		if _, exists := s.attachments[id]; exists || s.streamSessions[id] != "" {
			err := s.latchCorruptLocked(errors.New("requested stop reverse index mismatch"))
			s.mu.Unlock()
			return absentOnDemand(), err
		}
		s.mu.Unlock()
		return absentOnDemand(), nil
	}
	if !s.attachmentCoherentLocked(a) {
		err := s.latchCorruptLocked(errors.New("requested stop ownership mismatch"))
		s.mu.Unlock()
		return dvbOnDemandResult{State: dvbOnDemandActive}, err
	}
	session := a.session
	r := session.runtime
	if mode == sinkDetachPreservePlaceholder && !a.stream.OnDemand {
		s.mu.Unlock()
		return dvbOnDemandResult{State: dvbOnDemandActive}, schedulerError(ErrDVBSchedulerOwnership, "active stream is not on-demand")
	}
	a.retiring = true
	if len(r.attachments) == 1 {
		r.retiring = true
		session.healthy = false
	}
	last := len(r.attachments) == 1
	stopWorkers := last && r.pending == 0
	r.publicationRefs++
	s.mu.Unlock()
	if last {
		waitSessionCalls(session, stopWorkers)
	}
	r.publicationMu.Lock()
	next, err := s.detachSink(a.sinkToken, mode)
	s.mu.Lock()
	s.recordClosingCleanupLocked(err)
	s.eraseAttachmentLocked(a)
	closeOwned := s.claimCloseLocked(session)
	r.publicationRefs--
	s.mu.Unlock()
	r.publicationMu.Unlock()
	if closeOwned {
		err = errors.Join(err, s.closeOwnedSession(session, nil))
	}
	return placeholderOnDemand(next), err
}
func (s *dvbScheduler) Stop(id string) error {
	end, err := s.begin(id)
	if err != nil {
		return err
	}
	defer end()
	if err := validStreamID(id); err != nil {
		return err
	}
	_, err = s.detach(id, sinkDetachRemove)
	return err
}
func (s *dvbScheduler) SuspendOnDemand(id string) (dvbOnDemandResult, error) {
	end, err := s.begin(id)
	if err != nil {
		return s.resultingState(id, nil), err
	}
	defer end()
	s.mu.Lock()
	a := s.attachments[id]
	s.mu.Unlock()
	if a == nil {
		return absentOnDemand(), schedulerError(ErrDVBSchedulerOwnership, "on-demand suspend is active-only")
	}
	return s.detach(id, sinkDetachPreservePlaceholder)
}
func (s *dvbScheduler) replacePrepared(st model.Stream, force bool) (dvbReconcileAction, dvbOnDemandResult, error) {
	s.mu.Lock()
	if s.health != nil {
		err := s.health
		result := s.stateLocked(st.ID, nil)
		s.mu.Unlock()
		return dvbReconcileError, result, err
	}
	old := s.attachments[st.ID]
	if old == nil {
		s.mu.Unlock()
		r, err := s.startPrepared(st, nil, nil)
		return dvbReconcileStart, r, err
	}
	if !s.attachmentCoherentLocked(old) {
		err := s.latchCorruptLocked(errors.New("replace ownership mismatch"))
		s.mu.Unlock()
		return dvbReconcileError, dvbOnDemandResult{State: dvbOnDemandActive}, err
	}
	resolved, err := resolveTune(st, s.cards[old.session.cardID])
	same := err == nil && canonicalTuningKey(resolved) == old.session.key && placementPolicy(st) == old.policy
	if !force && same && pipelineFingerprint(st) == old.pipeline {
		s.mu.Unlock()
		return dvbReconcileNoop, dvbOnDemandResult{State: dvbOnDemandActive}, nil
	}
	if reason := s.cardAdmissionReasonLocked(s.cards[old.session.cardID]); reason != "" {
		s.mu.Unlock()
		return dvbReconcileError, dvbOnDemandResult{State: dvbOnDemandActive}, fixedCardConflict(old.session.card, reason, "")
	}
	var held *tuningSession
	if same {
		if s.generation == ^uint64(0) {
			s.mu.Unlock()
			return dvbReconcileError, dvbOnDemandResult{State: dvbOnDemandActive}, schedulerError(ErrDVBSchedulerOwnership, "generation space exhausted")
		}
		s.generation++
		held = old.session
		held.runtime.pending++
		s.streamReservations[st.ID] = s.newStreamReservationLocked(held, st.ID, s.generation)
	}
	mode := sinkDetachRemove
	// Checked promotion reuses the old output resources and requires the raw URL
	// to remain identical. Changed endpoints/protocols need fresh registration;
	// the pending session reservation still preserves a pipeline-only transport.
	sameOutput := old.stream.OutputURL == st.OutputURL &&
		strings.EqualFold(strings.TrimSpace(old.stream.Protocol), strings.TrimSpace(st.Protocol))
	if old.stream.OnDemand && st.OnDemand && sameOutput {
		mode = sinkDetachPreservePlaceholder
	}
	s.mu.Unlock()
	result, err := s.detach(st.ID, mode)
	if err != nil {
		if held != nil {
			err = errors.Join(err, s.releasePending(held, st.ID, 0))
		}
		return dvbReconcileError, result, err
	}
	result, err = s.startPrepared(st, result.Placeholder, held)
	action := dvbReconcileRefresh
	if err != nil {
		action = dvbReconcileError
	}
	return action, result, err
}
func (s *dvbScheduler) Restart(input model.Stream) error {
	end, err := s.begin(input.ID)
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	health := s.health
	s.mu.Unlock()
	if health != nil {
		return health
	}
	if input.OnDemand {
		return schedulerError(ErrDVBSchedulerOwnership, "use RestartOnDemand for active on-demand streams")
	}
	st, err := s.prepareStream(input)
	if err != nil {
		return err
	}
	_, _, err = s.replacePrepared(st, true)
	return err
}
func (s *dvbScheduler) RestartOnDemand(input model.Stream) (dvbOnDemandResult, error) {
	end, err := s.begin(input.ID)
	if err != nil {
		return s.resultingState(input.ID, nil), err
	}
	defer end()
	s.mu.Lock()
	old := s.attachments[input.ID]
	health := s.health
	s.mu.Unlock()
	result := absentOnDemand()
	if old != nil {
		result = dvbOnDemandResult{State: dvbOnDemandActive}
	}
	if health != nil {
		return result, health
	}
	if old == nil {
		return result, schedulerError(ErrDVBSchedulerOwnership, "on-demand restart is active-only")
	}
	if !input.OnDemand || !old.stream.OnDemand {
		return result, schedulerError(ErrDVBSchedulerOwnership, "on-demand restart requires active on-demand ownership")
	}
	st, err := s.prepareStream(input)
	if err != nil {
		return result, err
	}
	_, result, err = s.replacePrepared(st, true)
	return result, err
}
func (s *dvbScheduler) closeOwnedSession(session *tuningSession, rescue map[*streamAttachment]sinkRegistrationToken) error {
	r := session.runtime
	waitSessionCalls(session, true)
	r.publicationMu.Lock()
	var errs []error
	if s.removePublication != nil {
		errs = append(errs, s.removePublication(session.id, r.generation))
	}
	s.mu.Lock()
	attachments := make([]*streamAttachment, 0, len(r.attachments))
	seen := make(map[*streamAttachment]bool, len(r.attachments))
	for _, a := range r.attachments {
		if a != nil && !seen[a] {
			seen[a] = true
			attachments = append(attachments, a)
		}
	}
	s.mu.Unlock()
	for _, a := range attachments {
		token := a.sinkToken
		if saved, ok := rescue[a]; ok {
			token = saved
		}
		_, err := s.detachSink(token, sinkDetachRemove)
		errs = append(errs, err)
		s.mu.Lock()
		s.eraseAttachmentLocked(a)
		s.mu.Unlock()
	}
	r.publicationMu.Unlock()
	if r.demux != nil {
		errs = append(errs, schedulerWrap(ErrDVBSchedulerBackend, r.demux.Close()))
	}
	if r.frontend != nil {
		errs = append(errs, schedulerWrap(ErrDVBSchedulerBackend, r.frontend.Close()))
	}
	s.mu.Lock()
	s.removeSessionLocked(session.id)
	if s.sessionByPhysical[r.physical] == session {
		delete(s.sessionByPhysical, r.physical)
	}
	if s.physicalReservations[r.physical] == session {
		delete(s.physicalReservations, r.physical)
	}
	if s.ownedSessions[session.id] == session {
		delete(s.ownedSessions, session.id)
	}
	if res, ok := s.reservations[session.cardID]; ok && res.generation == r.generation {
		delete(s.reservations, session.cardID)
	}
	s.wakeSessionLocked(session)
	terminalErr := errors.Join(errs...)
	s.recordClosingCleanupLocked(terminalErr)
	r.publicationRefs--
	updates := s.applyIdleCardsLocked(nil)
	// Metadata saves can cache ownership even when no selection is pending.
	// Retire that fallback only after this exact session's terminal release.
	updates = append(updates, s.cardApplicationLocked(session.cardID))
	s.mu.Unlock()
	s.publishCardApplications(updates)
	return terminalErr
}
func (s *dvbScheduler) Close() error {
	l := s.lifecycle
	l.mu.Lock()
	if l.closing {
		done := l.done
		l.mu.Unlock()
		<-done
		l.mu.Lock()
		err := l.result
		l.mu.Unlock()
		return err
	}
	l.closing = true
	close(l.stopping)
	for l.active != 0 {
		l.cond.Wait()
	}
	l.mu.Unlock()
	s.mu.Lock()
	owned := make(map[*tuningSession]struct{}, len(s.ownedSessions))
	for _, session := range s.ownedSessions {
		if session != nil && session.runtime != nil {
			owned[session] = struct{}{}
		}
	}
	// Primary session pointers are an independent rescue path after index corruption.
	for _, session := range s.sessions {
		if session != nil && session.runtime != nil {
			owned[session] = struct{}{}
		}
	}
	rescue := make(map[*streamAttachment]sinkRegistrationToken, len(s.sinkTokens))
	for token, a := range s.sinkTokens {
		if a != nil && token.StreamID == a.id && token.Generation != 0 && (rescue[a].Generation == 0 || token == a.sinkToken) {
			rescue[a] = token
		}
	}
	for _, a := range s.attachments {
		if a != nil && a.session != nil && a.session.runtime != nil {
			owned[a.session] = struct{}{}
			r := a.session.runtime
			if r.attachments == nil {
				r.attachments = make(map[string]*streamAttachment)
			}
			r.attachments[a.id] = a
		}
	}
	for session := range owned {
		session.runtime.closing = true
		session.runtime.publicationRefs++
		session.healthy = false
		s.wakeSessionLocked(session)
	}
	s.mu.Unlock()
	for session := range owned {
		_ = s.closeOwnedSession(session, rescue)
	}
	var descramblingErr error
	if s.descrambling != nil {
		descramblingErr = s.descrambling.Close()
	}
	s.mu.Lock()
	err := errors.Join(append(s.closingCleanupErrors, descramblingErr)...)
	s.sessions = make(map[string]*tuningSession)
	s.sessionsByKey = make(map[tuningKey]map[string]struct{})
	s.sessionByCard = make(map[string]string)
	s.streamSessions = make(map[string]string)
	s.sessionOrderByKey = make(map[tuningKey][]string)
	s.sessionByPhysical = make(map[physicalFrontendKey]*tuningSession)
	s.ownedSessions = make(map[string]*tuningSession)
	s.physicalReservations = make(map[physicalFrontendKey]*tuningSession)
	s.reservations = make(map[string]cardReservation)
	s.streamReservations = make(map[string]dvbStreamReservation)
	s.attachments = make(map[string]*streamAttachment)
	s.subscriptions = make(map[string]*streamAttachment)
	s.sinkTokens = make(map[sinkRegistrationToken]*streamAttachment)
	s.mu.Unlock()
	l.mu.Lock()
	l.result = err
	l.closed = true
	close(l.done)
	l.mu.Unlock()
	return err
}
func (s *dvbScheduler) Placement(id string) (model.DVBPlacementRuntime, bool) {
	end, err := s.admit()
	if err != nil {
		return model.DVBPlacementRuntime{}, false
	}
	defer end()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attachments[id]
	if a == nil || a.retiring {
		return model.DVBPlacementRuntime{}, false
	}
	if s.counters != nil {
		s.counters.AttachmentVisits++
	}
	return model.DVBPlacementRuntime{RequestedMode: a.policy.Mode, RequestedCardID: a.policy.DeviceKey,
		ActualCardID: a.session.cardID, ActualAddress: a.session.card.Address, TuningSessionID: a.session.id}, true
}
func (s *dvbScheduler) CardRuntime(id string) (dvbCardOwnership, bool) {
	end, err := s.admit()
	if err != nil {
		return dvbCardOwnership{}, false
	}
	defer end()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cards[id]; !ok {
		return dvbCardOwnership{}, false
	}
	application := s.cardApplicationViewLocked(id).application
	session := s.sessions[s.sessionByCard[id]]
	if session == nil || session.runtime == nil {
		return dvbCardOwnership{Application: &application}, true
	}
	return dvbCardOwnership{Application: &application, CurrentTransport: cloneDVBStreamConfig(session.runtime.transport), ActiveSessions: 1, ActiveStreams: len(session.runtime.attachments)}, true
}

func nilDVBSession(session dvb.Session) bool {
	if session == nil {
		return true
	}
	v := reflect.ValueOf(session)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func (s *dvbScheduler) resultingState(id string, placeholder *sinkRegistrationToken) dvbOnDemandResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateLocked(id, placeholder)
}
