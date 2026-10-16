// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"math"
	"time"

	"astrax/internal/model"
)

func newManagerWithECMOptions(handler func(Event), opener func(context.Context, model.Softcam) (RuntimeSession, time.Duration, error), quota *ecmQuota, clock ecmClock) *Manager {
	if quota == nil {
		quota = processECMQuota
	}
	if clock == nil {
		clock = realECMClock{}
	}
	m := &Manager{contextOpener: opener, ecmQuota: quota, ecmClock: clock,
		workers: make(map[string]*worker), intents: make(map[string]*RuntimeCommand),
		owned: make(map[string]map[*worker]struct{}), runtimes: make(map[string]model.SoftcamRuntime),
		events: make(chan Event, 256), closed: make(chan struct{}), dispatchDone: make(chan struct{})}
	go m.dispatch(handler)
	return m
}

func (m *Manager) BindService(profileID string, identity ECMServiceIdentity) (*ECMClient, error) {
	return m.bindECMService(profileID, identity, false)
}

func (m *Manager) RebindService(profileID string, identity ECMServiceIdentity) (*ECMClient, error) {
	return m.bindECMService(profileID, identity, true)
}

func (m *Manager) workerCurrentLocked(w *worker) bool {
	intent := m.intents[w.profile.ID]
	return !m.closing && m.workers[w.profile.ID] == w && intent != nil && intent.generation == w.generation && w.ctx.Err() == nil
}

func (m *Manager) workerCurrent(w *worker) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.workerCurrentLocked(w)
}

// Classify the actual return before cancellation/partial-open cleanup or status
// callbacks. A metadata-only/opaque wrapper never acquires this join obligation.
func (m *Manager) classifyWorkerSession(w *worker, s RuntimeSession) {
	m.mu.Lock()
	w.newcamd = isNativeNewcamd(s)
	w.returnedSession = s != nil
	if _, ok := s.(ecmTransport); ok {
		w.native = true
	}
	m.mu.Unlock()
}

func (m *Manager) joinECMPredecessors(w *worker) error {
	m.mu.RLock()
	if !m.workerCurrentLocked(w) {
		m.mu.RUnlock()
		return ecmStaleError
	}
	predecessors := make([]*worker, 0, len(m.owned[w.profile.ID]))
	for old := range m.owned[w.profile.ID] {
		if old.generation < w.generation {
			predecessors = append(predecessors, old)
		}
	}
	m.mu.RUnlock()
	// Context-free metadata opens may overlap. Only an actual ECM-capable
	// successor waits here, including unresolved/retired opens that could still
	// return native transports. Never infer safety from a not-yet-set native bit.
	for _, old := range predecessors {
		select {
		case <-old.done:
		case <-w.ctx.Done():
			return ecmStaleError
		}
	}
	return nil
}

func (m *Manager) bindECMService(profileID string, identity ECMServiceIdentity, replace bool) (*ECMClient, error) {
	if err := validateECMIdentity(profileID, identity); err != nil {
		return nil, err
	}
	m.mu.RLock()
	w, intent := m.workers[profileID], m.intents[profileID]
	if m.closing || w == nil || intent == nil || intent.generation != w.generation || w.ctx.Err() != nil {
		m.mu.RUnlock()
		return nil, ecmStaleError
	}
	if w.ecmOwner == nil {
		m.mu.RUnlock()
		return nil, ecmError("ecm_unsupported", nil)
	}
	b := w.ecmBroker
	current := w.ecmOwner.current
	m.mu.RUnlock()
	if !current || b == nil {
		return nil, ecmStaleError
	}
	// bindClient reacquires the same current-owner guard. Never recursively hold
	// it here: a waiting Manager writer would deadlock a second read acquisition.
	return b.bindClient(identity, replace)
}

// Record the constructor's native-binding boundary, not an error-code category.
// A native bind returning even the shared quota error is still a session failure.
type managerECMAttachmentTransport struct {
	ecmTransport
	bindAttempted bool
}

func (t *managerECMAttachmentTransport) bindECMSession(epoch uint64) error {
	t.bindAttempted = true
	return t.ecmTransport.bindECMSession(epoch)
}

// Preserve the actual optional result fence; wrapping must neither hide a native
// fence nor grant that capability to an authentication-only transport.
type managerECMAttachmentFencedTransport struct {
	*managerECMAttachmentTransport
	ecmResultFence
}

// Keep the existing wrapper identity, but forward new validation to the actual
// transport only. Having a result fence alone is never publication success.
func (t *managerECMAttachmentFencedTransport) validateECMRouteLocked(route ECMRoute) error {
	fence, ok := t.ecmTransport.(ecmPublicationFence)
	if !ok {
		return ecmUnsupportedError
	}
	return fence.validateECMRouteLocked(route)
}
func (t *managerECMAttachmentFencedTransport) validateECMSessionLocked(epoch uint64) error {
	fence, ok := t.ecmTransport.(ecmSessionFence)
	if !ok {
		return ecmUnsupportedError
	}
	return fence.validateECMSessionLocked(epoch)
}

// Called only after authentication. Optional capability is taken from the actual
// opened session, never inferred from its profile or a metadata-only wrapper.
func (m *Manager) attachECMSession(w *worker, s RuntimeSession) error {
	protocol := normalizeSoftcamType(w.profile.Type)
	if protocol != "cccam" && (protocol != "newcamd" || !isNativeNewcamd(s)) {
		return nil
	}
	if protocol == "newcamd" {
		if _, ok := s.(ecmResultFence); !ok {
			return nil
		}
	}
	transport, ok := s.(ecmTransport)
	if !ok {
		return nil
	}
	var status SessionStatus
	if provider, ok := s.(sessionStateProvider); ok {
		var err error
		status, err = provider.sessionState()
		if err != nil {
			return err
		}
	} else if provider, ok := s.(sessionStatusProvider); ok {
		status = provider.SessionStatus()
	}
	if !status.Authenticated {
		return ecmError("ecm_session_unavailable", nil)
	}
	if err := m.joinECMPredecessors(w); err != nil {
		return err
	}
	m.mu.Lock()
	if !m.workerCurrentLocked(w) {
		m.mu.Unlock()
		return ecmStaleError
	}
	// These are ECM-only bounds, before native binding or any reservation. They
	// cannot change the authenticated session's lifetime or wrap its ECM epoch.
	if validateECMIdentity(w.profile.ID, ECMServiceIdentity{}) != nil {
		m.mu.Unlock()
		return nil
	}
	if m.nextECMSessionEpoch == math.MaxUint64 {
		m.mu.Unlock()
		return nil
	}
	m.nextECMSessionEpoch++
	owner := &ecmOwner{guard: &m.mu, profileID: w.profile.ID, profileGeneration: w.generation, sessionEpoch: m.nextECMSessionEpoch, current: true}
	w.ecmOwner = owner
	m.mu.Unlock()

	// The constructor owns epoch binding and quota, and acquires owner.guard.
	// Prepare may revoke this reserved owner while native attach is in progress.
	attempt := &managerECMAttachmentTransport{ecmTransport: transport}
	var candidate ecmTransport = attempt
	if fence, ok := transport.(ecmResultFence); ok {
		candidate = &managerECMAttachmentFencedTransport{attempt, fence}
	}
	b, err := newECMBroker(owner, candidate, m.ecmQuota, m.ecmClock)
	m.mu.Lock()
	current := owner.current && m.workerCurrentLocked(w)
	if err != nil || !current {
		// Only this constructor's pre-bind quota rejection is auth-independent.
		// Revocation wins even if quota exhaustion happened at the same boundary.
		admissionOnly := current && !attempt.bindAttempted && err == ecmCapacityError
		owner.current = false
		if w.ecmOwner == owner {
			w.ecmOwner = nil
		}
		m.mu.Unlock()
		if b != nil {
			_ = b.Close()
		}
		if !current {
			err = ecmStaleError
		}
		if admissionOnly {
			return nil
		}
		return err
	}
	w.ecmBroker = b
	m.mu.Unlock()
	return nil
}

// Manager already holds the owner guard. Only state and a bounded channel
// signal change here; the scheduler retires under the normal lock order.
func (m *Manager) revokeWorkerECMLocked(w *worker) {
	if w.ecmOwner != nil {
		w.ecmOwner.current = false
	}
	if w.ecmBroker != nil {
		w.ecmBroker.notify()
	}
}

func (m *Manager) closeWorkerSession(w *worker, s RuntimeSession) {
	m.mu.Lock()
	m.revokeWorkerECMLocked(w)
	b := w.ecmBroker
	w.ecmBroker, w.ecmOwner = nil, nil
	m.mu.Unlock()
	if b != nil {
		_ = b.Close()
	}
	// Native Close joins reader, writer and parent cancellation; worker.done is
	// not signaled until both those loops and the broker scheduler have joined.
	m.closeSession(s)
}
