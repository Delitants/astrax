// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"
	"sync"
	"time"
)

type ecmServiceBinding struct {
	client     *ECMClient
	broker     *ecmBroker
	identity   ECMServiceIdentity
	epoch      uint64
	current    bool
	operations int
	queue      []*ecmOperation
	ready      bool
}

type ecmWaiter struct {
	result       *ECMResult
	ctx          context.Context
	cancellation <-chan struct{}
	deadline     time.Time
	operation    *ecmOperation
	done         chan struct{}
	terminal     bool
	err          error
}

type ecmOperation struct {
	waiterReservations             int
	binding                        *ecmServiceBinding
	token                          ecmToken
	section                        []byte
	digest                         [32]byte
	deadline                       time.Time
	waiters                        []*ecmWaiter
	ctx                            *ecmOperationContext
	started, writerOwned, terminal bool
	err                            error
}

// A private signal-only context avoids cancellation callbacks under the claim
// fence. Closing done wakes the transport; no consumer function is invoked.
type ecmOperationContext struct {
	done     chan struct{}
	deadline time.Time
	err      error
}

func (c *ecmOperationContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *ecmOperationContext) Done() <-chan struct{}       { return c.done }
func (c *ecmOperationContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}
func (*ecmOperationContext) Value(any) any { return nil }
func (c *ecmOperationContext) cancel(err error) {
	if err == nil {
		err = context.Canceled
	}
	select {
	case <-c.done:
	default:
		c.err = err
		close(c.done)
	}
}

type ecmBroker struct {
	results                               map[uint64]*ecmResultOwner
	nextResult                            uint64
	signals                               []*ecmWaiter
	serviceOperations                     map[ECMServiceIdentity]int
	owner                                 *ecmOwner
	transport                             ecmTransport
	quota                                 *ecmQuota
	clock                                 ecmClock
	mu                                    sync.Mutex
	services                              map[ECMServiceIdentity]*ecmServiceBinding
	jobs                                  map[uint64]*ecmOperation
	index                                 map[[32]byte][]*ecmOperation
	ready                                 []*ecmServiceBinding
	active                                *ecmOperation
	operations, reservations              int
	nextService, nextOperation            uint64
	closed, abortSent                     bool
	retireCause                           error
	wake                                  chan struct{}
	work                                  chan *ecmOperation
	completed                             chan ecmExchangeCompletion
	schedulerDone, workerDone, workerStop chan struct{}
}

func newECMBroker(owner *ecmOwner, transport ecmTransport, quota *ecmQuota, clock ecmClock) (*ecmBroker, error) {
	if owner == nil || owner.guard == nil || transport == nil || quota == nil || clock == nil {
		return nil, ecmInvalidRequestError
	}
	if err := validateECMIdentity(owner.profileID, ECMServiceIdentity{}); err != nil {
		return nil, err
	}
	owner.guard.RLock()
	quota.mu.Lock()
	if !owner.current || owner.sessionEpoch == 0 || owner.profileGeneration == 0 {
		quota.mu.Unlock()
		owner.guard.RUnlock()
		return nil, ecmStaleError
	}
	if quota.brokers >= ecmProcessBrokers {
		quota.mu.Unlock()
		owner.guard.RUnlock()
		return nil, ecmCapacityError
	}
	quota.brokers++
	quota.mu.Unlock()
	owner.guard.RUnlock()
	// Native bind may acquire its own lock; no upper lock or goroutine exists yet.
	err := transport.bindECMSession(owner.sessionEpoch)
	owner.guard.RLock()
	quota.mu.Lock()
	if err == nil && !owner.current {
		err = ecmStaleError
	}
	if err != nil {
		quota.brokers--
		quota.mu.Unlock()
		owner.guard.RUnlock()
		return nil, err
	}
	b := &ecmBroker{owner: owner, transport: transport, quota: quota, clock: clock,
		serviceOperations: make(map[ECMServiceIdentity]int), services: make(map[ECMServiceIdentity]*ecmServiceBinding), jobs: make(map[uint64]*ecmOperation), index: make(map[[32]byte][]*ecmOperation),
		wake: make(chan struct{}, 1), work: make(chan *ecmOperation, 1), completed: make(chan ecmExchangeCompletion, 1), schedulerDone: make(chan struct{}), workerDone: make(chan struct{}), workerStop: make(chan struct{})}
	quota.mu.Unlock()
	owner.guard.RUnlock()
	go b.exchangeWorker()
	go b.schedule()
	return b, nil
}
func (b *ecmBroker) lock() {
	b.owner.guard.RLock()
	b.quota.mu.Lock()
	b.mu.Lock()
}
func (b *ecmBroker) unlock() {
	signals := b.signals
	b.signals = nil
	b.mu.Unlock()
	b.quota.mu.Unlock()
	b.owner.guard.RUnlock()
	for _, w := range signals {
		close(w.done)
	}
}
func (b *ecmBroker) notify() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}
func (b *ecmBroker) currentLocked() bool { return !b.closed && b.owner.current }
func (b *ecmBroker) bindingLocked(s *ecmServiceBinding) bool {
	return s != nil && s.broker == b && s.current && b.services[s.identity] == s
}

func (b *ecmBroker) bind(identity ECMServiceIdentity, replace bool) (*ecmServiceBinding, error) {
	if err := validateECMIdentity(b.owner.profileID, identity); err != nil {
		return nil, err
	}
	b.lock()
	defer b.unlock()
	if !b.currentLocked() {
		return nil, ecmStaleError
	}
	old := b.services[identity]
	if old != nil && !replace {
		return old, nil
	}
	if old == nil && len(b.services) >= ecmServiceBindings {
		return nil, ecmCapacityError
	}
	if b.nextService == math.MaxUint64 {
		return nil, ecmCapacityError
	}
	b.nextService++
	s := &ecmServiceBinding{broker: b, identity: identity, epoch: b.nextService, current: true}
	if old != nil {
		b.invalidateBindingLocked(old, ecmStaleError)
	}
	b.services[identity] = s
	b.notify()
	return s, nil
}
func (b *ecmBroker) releaseBinding(s *ecmServiceBinding) error {
	b.lock()
	if b.bindingLocked(s) {
		b.invalidateBindingLocked(s, ecmStaleError)
		delete(b.services, s.identity)
	}
	b.unlock()
	b.notify()
	return nil
}
func (b *ecmBroker) invalidateBindingLocked(s *ecmServiceBinding, cause error) {
	s.current = false
	b.revokeBindingResultsLocked(s)
	for _, op := range b.jobs {
		if op.binding == s {
			b.terminateLocked(op, cause)
		}
	}
}
func (b *ecmBroker) duplicateLocked(s *ecmServiceBinding, section []byte, route ECMRoute, digest [32]byte) *ecmOperation {
	for _, op := range b.index[digest] {
		if !op.terminal && op.binding == s && op.token.route == route && bytes.Equal(op.section, section) {
			return op
		}
	}
	return nil
}
func ecmContextState(cancellation <-chan struct{}, deadline time.Time, now time.Time) error {
	if !deadline.IsZero() && !now.Before(deadline) {
		return ecmTimeoutError
	}
	select {
	case <-cancellation:
		return ecmCancelledError
	default:
		return nil
	}
}
func (b *ecmBroker) waiterLocked(op *ecmOperation, ctx context.Context, done <-chan struct{}, deadline time.Time) *ecmWaiter {
	w := &ecmWaiter{ctx: ctx, cancellation: done, deadline: deadline, operation: op, done: make(chan struct{})}
	op.waiters = append(op.waiters, w)
	return w
}
func (b *ecmBroker) admit(ctx context.Context, s *ecmServiceBinding, section []byte, route ECMRoute) (*ecmWaiter, error) {
	if ctx == nil {
		return nil, ecmInvalidRequestError
	}
	if err := validateECMRequest(section, route); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nativeECMContextError(err)
	}
	deadline, _ := ctx.Deadline()
	digest := sha256.Sum256(section)
	b.lock()
	now := b.clock.Now()
	b.expireLocked(now)
	if !b.currentLocked() || !b.bindingLocked(s) {
		b.unlock()
		b.notify()
		return nil, ecmStaleError
	}
	if err := ecmContextState(nil, deadline, now); err != nil {
		b.unlock()
		return nil, err
	}
	original := b.duplicateLocked(s, section, route, digest)
	distinct := original == nil
	if b.quota.waiters >= ecmProcessWaiters {
		b.unlock()
		return nil, ecmCapacityError
	}
	if !distinct && len(original.waiters)+original.waiterReservations >= ecmOperationWaiters {
		b.unlock()
		return nil, ecmCapacityError
	}
	if distinct && (b.operations >= ecmProfileOperations || b.serviceOperations[s.identity] >= ecmServiceOperations || b.quota.operations >= ecmProcessOperations || b.nextOperation == math.MaxUint64) {
		b.unlock()
		return nil, ecmCapacityError
	}
	limit := now.Add(ecmOperationLifetime)
	if !deadline.IsZero() && deadline.Before(limit) {
		limit = deadline
	}
	b.quota.waiters++
	b.reservations++
	if distinct {
		b.reserveOperationQuotaLocked(s)
	} else {
		original.waiterReservations++
	}
	b.unlock()
	// Done can lazily allocate a caller cancellation channel. Both duplicate and
	// distinct admissions own bounded quota BEFORE acquiring that registration.
	// Neither caller context methods nor native inventory run under broker locks.
	cancellation := ctx.Done()
	var card ecmCardRef
	if distinct {
		for _, candidate := range b.transport.ecmInventory() {
			if candidate.CAID != route.CAID || candidate.Revision == 0 {
				continue
			}
			for _, provider := range candidate.Providers {
				if provider == route.Provider && (card.Revision == 0 || candidate.ID < card.ID) {
					card = candidate
				}
			}
		}
	}
	b.lock()
	now = b.clock.Now()
	b.expireLocked(now)
	b.reservations--
	if !distinct {
		original.waiterReservations--
	}
	rollback := func() {
		b.quota.waiters--
		if distinct {
			b.releaseOperationQuotaLocked(s)
		}
		b.notify()
	}
	if !b.currentLocked() || !b.bindingLocked(s) {
		rollback()
		b.unlock()
		return nil, ecmStaleError
	}
	if err := ecmContextState(cancellation, deadline, now); err != nil {
		rollback()
		b.unlock()
		return nil, err
	}
	if !distinct {
		if original.terminal {
			rollback()
			b.unlock()
			return nil, ecmStaleError
		}
		w := b.waiterLocked(original, ctx, cancellation, deadline)
		b.unlock()
		b.notify()
		return w, nil
	}
	if card.Revision == 0 {
		rollback()
		b.unlock()
		return nil, ecmNoRouteError
	}
	// Another caller may commit the same owned section during inventory copying.
	if op := b.duplicateLocked(s, section, route, digest); op != nil {
		if len(op.waiters)+op.waiterReservations >= ecmOperationWaiters {
			rollback()
			b.unlock()
			return nil, ecmCapacityError
		}
		b.releaseOperationQuotaLocked(s)
		w := b.waiterLocked(op, ctx, cancellation, deadline)
		b.unlock()
		b.notify()
		return w, nil
	}
	if b.nextOperation == math.MaxUint64 {
		rollback()
		b.unlock()
		return nil, ecmCapacityError
	}
	if !now.Before(limit) {
		rollback()
		b.unlock()
		return nil, ecmTimeoutError
	}
	b.nextOperation++
	op := &ecmOperation{binding: s, token: ecmToken{profileID: b.owner.profileID, profileGeneration: b.owner.profileGeneration, sessionEpoch: b.owner.sessionEpoch, identity: s.identity, serviceEpoch: s.epoch, cardID: card.ID, cardRevision: card.Revision, route: route, operationID: b.nextOperation}, section: append([]byte(nil), section...), digest: digest, deadline: limit}
	op.ctx = &ecmOperationContext{done: make(chan struct{}), deadline: limit}
	w := b.waiterLocked(op, ctx, cancellation, deadline)
	b.jobs[op.token.operationID] = op
	b.index[digest] = append(b.index[digest], op)
	s.queue = append(s.queue, op)
	if !s.ready {
		s.ready = true
		b.ready = append(b.ready, s)
	}
	b.unlock()
	b.notify()
	return w, nil
}
func (b *ecmBroker) completeWaiterLocked(w *ecmWaiter, cause error) {
	if w.terminal {
		return
	}
	w.terminal = true
	w.err = ecmPublicOutcome(cause)
	b.quota.waiters--
	b.signals = append(b.signals, w)
}
func (b *ecmBroker) unindexLocked(op *ecmOperation) {
	bucket := b.index[op.digest]
	for i, v := range bucket {
		if v == op {
			copy(bucket[i:], bucket[i+1:])
			bucket[len(bucket)-1] = nil
			bucket = bucket[:len(bucket)-1]
			break
		}
	}
	if len(bucket) == 0 {
		delete(b.index, op.digest)
	} else {
		b.index[op.digest] = bucket
	}
}
func (b *ecmBroker) removeQueuedLocked(op *ecmOperation) {
	s := op.binding
	for i, v := range s.queue {
		if v == op {
			copy(s.queue[i:], s.queue[i+1:])
			s.queue[len(s.queue)-1] = nil
			s.queue = s.queue[:len(s.queue)-1]
			break
		}
	}
	if len(s.queue) == 0 && s.ready {
		for i, v := range b.ready {
			if v == s {
				copy(b.ready[i:], b.ready[i+1:])
				b.ready[len(b.ready)-1] = nil
				b.ready = b.ready[:len(b.ready)-1]
				break
			}
		}
		s.ready = false
	}
}

// Identity-wide accounting survives service epoch replacement until old active
// work and provisional admissions drain. Zero entries are removed, bounding this
// map by the profile's 128 operation reservations, not by historical bindings.
func (b *ecmBroker) reserveOperationQuotaLocked(s *ecmServiceBinding) {
	b.quota.operations++
	b.operations++
	s.operations++
	b.serviceOperations[s.identity]++
}
func (b *ecmBroker) releaseOperationQuotaLocked(s *ecmServiceBinding) {
	b.quota.operations--
	b.operations--
	s.operations--
	b.serviceOperations[s.identity]--
	if b.serviceOperations[s.identity] == 0 {
		delete(b.serviceOperations, s.identity)
	}
}
func (b *ecmBroker) dropOperationLocked(op *ecmOperation) {
	if b.jobs[op.token.operationID] != op {
		return
	}
	delete(b.jobs, op.token.operationID)
	b.releaseOperationQuotaLocked(op.binding)
	clear(op.section)
	op.section = nil
}
func (b *ecmBroker) terminateLocked(op *ecmOperation, cause error) {
	if op.terminal {
		return
	}
	op.terminal = true
	op.err = cause
	b.unindexLocked(op)
	for _, w := range op.waiters {
		b.completeWaiterLocked(w, cause)
	}
	clear(op.waiters)
	op.waiters = nil
	ctxErr := context.Canceled
	if cause == ecmTimeoutError {
		ctxErr = context.DeadlineExceeded
	}
	op.ctx.cancel(ctxErr)
	if op == b.active {
		if op.writerOwned && !b.closed {
			b.closed = true
			b.retireCause = cause
		}
	} else {
		b.removeQueuedLocked(op)
		b.dropOperationLocked(op)
	}
}
func (b *ecmBroker) expireLocked(now time.Time) {
	b.expireResultsLocked(now)
	for _, op := range b.jobs {
		b.expireOperationLocked(op, now)
	}
}
func (b *ecmBroker) expireOperationLocked(op *ecmOperation, now time.Time) {
	if op.terminal {
		return
	}
	if !b.bindingLocked(op.binding) {
		b.terminateLocked(op, ecmStaleError)
		return
	}
	if !now.Before(op.deadline) {
		b.terminateLocked(op, ecmTimeoutError)
		return
	}
	live := op.waiters[:0]
	for _, w := range op.waiters {
		if cause := ecmContextState(w.cancellation, w.deadline, now); cause != nil {
			b.completeWaiterLocked(w, cause)
		} else {
			live = append(live, w)
		}
	}
	clear(op.waiters[len(live):])
	op.waiters = live
	if len(live) == 0 {
		b.terminateLocked(op, ecmCancelledError)
	}
}

// Retirement changes state/signals only; transport shutdown and joins are outside.
func (b *ecmBroker) retire(cause error) {
	if cause == nil {
		cause = ecmStaleError
	}
	b.lock()
	if !b.closed {
		b.closed = true
		b.retireCause = cause
	}
	b.revokeResultsLocked()
	b.unlock()
	b.notify()
}
func (b *ecmBroker) Close() error {
	b.retire(ecmStaleError)
	<-b.schedulerDone
	<-b.workerDone
	return nil
}
