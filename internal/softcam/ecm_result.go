// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"math"
	"time"
)

type ecmKeyBacking struct {
	keys                ecmKeys
	token               ecmToken
	responseAt, expires time.Time
	refs                int
}
type ecmResultOwner struct {
	handle  *ECMResult
	client  *ECMClient
	backing *ecmKeyBacking
}

var _ ecmClientBackend = (*ecmBroker)(nil)
var _ ecmResultBackend = (*ecmBroker)(nil)

func (c *ECMClient) SubmitECM(ctx context.Context, section []byte, route ECMRoute) (*ECMResult, error) {
	if c == nil || c.backend == nil {
		return nil, ecmStaleError
	}
	return c.backend.submit(c, ctx, section, route)
}
func (c *ECMClient) Release() error {
	if c == nil || c.backend == nil {
		return nil
	}
	return c.backend.releaseService(c)
}
func (c *ECMClient) ValidResult(r *ECMResult) bool {
	return c != nil && c.backend != nil && c.backend.validResult(c, r)
}
func (c *ECMClient) CopyKeys(r *ECMResult) (even, odd [8]byte, validMask uint8, err error) {
	if c == nil || c.backend == nil {
		return even, odd, 0, ecmStaleError
	}
	return c.backend.copyKeys(c, r)
}
func (r *ECMResult) Release() error {
	if r == nil || r.backend == nil {
		return nil
	}
	return r.backend.releaseResult(r)
}

func (b *ecmBroker) bindClient(identity ECMServiceIdentity, replace bool) (*ECMClient, error) {
	s, err := b.bind(identity, replace)
	if err != nil {
		return nil, err
	}
	// Allocate before the ownership chain, then snapshot its scope while guarded.
	candidate := &ECMClient{backend: b, identity: s.identity, epoch: s.epoch}
	b.lock()
	defer b.unlock()
	if !b.currentLocked() || !b.bindingLocked(s) {
		return nil, ecmStaleError
	}
	// bind also serves private Task3 callers, so wrapping is lazy and canonical.
	if s.client == nil {
		candidate.profileGeneration = b.owner.profileGeneration
		candidate.sessionEpoch = b.owner.sessionEpoch
		s.client = candidate
	}
	return s.client, nil
}
func (b *ecmBroker) clientBindingLocked(c *ECMClient) *ecmServiceBinding {
	if c == nil || c.backend != b {
		return nil
	}
	s := b.services[c.identity]
	if !b.bindingLocked(s) || s.client != c || s.epoch != c.epoch {
		return nil
	}
	return s
}
func (b *ecmBroker) submit(c *ECMClient, ctx context.Context, section []byte, route ECMRoute) (*ECMResult, error) {
	b.lock()
	s := b.clientBindingLocked(c)
	b.unlock()
	if s == nil {
		return nil, ecmStaleError
	}
	w, err := b.admit(ctx, s, section, route)
	if err != nil {
		return nil, err
	}
	// The scheduler owns cancellation/publication. Selecting caller cancellation
	// here would retract an already-linearized success or leak its owner.
	<-w.done
	return w.result, w.err
}
func (b *ecmBroker) releaseService(c *ECMClient) error {
	b.lock()
	s := b.clientBindingLocked(c)
	if s != nil {
		b.invalidateBindingLocked(s, ecmStaleError)
		delete(b.services, s.identity)
	}
	b.unlock()
	b.notify()
	return nil
}
func (b *ecmBroker) releaseResult(r *ECMResult) error {
	b.lock()
	if r != nil && r.backend == b {
		if owned := b.results[r.ownerID]; owned != nil && owned.handle == r {
			b.dropResultLocked(r.ownerID)
		}
	}
	b.unlock()
	b.notify()
	return nil
}
func (b *ecmBroker) dropResultLocked(id uint64) {
	owned := b.results[id]
	if owned == nil {
		return
	}
	delete(b.results, id)
	b.quota.results--
	backing := owned.backing
	backing.refs--
	if backing.refs == 0 {
		backing.keys = ecmKeys{}
	}
}
func (b *ecmBroker) resultLocked(c *ECMClient, r *ECMResult, now time.Time) *ecmKeyBacking {
	if !b.currentLocked() || b.clientBindingLocked(c) == nil || r == nil || r.backend != b {
		return nil
	}
	owned := b.results[r.ownerID]
	if owned == nil || owned.handle != r || owned.client != c {
		return nil
	}
	k := owned.backing
	if !now.Before(k.expires) || !b.tokenCurrentLocked(k.token) {
		b.dropResultLocked(r.ownerID)
		return nil
	}
	return k
}
func (b *ecmBroker) validResult(c *ECMClient, r *ECMResult) bool {
	b.lock()
	defer b.unlock()
	k := b.resultLocked(c, r, b.clock.Now())
	if k == nil {
		return false
	}
	fence, ok := b.transport.(ecmResultFence)
	if !ok {
		return false
	}
	fence.lockECMResults()
	defer fence.unlockECMResults()
	if !b.clock.Now().Before(k.expires) || fence.validateECMResultLocked(k.token) != nil {
		b.dropResultLocked(r.ownerID)
		return false
	}
	return true
}
func (b *ecmBroker) copyKeys(c *ECMClient, r *ECMResult) (even, odd [8]byte, mask uint8, err error) {
	b.lock()
	defer b.unlock()
	k := b.resultLocked(c, r, b.clock.Now())
	if k == nil {
		return even, odd, 0, ecmStaleError
	}
	fence, ok := b.transport.(ecmResultFence)
	if !ok {
		return even, odd, 0, ecmStaleError
	}
	fence.lockECMResults()
	defer fence.unlockECMResults()
	// Card removal/re-add cannot interleave the final revision check and copy.
	if !b.clock.Now().Before(k.expires) || fence.validateECMResultLocked(k.token) != nil {
		b.dropResultLocked(r.ownerID)
		return even, odd, 0, ecmStaleError
	}
	copy(even[:], k.keys.material[:8])
	copy(odd[:], k.keys.material[8:])
	return even, odd, k.keys.validMask, nil
}
func (b *ecmBroker) tokenCurrentLocked(t ecmToken) bool {
	s := b.services[t.identity]
	return b.currentLocked() && t.profileID == b.owner.profileID && t.profileGeneration == b.owner.profileGeneration && t.sessionEpoch == b.owner.sessionEpoch && b.bindingLocked(s) && t.serviceEpoch == s.epoch
}

// Native CW receipt owns eligibility; writer/scheduler delay cannot extend it.
func (b *ecmBroker) publishLocked(op *ecmOperation, keys ecmKeys, cause error) {
	now := b.clock.Now()
	b.expireOperationLocked(op, now)
	if op.terminal {
		return
	}
	if cause == nil && !b.tokenCurrentLocked(op.token) {
		cause = ecmStaleError
	}
	if cause == nil && keys.validMask == 0 {
		cause = ecmError("ecm_rejected", nil)
	}
	if cause == nil && keys.validMask & ^uint8(3) != 0 {
		cause = ecmError("ecm_invalid_response", nil)
	}
	responseAt := keys.receivedAt
	expires := responseAt.Add(ecmResultLifetime)
	if cause == nil && (responseAt.IsZero() || responseAt.After(now) || !now.Before(expires)) {
		cause = ecmStaleError
	}
	var fence ecmResultFence
	if cause == nil {
		var ok bool
		fence, ok = b.transport.(ecmResultFence)
		if !ok {
			cause = ecmStaleError
		} else {
			fence.lockECMResults()
			defer fence.unlockECMResults()
			cause = fence.validateECMResultLocked(op.token)
		}
	}
	// A contended native fence may cross a waiter deadline/cancellation. Poll
	// again at the publication boundary; no user context methods run here.
	if cause == nil {
		b.expireOperationLocked(op, b.clock.Now())
		if op.terminal {
			return
		}
		if !b.clock.Now().Before(expires) {
			cause = ecmStaleError
		}
	}
	count := len(op.waiters)
	if cause == nil && (len(b.results)+count > ecmProfileResults || b.quota.results+count > ecmProcessResults || uint64(count) > math.MaxUint64-b.nextResult) {
		cause = ecmCapacityError
	}
	var backing *ecmKeyBacking
	if cause == nil {
		if b.results == nil {
			b.results = make(map[uint64]*ecmResultOwner)
		}
		backing = &ecmKeyBacking{keys: keys, token: op.token, responseAt: responseAt, expires: expires, refs: count}
		b.quota.results += count
	}
	b.unindexLocked(op)
	for _, w := range op.waiters {
		if backing != nil {
			b.nextResult++
			r := &ECMResult{backend: b, ownerID: b.nextResult}
			w.result = r
			b.results[r.ownerID] = &ecmResultOwner{handle: r, client: op.binding.client, backing: backing}
		}
		b.completeWaiterLocked(w, cause)
	}
	clear(op.waiters)
	op.waiters = nil
	op.terminal = true
	op.err = cause
	op.ctx.cancel(nil)
}
func (b *ecmBroker) complete(operationID uint64, keys ecmKeys, cause error) {
	b.lock()
	op := b.jobs[operationID]
	if op != nil && b.active == op {
		b.finishExchangeLocked(ecmExchangeCompletion{operation: op, keys: keys, err: cause})
	}
	b.unlock()
	b.notify()
}
func (b *ecmBroker) expire(now time.Time) { b.lock(); b.expireLocked(now); b.unlock(); b.notify() }

// Never invoke a caller Error/As method beneath ownership locks. Causes remain
// available via Unwrap, but the public terminal projection is fixed/redacted.
func ecmPublicOutcome(cause error) error {
	switch e := cause.(type) {
	case nil:
		return nil
	case ecmFixedError:
		return e
	case *ECMError:
		if e == nil {
			return ecmError("", nil)
		}
		return ecmError(e.Code, e.cause)
	default:
		return ecmError("ecm_session_unavailable", cause)
	}
}
