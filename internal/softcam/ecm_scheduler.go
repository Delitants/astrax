// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"reflect"
	"time"
)

type ecmExchangeCompletion struct {
	keys      ecmKeys
	operation *ecmOperation
	err       error
}
type ecmOperationClaim struct {
	broker    *ecmBroker
	operation *ecmOperation
}

func (c *ecmOperationClaim) BeginWrite(tx ecmNativeTransaction) error {
	if tx == nil {
		return ecmInvalidRequestError
	}
	b, op := c.broker, c.operation
	b.lock()
	defer func() { b.unlock(); b.notify() }()
	now := b.clock.Now()
	b.expireLocked(now)
	if op.terminal {
		return op.err
	}
	if !b.currentLocked() || b.active != op || !op.started || op.writerOwned || !b.bindingLocked(op.binding) {
		return ecmStaleError
	}
	if !now.Before(op.deadline) {
		return ecmTimeoutError
	}
	tx.Lock()
	defer tx.Unlock()
	// Native inventory contention may cross cancellation or expiry. Fence again
	// with fresh monotonic time and at most sixteen channel polls before marking.
	now = b.clock.Now()
	b.expireOperationLocked(op, now)
	if op.terminal {
		return op.err
	}
	if err := tx.ValidateLocked(op.token, now); err != nil {
		return err
	}
	tx.MarkWriterOwnedLocked()
	op.writerOwned = true
	return nil
}

// One constant worker owns the serial exchange. It never enters broker locks;
// the native writer invokes the operation-specific claim outside native locks.
func (b *ecmBroker) exchangeWorker() {
	defer close(b.workerDone)
	for {
		select {
		case <-b.workerStop:
			return
		case op := <-b.work:
			keys, err := b.transport.exchangeECM(op.ctx, ecmWireRequest{token: op.token, section: op.section, deadline: op.deadline}, &ecmOperationClaim{broker: b, operation: op})
			b.completed <- ecmExchangeCompletion{operation: op, keys: keys, err: err}
			keys = ecmKeys{}
		}
	}
}
func (b *ecmBroker) selectOperationLocked() *ecmOperation {
	if b.active != nil || len(b.ready) == 0 {
		return nil
	}
	s := b.ready[0]
	copy(b.ready, b.ready[1:])
	b.ready[len(b.ready)-1] = nil
	b.ready = b.ready[:len(b.ready)-1]
	op := s.queue[0]
	copy(s.queue, s.queue[1:])
	s.queue[len(s.queue)-1] = nil
	s.queue = s.queue[:len(s.queue)-1]
	if len(s.queue) > 0 {
		b.ready = append(b.ready, s)
	} else {
		s.ready = false
	}
	b.active = op
	op.started = true
	return op
}
func (b *ecmBroker) finishExchangeLocked(result ecmExchangeCompletion) {
	op := result.operation
	if b.active != op {
		return
	}
	if !op.terminal {
		b.publishLocked(op, result.keys, result.err)
	}
	b.active = nil
	b.dropOperationLocked(op)
}
func (b *ecmBroker) schedule() {
	var timer ecmTimer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		close(b.workerStop)
		close(b.schedulerDone)
	}()
	for {
		b.lock()
		now := b.clock.Now()
		if !b.owner.current && !b.closed {
			b.closed = true
			b.retireCause = ecmStaleError
		}
		b.expireLocked(now)
		var abort error
		if b.closed {
			b.revokeResultsLocked()
			if b.retireCause == nil {
				b.retireCause = ecmStaleError
			}
			for _, op := range b.jobs {
				b.terminateLocked(op, b.retireCause)
			}
			for _, s := range b.services {
				s.current = false
			}
			clear(b.services)
			if !b.abortSent {
				b.abortSent = true
				abort = b.retireCause
			}
		}
		var dispatch *ecmOperation
		if !b.closed {
			dispatch = b.selectOperationLocked()
		}
		exit := b.closed && b.active == nil && b.reservations == 0
		if exit {
			b.quota.brokers--
		}
		cases := []reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(b.wake)}, {Dir: reflect.SelectRecv, Chan: reflect.ValueOf(b.completed)}}
		var earliest time.Time
		for _, owned := range b.results {
			expires := owned.backing.expires
			if earliest.IsZero() || expires.Before(earliest) {
				earliest = expires
			}
		}
		for _, op := range b.jobs {
			if op.terminal {
				continue
			}
			if earliest.IsZero() || op.deadline.Before(earliest) {
				earliest = op.deadline
			}
			for _, w := range op.waiters {
				if w.cancellation != nil {
					cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(w.cancellation)})
				}
				if !w.deadline.IsZero() && (earliest.IsZero() || w.deadline.Before(earliest)) {
					earliest = w.deadline
				}
			}
		}
		b.unlock()
		if abort != nil {
			b.transport.abortECM(abort)
		}
		if dispatch != nil {
			b.work <- dispatch
		}
		if exit {
			return
		}
		if timer != nil {
			timer.Stop()
			select {
			case <-timer.C():
			default:
			}
		}
		if !earliest.IsZero() {
			d := max(earliest.Sub(b.clock.Now()), 0)
			if timer == nil {
				timer = b.clock.NewTimer(d)
			} else {
				timer.Reset(d)
			}
			cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timer.C())})
			// Relative arming can race monotonic advancement. Recheck the absolute fence
			// after arming so an elapsed deadline never waits for another external event.
			if !b.clock.Now().Before(earliest) {
				b.notify()
			}
		}
		chosen, value, _ := reflect.Select(cases)
		if chosen == 1 {
			b.lock()
			// Recheck context/epochs at the completion fence before any private outcome.
			b.expireLocked(b.clock.Now())
			if !b.owner.current && !b.closed {
				b.closed = true
				b.retireCause = ecmStaleError
			}
			if b.closed {
				for _, op := range b.jobs {
					b.terminateLocked(op, b.retireCause)
				}
			}
			b.finishExchangeLocked(value.Interface().(ecmExchangeCompletion))
			b.unlock()
		}
	}
}
