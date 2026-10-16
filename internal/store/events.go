// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"strings"
	"sync"
	"time"

	"astrax/internal/model"
)

const defaultEventBuffer = 64
const maxEventBuffer = 256

type eventSubscriber struct {
	queue       chan model.ResourceEvent
	needsResync bool
}
type storeEventBus struct {
	mu             sync.Mutex
	subscribers    map[int]*eventSubscriber
	revisions      map[string]uint64
	nextSubscriber int
	nextEvent      uint64
	closed         bool
}

// SubscribeEvents defaults to 64 queued deltas and caps requests at 256. An
// overflowed subscription yields one resync_required marker and remains latched;
// take a fresh snapshot and resubscribe rather than treating partial deltas as complete.
func (s *Store) SubscribeEvents(buffer int) (int, <-chan model.ResourceEvent) {
	id, _, ch := s.SubscribeEventsWithRevision(buffer)
	return id, ch
}

// SubscribeEventsWithRevision installs the subscription and reads its starting
// revision under one bus lock, so a ready frame cannot hide an intervening delta.
func (s *Store) SubscribeEventsWithRevision(buffer int) (int, uint64, <-chan model.ResourceEvent) {
	if buffer <= 0 {
		buffer = defaultEventBuffer
	}
	if buffer > maxEventBuffer {
		buffer = maxEventBuffer
	}
	ch := make(chan model.ResourceEvent, buffer)
	end, err := s.admitRuntime()
	if err != nil {
		close(ch)
		return -1, 0, ch
	}
	defer end()
	b := &s.events
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		close(ch)
		return -1, b.nextEvent, ch
	}
	if b.subscribers == nil {
		b.subscribers = make(map[int]*eventSubscriber)
	}
	id := b.nextSubscriber
	b.nextSubscriber++
	b.subscribers[id] = &eventSubscriber{queue: ch}
	return id, b.nextEvent, ch
}
func (s *Store) UnsubscribeEvents(id int) {
	b := &s.events
	b.mu.Lock()
	defer b.mu.Unlock()
	if sub := b.subscribers[id]; sub != nil {
		delete(b.subscribers, id)
		close(sub.queue)
	}
}

// PublishEvent admits one lifetime through both publication and observation.
// Observer callbacks must not join Close, which waits for admitted lifetimes.
func (s *Store) PublishEvent(kind, resourceID string, payload any) {
	end, err := s.admitRuntime()
	if err != nil {
		return
	}
	defer end()
	if event, ok := s.queueEvent(kind, resourceID, payload); ok {
		s.emitQueuedEvent(event)
	}
}

// queueEvent requires an already admitted lifetime. Store.mu -> bus.mu is the
// only permitted lock order; this path never takes Store/lifetime locks, invokes
// hooks (including the injected clock), or calls observers. Queue while the
// relevant committed state is locked; emit only after releasing those locks.
func (s *Store) queueEvent(kind, resourceID string, payload any) (model.ResourceEvent, bool) {
	owned, wire, wireErr := prepareEventPayload(kind, payload)
	now := time.Now().UTC()
	b := &s.events
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return model.ResourceEvent{}, false
	}
	if b.revisions == nil {
		b.revisions = make(map[string]uint64)
	}
	family := kind
	if i := strings.LastIndexByte(kind, '.'); i >= 0 {
		family = kind[:i]
	}
	key := family + "\x00" + resourceID
	b.nextEvent++
	b.revisions[key]++
	event := model.ResourceEvent{ID: b.nextEvent, Kind: strings.Clone(kind), ResourceID: strings.Clone(resourceID), Revision: b.revisions[key], Payload: owned, At: now}
	queued := event
	queued.Payload = wire
	if wireErr == nil {
		_, wireErr = model.ResourceEventFrame(queued)
	}
	for _, sub := range b.subscribers {
		if sub.needsResync {
			continue
		}
		if wireErr == nil {
			select {
			case sub.queue <- queued:
				continue
			default:
			}
		}
		sub.needsResync = true
		for len(sub.queue) > 0 {
			select {
			case <-sub.queue:
			default:
			}
		}
		sub.queue <- model.ResourceEvent{ID: event.ID, Kind: "resync_required", At: now}
	}
	return event, true
}

// emitQueuedEvent must be called outside Store and bus locks, with the caller's
// admitted lifetime retained until Emit returns. The observer never sees wire DTOs.
func (s *Store) emitQueuedEvent(event model.ResourceEvent) {
	if s.runtimeDeps != nil {
		s.runtimeDeps.Emit(event)
	}
}
func (s *Store) closeEvents() {
	b := &s.events
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for id, sub := range b.subscribers {
		close(sub.queue)
		delete(b.subscribers, id)
	}
}
