// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"fmt"
	"reflect"
	"sort"

	"astrax/internal/model"
)

// Desired inventory never replaces a resource-bearing selection. Epochs fence
// new work independently of the applied revisions that keep its workers valid.
type dvbDesiredCard struct {
	target *model.DVBCard
	epoch  uint64
}
type dvbCardUpdate struct {
	next     map[string]model.DVBCard
	changed  map[string]bool
	physical map[physicalFrontendKey]bool
	done     chan struct{}
	end      func()
}
type dvbCardApplicationUpdate struct {
	serial      uint64
	id          string
	card        model.DVBCard
	application model.DVBCardApplication
}

func validateCardInventory(cards []model.DVBCard) (map[string]model.DVBCard, error) {
	next := make(map[string]model.DVBCard, len(cards))
	physical := make(map[physicalFrontendKey]string)
	for _, input := range cards {
		card := cloneDVBCard(input)
		if _, ok := next[card.ID]; ok {
			return nil, fmt.Errorf("duplicate DVB card ID %q", card.ID)
		}
		if err := validateSchedulerCardSnapshot(card); err != nil {
			return nil, err
		}
		if card.Config.DeviceKey != "" && card.Config.DeviceKey != card.ID {
			return nil, fmt.Errorf("card %q embedded config identity differs", card.ID)
		}
		if key, ok := canonicalPhysicalFrontendKey(card); ok {
			if id := physical[key]; id != "" {
				return nil, fmt.Errorf("physical frontend %s aliases %s and %s", card.Address, id, card.ID)
			}
			physical[key] = card.ID
		}
		next[card.ID] = card
	}
	return next, nil
}

func (s *dvbScheduler) desiredCardLocked(id string) (*model.DVBCard, uint64) {
	if d, ok := s.desiredCards[id]; ok {
		return d.target, d.epoch
	}
	if c, ok := s.cards[id]; ok {
		return &c, s.cardRevisions[id]
	}
	return nil, s.cardRevisions[id]
}
func sameCardSelection(a, b *model.DVBCard) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return cardSelectionFingerprint(*a) == cardSelectionFingerprint(*b)
}

// Preparation has no I/O and consumes no revisions. Entered synchronous calls
// wait at their publication boundary; abort restores precisely their old epoch.
func (s *dvbScheduler) prepareCardUpdate(cards []model.DVBCard) (*dvbCardUpdate, error) {
	next, err := validateCardInventory(cards)
	if err != nil {
		return nil, err
	}
	end, err := s.admit()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	fail := func(err error) (*dvbCardUpdate, error) { s.mu.Unlock(); end(); return nil, err }
	if s.isClosing() {
		return fail(ErrDVBSchedulerClosed)
	}
	if err := s.auditAndLatchLocked(); err != nil {
		return fail(err)
	}
	if s.cardUpdate != nil {
		return fail(schedulerError(ErrDVBSchedulerOwnership, "card publication already prepared"))
	}
	tx := &dvbCardUpdate{next: next, changed: make(map[string]bool), physical: make(map[physicalFrontendKey]bool), done: make(chan struct{}), end: end}
	ids := make(map[string]bool)
	for id := range s.cards {
		ids[id] = true
	}
	for id := range s.desiredCards {
		ids[id] = true
	}
	for id := range next {
		ids[id] = true
	}
	for id := range ids {
		old, _ := s.desiredCardLocked(id)
		var target *model.DVBCard
		if card, ok := next[id]; ok {
			target = &card
		}
		if sameCardSelection(old, target) {
			continue
		}
		tx.changed[id] = true
		for _, c := range []*model.DVBCard{old, target} {
			if c != nil {
				if p, ok := canonicalPhysicalFrontendKey(*c); ok {
					tx.physical[p] = true
				}
			}
		}
		if c, ok := s.cards[id]; ok {
			if p, ok := canonicalPhysicalFrontendKey(c); ok {
				tx.physical[p] = true
			}
		}
	}
	// Reserve enough revision space for desired epochs and all eventual promotions.
	if uint64(len(ids))*3 > ^uint64(0)-s.cardRevisionCounter {
		return fail(schedulerError(ErrDVBSchedulerOwnership, "card revision space exhausted"))
	}
	s.cardUpdate = tx
	s.mu.Unlock()
	return tx, nil
}
func (s *dvbScheduler) abortCardUpdate(tx *dvbCardUpdate) []dvbCardApplicationUpdate {
	s.mu.Lock()
	if s.cardUpdate == tx {
		s.cardUpdate = nil
		close(tx.done)
	}
	updates := s.applyIdleCardsLocked(nil)
	s.mu.Unlock()
	tx.end()
	return updates
}
func (s *dvbScheduler) cardUpdateFenceLocked(card model.DVBCard) *dvbCardUpdate {
	tx := s.cardUpdate
	if tx == nil {
		return nil
	}
	p, _ := canonicalPhysicalFrontendKey(card)
	if tx.changed[card.ID] || tx.physical[p] {
		return tx
	}
	return nil
}
func (s *dvbScheduler) lockCardPublication(session *tuningSession) {
	for {
		s.mu.Lock()
		tx := s.cardUpdateFenceLocked(session.card)
		if tx == nil {
			return
		}
		s.mu.Unlock()
		<-tx.done
	}
}

// Recovery depends on both the destination selection and its originating
// maintenance lease. A prepared source save must resolve before publication;
// an abort preserves the captured epoch rather than cancelling valid recovery.
func (s *dvbScheduler) lockStreamPublication(session *tuningSession, id string, generation uint64) {
	for {
		s.mu.Lock()
		tx := s.cardUpdateFenceLocked(session.card)
		reservation := s.streamReservations[id]
		if tx == nil && reservation.session == session && reservation.generation == generation && reservation.recoveryLease != nil {
			tx = s.cardUpdateFenceLocked(reservation.recoveryLease.card)
		}
		if tx == nil {
			return
		}
		s.mu.Unlock()
		<-tx.done
	}
}
func (s *dvbScheduler) cardAdmissionReasonLocked(card model.DVBCard) string {
	if s.cardUpdateFenceLocked(card) != nil {
		return "updating"
	}
	desired, _ := s.desiredCardLocked(card.ID)
	if desired == nil {
		return "removed"
	}
	if !desired.Present {
		return "offline"
	}
	if !desired.Config.Enabled {
		return "disabled"
	}
	if desired.Status == "busy_external" {
		return "busy_external"
	}
	if desired.Status == "error" || desired.LastError != "" {
		return "error"
	}
	if !sameCardSelection(&card, desired) {
		return "pending"
	}
	return ""
}
func (s *dvbScheduler) cardHeldLocked(id string, card *model.DVBCard, except *dvbCardOperationLease) bool {
	if _, ok := s.reservations[id]; ok {
		return true
	}
	if s.sessionByCard[id] != "" {
		return true
	}
	check := func(c model.DVBCard) bool {
		p, ok := canonicalPhysicalFrontendKey(c)
		if !ok {
			return false
		}
		return s.physicalReservations[p] != nil || s.cardOperations[p] != nil && s.cardOperations[p] != except
	}
	if old, ok := s.cards[id]; ok && check(old) {
		return true
	}
	return card != nil && check(*card)
}

// Called only after exact terminal ownership release, or under the authorized
// maintenance lease after teardown. It never opens, tunes or reconciles streams.
func (s *dvbScheduler) applyIdleCardsLocked(except *dvbCardOperationLease) []dvbCardApplicationUpdate {
	if s.health != nil {
		return nil
	}
	ids := make([]string, 0, len(s.desiredCards))
	for id := range s.desiredCards {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	changed := false
	updated := make(map[string]bool)
	// Remove obsolete unowned identities first so a rebind cannot introduce aliases.
	for _, id := range ids {
		d := s.desiredCards[id]
		old, ok := s.cards[id]
		if !ok || sameCardSelection(&old, d.target) || s.cardHeldLocked(id, d.target, except) {
			continue
		}
		if s.cardUpdateFenceLocked(old) != nil {
			continue
		}
		delete(s.cards, id)
		delete(s.cardFingerprints, id)
		s.cardRevisionCounter++
		s.cardRevisions[id] = s.cardRevisionCounter
		changed = true
		updated[id] = true
	}
	for _, id := range ids {
		d := s.desiredCards[id]
		old, exists := s.cards[id]
		if s.cardHeldLocked(id, d.target, except) {
			continue
		}
		if d.target != nil && s.cardUpdateFenceLocked(*d.target) != nil {
			continue
		}
		if d.target != nil {
			conflict := false
			p, present := canonicalPhysicalFrontendKey(*d.target)
			if present {
				for other, c := range s.cards {
					q, ok := canonicalPhysicalFrontendKey(c)
					if other != id && ok && p == q {
						conflict = true
						break
					}
				}
			}
			if conflict {
				continue
			}
			if !exists {
				s.cardRevisionCounter++
				s.cardRevisions[id] = s.cardRevisionCounter
				changed = true
				updated[id] = true
			}
			s.cards[id] = cloneDVBCard(*d.target)
			s.cardFingerprints[id] = cardSelectionFingerprint(*d.target)
		}
		if !exists && d.target == nil {
			continue
		}
		if d.target == nil || !sameCardSelection(&old, d.target) {
			updated[id] = true
		}
	}
	if changed {
		s.rebuildCardOrderLocked()
	}
	updates := make([]dvbCardApplicationUpdate, 0, len(updated))
	for _, id := range ids {
		if updated[id] {
			updates = append(updates, s.cardApplicationLocked(id))
		}
	}
	return updates
}
func (s *dvbScheduler) cardApplicationLocked(id string) dvbCardApplicationUpdate {
	u := s.cardApplicationViewLocked(id)
	s.cardApplicationCounter++
	u.serial = s.cardApplicationCounter
	return u
}
func (s *dvbScheduler) cardApplicationViewLocked(id string) dvbCardApplicationUpdate {
	desired, epoch := s.desiredCardLocked(id)
	applied, ok := s.cards[id]
	app := model.DVBCardApplication{DesiredRevision: epoch, SelectionRevision: s.cardRevisions[id], State: "current"}
	card := cloneDVBCard(applied)
	if desired != nil {
		card = cloneDVBCard(*desired)
	} else {
		card.Present = false
		card.Status = "offline"
	}
	if ok {
		cfg := applied.Config
		app.AppliedConfig = &cfg
	}
	if session := s.sessions[s.sessionByCard[id]]; session != nil && session.runtime != nil {
		card.CurrentTransport = cloneDVBStreamConfig(session.runtime.transport)
		card.ActiveSessions = 1
		card.ActiveStreams = len(session.runtime.attachments)
	}
	app.Reason = s.cardAdmissionReasonLocked(applied)
	if desired == nil {
		app.Reason = "removed"
	} else if !ok {
		app.Reason = "pending"
	}
	app.AdmissionBlocked = app.Reason != ""
	var appliedSelection *model.DVBCard
	if ok {
		appliedSelection = &applied
	}
	if !sameCardSelection(appliedSelection, desired) {
		app.State = "pending"
	}

	if s.health != nil {
		app.State = "failed"
		app.AdmissionBlocked = true
		app.Reason = "runtime_error"
		app.Error = s.health.Error()
	}
	return dvbCardApplicationUpdate{id: id, card: card, application: app}
}
func (s *dvbScheduler) commitCardUpdate(tx *dvbCardUpdate) []dvbCardApplicationUpdate {
	s.mu.Lock()
	if s.cardUpdate != tx {
		s.mu.Unlock()
		return nil
	}
	if s.desiredCards == nil {
		s.desiredCards = make(map[string]dvbDesiredCard)
	}
	ids := make(map[string]bool)
	for id := range s.cards {
		ids[id] = true
	}
	for id := range s.desiredCards {
		ids[id] = true
	}
	for id := range tx.next {
		ids[id] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	notify := make(map[string]bool)
	for _, id := range ordered {
		old, epoch := s.desiredCardLocked(id)
		var target *model.DVBCard
		if card, ok := tx.next[id]; ok {
			c := cloneDVBCard(card)
			target = &c
		}
		if tx.changed[id] {
			s.cardRevisionCounter++
			epoch = s.cardRevisionCounter
		}
		if !reflect.DeepEqual(old, target) {
			notify[id] = true
		}
		s.desiredCards[id] = dvbDesiredCard{target, epoch}
		if applied, ok := s.cards[id]; ok && sameCardSelection(&applied, target) {
			s.cards[id] = cloneDVBCard(*target)
		}
	}
	s.cardUpdate = nil
	idle := s.applyIdleCardsLocked(nil)
	for _, u := range idle {
		notify[u.id] = true
	}
	s.rebuildCardOrderLocked()
	for _, session := range s.ownedSessions {
		if tx.changed[session.cardID] || tx.physical[session.runtime.physical] {
			s.wakeSessionLocked(session)
		}
	}
	out := make([]dvbCardApplicationUpdate, 0, len(notify))
	for _, id := range ordered {
		if notify[id] {
			out = append(out, s.cardApplicationLocked(id))
		}
	}
	close(tx.done)
	s.mu.Unlock()
	tx.end()
	return out
}
func (s *dvbScheduler) publishCardApplications(updates []dvbCardApplicationUpdate) {
	if len(updates) > 0 && s.cardApplicationChanged != nil {
		s.cardApplicationChanged(updates)
	}
}
