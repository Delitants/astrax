// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"sort"

	"astrax/internal/model"
)

// A maintenance lease fences the physical frontend even if inventory identity
// changes. Only the restart worker's gate-held recovery IDs may place on it.
type dvbCardOperationLease struct {
	desired        model.DVBCard
	admissionEpoch uint64
	card           model.DVBCard
	physical       physicalFrontendKey
	revision       uint64
	relocations    map[string]map[string]tuningKey
	recovery       map[string]bool
	attached       map[string]*streamAttachment
	end            func()
}

func (s *dvbScheduler) cardOperationBlockedLocked(card model.DVBCard, id string) bool {
	if s.cardAdmissionReasonLocked(card) != "" {
		return true
	}
	physical, ok := canonicalPhysicalFrontendKey(card)
	if !ok {
		return false
	}
	lease := s.cardOperations[physical]
	if lease != nil && (!lease.recovery[id] || s.cardOperationCurrentLocked(lease) != nil) {
		return true
	}
	for _, operation := range s.cardOperations {
		if allowed, relocating := operation.relocations[id]; relocating {
			if s.cardOperationCurrentLocked(operation) != nil {
				return true
			}
			if fingerprint, ok := allowed[card.ID]; !ok || fingerprint != cardSelectionFingerprint(card) {
				return true
			}
		}
	}
	return false
}

func (s *dvbScheduler) reserveCardOperation(cardID string, scan *model.Stream) (*dvbCardOperationLease, error) {
	end, err := s.admit()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	lease, err := s.reserveCardOperationLocked(cardID, scan)
	s.mu.Unlock()
	if err != nil {
		end()
		return nil, err
	}
	lease.end = end
	return lease, nil
}

func (s *dvbScheduler) reserveCardOperationLocked(cardID string, scan *model.Stream) (*dvbCardOperationLease, error) {
	if s.health != nil {
		return nil, s.health
	}
	if s.isClosing() {
		return nil, ErrDVBSchedulerClosed
	}
	var card model.DVBCard
	if scan == nil {
		var ok bool
		card, ok = s.cards[cardID]
		if !ok {
			return nil, ErrDVBCardNotFound
		}
	} else if scan.DVB.Adapter.Mode == "fixed" {
		var err error
		card, err = s.fixedTargetLocked(scan.DVB.Adapter)
		if err != nil {
			return nil, err
		}
	} else {
		for _, id := range s.cardOrder {
			candidate := s.cards[id]
			if s.cardOperationBlockedLocked(candidate, "") || !s.autoCardIdleLocked(candidate, scan.DVB.DeliverySystem) {
				continue
			}
			if _, err := resolveTune(*scan, candidate); err != nil {
				continue
			}
			card = candidate
			break
		}
		if card.ID == "" {
			return nil, ErrNoDVBCardAvailable
		}
	}
	desired, epoch := s.desiredCardLocked(card.ID)
	reason := s.cardAdmissionReasonLocked(card)
	if reason == "busy_external" {
		return nil, ErrCardExternallyBusy
	}
	if reason != "" && (reason != "pending" || scan != nil) {
		return nil, fixedCardConflict(card, reason, "")
	}
	if desired == nil {
		return nil, ErrDVBCardNotFound
	}
	physical, _ := canonicalPhysicalFrontendKey(card)
	if p, ok := canonicalPhysicalFrontendKey(*desired); !ok || p != physical {
		return nil, ErrDVBSchedulerSuperseded
	}
	if card.Status == "busy_external" {
		return nil, ErrCardExternallyBusy
	}
	if err := validateSchedulerTunableCardSnapshot(card); err != nil {
		return nil, err
	}
	if !card.Config.Enabled {
		return nil, fixedCardConflict(card, "disabled", "")
	}
	if !s.cardLocalCoherentLocked(card.ID) {
		return nil, s.health
	}
	if s.cardOperations[physical] != nil {
		return nil, fixedCardConflict(card, "reserved", "card operation in progress")
	}
	if _, ok := s.reservations[card.ID]; ok {
		return nil, fixedCardConflict(card, "reserved", "pending stream operation")
	}
	lease := &dvbCardOperationLease{desired: cloneDVBCard(*desired), admissionEpoch: epoch, card: cloneDVBCard(card), physical: physical, revision: s.cardRevisions[card.ID], recovery: make(map[string]bool), attached: make(map[string]*streamAttachment)}
	if scan != nil {
		if reason, detail := fixedCardUnavailableReason(card, scan.DVB.DeliverySystem); reason != "" {
			return nil, fixedCardConflict(card, reason, detail)
		}
		if _, err := resolveTune(*scan, card); err != nil {
			return nil, err
		}
		if !s.autoCardIdleLocked(card, scan.DVB.DeliverySystem) {
			return nil, fixedCardConflict(card, "reserved", "scan requires an idle frontend")
		}
	} else if session := s.physicalReservations[physical]; session != nil {
		r := session.runtime
		if r == nil || !r.ready || r.pending != 0 || r.retiring || r.closing {
			return nil, fixedCardConflict(card, "reserved", "stream lifecycle in progress")
		}
		for id, a := range r.attachments {
			if !s.attachmentCoherentLocked(a) || a.retiring {
				return nil, schedulerError(ErrDVBSchedulerOwnership, "attachment not stable for restart")
			}
			lease.attached[id] = a
		}
	} else if s.sessionByCard[card.ID] != "" || card.ActiveSessions > 0 || card.CurrentTransport != nil || card.Status == "active" {
		return nil, fixedCardConflict(card, "reserved", "no exact AstraX owner")
	}
	if s.cardOperations == nil {
		s.cardOperations = make(map[physicalFrontendKey]*dvbCardOperationLease)
	}
	s.cardOperations[physical] = lease
	return lease, nil
}

func (s *dvbScheduler) releaseCardOperation(lease *dvbCardOperationLease) {
	s.mu.Lock()
	if s.cardOperations[lease.physical] == lease {
		delete(s.cardOperations, lease.physical)
	}
	updates := s.applyIdleCardsLocked(nil)
	s.mu.Unlock()
	s.publishCardApplications(updates)
	lease.end()
}

func (s *dvbScheduler) cardOperationCurrent(lease *dvbCardOperationLease) error {
	s.lockCardPublication(&tuningSession{card: lease.card})
	defer s.mu.Unlock()
	return s.cardOperationCurrentLocked(lease)
}
func (s *dvbScheduler) cardOperationCurrentLocked(lease *dvbCardOperationLease) error {
	if s.health != nil {
		return s.health
	}
	if s.isClosing() {
		return ErrDVBSchedulerClosed
	}
	_, epoch := s.desiredCardLocked(lease.card.ID)
	if s.cardUpdateFenceLocked(lease.card) != nil || epoch != lease.admissionEpoch || s.cardOperations[lease.physical] != lease || s.cardRevisions[lease.card.ID] != lease.revision {
		return ErrDVBSchedulerSuperseded
	}
	card, ok := s.cards[lease.card.ID]
	physical, present := canonicalPhysicalFrontendKey(card)
	if !ok || !present || physical != lease.physical {
		return ErrDVBSchedulerSuperseded
	}
	if card.Status == "busy_external" {
		return ErrCardExternallyBusy
	}
	return nil
}

func (s *dvbScheduler) restartAttachmentCurrent(lease *dvbCardOperationLease, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attachments[id] == lease.attached[id] && lease.attached[id] != nil
}

func (s *dvbScheduler) allowCardRecovery(lease *dvbCardOperationLease, id string) {
	s.mu.Lock()
	lease.recovery[id] = true
	s.mu.Unlock()
}

// The restart has joined every recovery call and still holds its Store stream
// gates. Retire its permissions before a queued successor acquires those gates;
// the physical maintenance lease remains held until releaseCardOperation.
func (s *dvbScheduler) retireCardRecovery(lease *dvbCardOperationLease) {
	s.mu.Lock()
	clear(lease.recovery)
	clear(lease.relocations)
	s.mu.Unlock()
}

// Keep the failed target fenced and constrain ordinary Auto selection to the
// fresh, conservative inventory. The caller holds this stream's Store gate.
func (s *dvbScheduler) allowCardRelocation(lease *dvbCardOperationLease, id string, allowed map[string]tuningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health != nil {
		return s.health
	}
	if s.isClosing() {
		return ErrDVBSchedulerClosed
	}
	_, epoch := s.desiredCardLocked(lease.card.ID)
	if s.cardUpdateFenceLocked(lease.card) != nil || epoch != lease.admissionEpoch || s.cardOperations[lease.physical] != lease || s.cardRevisions[lease.card.ID] != lease.revision {
		return ErrDVBSchedulerSuperseded
	}
	if lease.relocations == nil {
		lease.relocations = make(map[string]map[string]tuningKey)
	}
	lease.relocations[id] = allowed
	return nil
}

func (l *dvbCardOperationLease) ids() []string {
	ids := make([]string, 0, len(l.attached))
	for id := range l.attached {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

var ErrCardExternallyBusy = errors.New("DVB card is owned by another process")

func (s *dvbScheduler) applyCardUnderLease(lease *dvbCardOperationLease) error {
	s.lockCardPublication(&tuningSession{card: lease.card})
	if err := s.cardOperationCurrentLocked(lease); err != nil {
		s.mu.Unlock()
		return err
	}
	target, epoch := s.desiredCardLocked(lease.card.ID)
	if target == nil || epoch != lease.admissionEpoch || !target.Present || !target.Config.Enabled || target.Status == "busy_external" || target.Status == "error" || target.LastError != "" {
		s.mu.Unlock()
		return ErrDVBSchedulerSuperseded
	}
	if s.cardHeldLocked(lease.card.ID, target, lease) {
		s.mu.Unlock()
		return schedulerError(ErrDVBSchedulerOwnership, "restart teardown is not terminal")
	}
	updates := s.applyIdleCardsLocked(lease)
	card, ok := s.cards[lease.card.ID]
	if !ok || !sameCardSelection(&card, target) {
		s.mu.Unlock()
		return ErrDVBSchedulerSuperseded
	}
	lease.card = cloneDVBCard(card)
	lease.revision = s.cardRevisions[card.ID]
	s.mu.Unlock()
	s.publishCardApplications(updates)
	return nil
}
