// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"astrax/internal/model"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

func cardSelectionFingerprint(card model.DVBCard) tuningKey {
	card = cloneDVBCard(card)
	card.Manufacturer = ""
	card.Model = ""
	card.Signal = nil
	card.CurrentTransport = nil
	card.ActiveSessions = 0
	card.ActiveStreams = 0
	card.Warning = ""
	card.OwnerPID = 0
	card.OwnerCommand = ""
	// Serialize only selection inputs, not display/runtime metadata.
	payload := struct {
		ID, DeviceKey, Address, FrontendType, SysfsPath, DevicePath, Status string
		Adapter, Frontend                                                   int
		Present, Enabled                                                    bool
		Error                                                               bool
		Delivery                                                            []string
		RF                                                                  model.AdapterLNBConfig
		Advanced                                                            model.AdapterAdvancedConfig
	}{card.ID, card.DeviceKey, card.Address, card.FrontendType, card.SysfsPath, card.DevicePath, card.Status, card.Adapter, card.Frontend,
		card.Present, card.Config.Enabled, card.LastError != "", card.DeliverySystems, card.Config.RFDefaults, card.Config.Advanced}
	if payload.Status == "active" {
		payload.Status = "available"
	}
	payload.Advanced.EnableMonitoring = false
	// Timeout is validated but not emitted into dvb.Config. Positive values
	// must not retire an opener; an invalid negative default changes eligibility.
	if payload.Advanced.TimeoutSec >= 0 {
		payload.Advanced.TimeoutSec = 0
	}
	data, _ := json.Marshal(payload)
	return sha256.Sum256(data)
}
func (s *dvbScheduler) rebuildCardOrderLocked() {
	s.cardOrder = make([]string, 0, len(s.cards))
	s.cardsByAddress = make(map[string][]string)
	for id := range s.cards {
		s.cardOrder = append(s.cardOrder, id)
	}
	if s.counters != nil {
		s.counters.Sorts++
	}
	sort.Slice(s.cardOrder, func(i, j int) bool {
		if s.counters != nil {
			s.counters.Comparisons++
		}
		return compareDVBCardDefault(s.cards[s.cardOrder[i]], s.cards[s.cardOrder[j]]) < 0
	})
	for _, id := range s.cardOrder {
		card := s.cards[id]
		s.cardsByAddress[card.Address] = append(s.cardsByAddress[card.Address], id)
	}
}
func (s *dvbScheduler) rebuildSessionOrderLocked() {
	s.sessionOrderByKey = make(map[tuningKey][]string)
	for key, bucket := range s.sessionsByKey {
		ids := make([]string, 0, len(bucket))
		for id := range bucket {
			ids = append(ids, id)
		}
		if s.counters != nil {
			s.counters.Sorts++
		}
		sort.Slice(ids, func(i, j int) bool {
			if s.counters != nil {
				s.counters.Comparisons++
			}
			a, b := s.sessions[ids[i]], s.sessions[ids[j]]
			if a == nil || b == nil {
				return ids[i] < ids[j]
			}
			n := compareDVBCardDefault(a.card, b.card)
			return n < 0 || n == 0 && ids[i] < ids[j]
		})
		s.sessionOrderByKey[key] = ids
	}
}
func (s *dvbScheduler) ReplaceCards(cards []model.DVBCard) error {
	end, err := s.admit()
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health != nil {
		return s.health
	}
	if s.isClosing() {
		return ErrDVBSchedulerClosed
	}
	if err := s.auditAndLatchLocked(); err != nil {
		return err
	}
	if s.cardUpdate != nil {
		return schedulerError(ErrDVBSchedulerOwnership, "card publication already prepared")
	}
	next, err := validateCardInventory(cards)
	if err != nil {
		return err
	}
	fingerprints := make(map[string]tuningKey, len(next))
	for id, card := range next {
		fingerprints[id] = cardSelectionFingerprint(card)
	}
	for id, sessionID := range s.sessionByCard {
		session := s.sessions[sessionID]
		if session == nil {
			return s.latchCorruptLocked(fmt.Errorf("missing active session %q", sessionID))
		}
		card, ok := next[id]
		if !ok || cardSelectionFingerprint(s.cards[id]) != fingerprints[id] {
			return schedulerError(ErrDVBSchedulerOwnership, "active card must be torn down before inventory removal or selection change")
		}
		if err := s.validateSessionSnapshotWithCardOverrideLocked(session, &card); err != nil {
			return err
		}
	}
	// All rejection paths precede revision allocation and the single inventory swap.
	changed := make(map[string]bool)
	for id := range s.cards {
		if _, ok := next[id]; !ok {
			changed[id] = true
		}
	}
	for id, fp := range fingerprints {
		if _, exists := s.cards[id]; !exists || s.cardFingerprints[id] != fp {
			changed[id] = true
		}
	}
	// A strict replacement also replaces any staged desired inventory, without
	// changing an active applied revision when it only cancels a pending edit.
	var desired map[string]dvbDesiredCard
	desiredChanged := make(map[string]bool)
	allocate := make(map[string]bool, len(changed))
	for id := range changed {
		allocate[id] = true
	}
	if s.desiredCards != nil {
		desired = make(map[string]dvbDesiredCard, len(s.desiredCards)+len(next))
		for id, d := range s.desiredCards {
			desired[id] = dvbDesiredCard{epoch: d.epoch}
		}
		for id, card := range next {
			_, epoch := s.desiredCardLocked(id)
			c := cloneDVBCard(card)
			desired[id] = dvbDesiredCard{target: &c, epoch: epoch}
		}
		for id, d := range desired {
			old, _ := s.desiredCardLocked(id)
			if !sameCardSelection(old, d.target) {
				desiredChanged[id] = true
				allocate[id] = true
			}
		}
	}
	if uint64(len(allocate)) > ^uint64(0)-s.cardRevisionCounter {
		return schedulerError(ErrDVBSchedulerOwnership, "card revision space exhausted")
	}
	ids := make([]string, 0, len(allocate))
	for id := range allocate {
		ids = append(ids, id)
	}
	if s.counters != nil {
		s.counters.Sorts++
	}
	sort.Slice(ids, func(i, j int) bool {
		if s.counters != nil {
			s.counters.Comparisons++
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids {
		s.cardRevisionCounter++
		if changed[id] {
			s.cardRevisions[id] = s.cardRevisionCounter
		}
		if desiredChanged[id] {
			d := desired[id]
			d.epoch = s.cardRevisionCounter
			desired[id] = d
		}
	}
	s.desiredCards = desired
	s.cards = next
	s.cardFingerprints = fingerprints
	s.runtimeMode = true
	s.rebuildCardOrderLocked()
	for id := range changed {
		if reservation, ok := s.reservations[id]; ok {
			session := s.ownedSessions[fmt.Sprintf("dvb-session-%d", reservation.generation)]
			if session != nil && session.cardID == id {
				s.wakeSessionLocked(session)
			}
		}
	}
	return nil
}

// auditLocked does not mutate ownership or health. Diagnostics are counted by the caller.
func (s *dvbScheduler) auditLocked() error {
	if err := s.validateCardMapKeysLocked(); err != nil {
		return err
	}
	for _, card := range s.cards {
		if err := validateSchedulerCardSnapshot(card); err != nil {
			return err
		}
	}
	if err := s.validatePhysicalFrontendInventoryLocked(nil); err != nil {
		return err
	}
	if err := s.validateSessionIndexStateLocked(s.sessionIndexStateViewLocked()); err != nil {
		return err
	}
	for id, a := range s.attachments {
		if a == nil || id != a.id || !s.attachmentCoherentLocked(a) {
			return fmt.Errorf("incoherent attachment %q", id)
		}
	}
	for token, a := range s.subscriptions {
		if a == nil || token != a.subscription || s.attachments[a.id] != a {
			return errors.New("orphan subscription token")
		}
	}
	for token, a := range s.sinkTokens {
		if a == nil || token != a.sinkToken || s.attachments[a.id] != a {
			return errors.New("orphan sink token")
		}
	}
	for id, session := range s.ownedSessions {
		if session == nil || session.id != id || session.runtime == nil {
			return errors.New("incoherent primary resource")
		}
		r := session.runtime
		if s.physicalReservations[r.physical] != session {
			return errors.New("missing exact physical reservation")
		}
		if r.ready && !r.closing && (s.sessions[id] != session || s.sessionByPhysical[r.physical] != session) {
			return errors.New("resource publication index mismatch")
		}
		for streamID, a := range r.attachments {
			if a == nil || a.id != streamID || a.session != session || s.attachments[streamID] != a {
				return errors.New("resource attachment mismatch")
			}
		}
	}
	for key, session := range s.sessionByPhysical {
		if session == nil || session.runtime == nil || session.runtime.physical != key || s.sessions[session.id] != session {
			return errors.New("orphan physical session index")
		}
	}
	for key, session := range s.physicalReservations {
		if session == nil || session.runtime == nil || session.runtime.physical != key || s.ownedSessions[session.id] != session {
			return errors.New("orphan physical reservation")
		}
	}

	if s.runtimeMode {
		pending := make(map[*tuningSession]int)
		generations := make(map[uint64]bool, len(s.streamReservations))
		for id, reservation := range s.streamReservations {
			session := reservation.session
			if validStreamID(id) != nil || session == nil || session.runtime == nil || s.ownedSessions[session.id] != session ||
				reservation.generation == 0 || reservation.generation > s.generation || generations[reservation.generation] {
				return errors.New("orphan or incoherent stream reservation")
			}
			generations[reservation.generation] = true
			pending[session]++
		}
		for _, session := range s.ownedSessions {
			if session.runtime.pending != pending[session] {
				return errors.New("pending attachment count differs from exact reservations")
			}
		}
		ordered := make(map[string]bool, len(s.cardOrder))
		for i, id := range s.cardOrder {
			card, ok := s.cards[id]
			if !ok || ordered[id] {
				return errors.New("card order membership mismatch")
			}
			if i > 0 && compareDVBCardDefault(s.cards[s.cardOrder[i-1]], card) >= 0 {
				return errors.New("card order is not canonical")
			}
			ordered[id] = true
		}
		if len(ordered) != len(s.cards) {
			return errors.New("incomplete card order")
		}
		addressed := make(map[string]bool, len(s.cards))
		for address, ids := range s.cardsByAddress {
			for _, id := range ids {
				card, ok := s.cards[id]
				if !ok || addressed[id] || card.Address != address {
					return errors.New("card address index mismatch")
				}
				addressed[id] = true
			}
		}
		if len(addressed) != len(s.cards) {
			return errors.New("incomplete card address index")
		}
		used := make(map[uint64]bool, len(s.cardRevisions))
		for id, revision := range s.cardRevisions {
			if id == "" || revision == 0 || revision > s.cardRevisionCounter || used[revision] {
				return errors.New("card revision tombstone mismatch")
			}
			used[revision] = true
		}
		for id, card := range s.cards {
			if s.cardRevisions[id] == 0 || s.cardFingerprints[id] != cardSelectionFingerprint(card) {
				return errors.New("live card revision/fingerprint mismatch")
			}
		}
		if len(s.cardFingerprints) != len(s.cards) {
			return errors.New("orphan card fingerprint")
		}
		if len(s.sessionOrderByKey) != len(s.sessionsByKey) {
			return errors.New("session order bucket count mismatch")
		}
		for key, bucket := range s.sessionsByKey {
			seen := make(map[string]bool, len(bucket))
			ids := s.sessionOrderByKey[key]
			for i, id := range ids {
				if _, ok := bucket[id]; !ok || seen[id] {
					return errors.New("session order membership mismatch")
				}
				seen[id] = true
				if i > 0 {
					previous, current := s.sessions[ids[i-1]], s.sessions[id]
					n := compareDVBCardDefault(previous.card, current.card)
					if n > 0 || n == 0 && previous.id >= current.id {
						return errors.New("session order is not canonical")
					}
				}
			}
			if len(seen) != len(bucket) {
				return errors.New("incomplete session order")
			}
		}
		for id, session := range s.sessions {
			if session.runtime == nil || s.ownedSessions[id] != session {
				return errors.New("published session has no resource owner")
			}
			r := session.runtime
			if r.cardRevision != s.cardRevisions[session.cardID] || r.generation == 0 || r.generation > s.generation ||
				r.inputGeneration != r.generation || r.catalog == nil || r.demux == nil || r.catalog != r.demux.catalog ||
				r.pending < 0 || len(session.streamIDs) != len(r.attachments) {
				return errors.New("session generation or attachment count mismatch")
			}
		}
		for cardID, reservation := range s.reservations {
			session := s.ownedSessions[fmt.Sprintf("dvb-session-%d", reservation.generation)]
			if session == nil || session.cardID != cardID || session.key != reservation.key || session.runtime.ready {
				return errors.New("orphan creation reservation")
			}
		}
		for _, session := range s.ownedSessions {
			if !session.runtime.ready {
				reservation, ok := s.reservations[session.cardID]
				if !ok || reservation.generation != session.runtime.generation || reservation.key != session.key {
					return errors.New("unpublished resource lacks creation reservation")
				}
			}
		}
	}
	return nil
}
func (s *dvbScheduler) auditAndLatchLocked() error {
	if s.health != nil {
		return s.health
	}
	if s.counters != nil {
		s.counters.FullAudits++
	}
	if err := s.auditLocked(); err != nil {
		return s.latchCorruptLocked(fmt.Errorf("scheduler indexes are inconsistent: %w", err))
	}
	return nil
}
func (s *dvbScheduler) attachmentCoherentLocked(a *streamAttachment) bool {
	if s.counters != nil {
		s.counters.AttachmentVisits++
		s.counters.ReverseVisits += 10
	}
	if a == nil || a.id == "" || a.generation == 0 || a.session == nil || a.session.runtime == nil {
		return false
	}
	session := a.session
	r := session.runtime
	_, member := session.streamIDs[a.id]
	_, bucket := s.sessionsByKey[session.key][session.id]
	source, sourceOK := a.source.(*streamPacketSource)
	outputOK := a.outputSource == source
	if descramblingEnabled(a.stream) {
		out, ok := a.outputSource.(*dvbDescramblingSource)
		outputOK = ok && out != nil && out.tap != nil && out.output != nil && out.base == source && out.tap.sd == r.demux &&
			out.inputGeneration == r.inputGeneration && out.tap.key.InputID == session.id && out.tap.key.InputGeneration == r.inputGeneration && a.stream.DVB != nil &&
			out.tap.key.ServiceID == uint16(a.stream.DVB.ServiceID) && out.tap.key.ProfileID == a.stream.SoftcamID
	}
	return member && bucket && sourceOK && source != nil && a.baseSource == source && outputOK &&
		r.inputGeneration != 0 && r.inputGeneration == r.generation && r.catalog != nil && r.demux != nil && r.catalog == r.demux.catalog &&
		source.sd == r.demux && source.id == a.subscription &&
		a.subscription == fmt.Sprintf("%s@%d", a.id, a.generation) &&
		s.attachments[a.id] == a && s.streamSessions[a.id] == session.id && s.sessions[session.id] == session &&
		s.ownedSessions[session.id] == session && s.sessionByCard[session.cardID] == session.id &&
		s.sessionByPhysical[r.physical] == session && s.physicalReservations[r.physical] == session &&
		r.attachments[a.id] == a && s.subscriptions[a.subscription] == a && a.sinkToken.StreamID == a.id &&
		a.sinkToken.Generation != 0 && s.sinkTokens[a.sinkToken] == a
}

func servicePIDs(stream model.Stream) ([]int, error) {
	cfg := cloneDVBStreamConfig(stream.DVB)
	if cfg == nil {
		return nil, errors.New("structured DVB configuration is required")
	}
	cfg.Normalize()
	seen := make(map[int]bool)
	out := make([]int, 0, len(cfg.AudioPIDs)+2)
	for _, pid := range append([]int{cfg.PCRPID, cfg.VideoPID}, cfg.AudioPIDs...) {
		if pid < 0 || pid > 8191 {
			return nil, fmt.Errorf("PID %d is outside 0..8191", pid)
		}
		if pid != 0 && !seen[pid] {
			seen[pid] = true
			out = append(out, pid)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("service has no non-zero PID")
	}
	return out, nil
}
func validStreamID(id string) error {
	if id == "" || strings.TrimSpace(id) != id {
		return errors.New("stream ID must be non-empty and trimmed")
	}
	return nil
}
