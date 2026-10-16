// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/packetbudget"
	"astrax/internal/softcam"
)

type tuningKey [sha256.Size]byte

type physicalFrontendKey struct {
	adapter  int
	frontend int
	address  string
}

type resolvedTune struct {
	config         dvb.Config
	adapterMode    string
	fixedDeviceKey string
	fixedAddress   string
}

type cardSelection struct {
	card      model.DVBCard
	config    dvb.Config
	key       tuningKey
	sessionID string
	shared    bool
}

type cardResolutionFailure struct {
	card      model.DVBCard
	sessionID string
	err       error
}

type cardReservation struct {
	key        tuningKey
	generation uint64
}

// tuningSession is the authoritative transport owner. Metadata-only Task 7
// fixtures leave runtime nil; a resource-bearing owner is never cloned.
type tuningSession struct {
	id        string
	key       tuningKey
	cardID    string
	card      model.DVBCard
	config    dvb.Config
	healthy   bool
	streamIDs map[string]struct{}
	runtime   *dvbSessionRuntime
}

type dvbScheduler struct {
	// Installed once, before input/session admission, with guarded resources.
	descramblingHookup     bool
	acquireDescrambling    descramblingAcquire
	descrambling           *softcam.DescramblingRegistry
	descramblingPreparing  bool
	packetBudget           *packetbudget.Budget
	cardApplicationCounter uint64
	desiredCards           map[string]dvbDesiredCard
	cardUpdate             *dvbCardUpdate
	cardApplicationChanged func([]dvbCardApplicationUpdate)
	cardOperations         map[physicalFrontendKey]*dvbCardOperationLease
	mu                     sync.Mutex

	opener dvb.SessionOpener
	sink   schedulerStreamSink
	emit   func(model.ResourceEvent)

	cards                map[string]model.DVBCard
	sessions             map[string]*tuningSession
	sessionsByKey        map[tuningKey]map[string]struct{}
	sessionByCard        map[string]string
	reservations         map[string]cardReservation
	streamSessions       map[string]string
	lifecycle            *dvbSchedulerLifecycle
	runtimeMode          bool
	health               error
	counters             *dvbSchedulerCounters
	cardOrder            []string
	cardsByAddress       map[string][]string
	sessionOrderByKey    map[tuningKey][]string
	cardRevisions        map[string]uint64
	cardFingerprints     map[string]tuningKey
	cardRevisionCounter  uint64
	generation           uint64
	streamReservations   map[string]dvbStreamReservation
	sessionByPhysical    map[physicalFrontendKey]*tuningSession
	physicalReservations map[physicalFrontendKey]*tuningSession
	ownedSessions        map[string]*tuningSession
	attachments          map[string]*streamAttachment
	subscriptions        map[string]*streamAttachment
	sinkTokens           map[sinkRegistrationToken]*streamAttachment
	removePublication    func(string, uint64) error
	closingCleanupErrors []error
}

var (
	ErrNoDVBCardAvailable = errors.New("no compatible DVB card is available")
	ErrDVBCardNotFound    = errors.New("DVB card not found")
)

// DVBCardConflictError is returned when fixed placement cannot use its exact
// target and moving to another card would violate policy.
type DVBCardConflictError struct {
	CardID    string
	DeviceKey string
	Address   string
	Reason    string
	Detail    string
}

func (e *DVBCardConflictError) Error() string {
	message := fmt.Sprintf("fixed DVB card %q at %s conflicts: %s", e.CardID, e.Address, e.Reason)
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

// Runtime use requires exact-token sink ownership and a sink lifetime extending
// through scheduler Close. Store must finish its callbacks/actions and scheduler
// cleanup before Streamer Shutdown, including constructor rollback.
func newDVBScheduler(opener dvb.SessionOpener, sink schedulerStreamSink, emit func(model.ResourceEvent)) *dvbScheduler {
	if emit == nil {
		emit = func(model.ResourceEvent) {}
	}
	s := &dvbScheduler{
		opener:         opener,
		sink:           sink,
		emit:           emit,
		cards:          make(map[string]model.DVBCard),
		sessions:       make(map[string]*tuningSession),
		sessionsByKey:  make(map[tuningKey]map[string]struct{}),
		sessionByCard:  make(map[string]string),
		reservations:   make(map[string]cardReservation),
		streamSessions: make(map[string]string),
	}
	s.initRuntimeState()
	return s
}

func validateSchedulerCardSnapshot(card model.DVBCard) error {
	if card.ID == "" || card.ID != strings.TrimSpace(card.ID) {
		return errors.New("DVB card ID must be non-empty and trimmed")
	}
	if card.Adapter < 0 || card.Frontend < 0 {
		return fmt.Errorf("DVB card %q adapter/frontend must be non-negative", card.ID)
	}
	if card.DeviceKey != strings.TrimSpace(card.DeviceKey) {
		return fmt.Errorf("DVB card %q device_key must be trimmed", card.ID)
	}
	if card.Address == "" {
		switch {
		case card.Present:
			return fmt.Errorf("DVB card %q cannot be present without an address", card.ID)
		case card.Status != "offline":
			return fmt.Errorf("addressless DVB card %q must be offline", card.ID)
		case card.Adapter != 0 || card.Frontend != 0:
			return fmt.Errorf("addressless DVB card %q must use zero adapter/frontend placeholders", card.ID)
		case card.DeviceKey == "":
			return fmt.Errorf("addressless DVB card %q requires a stable device_key", card.ID)
		case strings.HasPrefix(card.DeviceKey, "address:"):
			return fmt.Errorf("addressless DVB card %q cannot use address identity %q", card.ID, card.DeviceKey)
		case card.ID != card.DeviceKey:
			return fmt.Errorf("DVB card ID %q must equal device_key %q", card.ID, card.DeviceKey)
		default:
			return nil
		}
	}
	expectedAddress := fmt.Sprintf("%d.%d", card.Adapter, card.Frontend)
	if card.Address != expectedAddress {
		return fmt.Errorf("DVB card %q address %q must equal adapter/frontend %s", card.ID, card.Address, expectedAddress)
	}
	if card.DeviceKey == "" {
		if want := "address:" + card.Address; card.ID != want {
			return fmt.Errorf("DVB card %q without a stable device_key must use address identity %q", card.ID, want)
		}
		return nil
	}
	if card.ID != card.DeviceKey {
		return fmt.Errorf("DVB card ID %q must equal device_key %q", card.ID, card.DeviceKey)
	}
	if strings.HasPrefix(card.DeviceKey, "address:") && strings.TrimPrefix(card.DeviceKey, "address:") != card.Address {
		return fmt.Errorf("DVB card address identity %q must match address %q", card.DeviceKey, card.Address)
	}
	return nil
}

func validateSchedulerTunableCardSnapshot(card model.DVBCard) error {
	if err := validateSchedulerCardSnapshot(card); err != nil {
		return err
	}
	if !card.Present || card.Address == "" || card.Status == "offline" {
		return fmt.Errorf("DVB card %q is not a tunable present frontend", card.ID)
	}
	return nil
}

func canonicalPhysicalFrontendKey(card model.DVBCard) (physicalFrontendKey, bool) {
	if err := validateSchedulerCardSnapshot(card); err != nil || !card.Present {
		return physicalFrontendKey{}, false
	}
	return physicalFrontendKey{
		adapter:  card.Adapter,
		frontend: card.Frontend,
		address:  card.Address,
	}, true
}

func (s *dvbScheduler) validateCardMapKeysLocked() error {
	mapIDs := make([]string, 0, len(s.cards))
	for mapID := range s.cards {
		mapIDs = append(mapIDs, mapID)
	}
	if s.counters != nil {
		s.counters.Sorts++
	}
	sort.Slice(mapIDs, func(i, j int) bool {
		if s.counters != nil {
			s.counters.Comparisons++
		}
		return mapIDs[i] < mapIDs[j]
	})
	for _, mapID := range mapIDs {
		card := s.cards[mapID]
		if mapID == "" {
			return errors.New("DVB card map contains an empty map key")
		}
		if card.ID != mapID {
			return fmt.Errorf("DVB card map key %q does not match embedded card ID %q", mapID, card.ID)
		}
	}
	return nil
}

func (s *dvbScheduler) validatePhysicalFrontendInventoryLocked(cardOverride *model.DVBCard) error {
	if err := s.validateCardMapKeysLocked(); err != nil {
		return err
	}

	type inventoryEntry struct {
		mapID string
		card  model.DVBCard
	}

	entries := make([]inventoryEntry, 0, len(s.cards)+1)
	replaced := false
	for mapID, card := range s.cards {
		if cardOverride != nil && mapID == cardOverride.ID {
			card = *cardOverride
			replaced = true
		}
		entries = append(entries, inventoryEntry{mapID: mapID, card: card})
	}
	if cardOverride != nil && !replaced {
		entries = append(entries, inventoryEntry{mapID: cardOverride.ID, card: *cardOverride})
	}
	if s.counters != nil {
		s.counters.Sorts++
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if s.counters != nil {
			s.counters.Comparisons++
		}
		if result := compareDVBCardDefault(entries[i].card, entries[j].card); result != 0 {
			return result < 0
		}
		return entries[i].mapID < entries[j].mapID
	})

	owners := make(map[physicalFrontendKey]string, len(entries))
	for _, entry := range entries {
		key, present := canonicalPhysicalFrontendKey(entry.card)
		if !present {
			continue
		}
		if owner := owners[key]; owner != "" && owner != entry.mapID {
			return fmt.Errorf("physical DVB frontend %q (adapter %d frontend %d) is represented by present cards %q and %q", key.address, key.adapter, key.frontend, owner, entry.mapID)
		}
		owners[key] = entry.mapID
	}
	return nil
}

func (s *dvbScheduler) storeCardLocked(card model.DVBCard) error {
	if s.runtimeMode {
		return schedulerError(ErrDVBSchedulerOwnership, "metadata card helper cannot mutate runtime inventory")
	}
	stored := cloneDVBCard(card)
	if err := validateSchedulerCardSnapshot(stored); err != nil {
		return err
	}
	state := s.sessionIndexStateViewLocked()
	if err := s.validateSessionIndexStateLocked(state); err != nil {
		return fmt.Errorf("store DVB card %q: existing session indexes are inconsistent: %w", stored.ID, err)
	}
	if err := s.validatePhysicalFrontendInventoryLocked(&stored); err != nil {
		return fmt.Errorf("store DVB card %q: proposed inventory is inconsistent: %w", stored.ID, err)
	}
	// Validate the candidate without exposing an intermediate card-map state.
	if err := s.validateSessionIndexStateWithCardOverrideLocked(state, &stored); err != nil {
		return fmt.Errorf("store DVB card %q: proposed card/session composition is inconsistent: %w", stored.ID, err)
	}
	s.cards[stored.ID] = stored
	return nil
}

func cloneTuningSession(in *tuningSession) *tuningSession {
	if in == nil {
		return nil
	}
	if in.runtime != nil {
		panic("resource-bearing tuningSession cannot be cloned")
	}
	out := *in
	out.card = cloneDVBCard(in.card)
	out.streamIDs = make(map[string]struct{}, len(in.streamIDs))
	for streamID := range in.streamIDs {
		out.streamIDs[streamID] = struct{}{}
	}
	return &out
}

type sessionIndexState struct {
	sessions       map[string]*tuningSession
	sessionsByKey  map[tuningKey]map[string]struct{}
	sessionByCard  map[string]string
	streamSessions map[string]string
}

func (s *dvbScheduler) sessionIndexStateViewLocked() sessionIndexState {
	return sessionIndexState{
		sessions:       s.sessions,
		sessionsByKey:  s.sessionsByKey,
		sessionByCard:  s.sessionByCard,
		streamSessions: s.streamSessions,
	}
}

func (s *dvbScheduler) cloneSessionIndexStateLocked() sessionIndexState {
	if s.counters != nil {
		s.counters.IndexClones++
		s.counters.SessionClones += uint64(len(s.sessions))
	}
	state := sessionIndexState{
		sessions:       make(map[string]*tuningSession, len(s.sessions)),
		sessionsByKey:  make(map[tuningKey]map[string]struct{}, len(s.sessionsByKey)),
		sessionByCard:  make(map[string]string, len(s.sessionByCard)),
		streamSessions: make(map[string]string, len(s.streamSessions)),
	}
	for id, session := range s.sessions {
		state.sessions[id] = cloneTuningSession(session)
	}
	for key, indexed := range s.sessionsByKey {
		cloned := make(map[string]struct{}, len(indexed))
		for id := range indexed {
			cloned[id] = struct{}{}
		}
		state.sessionsByKey[key] = cloned
	}
	for cardID, sessionID := range s.sessionByCard {
		state.sessionByCard[cardID] = sessionID
	}
	for streamID, sessionID := range s.streamSessions {
		state.streamSessions[streamID] = sessionID
	}
	return state
}

func removeSessionFromIndexState(state *sessionIndexState, sessionID string) {
	session := state.sessions[sessionID]
	if session == nil {
		return
	}
	delete(state.sessions, sessionID)
	if indexed := state.sessionsByKey[session.key]; indexed != nil {
		delete(indexed, sessionID)
		if len(indexed) == 0 {
			delete(state.sessionsByKey, session.key)
		}
	}
	if state.sessionByCard[session.cardID] == sessionID {
		delete(state.sessionByCard, session.cardID)
	}
	for streamID, indexedSessionID := range state.streamSessions {
		if indexedSessionID == sessionID {
			delete(state.streamSessions, streamID)
		}
	}
}

func (s *dvbScheduler) validateSessionIndexStateLocked(state sessionIndexState) error {
	return s.validateSessionIndexStateWithCardOverrideLocked(state, nil)
}

func (s *dvbScheduler) validateSessionIndexStateWithCardOverrideLocked(state sessionIndexState, cardOverride *model.DVBCard) error {
	keyOccurrences := make(map[string]int, len(state.sessions))
	for key, indexed := range state.sessionsByKey {
		if key == (tuningKey{}) {
			return errors.New("session key index contains a zero tuning key")
		}
		if len(indexed) == 0 {
			return fmt.Errorf("session key index %x is empty", key)
		}
		for id := range indexed {
			keyOccurrences[id]++
			session := state.sessions[id]
			if session == nil || session.id != id || session.key != key {
				return fmt.Errorf("session key index %x references incoherent session %q", key, id)
			}
		}
	}

	cardReverseOccurrences := make(map[string]int, len(state.sessions))
	for cardID, sessionID := range state.sessionByCard {
		if cardID == "" || sessionID == "" {
			return errors.New("session card index contains an empty identity")
		}
		cardReverseOccurrences[sessionID]++
		session := state.sessions[sessionID]
		if session == nil || session.id != sessionID || session.cardID != cardID {
			return fmt.Errorf("session card index %q references incoherent session %q", cardID, sessionID)
		}
	}

	streamReverseOccurrences := make(map[string]int, len(state.sessions))
	for streamID, sessionID := range state.streamSessions {
		if streamID == "" || sessionID == "" {
			return errors.New("session stream index contains an empty identity")
		}
		streamReverseOccurrences[sessionID]++
		session := state.sessions[sessionID]
		if session == nil || session.id != sessionID {
			return fmt.Errorf("session stream index %q references missing session %q", streamID, sessionID)
		}
		if _, ok := session.streamIDs[streamID]; !ok {
			return fmt.Errorf("session stream index %q is absent from session %q", streamID, sessionID)
		}
	}

	cardOwners := make(map[string]string, len(state.sessions))
	type physicalSessionOwner struct {
		sessionID string
		cardID    string
	}
	physicalOwners := make(map[physicalFrontendKey]physicalSessionOwner, len(state.sessions))
	streamOwners := make(map[string]string, len(state.streamSessions))
	for id, session := range state.sessions {
		if session == nil || session.id != id {
			return fmt.Errorf("primary session %q is incoherent", id)
		}
		if err := s.validateSessionSnapshotWithCardOverrideLocked(session, cardOverride); err != nil {
			return err
		}
		if owner := cardOwners[session.cardID]; owner != "" && owner != id {
			return fmt.Errorf("card %q is claimed by sessions %q and %q", session.cardID, owner, id)
		}
		cardOwners[session.cardID] = id
		physicalKey, present := canonicalPhysicalFrontendKey(session.card)
		if !present {
			return fmt.Errorf("session %q has no present physical frontend", id)
		}
		if owner, ok := physicalOwners[physicalKey]; ok && owner.sessionID != id {
			return fmt.Errorf("physical DVB frontend %q is claimed by sessions %q (card %q) and %q (card %q)", physicalKey.address, owner.sessionID, owner.cardID, id, session.cardID)
		}
		physicalOwners[physicalKey] = physicalSessionOwner{sessionID: id, cardID: session.cardID}
		if state.sessionByCard[session.cardID] != id || cardReverseOccurrences[id] != 1 {
			return fmt.Errorf("session %q card indexes are inconsistent", id)
		}
		if keyOccurrences[id] != 1 {
			return fmt.Errorf("session %q occurs in %d tuning-key indexes", id, keyOccurrences[id])
		}
		if _, ok := state.sessionsByKey[session.key][id]; !ok {
			return fmt.Errorf("session %q is absent from its tuning-key index", id)
		}
		for streamID := range session.streamIDs {
			if streamID == "" {
				return fmt.Errorf("session %q contains an empty stream ID", id)
			}
			if owner := streamOwners[streamID]; owner != "" && owner != id {
				return fmt.Errorf("stream %q is claimed by sessions %q and %q", streamID, owner, id)
			}
			streamOwners[streamID] = id
			if state.streamSessions[streamID] != id {
				return fmt.Errorf("session %q stream %q has no matching reverse index", id, streamID)
			}
		}
		if streamReverseOccurrences[id] != len(session.streamIDs) {
			return fmt.Errorf("session %q stream indexes are inconsistent", id)
		}
	}
	return nil
}

func (s *dvbScheduler) storeSessionLocked(session *tuningSession) error {
	if s.runtimeMode || session != nil && session.runtime != nil {
		return schedulerError(ErrDVBSchedulerOwnership, "metadata session helper cannot publish resource ownership")
	}
	if err := s.validatePhysicalFrontendInventoryLocked(nil); err != nil {
		sessionID := ""
		if session != nil {
			sessionID = session.id
		}
		return fmt.Errorf("store tuning session %q: card inventory is inconsistent: %w", sessionID, err)
	}

	stored := cloneTuningSession(session)
	if err := s.validateSessionSnapshotLocked(stored); err != nil {
		return err
	}

	if err := s.validateSessionIndexStateLocked(s.sessionIndexStateViewLocked()); err != nil {
		return fmt.Errorf("store tuning session %q: existing indexes are inconsistent: %w", stored.id, err)
	}

	next := s.cloneSessionIndexStateLocked()
	removeSessionFromIndexState(&next, stored.id)
	if existingID := next.sessionByCard[stored.cardID]; existingID != "" {
		return fmt.Errorf("store tuning session %q: card %q is already claimed by session %q", stored.id, stored.cardID, existingID)
	}
	for streamID := range stored.streamIDs {
		if streamID == "" {
			return fmt.Errorf("store tuning session %q: stream ID is required", stored.id)
		}
		if existingID := next.streamSessions[streamID]; existingID != "" {
			return fmt.Errorf("store tuning session %q: stream %q is already claimed by session %q", stored.id, streamID, existingID)
		}
	}

	next.sessions[stored.id] = stored
	if next.sessionsByKey[stored.key] == nil {
		next.sessionsByKey[stored.key] = make(map[string]struct{})
	}
	next.sessionsByKey[stored.key][stored.id] = struct{}{}
	next.sessionByCard[stored.cardID] = stored.id
	for streamID := range stored.streamIDs {
		next.streamSessions[streamID] = stored.id
	}
	if err := s.validateSessionIndexStateLocked(next); err != nil {
		return fmt.Errorf("store tuning session %q: proposed indexes are inconsistent: %w", stored.id, err)
	}

	s.sessions = next.sessions
	s.sessionsByKey = next.sessionsByKey
	s.sessionByCard = next.sessionByCard
	s.streamSessions = next.streamSessions
	return nil
}

func (s *dvbScheduler) validateSessionSnapshotLocked(session *tuningSession) error {
	return s.validateSessionSnapshotWithCardOverrideLocked(session, nil)
}

func (s *dvbScheduler) validateSessionSnapshotWithCardOverrideLocked(session *tuningSession, cardOverride *model.DVBCard) error {
	if session == nil {
		return errors.New("tuning session is required")
	}
	if session.id == "" {
		return errors.New("tuning session ID is required")
	}
	if session.key == (tuningKey{}) {
		return fmt.Errorf("tuning session %q has a zero tuning key", session.id)
	}
	if session.cardID == "" {
		return fmt.Errorf("tuning session %q has no card ID", session.id)
	}
	current, ok := s.cards[session.cardID]
	if cardOverride != nil && cardOverride.ID == session.cardID {
		current = *cardOverride
		ok = true
	}
	if !ok {
		return fmt.Errorf("tuning session %q references unknown card %q", session.id, session.cardID)
	}
	if err := validateSchedulerTunableCardSnapshot(current); err != nil {
		return fmt.Errorf("tuning session %q current card is invalid: %w", session.id, err)
	}
	if err := validateSchedulerTunableCardSnapshot(session.card); err != nil {
		return fmt.Errorf("tuning session %q card snapshot is invalid: %w", session.id, err)
	}
	if session.card.ID != session.cardID || current.ID != session.cardID {
		return fmt.Errorf("tuning session %q card snapshot does not match card %q", session.id, session.cardID)
	}
	if session.card.DeviceKey != current.DeviceKey || session.card.Address != current.Address {
		return fmt.Errorf("tuning session %q physical card identity does not match current card %q", session.id, session.cardID)
	}
	if session.card.Adapter != current.Adapter || session.card.Frontend != current.Frontend ||
		session.config.Adapter != current.Adapter || session.config.Frontend != current.Frontend {
		return fmt.Errorf("tuning session %q adapter/frontend does not match current card %q", session.id, session.cardID)
	}
	if err := validateStructuredSessionConfig(session.config); err != nil {
		return fmt.Errorf("tuning session %q config is invalid: %w", session.id, err)
	}
	if expectedKey := canonicalTuningKey(resolvedTune{config: session.config}); expectedKey != session.key {
		return fmt.Errorf("tuning session %q key does not match its config", session.id)
	}
	return nil
}

func validateStructuredSessionConfig(cfg dvb.Config) error {
	if cfg.Adapter < 0 || cfg.Frontend < 0 {
		return errors.New("adapter/frontend must be non-negative")
	}
	if cfg.DiseqcPort != cfg.UnicablePosition {
		return fmt.Errorf("DiseqcPort %d contradicts UnicablePosition %d", cfg.DiseqcPort, cfg.UnicablePosition)
	}
	if cfg.DiseqcPort < 0 || cfg.DiseqcPort > 3 {
		return fmt.Errorf("satellite position %d is outside A-D", cfg.DiseqcPort)
	}

	// Rebuild through the sole structured producer so stored snapshots cannot
	// drift from ConfigFromStream token, RF, or service validation.
	mode := "custom"
	switch cfg.UnicableType {
	case 0:
	case 1:
		mode = "unicable1"
	case 2:
		mode = "unicable2"
	default:
		return fmt.Errorf("unsupported Unicable type %d", cfg.UnicableType)
	}
	position := string("ABCD"[cfg.DiseqcPort])
	rf := model.AdapterLNBConfig{
		LOF1:          cfg.LnbLowMHz,
		LOF2:          cfg.LnbHighMHz,
		SLOF:          cfg.LnbSwitchMHz,
		ForceTone:     cfg.ForceTone,
		Mode:          mode,
		UnicableSlot:  cfg.UnicableSlot,
		SlotPosition:  position,
		SlotFrequency: cfg.UnicableFreq,
	}
	stream := model.DVBStreamConfig{
		DeliverySystem: cfg.Delivery,
		FrequencyKHz:   cfg.FrequencyKHz,
		SymbolRate:     cfg.SymbolRate,
		Polarization:   cfg.Polarization,
		Modulation:     cfg.Modulation,
		FEC:            cfg.FEC,
		RollOff:        cfg.RollOff,
		StreamID:       cfg.StreamID,
		ServiceID:      cfg.ServiceID,
		VideoPID:       cfg.VideoPID,
		PCRPID:         cfg.PCR_PID,
		RFOverride:     &rf,
		Advanced: model.AdapterAdvancedConfig{
			DVBAPI:   cfg.DVBAPI,
			DVBAPIV3: cfg.DVBAPIV3,
		},
		Adapter: model.DVBAdapterPolicy{Mode: "auto"},
	}
	if cfg.AudioPID != 0 {
		stream.AudioPIDs = []int{cfg.AudioPID}
	}
	rebuilt, err := dvb.ConfigFromStream(stream, model.DVBCardConfig{}, fmt.Sprintf("%d.%d", cfg.Adapter, cfg.Frontend))
	if err != nil {
		return err
	}
	if rebuilt != cfg {
		return errors.New("config is not canonical ConfigFromStream output")
	}
	return nil
}

func (s *dvbScheduler) sessionClaimIDsLocked(cardID string) []string {
	if id := s.sessionByCard[cardID]; id != "" {
		return []string{id}
	}
	return nil
}
func (s *dvbScheduler) sessionIndexesCoherentLocked(id string, session *tuningSession) bool {
	if session == nil || session.id != id || s.sessions[id] != session || s.sessionByCard[session.cardID] != id {
		return false
	}
	if _, ok := s.sessionsByKey[session.key][id]; !ok {
		return false
	}
	if session.runtime != nil {
		r := session.runtime
		if s.ownedSessions[id] != session || s.sessionByPhysical[r.physical] != session ||
			s.physicalReservations[r.physical] != session || s.cardRevisions[session.cardID] != r.cardRevision {
			return false
		}
	}
	return s.validateSessionSnapshotLocked(session) == nil
}
func (s *dvbScheduler) removeSessionLocked(sessionID string) {
	session := s.sessions[sessionID]
	if session == nil {
		return
	}
	ids := s.sessionOrderByKey[session.key]
	for i, id := range ids {
		if s.counters != nil {
			s.counters.ExactBucketVisits++
			s.counters.Comparisons++
		}
		if id == sessionID {
			ids = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if len(ids) == 0 {
		delete(s.sessionOrderByKey, session.key)
	} else {
		s.sessionOrderByKey[session.key] = ids
	}
	delete(s.sessions, sessionID)
	if indexed := s.sessionsByKey[session.key]; indexed != nil {
		delete(indexed, sessionID)
		if len(indexed) == 0 {
			delete(s.sessionsByKey, session.key)
		}
	}
	if s.sessionByCard[session.cardID] == sessionID {
		delete(s.sessionByCard, session.cardID)
	}
	for streamID := range session.streamIDs {
		if s.counters != nil {
			s.counters.AttachmentVisits++
			s.counters.ReverseVisits++
		}
		if s.streamSessions[streamID] == sessionID {
			delete(s.streamSessions, streamID)
		}
	}
}

func resolveTune(stream model.Stream, card model.DVBCard) (resolvedTune, error) {
	stream = cloneStream(stream)
	card = cloneDVBCard(card)
	if stream.DVB == nil {
		return resolvedTune{}, errors.New("structured DVB stream configuration is required")
	}
	if err := validateSchedulerTunableCardSnapshot(card); err != nil {
		return resolvedTune{}, err
	}
	stream.DVB.Normalize()
	cfg, err := dvb.ConfigFromStream(*stream.DVB, card.Config, card.Address)
	if err != nil {
		return resolvedTune{}, err
	}

	resolved := resolvedTune{config: cfg, adapterMode: stream.DVB.Adapter.Mode}
	if resolved.adapterMode == "" {
		resolved.adapterMode = "auto"
	}
	if resolved.adapterMode != "fixed" {
		return resolved, nil
	}

	deviceKey := strings.TrimSpace(stream.DVB.Adapter.DeviceKey)
	lastAddress := strings.TrimSpace(stream.DVB.Adapter.LastAddress)
	switch {
	case deviceKey != "" && !strings.HasPrefix(deviceKey, "address:"):
		resolved.fixedDeviceKey = deviceKey
	case strings.HasPrefix(deviceKey, "address:"):
		address := strings.TrimPrefix(deviceKey, "address:")
		if !isCanonicalDVBAddress(address) {
			return resolvedTune{}, fmt.Errorf("fixed address identity %q is invalid", deviceKey)
		}
		if lastAddress != "" && lastAddress != address {
			return resolvedTune{}, fmt.Errorf("fixed address identity %q conflicts with last_address %q", deviceKey, lastAddress)
		}
		resolved.fixedAddress = address
	case isCanonicalDVBAddress(lastAddress):
		resolved.fixedAddress = lastAddress
	default:
		return resolvedTune{}, errors.New("fixed adapter target is required")
	}
	return resolved, nil
}

type transportKeyPayload struct {
	Version           uint8  `json:"version"`
	Delivery          string `json:"delivery"`
	FrequencyKHz      uint32 `json:"frequency_khz"`
	SymbolRate        uint32 `json:"symbol_rate"`
	Polarization      string `json:"polarization"`
	Modulation        string `json:"modulation"`
	FEC               string `json:"fec"`
	RollOff           string `json:"rolloff"`
	StreamID          string `json:"stream_id"`
	LNBLoLowMHz       int    `json:"lnb_lo_low_mhz"`
	LNBLoHighMHz      int    `json:"lnb_lo_high_mhz"`
	LNBSwitchMHz      int    `json:"lnb_switch_mhz"`
	ForceTone         bool   `json:"force_tone"`
	UnicableType      int    `json:"unicable_type"`
	UnicableSlot      int    `json:"unicable_slot"`
	UnicableFrequency int    `json:"unicable_frequency"`
	SatellitePosition int    `json:"satellite_position"`
	DVBAPI            string `json:"dvb_api"`
	DVBAPIV3          bool   `json:"dvb_api_v3"`
}

// canonicalTuningKey hashes fixed-order transport/RF JSON. Placement policy,
// card identity, and per-service/output fields never enter the payload.
func canonicalTuningKey(in resolvedTune) tuningKey {
	payload := transportPayload(in.config)
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("serialize canonical DVB tune: %v", err))
	}
	return sha256.Sum256(encoded)
}

func transportPayload(cfg dvb.Config) transportKeyPayload {
	delivery := canonicalDVBDeliverySystem(cfg.Delivery)
	polarization := strings.ToUpper(strings.TrimSpace(cfg.Polarization))
	switch polarization {
	case "H", "HORIZONTAL":
		polarization = "H"
	case "V", "VERTICAL":
		polarization = "V"
	}
	modulation := strings.ToLower(strings.TrimSpace(cfg.Modulation))
	rollOff := strings.ToLower(strings.TrimSpace(cfg.RollOff))
	streamID := strings.TrimSpace(cfg.StreamID)
	if delivery == "dvbs" {
		// The current DVB-S property list does not send these DVB-S2 fields.
		modulation = ""
		rollOff = ""
		streamID = ""
	}
	unicableSlot := cfg.UnicableSlot
	unicableFrequency := cfg.UnicableFreq
	if cfg.UnicableType == 0 {
		unicableSlot = 0
		unicableFrequency = 0
	}
	dvbAPI, dvbAPIV3 := linuxEffectiveDVBAPI(cfg, delivery)
	fec := strings.ToLower(strings.TrimSpace(cfg.FEC))
	if delivery == "dvbs" && dvbAPIV3 {
		fec = "auto"
	}
	return transportKeyPayload{
		Version:           1,
		Delivery:          delivery,
		FrequencyKHz:      cfg.FrequencyKHz,
		SymbolRate:        cfg.SymbolRate,
		Polarization:      polarization,
		Modulation:        modulation,
		FEC:               fec,
		RollOff:           rollOff,
		StreamID:          streamID,
		LNBLoLowMHz:       cfg.LnbLowMHz,
		LNBLoHighMHz:      cfg.LnbHighMHz,
		LNBSwitchMHz:      cfg.LnbSwitchMHz,
		ForceTone:         linuxEffectiveForceTone(cfg),
		UnicableType:      cfg.UnicableType,
		UnicableSlot:      unicableSlot,
		UnicableFrequency: unicableFrequency,
		SatellitePosition: cfg.DiseqcPort,
		DVBAPI:            dvbAPI,
		DVBAPIV3:          dvbAPIV3,
	}
}

func linuxEffectiveDVBAPI(cfg dvb.Config, delivery string) (string, bool) {
	requested := strings.ToLower(strings.TrimSpace(cfg.DVBAPI))
	if requested == "" && cfg.DVBAPIV3 {
		requested = "v3"
	}
	if requested == "v3" && delivery == "dvbs" {
		return "v3", true
	}
	return "v5", false
}

func linuxEffectiveForceTone(cfg dvb.Config) bool {
	if cfg.UnicableType > 0 {
		return false
	}
	return cfg.ForceTone
}

func (s *dvbScheduler) selectCardLocked(input model.Stream, hint tuningKey) (cardSelection, error) {
	if s.health != nil {
		return cardSelection{}, s.health
	}
	stream := cloneStream(input)
	if stream.DVB == nil {
		return cardSelection{}, errors.New("structured DVB stream configuration is required")
	}
	stream.DVB.Normalize()
	if err := dvb.ValidateStreamForLinux(*stream.DVB); err != nil {
		return cardSelection{}, err
	}
	if stream.DVB.Adapter.Mode == "fixed" {
		return s.selectFixedCardLocked(stream, hint)
	}
	choice, ok, failures := s.matchingSessionLocked(stream, hint, "")
	if s.health != nil {
		return cardSelection{}, s.health
	}
	if ok {
		return choice, nil
	}
	var first, preferred *cardSelection
	delivery := canonicalDVBDeliverySystem(stream.DVB.DeliverySystem)
	for _, id := range s.cardOrder {
		if s.counters != nil {
			s.counters.CardCandidates++
		}
		card := s.cards[id]
		if s.cardOperationBlockedLocked(card, stream.ID) || !s.autoCardIdleLocked(card, delivery) {
			continue
		}
		resolved, err := resolveTune(stream, card)
		if err != nil {
			failures = append(failures, cardResolutionFailure{card: card, err: err})
			continue
		}
		candidate := cardSelection{card: cloneDVBCard(card), config: resolved.config, key: canonicalTuningKey(resolved)}
		if first == nil {
			copy := candidate
			first = &copy
		}
		match := hint != (tuningKey{}) && candidate.key == hint
		if stream.DVB.RFOverride != nil {
			defaults := cloneStream(stream)
			defaults.DVB.RFOverride = nil
			r, e := resolveTune(defaults, card)
			match = e == nil && sameResolvedRF(r.config, resolved.config)
		}
		if match && preferred == nil {
			copy := candidate
			preferred = &copy
		}
	}
	if s.health != nil {
		return cardSelection{}, s.health
	}
	if preferred != nil {
		return *preferred, nil
	}
	if first != nil {
		return *first, nil
	}
	if err := s.firstCardResolutionError(failures); err != nil {
		return cardSelection{}, err
	}
	return cardSelection{}, ErrNoDVBCardAvailable
}
func (s *dvbScheduler) firstCardResolutionError(failures []cardResolutionFailure) error {
	if len(failures) == 0 {
		return nil
	}
	first := failures[0]
	for _, f := range failures[1:] {
		if s.counters != nil {
			s.counters.Comparisons++
		}
		n := compareDVBCardDefault(f.card, first.card)
		if n < 0 || n == 0 && f.sessionID < first.sessionID {
			first = f
		}
	}
	return first.err
}
func (s *dvbScheduler) selectFixedCardLocked(stream model.Stream, hint tuningKey) (cardSelection, error) {
	card, err := s.fixedTargetLocked(stream.DVB.Adapter)
	if err != nil {
		return cardSelection{}, err
	}
	if reason := s.cardAdmissionReasonLocked(card); reason != "" {
		return cardSelection{}, fixedCardConflict(card, reason, "")
	}
	if s.cardOperationBlockedLocked(card, stream.ID) {
		return cardSelection{}, fixedCardConflict(card, "reserved", "card operation in progress")
	}
	if !s.cardLocalCoherentLocked(card.ID) {
		return cardSelection{}, s.health
	}
	if reason, detail := fixedCardUnavailableReason(card, canonicalDVBDeliverySystem(stream.DVB.DeliverySystem)); reason != "" {
		return cardSelection{}, fixedCardConflict(card, reason, detail)
	}
	if _, reserved := s.reservations[card.ID]; reserved {
		return cardSelection{}, fixedCardConflict(card, "reserved", "another scheduler operation owns the reservation")
	}
	resolved, err := resolveTune(stream, card)
	if err != nil {
		return cardSelection{}, err
	}
	if choice, ok, _ := s.matchingSessionLocked(stream, hint, card.ID); ok {
		return choice, nil
	}
	if s.health != nil {
		return cardSelection{}, s.health
	}
	if id := s.sessionByCard[card.ID]; id != "" {
		session := s.sessions[id]
		if !s.sessionIndexesCoherentLocked(id, session) {
			return cardSelection{}, s.latchCorruptLocked(fmt.Errorf("incoherent session %q", id))
		}
		if session.key != canonicalTuningKey(resolved) || !sameSessionTuneConfig(resolved.config, session.config) {
			return cardSelection{}, fixedCardConflict(card, "tuned_different", "frontend owns a different tuning key")
		}
		return cardSelection{}, fixedCardConflict(card, "unavailable", "matching tuning session is not healthy")
	}
	physical, _ := canonicalPhysicalFrontendKey(card)
	if s.physicalReservations[physical] != nil {
		return cardSelection{}, fixedCardConflict(card, "reserved", "physical frontend has a pending or closing owner")
	}
	if card.ActiveSessions > 0 || card.CurrentTransport != nil || card.Status == "active" {
		return cardSelection{}, fixedCardConflict(card, "tuned_different", "frontend is already owned")
	}
	return cardSelection{card: cloneDVBCard(card), config: resolved.config, key: canonicalTuningKey(resolved)}, nil
}
func (s *dvbScheduler) fixedTargetLocked(policy model.DVBAdapterPolicy) (model.DVBCard, error) {
	key := strings.TrimSpace(policy.DeviceKey)
	address := strings.TrimSpace(policy.LastAddress)
	if key != "" && !strings.HasPrefix(key, "address:") {
		if card, ok := s.cards[key]; ok && card.DeviceKey == key {
			return cloneDVBCard(card), nil
		}
		return model.DVBCard{}, fmt.Errorf("%w: fixed device_key %q", ErrDVBCardNotFound, key)
	}
	if strings.HasPrefix(key, "address:") {
		target := strings.TrimPrefix(key, "address:")
		if address != "" && address != target {
			return model.DVBCard{}, fmt.Errorf("fixed address identity %q conflicts with last_address %q", key, address)
		}
		address = target
	}
	if !isCanonicalDVBAddress(address) {
		return model.DVBCard{}, fmt.Errorf("fixed adapter address %q is invalid", address)
	}
	var present, offline []model.DVBCard
	for _, id := range s.cardsByAddress[address] {
		if s.counters != nil {
			s.counters.CardCandidates++
		}
		card := s.cards[id]
		if card.Present {
			present = append(present, card)
		} else {
			offline = append(offline, card)
		}
	}
	if len(present) == 1 {
		return cloneDVBCard(present[0]), nil
	}
	if len(present) > 1 || len(offline) > 1 {
		return model.DVBCard{}, fmt.Errorf("fixed address %q is ambiguous", address)
	}
	if len(offline) == 1 {
		return cloneDVBCard(offline[0]), nil
	}
	return model.DVBCard{}, fmt.Errorf("%w: fixed address %q", ErrDVBCardNotFound, address)
}
func (s *dvbScheduler) sortedCardsLocked() []model.DVBCard {
	cards := make([]model.DVBCard, 0, len(s.cardOrder))
	for _, id := range s.cardOrder {
		cards = append(cards, cloneDVBCard(s.cards[id]))
	}
	return cards
}
func (s *dvbScheduler) sortedSessionIDsLocked(key tuningKey) []string {
	return s.sessionOrderByKey[key]
}
func (s *dvbScheduler) cardLocalCoherentLocked(id string) bool {
	card, ok := s.cards[id]
	if !ok || card.ID != id || validateSchedulerCardSnapshot(card) != nil {
		s.latchCorruptLocked(fmt.Errorf("card index %q is incoherent", id))
		return false
	}
	if sessionID := s.sessionByCard[id]; sessionID != "" && !s.sessionIndexesCoherentLocked(sessionID, s.sessions[sessionID]) {
		s.latchCorruptLocked(fmt.Errorf("card %q references incoherent session %q", id, sessionID))
		return false
	}
	return true
}
func (s *dvbScheduler) matchingSessionLocked(stream model.Stream, _ tuningKey, fixed string) (cardSelection, bool, []cardResolutionFailure) {
	var best *cardSelection
	var failures []cardResolutionFailure
	seen := make(map[tuningKey]bool)
	delivery := canonicalDVBDeliverySystem(stream.DVB.DeliverySystem)
	ids := s.cardOrder
	if fixed != "" {
		ids = []string{fixed}
	}
	for _, cardID := range ids {
		if s.counters != nil {
			s.counters.CardCandidates++
		}
		if !s.cardLocalCoherentLocked(cardID) {
			return cardSelection{}, false, nil
		}
		card := s.cards[cardID]
		if s.cardOperationBlockedLocked(card, stream.ID) || !sessionCardUsable(card, delivery) {
			continue
		}
		r, err := resolveTune(stream, card)
		if err != nil {
			if id := s.sessionByCard[cardID]; id != "" {
				failures = append(failures, cardResolutionFailure{card: card, sessionID: id, err: err})
			}
			continue
		}
		key := canonicalTuningKey(r)
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, id := range s.sessionOrderByKey[key] {
			if s.counters != nil {
				s.counters.ExactBucketVisits++
			}
			session := s.sessions[id]
			if !s.sessionIndexesCoherentLocked(id, session) {
				s.latchCorruptLocked(fmt.Errorf("incoherent exact-key session %q", id))
				return cardSelection{}, false, nil
			}
			current := s.cards[session.cardID]
			if s.cardOperationBlockedLocked(current, stream.ID) || fixed != "" && current.ID != fixed || !session.healthy || !sessionCardUsable(current, delivery) {
				continue
			}
			if session.runtime != nil && (session.runtime.retiring || session.runtime.closing) {
				continue
			}
			if _, reserved := s.reservations[current.ID]; reserved {
				continue
			}
			resolved, e := resolveTune(stream, current)
			if e != nil {
				failures = append(failures, cardResolutionFailure{card: current, sessionID: id, err: e})
				continue
			}
			if canonicalTuningKey(resolved) != session.key || !sameSessionTuneConfig(resolved.config, session.config) {
				continue
			}
			choice := sessionCardSelection(current, session, resolved.config)
			if best == nil {
				best = &choice
			} else {
				if s.counters != nil {
					s.counters.Comparisons++
				}
				if compareDVBCardDefault(choice.card, best.card) < 0 {
					best = &choice
				}
			}
		}
	}
	if best != nil {
		return *best, true, nil
	}
	return cardSelection{}, false, failures
}
func (s *dvbScheduler) sessionCardLocked(session *tuningSession) model.DVBCard {
	if session == nil {
		return model.DVBCard{}
	}
	if card, ok := s.cards[session.cardID]; ok {
		return cloneDVBCard(card)
	}
	return cloneDVBCard(session.card)
}
func (s *dvbScheduler) autoCardIdleLocked(card model.DVBCard, delivery string) bool {
	if !s.cardLocalCoherentLocked(card.ID) {
		return false
	}
	if !sessionCardUsable(card, delivery) || card.Status != "available" || card.ActiveSessions > 0 || card.CurrentTransport != nil {
		return false
	}
	if _, reserved := s.reservations[card.ID]; reserved {
		return false
	}
	if s.sessionByCard[card.ID] != "" {
		return false
	}
	physical, _ := canonicalPhysicalFrontendKey(card)
	return s.physicalReservations[physical] == nil
}

func sessionCardUsable(card model.DVBCard, delivery string) bool {
	if !card.Present || !card.Config.Enabled || !dvbCardSupportsDelivery(card, delivery) {
		return false
	}
	if card.LastError != "" {
		return false
	}
	switch card.Status {
	case "available", "active":
		return true
	default:
		return false
	}
}

func fixedCardUnavailableReason(card model.DVBCard, delivery string) (string, string) {
	switch {
	case card.Status == "busy_external":
		return "busy_external", "frontend is owned by another process"
	case !card.Present || card.Status == "offline":
		return "offline", "frontend is not present"
	case !card.Config.Enabled || card.Status == "disabled":
		return "disabled", "frontend is disabled"
	case card.Status == "error" || card.LastError != "":
		return "error", strings.TrimSpace(card.LastError)
	case !dvbCardSupportsDelivery(card, delivery):
		return "incompatible", fmt.Sprintf("frontend does not support %s", delivery)
	case card.Status != "available" && card.Status != "active":
		return "unavailable", fmt.Sprintf("frontend status is %q", card.Status)
	default:
		return "", ""
	}
}

func fixedCardConflict(card model.DVBCard, reason, detail string) error {
	return &DVBCardConflictError{
		CardID:    card.ID,
		DeviceKey: card.DeviceKey,
		Address:   card.Address,
		Reason:    reason,
		Detail:    detail,
	}
}

func sessionCardSelection(card model.DVBCard, session *tuningSession, config dvb.Config) cardSelection {
	return cardSelection{
		card:      cloneDVBCard(card),
		config:    config,
		key:       session.key,
		sessionID: session.id,
		shared:    true,
	}
}

func cloneCardSelection(in cardSelection) cardSelection {
	out := in
	out.card = cloneDVBCard(in.card)
	return out
}

func sameSessionTuneConfig(left, right dvb.Config) bool {
	return left.DiseqcPort == left.UnicablePosition &&
		right.DiseqcPort == right.UnicablePosition &&
		left.Adapter == right.Adapter &&
		left.Frontend == right.Frontend &&
		transportPayload(left) == transportPayload(right)
}

func sameResolvedRF(left, right dvb.Config) bool {
	return left.DiseqcPort == left.UnicablePosition &&
		right.DiseqcPort == right.UnicablePosition &&
		left.LnbLowMHz == right.LnbLowMHz &&
		left.LnbHighMHz == right.LnbHighMHz &&
		left.LnbSwitchMHz == right.LnbSwitchMHz &&
		linuxEffectiveForceTone(left) == linuxEffectiveForceTone(right) &&
		left.UnicableType == right.UnicableType &&
		left.UnicableSlot == right.UnicableSlot &&
		left.UnicableFreq == right.UnicableFreq &&
		left.DiseqcPort == right.DiseqcPort
}
