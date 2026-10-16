// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"astrax/internal/model"
)

type dvbCardOwnership struct {
	Application      *model.DVBCardApplication `json:"application,omitempty"`
	CurrentTransport *model.DVBStreamConfig
	ActiveSessions   int
	ActiveStreams    int
	Signal           *model.DVBSignal
	LastError        string
}

type mergedDVBCard struct {
	card          model.DVBCard
	configIndex   int
	fallbackMatch bool
}

// ErrDVBRefreshSuperseded reports that a validated refresh result lost to a newer request.
var ErrDVBRefreshSuperseded = errors.New("DVB card refresh superseded")

func cloneDVBStreamConfig(in *model.DVBStreamConfig) *model.DVBStreamConfig {
	if in == nil {
		return nil
	}
	out := *in
	out.AudioPIDs = slices.Clone(in.AudioPIDs)
	if in.Service != nil {
		service := cloneDVBService(*in.Service)
		out.Service = &service
	}
	if in.RFOverride != nil {
		rf := *in.RFOverride
		out.RFOverride = &rf
	}
	return &out
}

func cloneDVBSignal(in *model.DVBSignal) *model.DVBSignal {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneDVBCard(in model.DVBCard) model.DVBCard {
	out := in
	out.DeliverySystems = slices.Clone(in.DeliverySystems)
	out.CurrentTransport = cloneDVBStreamConfig(in.CurrentTransport)
	out.Signal = cloneDVBSignal(in.Signal)
	if in.Application != nil {
		a := *in.Application
		if a.AppliedConfig != nil {
			c := *a.AppliedConfig
			a.AppliedConfig = &c
		}
		out.Application = &a
	}
	return out
}

func cloneDVBCards(in []model.DVBCard) []model.DVBCard {
	out := make([]model.DVBCard, len(in))
	for i := range in {
		out[i] = cloneDVBCard(in[i])
	}
	return out
}

func cloneDVBCardOwnership(in dvbCardOwnership) dvbCardOwnership {
	out := in
	out.CurrentTransport = cloneDVBStreamConfig(in.CurrentTransport)
	out.Signal = cloneDVBSignal(in.Signal)
	out.Application = cloneDVBCard(model.DVBCard{Application: in.Application}).Application
	return out
}

func appendDVBCardWarning(existing, addition string) string {
	existing = strings.TrimSpace(existing)
	addition = strings.TrimSpace(addition)
	if addition == "" {
		return existing
	}
	if existing == "" {
		return addition
	}
	if strings.Contains(existing, addition) {
		return existing
	}
	return existing + "; " + addition
}

func isDVBAddressIdentity(deviceKey string) bool {
	return deviceKey == "" || strings.HasPrefix(deviceKey, "address:")
}

func dvbAddressWarning(address string) string {
	return fmt.Sprintf("matched persisted settings by unstable address %s; Linux renumbering may select a different frontend", address)
}

func parseDVBCardAddress(address string) (int, int, bool) {
	if !isCanonicalDVBAddress(address) {
		return 0, 0, false
	}
	adapterText, frontendText, _ := strings.Cut(address, ".")
	adapter, err := strconv.Atoi(adapterText)
	if err != nil {
		return 0, 0, false
	}
	frontend, err := strconv.Atoi(frontendText)
	if err != nil {
		return 0, 0, false
	}
	return adapter, frontend, true
}

func validateAndCloneDetectedDVBCards(ctx context.Context, cards []model.DVBCard) ([]model.DVBCard, error) {
	seenIDs := make(map[string]int, len(cards))
	seenKeys := make(map[string]int, len(cards))
	seenAddresses := make(map[string]int, len(cards))
	out := make([]model.DVBCard, len(cards))
	for i, card := range cards {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if card.ID == "" || card.ID != strings.TrimSpace(card.ID) {
			return nil, fmt.Errorf("detected DVB card at index %d: id must be non-empty and trimmed", i)
		}
		if card.DeviceKey == "" || card.DeviceKey != strings.TrimSpace(card.DeviceKey) {
			return nil, fmt.Errorf("detected DVB card at index %d: device_key must be non-empty and trimmed", i)
		}
		if card.ID != card.DeviceKey {
			return nil, fmt.Errorf("detected DVB card at index %d: id %q must equal device_key %q", i, card.ID, card.DeviceKey)
		}
		if other, ok := seenIDs[card.ID]; ok {
			return nil, fmt.Errorf("detected DVB card at index %d: duplicate id %q from index %d", i, card.ID, other)
		}
		if other, ok := seenKeys[card.DeviceKey]; ok {
			return nil, fmt.Errorf("detected DVB card at index %d: duplicate device_key %q from index %d", i, card.DeviceKey, other)
		}
		adapter, frontend, ok := parseDVBCardAddress(card.Address)
		if !ok || adapter != card.Adapter || frontend != card.Frontend {
			return nil, fmt.Errorf("detected DVB card at index %d: address %q must be canonical A.F matching adapter/frontend", i, card.Address)
		}
		if other, ok := seenAddresses[card.Address]; ok {
			return nil, fmt.Errorf("detected DVB card at index %d: duplicate address %q from index %d", i, card.Address, other)
		}
		if strings.HasPrefix(card.DeviceKey, "address:") && strings.TrimPrefix(card.DeviceKey, "address:") != card.Address {
			return nil, fmt.Errorf("detected DVB card at index %d: address identity %q must match address %q", i, card.DeviceKey, card.Address)
		}
		if !card.Present {
			return nil, fmt.Errorf("detected DVB card at index %d: detected card must be present", i)
		}
		seenIDs[card.ID] = i
		seenKeys[card.DeviceKey] = i
		seenAddresses[card.Address] = i
		out[i] = cloneDVBCard(card)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) nextDVBRefreshGeneration() uint64 {
	s.dvbRefreshSequenceMu.Lock()
	s.dvbRefreshNext++
	generation := s.dvbRefreshNext
	s.dvbRefreshSequenceMu.Unlock()
	return generation
}

func (s *Store) acquireDVBRefresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.dvbRefreshGate:
		if err := ctx.Err(); err != nil {
			s.dvbRefreshGate <- struct{}{}
			return err
		}
		return nil
	default:
	}

	if s.testHookDVBRefreshWaiting != nil {
		s.testHookDVBRefreshWaiting()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.dvbRefreshGate:
		if err := ctx.Err(); err != nil {
			s.dvbRefreshGate <- struct{}{}
			return err
		}
		return nil
	}
}

func (s *Store) releaseDVBRefresh() {
	s.dvbRefreshGate <- struct{}{}
}

func (s *Store) publishDVBRefreshFailure(generation uint64, cause error) model.DVBCardSummary {
	s.dvbRefreshStateMu.Lock()
	if generation >= s.dvbRefreshPublished {
		s.dvbRefreshPublished = generation
		s.dvbStale = true
		s.dvbRefreshError = cause.Error()
	}
	summary := s.dvbLastSummary
	s.dvbRefreshStateMu.Unlock()
	return summary
}

func (s *Store) supersededDVBRefreshError(generation, published uint64, winningError string) error {
	if winningError != "" {
		return fmt.Errorf("%w: generation %d was not published; generation %d retained a failed registry state: %s", ErrDVBRefreshSuperseded, generation, published, winningError)
	}
	return fmt.Errorf("%w: generation %d was not published; generation %d retained the registry state", ErrDVBRefreshSuperseded, generation, published)
}

func (s *Store) RefreshDVBCards(ctx context.Context) (model.DVBCardSummary, error) {
	end, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.DVBCardSummary{}, admissionErr
	}
	defer end()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := s.cardRefreshContext(ctx)
	defer cancel()
	generation := s.nextDVBRefreshGeneration()
	if err := s.acquireDVBRefresh(ctx); err != nil {
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	defer s.releaseDVBRefresh()

	detected, err := s.adapterDetector.DetectDVB(ctx)
	if err != nil {
		wrapped := fmt.Errorf("detect DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	if err := ctx.Err(); err != nil {
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	validated, err := validateAndCloneDetectedDVBCards(ctx, detected)
	if err != nil {
		wrapped := fmt.Errorf("validate detected DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	refreshedAt := s.now().UTC()

	if err := s.cardPublicationMu.LockContext(ctx); err != nil {
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	publicationLocked := true
	var abortUpdates []dvbCardApplicationUpdate
	defer func() {
		if publicationLocked {
			s.cardPublicationMu.Unlock()
		}
		s.installCardApplications(abortUpdates)
	}()
	// Use cancelable admission for this short snapshot too; an ordinary read
	// lock can otherwise strand a canceled refresh behind a store writer.
	if err := s.mu.LockContext(ctx); err != nil {
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	inventory := cardSelectionInventory(validated, s.config.DVBCards)
	s.mu.Unlock()
	var tx *dvbCardUpdate
	if s.scheduler != nil {
		tx, err = s.scheduler.prepareCardUpdate(inventory)
		if err != nil {
			return s.publishDVBRefreshFailure(generation, err), err
		}
	}
	defer func() {
		if tx != nil {
			abortUpdates = s.scheduler.abortCardUpdate(tx)
		}
	}()
	if err := s.mu.LockContext(ctx); err != nil {
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	var before []mergedDVBCard
	if s.scheduler == nil {
		before = s.mergeDVBCardsLocked()
	}
	var events dvbEventBatch
	s.dvbRefreshStateMu.Lock()
	if err := ctx.Err(); err != nil {
		s.dvbRefreshStateMu.Unlock()
		s.mu.Unlock()
		wrapped := fmt.Errorf("refresh DVB cards: %w", err)
		return s.publishDVBRefreshFailure(generation, wrapped), wrapped
	}
	if generation < s.dvbRefreshPublished {
		summary := s.dvbLastSummary
		published := s.dvbRefreshPublished
		winningError := s.dvbRefreshError
		s.dvbRefreshStateMu.Unlock()
		s.mu.Unlock()
		return summary, s.supersededDVBRefreshError(generation, published, winningError)
	}
	s.dvbRefreshPublished = generation
	s.dvbDetected = validated
	s.dvbRefreshedAt = refreshedAt
	s.dvbRefreshError = ""
	s.dvbStale = false
	rows := s.mergeDVBCardsLocked()
	summary := summarizeDVBCards(rows)
	s.dvbLastSummary = summary
	if s.scheduler == nil {
		s.queueCardInventoryLocked(&events, before, rows)
	}
	s.mu.Unlock()
	var updates []dvbCardApplicationUpdate
	if tx != nil {
		updates = s.scheduler.commitCardUpdate(tx)
		tx = nil
	}
	s.dvbRefreshStateMu.Unlock()
	s.cardPublicationMu.Unlock()
	publicationLocked = false
	events.emit(s)
	s.installCardApplications(updates)
	return summary, nil
}

func defaultDetectedDVBCardConfig(card model.DVBCard) model.DVBCardConfig {
	return model.DVBCardConfig{
		DeviceKey:   card.DeviceKey,
		LastAddress: card.Address,
		Enabled:     true,
		RFDefaults:  model.DefaultAdapterLNB(),
		Advanced:    model.DefaultAdapterAdvanced(),
	}
}

func detectedDVBCardConfig(configs []model.DVBCardConfig, card model.DVBCard, consumed []bool) (model.DVBCardConfig, int, bool) {
	for i, config := range configs {
		if consumed[i] || config.DeviceKey == "" || config.DeviceKey != card.DeviceKey {
			continue
		}
		consumed[i] = true
		return config, i, isDVBAddressIdentity(config.DeviceKey)
	}
	for i, config := range configs {
		if consumed[i] || !isDVBAddressIdentity(config.DeviceKey) || config.LastAddress != card.Address {
			continue
		}
		consumed[i] = true
		return config, i, true
	}
	return defaultDetectedDVBCardConfig(card), -1, isDVBAddressIdentity(card.DeviceKey)
}

func (s *Store) detectedDVBCardConfigLocked(card model.DVBCard, consumed []bool) (model.DVBCardConfig, int, bool) {
	return detectedDVBCardConfig(s.config.DVBCards, card, consumed)
}

func applyDVBCardOwnership(card *model.DVBCard, ownership dvbCardOwnership) {
	copyOwnership := cloneDVBCardOwnership(ownership)
	card.CurrentTransport = copyOwnership.CurrentTransport
	card.ActiveSessions = copyOwnership.ActiveSessions
	card.ActiveStreams = copyOwnership.ActiveStreams
	card.Signal = copyOwnership.Signal
	card.LastError = copyOwnership.LastError
	card.OwnerPID = 0
	card.OwnerCommand = ""
}

func applyDVBCardStatus(card *model.DVBCard, owned bool) {
	switch {
	case !card.Present:
		card.Status = "offline"
	case !card.Config.Enabled:
		card.Status = "disabled"
	case owned:
		card.Status = "active"
	case card.Status == "busy_external":
		card.Status = "busy_external"
	case card.Status == "error" || card.LastError != "":
		card.Status = "error"
	default:
		card.Status = "available"
	}
}

func selectionDVBCards(detectedCards []model.DVBCard, configs []model.DVBCardConfig) []mergedDVBCard {
	consumed := make([]bool, len(configs))
	rows := make([]mergedDVBCard, 0, len(detectedCards)+len(configs))
	for _, detected := range detectedCards {
		card := cloneDVBCard(detected)
		config, configIndex, fallbackMatch := detectedDVBCardConfig(configs, card, consumed)
		card.Config = config
		card.UpdatedAt = config.UpdatedAt
		if fallbackMatch {
			card.Warning = appendDVBCardWarning(card.Warning, dvbAddressWarning(card.Address))
		}
		applyDVBCardStatus(&card, false)
		rows = append(rows, mergedDVBCard{card: card, configIndex: configIndex, fallbackMatch: fallbackMatch})
	}

	for i, config := range configs {
		if consumed[i] {
			continue
		}
		id := config.DeviceKey
		if id == "" {
			id = "address:" + config.LastAddress
		}
		adapter, frontend, _ := parseDVBCardAddress(config.LastAddress)
		card := model.DVBCard{
			ID:            id,
			DeviceKey:     config.DeviceKey,
			Address:       config.LastAddress,
			Adapter:       adapter,
			Frontend:      frontend,
			Present:       false,
			Status:        "offline",
			Config:        config,
			UpdatedAt:     config.UpdatedAt,
			ActiveStreams: 0,
		}
		if isDVBAddressIdentity(config.DeviceKey) {
			card.Warning = appendDVBCardWarning(card.Warning, dvbAddressWarning(config.LastAddress))
		}
		applyDVBCardStatus(&card, false)
		rows = append(rows, mergedDVBCard{card: card, configIndex: i, fallbackMatch: isDVBAddressIdentity(config.DeviceKey)})
	}
	return rows
}

func (s *Store) mergeDVBCardsLocked() []mergedDVBCard {
	rows := selectionDVBCards(s.dvbDetected, s.config.DVBCards)
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		seen[row.card.ID] = true
	}
	for id, u := range s.cardApplications {
		if !seen[id] && (u.application.State == "pending" || u.application.AppliedConfig != nil) {
			card := cloneDVBCard(u.card)
			card.Present = false
			card.Status = "offline"
			rows = append(rows, mergedDVBCard{card: card, configIndex: -1})
		}
	}
	for i := range rows {
		card := &rows[i].card
		selection := cloneDVBCard(*card)
		selection.Config.DeviceKey = selection.ID
		ownership, owned := s.dvbOwnership[card.DeviceKey]
		if !owned {
			if u, ok := s.cardApplications[card.ID]; ok && u.card.ActiveSessions != 0 {
				ownership = dvbCardOwnership{CurrentTransport: u.card.CurrentTransport, ActiveSessions: u.card.ActiveSessions, ActiveStreams: u.card.ActiveStreams}
				owned = true
			}
		}
		if owned {
			applyDVBCardOwnership(card, ownership)
		}
		applyDVBCardStatus(card, owned)
		if u, ok := s.cardApplications[card.ID]; ok {
			a := u.application
			if a.AppliedConfig != nil {
				cfg := *a.AppliedConfig
				a.AppliedConfig = &cfg
			}
			// Persistence and scheduler publication have separate lock boundaries.
			// Never describe newer durable settings as already accepted in that gap.
			if cardSelectionFingerprint(selection) != cardSelectionFingerprint(u.card) && a.State != "failed" {
				a.State = "pending"
				a.Reason = "publishing"
				a.DesiredRevision = 0
				a.AdmissionBlocked = true
			}
			card.Application = &a
		}
		if s.disableRuntime {
			card.Application = &model.DVBCardApplication{State: "runtime_disabled", AdmissionBlocked: true, Reason: "runtime_disabled"}
		}
		if status := s.dvbCardOperationStatus(card.ID); status != "" && card.Present && card.Status != "busy_external" {
			card.Status = status
		}
	}
	return rows
}
func cardSelectionInventory(detected []model.DVBCard, configs []model.DVBCardConfig) []model.DVBCard {
	rows := selectionDVBCards(detected, configs)
	cards := make([]model.DVBCard, 0, len(rows))
	for _, row := range rows {
		card := cloneDVBCard(row.card)
		card.Config.DeviceKey = card.ID
		card.Application = nil
		card.CurrentTransport = nil
		card.ActiveSessions = 0
		card.ActiveStreams = 0
		card.Signal = nil
		cards = append(cards, card)
	}
	return cards
}

func summarizeDVBCards(rows []mergedDVBCard) model.DVBCardSummary {
	summary := model.DVBCardSummary{Total: len(rows)}
	for _, row := range rows {
		switch row.card.Status {
		case "available":
			summary.Available++
		case "active":
			summary.Active++
		case "busy_external":
			summary.BusyExternal++
		case "error":
			summary.Error++
		case "offline":
			summary.Offline++
		case "disabled":
			summary.Disabled++
		}
	}
	return summary
}

func canonicalDVBDeliverySystem(value string) string {
	canonical, ok := model.CanonicalDVBDeliverySystem(value)
	if !ok {
		return ""
	}
	return canonical
}

func dvbCardSupportsDelivery(card model.DVBCard, delivery string) bool {
	if delivery == "" {
		return false
	}
	for _, supported := range card.DeliverySystems {
		if canonicalDVBDeliverySystem(supported) == delivery {
			return true
		}
	}
	return false
}

func dvbCardMatchesQuery(card model.DVBCard, query model.DVBCardQuery) bool {
	if status := strings.ToLower(strings.TrimSpace(query.Status)); status != "" && card.Status != status {
		return false
	}
	if delivery := strings.TrimSpace(query.DeliverySystem); delivery != "" {
		canonical, ok := model.CanonicalDVBInventoryDeliverySystem(delivery)
		if !ok {
			return false
		}
		matches := slices.ContainsFunc(card.DeliverySystems, func(token string) bool {
			system, valid := model.CanonicalDVBInventoryDeliverySystem(token)
			return valid && system == canonical
		})
		if !matches {
			return false
		}
	}
	if wantedModel := strings.TrimSpace(query.Model); wantedModel != "" && !strings.EqualFold(strings.TrimSpace(card.Model), wantedModel) {
		return false
	}
	if text := strings.ToLower(strings.TrimSpace(query.Q)); text != "" {
		haystack := strings.ToLower(strings.Join([]string{
			card.ID,
			card.DeviceKey,
			card.Address,
			card.FrontendType,
			strings.Join(card.DeliverySystems, " "),
			card.Manufacturer,
			card.Model,
			card.OwnerCommand,
			card.Config.Alias,
			card.Warning,
			card.LastError,
		}, " "))
		if !strings.Contains(haystack, text) {
			return false
		}
	}
	return true
}

func compareInts(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareTimes(left, right time.Time) int {
	if left.Before(right) {
		return -1
	}
	if left.After(right) {
		return 1
	}
	return 0
}

func compareDVBCardDefault(left, right model.DVBCard) int {
	if result := compareInts(left.Adapter, right.Adapter); result != 0 {
		return result
	}
	if result := compareInts(left.Frontend, right.Frontend); result != 0 {
		return result
	}
	return strings.Compare(left.ID, right.ID)
}

func compareDVBCardForQuery(left, right model.DVBCard, sortField string) int {
	var result int
	switch strings.ToLower(strings.TrimSpace(sortField)) {
	case "adapter":
		result = compareInts(left.Adapter, right.Adapter)
	case "frontend":
		result = compareInts(left.Frontend, right.Frontend)
	case "address":
		result = compareInts(left.Adapter, right.Adapter)
		if result == 0 {
			result = compareInts(left.Frontend, right.Frontend)
		}
	case "id", "device_key":
		result = strings.Compare(left.ID, right.ID)
	case "model":
		result = strings.Compare(strings.ToLower(left.Model), strings.ToLower(right.Model))
	case "type":
		result = strings.Compare(strings.ToLower(strings.TrimSpace(left.FrontendType)), strings.ToLower(strings.TrimSpace(right.FrontendType)))
	case "manufacturer":
		result = strings.Compare(strings.ToLower(left.Manufacturer), strings.ToLower(right.Manufacturer))
	case "status":
		result = strings.Compare(left.Status, right.Status)
	case "alias":
		result = strings.Compare(strings.ToLower(left.Config.Alias), strings.ToLower(right.Config.Alias))
	case "updated_at":
		result = compareTimes(left.UpdatedAt, right.UpdatedAt)
	default:
		return compareDVBCardDefault(left, right)
	}
	if result != 0 {
		return result
	}
	return compareDVBCardDefault(left, right)
}

func (s *Store) ListDVBCards(query model.DVBCardQuery) model.DVBCardPage {
	return s.listDVBCards(query, false)
}

// ListPublicDVBCards prevents query results from depending on private process
// arguments or raw diagnostics while retaining the management query contract.
func (s *Store) ListPublicDVBCards(query model.DVBCardQuery) model.DVBCardPage {
	return s.listDVBCards(query, true)
}

func (s *Store) listDVBCards(query model.DVBCardQuery, public bool) model.DVBCardPage {
	pageNumber := query.Page
	if pageNumber < 1 {
		pageNumber = 1
	}
	limit := query.Limit
	switch limit {
	case 50, 100, 200:
	default:
		limit = 100
	}

	s.mu.RLock()
	rows := s.mergeDVBCardsLocked()
	refreshedAt := s.dvbRefreshedAt
	summary := summarizeDVBCards(rows)
	s.dvbRefreshStateMu.Lock()
	refreshError := s.dvbRefreshError
	stale := s.dvbStale
	s.dvbLastSummary = summary
	s.dvbRefreshStateMu.Unlock()
	s.mu.RUnlock()

	filtered := make([]model.DVBCard, 0, len(rows))
	for _, row := range rows {
		if public {
			row.card.OwnerCommand = ""
			row.card.Warning = ""
			row.card.LastError = ""
		}
		if dvbCardMatchesQuery(row.card, query) {
			filtered = append(filtered, cloneDVBCard(row.card))
		}
	}
	descending := strings.EqualFold(strings.TrimSpace(query.Order), "desc")
	slices.SortStableFunc(filtered, func(left, right model.DVBCard) int {
		result := compareDVBCardForQuery(left, right, query.Sort)
		if descending {
			return -result
		}
		return result
	})

	start := len(filtered)
	if pageNumber <= (len(filtered)+limit-1)/limit {
		start = (pageNumber - 1) * limit
	}
	end := min(start+limit, len(filtered))
	items := cloneDVBCards(filtered[start:end])
	return model.DVBCardPage{
		Items:        items,
		Total:        len(filtered),
		Page:         pageNumber,
		Limit:        limit,
		Summary:      summary,
		RefreshedAt:  refreshedAt,
		RefreshError: refreshError,
		Stale:        stale,
		Facets:       dvbCardFacets(rows),
	}
}

func dvbCardFacets(rows []mergedDVBCard) model.DVBCardFacets {
	models := make(map[string]string)
	delivery := make(map[string]bool)
	for _, row := range rows {
		name := strings.TrimSpace(row.card.Model)
		key := strings.ToLower(name)
		if old, exists := models[key]; name != "" && (!exists || name < old) {
			models[key] = name
		}
		for _, token := range row.card.DeliverySystems {
			if canonical, ok := model.CanonicalDVBInventoryDeliverySystem(token); ok {
				delivery[canonical] = true
			}
		}
	}
	result := model.DVBCardFacets{Models: make([]string, 0, len(models)), DeliverySystems: make([]string, 0, len(delivery))}
	for _, name := range models {
		result.Models = append(result.Models, name)
	}
	for token := range delivery {
		result.DeliverySystems = append(result.DeliverySystems, token)
	}
	slices.SortFunc(result.Models, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	slices.Sort(result.DeliverySystems)
	return result
}

func (s *Store) DVBCard(id string) (model.DVBCard, error) {
	id = strings.TrimSpace(id)
	s.mu.RLock()
	rows := s.mergeDVBCardsLocked()
	for _, row := range rows {
		if row.card.ID == id {
			card := cloneDVBCard(row.card)
			s.mu.RUnlock()
			return card, nil
		}
	}
	s.mu.RUnlock()
	return model.DVBCard{}, errors.New("dvb card not found")
}

func normalizeDVBCardRF(in model.AdapterLNBConfig) model.AdapterLNBConfig {
	defaults := model.DefaultAdapterLNB()
	out := in
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	if out.Mode == "" {
		out.Mode = defaults.Mode
	}
	out.SlotPosition = strings.ToUpper(strings.TrimSpace(out.SlotPosition))
	if out.SlotPosition == "" {
		out.SlotPosition = defaults.SlotPosition
	}
	if out.LOF1 == 0 {
		out.LOF1 = defaults.LOF1
	}
	if out.LOF2 == 0 {
		out.LOF2 = defaults.LOF2
	}
	if out.SLOF == 0 {
		out.SLOF = defaults.SLOF
	}
	if out.SlotFrequency == 0 {
		out.SlotFrequency = defaults.SlotFrequency
	}
	return out
}

func normalizeDVBCardAdvanced(in model.AdapterAdvancedConfig) model.AdapterAdvancedConfig {
	defaults := model.DefaultAdapterAdvanced()
	out := in
	out.Modulation = strings.TrimSpace(out.Modulation)
	if out.Modulation == "" {
		out.Modulation = defaults.Modulation
	}
	out.FEC = strings.TrimSpace(out.FEC)
	if out.FEC == "" {
		out.FEC = defaults.FEC
	}
	out.RollOff = strings.TrimSpace(out.RollOff)
	if out.RollOff == "" {
		out.RollOff = defaults.RollOff
	}
	out.StreamID = strings.TrimSpace(out.StreamID)
	if out.TimeoutSec == 0 {
		out.TimeoutSec = defaults.TimeoutSec
	}
	out.DVBAPI = strings.ToLower(strings.TrimSpace(out.DVBAPI))
	if out.DVBAPI == "" {
		out.DVBAPI = defaults.DVBAPI
	}
	return out
}

func validateSatelliteRF(rf model.AdapterLNBConfig) error {
	if rf.LOF1 <= 0 || rf.LOF2 <= 0 || rf.SLOF <= 0 {
		return errors.New("satellite RF requires positive LOF1, LOF2, and SLOF")
	}
	switch strings.ToLower(strings.TrimSpace(rf.Mode)) {
	case "unicable1":
		if rf.UnicableSlot < 1 || rf.UnicableSlot > 8 {
			return errors.New("Unicable I slot must be between 1 and 8")
		}
		if rf.SlotFrequency <= 0 {
			return errors.New("Unicable I user-band frequency must be positive")
		}
	case "unicable2":
		if rf.UnicableSlot < 1 || rf.UnicableSlot > 32 {
			return errors.New("Unicable II slot must be between 1 and 32")
		}
		if rf.SlotFrequency <= 0 {
			return errors.New("Unicable II user-band frequency must be positive")
		}
	}
	return nil
}

func normalizeAndValidateDVBCardConfig(in model.DVBCardConfig) (model.DVBCardConfig, error) {
	out := in
	out.Alias = strings.TrimSpace(out.Alias)
	out.RFDefaults = normalizeDVBCardRF(out.RFDefaults)
	out.Advanced = normalizeDVBCardAdvanced(out.Advanced)
	if err := validateSatelliteRF(out.RFDefaults); err != nil {
		return model.DVBCardConfig{}, err
	}
	if out.Advanced.TimeoutSec < 0 {
		return model.DVBCardConfig{}, errors.New("advanced timeout_sec must be non-negative")
	}
	return out, nil
}

func (s *Store) UpdateDVBCard(id string, in model.DVBCardConfig) (model.DVBCard, error) {
	end, err := s.admitRuntime()
	if err != nil {
		return model.DVBCard{}, err
	}
	defer end()
	s.cardPublicationMu.Lock()
	locked := true
	var abortUpdates []dvbCardApplicationUpdate
	defer func() {
		if locked {
			s.cardPublicationMu.Unlock()
		}
		s.installCardApplications(abortUpdates)
	}()
	if s.runtimeClosing() {
		return model.DVBCard{}, ErrStoreClosed
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	rows := selectionDVBCards(s.dvbDetected, s.config.DVBCards)
	var target *mergedDVBCard
	for i := range rows {
		if rows[i].card.ID == id {
			target = &rows[i]
			break
		}
	}
	if target == nil {
		s.mu.Unlock()
		return model.DVBCard{}, errors.New("dvb card not found")
	}

	normalized, err := normalizeAndValidateDVBCardConfig(in)
	if err != nil {
		s.mu.Unlock()
		return model.DVBCard{}, err
	}
	card := target.card
	config := normalized
	if target.configIndex >= 0 {
		existing := s.config.DVBCards[target.configIndex]
		config.DeviceKey = existing.DeviceKey
		config.LastAddress = existing.LastAddress
	}
	if card.Present && !isDVBAddressIdentity(card.DeviceKey) {
		config.DeviceKey = card.DeviceKey
		config.LastAddress = card.Address
	} else if target.configIndex < 0 {
		config.DeviceKey = card.DeviceKey
		config.LastAddress = card.Address
	}
	config.UpdatedAt = s.now().UTC()

	candidate := slices.Clone(s.config.DVBCards)
	if target.configIndex >= 0 {
		candidate[target.configIndex] = config
	} else {
		candidate = append(candidate, config)
	}
	inventory := cardSelectionInventory(s.dvbDetected, candidate)
	s.mu.Unlock()
	var tx *dvbCardUpdate
	if s.scheduler != nil {
		tx, err = s.scheduler.prepareCardUpdate(inventory)
		if err != nil {
			return model.DVBCard{}, err
		}
	}
	s.mu.Lock()
	if s.runtimeClosing() {
		s.mu.Unlock()
		if tx != nil {
			abortUpdates = s.scheduler.abortCardUpdate(tx)
		}
		return model.DVBCard{}, ErrStoreClosed
	}
	previousCards := s.config.DVBCards
	previousUpdatedAt := s.config.UpdatedAt
	previousLogs := slices.Clone(s.logs)
	s.config.DVBCards = candidate
	if err := s.saveLocked(); err != nil {
		s.config.DVBCards = previousCards
		s.config.UpdatedAt = previousUpdatedAt
		s.logs = previousLogs
		s.mu.Unlock()
		if tx != nil {
			abortUpdates = s.scheduler.abortCardUpdate(tx)
		}
		return model.DVBCard{}, err
	}
	s.appendLogLocked("info", fmt.Sprintf("DVB card updated: %s (%s)", config.Alias, card.ID))
	var events dvbEventBatch
	var committed model.DVBCard
	if s.scheduler == nil {
		for _, row := range s.mergeDVBCardsLocked() {
			if row.card.ID == id {
				committed = cloneDVBCard(row.card)
				events.add(s, "dvb.card.changed", id, committed)
				break
			}
		}
		events.add(s, "dvb.collection.changed", "", model.DVBInvalidation{Cards: true})
	}
	s.mu.Unlock()
	var updates []dvbCardApplicationUpdate
	if tx != nil {
		updates = s.scheduler.commitCardUpdate(tx)
	}
	s.cardPublicationMu.Unlock()
	locked = false
	events.emit(s)
	s.installCardApplications(updates)
	if s.scheduler == nil {
		return committed, nil
	}
	return s.DVBCard(id)
}

func (s *Store) setDVBCardOwnership(deviceKey string, ownership dvbCardOwnership) {
	deviceKey = strings.TrimSpace(deviceKey)
	if deviceKey == "" {
		return
	}
	s.mu.Lock()
	s.dvbOwnership[deviceKey] = cloneDVBCardOwnership(ownership)
	s.dvbRefreshStateMu.Lock()
	s.dvbLastSummary = summarizeDVBCards(s.mergeDVBCardsLocked())
	s.dvbRefreshStateMu.Unlock()
	s.mu.Unlock()
}

func (s *Store) clearDVBCardOwnership(deviceKey string) {
	deviceKey = strings.TrimSpace(deviceKey)
	if deviceKey == "" {
		return
	}
	s.mu.Lock()
	delete(s.dvbOwnership, deviceKey)
	s.dvbRefreshStateMu.Lock()
	s.dvbLastSummary = summarizeDVBCards(s.mergeDVBCardsLocked())
	s.dvbRefreshStateMu.Unlock()
	s.mu.Unlock()
}

func usableSatelliteRF(rf model.AdapterLNBConfig) bool {
	return validateSatelliteRF(rf) == nil
}

func cardCandidateMatchesPolicy(card model.DVBCard, policy model.DVBAdapterPolicy) (bool, bool) {
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" || mode == "auto" {
		return true, false
	}
	if mode != "fixed" {
		return false, false
	}
	deviceKey := strings.TrimSpace(policy.DeviceKey)
	if deviceKey != "" && !strings.HasPrefix(deviceKey, "address:") {
		return card.DeviceKey == deviceKey, false
	}

	address := strings.TrimSpace(policy.LastAddress)
	if strings.HasPrefix(deviceKey, "address:") {
		keyAddress := strings.TrimPrefix(deviceKey, "address:")
		if !isCanonicalDVBAddress(keyAddress) {
			return false, false
		}
		if address == "" {
			address = keyAddress
		} else if address != keyAddress {
			return false, false
		}
	}
	if !isCanonicalDVBAddress(address) {
		return false, false
	}
	return card.Address == address, card.Address == address
}

func (s *Store) cardCandidates(policy model.DVBAdapterPolicy, cfg model.DVBStreamConfig) []model.DVBCard {
	delivery := canonicalDVBDeliverySystem(cfg.DeliverySystem)
	if delivery == "" {
		return nil
	}
	s.mu.RLock()
	rows := s.mergeDVBCardsLocked()
	s.mu.RUnlock()

	candidates := make([]model.DVBCard, 0, len(rows))
	for _, row := range rows {
		card := cloneDVBCard(row.card)
		if !card.Present || !card.Config.Enabled || (card.Status != "available" && card.Status != "active") {
			continue
		}
		if !dvbCardSupportsDelivery(card, delivery) {
			continue
		}
		matches, addressFallback := cardCandidateMatchesPolicy(card, policy)
		if !matches {
			continue
		}
		resolvedRF := card.Config.RFDefaults
		if cfg.RFOverride != nil {
			resolvedRF = *cfg.RFOverride
		}
		if (delivery == "dvbs" || delivery == "dvbs2") && !usableSatelliteRF(resolvedRF) {
			continue
		}
		card.Config.RFDefaults = resolvedRF
		if addressFallback {
			card.Warning = appendDVBCardWarning(card.Warning, dvbAddressWarning(card.Address))
		}
		candidates = append(candidates, card)
	}
	slices.SortStableFunc(candidates, compareDVBCardDefault)
	return cloneDVBCards(candidates)
}
