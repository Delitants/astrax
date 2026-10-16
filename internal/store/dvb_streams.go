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

	"astrax/internal/csa"
	"astrax/internal/model"
)

const (
	dvbActualAdapterUnassigned        = "unassigned"
	dvbStructuredSchedulerUnavailable = "structured DVB scheduler unavailable"
)

type dvbStreamRuntimeAction struct {
	ID     string
	Action string
	Stream model.Stream
}

type dvbStreamMutationSnapshot struct {
	streams []model.Stream
	runtime map[string]model.StreamRuntime
	logs    []model.LogEntry
	updated time.Time
}

func cloneDVBPlacement(in *model.DVBPlacementRuntime) *model.DVBPlacementRuntime {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneStreamRuntime(in model.StreamRuntime) model.StreamRuntime {
	out := in
	out.Signal = cloneDVBSignal(in.Signal)
	out.Placement = cloneDVBPlacement(in.Placement)
	out.Descrambling = in.Descrambling.Clone()
	return out
}

func cloneStream(in model.Stream) model.Stream {
	out := in
	out.CAIDs = slices.Clone(in.CAIDs)
	out.DVB = cloneDVBStreamConfig(in.DVB)
	out.DVBDescrambling = in.DVBDescrambling.Clone()
	out.Runtime = cloneStreamRuntime(in.Runtime)
	return out
}

func cloneStreams(in []model.Stream) []model.Stream {
	out := make([]model.Stream, len(in))
	for i := range in {
		out[i] = cloneStream(in[i])
	}
	return out
}

func cloneStreamRuntimeMap(in map[string]model.StreamRuntime) map[string]model.StreamRuntime {
	out := make(map[string]model.StreamRuntime, len(in))
	for id, runtime := range in {
		out[id] = cloneStreamRuntime(runtime)
	}
	return out
}

func (s *Store) snapshotDVBStreamMutationLocked() dvbStreamMutationSnapshot {
	return dvbStreamMutationSnapshot{
		streams: cloneStreams(s.config.Streams),
		runtime: cloneStreamRuntimeMap(s.runtime),
		logs:    slices.Clone(s.logs),
		updated: s.config.UpdatedAt,
	}
}

func (s *Store) restoreDVBStreamMutationLocked(snapshot dvbStreamMutationSnapshot) {
	s.config.Streams = snapshot.streams
	s.runtime = snapshot.runtime
	s.logs = snapshot.logs
	s.config.UpdatedAt = snapshot.updated
	s.rebuildDVBIndexesLocked()
}

func (s *Store) rebuildDVBIndexesLocked() {
	byID := make(map[string]int, len(s.config.Streams))
	dvbIDs := make([]string, 0, len(s.config.Streams))
	groupIDs := map[string][]string{"": {}}
	for _, group := range s.config.DVBGroups {
		groupIDs[group.ID] = []string{}
	}
	for i := range s.config.Streams {
		stream := s.config.Streams[i]
		byID[stream.ID] = i
		if stream.DVB == nil {
			continue
		}
		dvbIDs = append(dvbIDs, stream.ID)
		groupIDs[stream.GroupID] = append(groupIDs[stream.GroupID], stream.ID)
	}
	slices.Sort(dvbIDs)
	for groupID := range groupIDs {
		slices.Sort(groupIDs[groupID])
	}
	s.streamIndexByID = byID
	s.dvbStreamIDs = dvbIDs
	s.groupStreamIDs = groupIDs
}

func requestedDVBAdapterKey(stream model.Stream) string {
	if stream.DVB == nil {
		return ""
	}
	policy := stream.DVB.Adapter
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" || mode == "auto" {
		return "auto"
	}
	if key := strings.TrimSpace(policy.DeviceKey); key != "" {
		return key
	}
	if address := strings.TrimSpace(policy.LastAddress); address != "" {
		return "address:" + address
	}
	return ""
}

func actualDVBAdapterKey(stream model.Stream) string {
	if stream.Runtime.Placement == nil || strings.TrimSpace(stream.Runtime.Placement.ActualCardID) == "" {
		return dvbActualAdapterUnassigned
	}
	return strings.TrimSpace(stream.Runtime.Placement.ActualCardID)
}

func normalizeRequestedDVBAdapterKey(value string) string {
	if strings.EqualFold(value, "auto") {
		return "auto"
	}
	if len(value) >= len("address:") && strings.EqualFold(value[:len("address:")], "address:") {
		return "address:" + value[len("address:"):]
	}
	return value
}

func normalizedDVBProtocol(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizedDVBStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func dvbStreamMatchesQuery(stream model.Stream, query model.DVBStreamQuery) bool {
	if query.DescramblingState != "" || query.DescramblingReason != "" {
		rt := stream.Runtime.Descrambling
		if rt == nil {
			rt = descramblingBaseRuntime(stream)
		}
		if query.DescramblingState != "" && rt.State != query.DescramblingState {
			return false
		}
		if query.DescramblingReason != "" && rt.Reason != query.DescramblingReason {
			return false
		}
	}
	if status := normalizedDVBStatus(query.Status); status != "" && normalizedDVBStatus(stream.Runtime.State) != status {
		return false
	}
	if requested := normalizeRequestedDVBAdapterKey(query.RequestedAdapter); requested != "" && requestedDVBAdapterKey(stream) != requested {
		return false
	}
	actual := query.ActualAdapter
	if strings.EqualFold(actual, dvbActualAdapterUnassigned) {
		actual = dvbActualAdapterUnassigned
	}
	if actual != "" && actualDVBAdapterKey(stream) != actual {
		return false
	}
	if rawDelivery := strings.TrimSpace(query.DeliverySystem); rawDelivery != "" {
		delivery := canonicalDVBDeliverySystem(rawDelivery)
		if delivery == "" || canonicalDVBDeliverySystem(stream.DVB.DeliverySystem) != delivery {
			return false
		}
	}
	if protocol := normalizedDVBProtocol(query.Protocol); protocol != "" && normalizedDVBProtocol(stream.Protocol) != protocol {
		return false
	}
	if text := strings.ToLower(strings.TrimSpace(query.Q)); text != "" {
		haystack := strings.ToLower(strings.Join([]string{
			stream.ID,
			stream.Name,
			stream.InputURL,
			stream.OutputURL,
			stream.GroupID,
			stream.Protocol,
			stream.DVB.DeliverySystem,
			stream.DVB.Polarization,
			strconv.FormatUint(uint64(stream.DVB.FrequencyKHz), 10),
			strconv.Itoa(stream.DVB.ServiceID),
			requestedDVBAdapterKey(stream),
			actualDVBAdapterKey(stream),
		}, " "))
		if !strings.Contains(haystack, text) {
			return false
		}
	}
	return true
}

func newDVBStreamFacets() model.DVBStreamFacets {
	return model.DVBStreamFacets{
		Groups:            make(map[string]int),
		Statuses:          make(map[string]int),
		RequestedAdapters: make(map[string]int),
		ActualAdapters:    make(map[string]int),
		DeliverySystems:   make(map[string]int),
		Protocols:         make(map[string]int),
	}
}

func addDVBStreamFacets(facets *model.DVBStreamFacets, stream model.Stream) {
	facets.Groups[stream.GroupID]++
	facets.Statuses[normalizedDVBStatus(stream.Runtime.State)]++
	facets.RequestedAdapters[requestedDVBAdapterKey(stream)]++
	facets.ActualAdapters[actualDVBAdapterKey(stream)]++
	facets.DeliverySystems[canonicalDVBDeliverySystem(stream.DVB.DeliverySystem)]++
	facets.Protocols[normalizedDVBProtocol(stream.Protocol)]++
}

func compareDVBStreamsForQuery(left, right model.Stream, sortField string) int {
	var result int
	switch strings.ToLower(strings.TrimSpace(sortField)) {
	case "id":
		result = strings.Compare(left.ID, right.ID)
	case "status", "state":
		result = strings.Compare(normalizedDVBStatus(left.Runtime.State), normalizedDVBStatus(right.Runtime.State))
	case "group", "group_id":
		result = strings.Compare(strings.ToLower(left.GroupID), strings.ToLower(right.GroupID))
	case "service", "service_id":
		result = compareInts(left.DVB.ServiceID, right.DVB.ServiceID)
		if result == 0 {
			result = compareInts(int(left.DVB.FrequencyKHz), int(right.DVB.FrequencyKHz))
		}
	case "transponder", "frequency", "frequency_khz":
		if left.DVB.FrequencyKHz < right.DVB.FrequencyKHz {
			result = -1
		} else if left.DVB.FrequencyKHz > right.DVB.FrequencyKHz {
			result = 1
		}
		if result == 0 {
			result = compareInts(left.DVB.ServiceID, right.DVB.ServiceID)
		}
	case "requested_adapter":
		result = strings.Compare(strings.ToLower(requestedDVBAdapterKey(left)), strings.ToLower(requestedDVBAdapterKey(right)))
	case "actual_adapter":
		result = strings.Compare(strings.ToLower(actualDVBAdapterKey(left)), strings.ToLower(actualDVBAdapterKey(right)))
	case "output", "output_url":
		result = strings.Compare(strings.ToLower(left.OutputURL), strings.ToLower(right.OutputURL))
	case "protocol":
		result = strings.Compare(normalizedDVBProtocol(left.Protocol), normalizedDVBProtocol(right.Protocol))
	case "updated", "updated_at", "updated_time":
		result = compareTimes(left.UpdatedAt, right.UpdatedAt)
	case "name", "":
		result = strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name))
	default:
		result = strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name))
	}
	if result != 0 {
		return result
	}
	return strings.Compare(left.ID, right.ID)
}

// ListDVBStreams defaults to name then ID ordering. All filtering, facets,
// sorting, and pagination operate on the bounded index snapshot after unlock.
func (s *Store) ListDVBStreams(query model.DVBStreamQuery) model.DVBStreamPage {
	return s.listDVBStreams(query, false)
}

// ListPublicDVBStreams excludes withheld URLs before search, ordering and
// facet calculation, not merely after a management page has been selected.
func (s *Store) ListPublicDVBStreams(query model.DVBStreamQuery) model.DVBStreamPage {
	return s.listDVBStreams(query, true)
}

func (s *Store) listDVBStreams(query model.DVBStreamQuery, public bool) model.DVBStreamPage {
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

	groupFilter := query.Group
	candidateGroup := groupFilter
	if strings.EqualFold(groupFilter, "ungrouped") {
		candidateGroup = ""
	}

	s.mu.RLock()
	candidateIDs := s.dvbStreamIDs
	if groupFilter != "" {
		candidateIDs = s.groupStreamIDs[candidateGroup]
	}
	if s.testHookDVBStreamQueryCandidatesLocked != nil {
		s.testHookDVBStreamQueryCandidatesLocked(slices.Clone(candidateIDs))
	}
	if s.testHookBeforeDVBStreamQueryCopyLocked != nil {
		s.testHookBeforeDVBStreamQueryCopyLocked()
	}
	candidates := make([]model.Stream, 0, len(candidateIDs))
	for _, id := range candidateIDs {
		idx, ok := s.streamIndexByID[id]
		if !ok || idx < 0 || idx >= len(s.config.Streams) {
			continue
		}
		stream := cloneStream(s.config.Streams[idx])
		if stream.DVB == nil {
			continue
		}
		if runtime, ok := s.runtime[id]; ok {
			stream.Runtime = cloneStreamRuntime(runtime)
		} else if stream.Enabled {
			stream.Runtime = model.StreamRuntime{State: "starting"}
		} else {
			stream.Runtime = model.StreamRuntime{State: "stopped"}
		}
		projectDescramblingRuntime(&stream)
		candidates = append(candidates, stream)
	}
	s.mu.RUnlock()

	filtered := make([]model.Stream, 0, len(candidates))
	facets := newDVBStreamFacets()
	for _, stream := range candidates {
		if public {
			stream.InputURL = ""
			stream.OutputURL = ""
		}
		if !dvbStreamMatchesQuery(stream, query) {
			continue
		}
		filtered = append(filtered, stream)
		addDVBStreamFacets(&facets, stream)
	}
	descending := strings.EqualFold(strings.TrimSpace(query.Order), "desc")
	slices.SortStableFunc(filtered, func(left, right model.Stream) int {
		result := compareDVBStreamsForQuery(left, right, query.Sort)
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
	return model.DVBStreamPage{
		Items:  cloneStreams(filtered[start:end]),
		Total:  len(filtered),
		Page:   pageNumber,
		Limit:  limit,
		Facets: facets,
	}
}

func normalizeDVBStreamInput(in model.Stream) model.Stream {
	out := cloneStream(in)
	out.Name = strings.TrimSpace(out.Name)
	out.InputURL = strings.TrimSpace(out.InputURL)
	out.OutputURL = strings.TrimSpace(out.OutputURL)
	out.Protocol = normalizedDVBProtocol(out.Protocol)
	if out.Protocol == "" {
		out.Protocol = "mpegts"
	}
	out.GroupID = strings.TrimSpace(out.GroupID)
	out.SoftcamID = strings.TrimSpace(out.SoftcamID)
	out.AdapterProfileID = strings.TrimSpace(out.AdapterProfileID)
	out.XMLTVChannelID = strings.TrimSpace(out.XMLTVChannelID)
	out.Runtime = model.StreamRuntime{}
	if out.DVB != nil {
		out.DVB.Normalize()
	}
	return out
}

func (s *Store) validateDVBStreamLocked(stream model.Stream) error {
	if stream.DVB == nil {
		return errors.New("DVB configuration is required")
	}
	if strings.TrimSpace(stream.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(stream.OutputURL) == "" {
		return errors.New("output_url is required")
	}
	if err := stream.DVB.Validate(); err != nil {
		return fmt.Errorf("validate DVB configuration: %w", err)
	}
	if stream.DVB.Adapter.Mode == "auto" && stream.DVB.Adapter.LastAddress == "0.0" {
		return errors.New("auto adapter cannot use LastAddress 0.0")
	}
	if stream.GroupID != "" && s.findDVBGroupIndexLocked(stream.GroupID) < 0 {
		return errors.New("dvb group not found")
	}
	if err := s.validateDVBDescramblingLocked(stream); err != nil {
		return err
	}
	if stream.SoftcamID != "" && s.findSoftcamIndexLocked(stream.SoftcamID) < 0 {
		return errors.New("softcam not found")
	}
	return s.validateConfiguredOutputLocked(stream)
}

func newDVBStreamRuntime(stream model.Stream, now time.Time) (result model.StreamRuntime) {
	defer func() { stream.Runtime = result; projectDescramblingRuntime(&stream); result = stream.Runtime }()
	if stream.Enabled && descramblingEnabled(stream) {
		rt := model.StreamRuntime{State: "error", Since: now.UTC(), LastError: descramblingRuntimeGate(stream).Error()}
		if available, _ := csa.Capability(); available {
			rt.State = "waiting_psi"
		}
		return rt
	}
	if stream.Enabled {
		return model.StreamRuntime{
			State:     "error",
			Since:     now.UTC(),
			LastError: dvbStructuredSchedulerUnavailable,
		}
	}
	return model.StreamRuntime{State: "stopped", Since: now.UTC()}
}

func (s *Store) setStructuredDVBStreamEnabled(id string, enabled bool, action string) (model.Stream, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	id = strings.TrimSpace(id)
	release := s.lockStructuredIDs([]string{id})
	defer release()
	s.mu.Lock()
	idx, exists := s.streamIndexByID[id]
	if !exists || idx < 0 || idx >= len(s.config.Streams) || !isStructuredDVBStream(s.config.Streams[idx]) {
		s.mu.Unlock()
		return model.Stream{}, errors.New("DVB stream not found")
	}

	stream := cloneStream(s.config.Streams[idx])
	if enabled {
		if err := s.validateDVBDescramblingLocked(stream); err != nil {
			s.mu.Unlock()
			return model.Stream{}, err
		}
	}
	snapshot := s.snapshotDVBStreamMutationLocked()
	now := s.now().UTC()
	if stream.Enabled != enabled {
		stream.Enabled = enabled
		stream.UpdatedAt = now
		s.config.Streams[idx] = cloneStream(stream)
		if err := s.saveLocked(); err != nil {
			s.restoreDVBStreamMutationLocked(snapshot)
			s.mu.Unlock()
			return model.Stream{}, err
		}
	}
	s.prepareStructuredRuntimeLocked(id, stream, now)
	level := "info"
	if action == "stop" || action == "restart" {
		level = "warn"
	}
	s.bumpStructuredConfigLocked(id)
	s.appendLogLocked(level, fmt.Sprintf("structured DVB stream %s requested: %s (%s)", action, stream.Name, stream.ID))
	result := cloneStream(s.config.Streams[idx])
	result.Runtime = cloneStreamRuntime(s.runtime[id])
	events.streamLocked(s, id)
	events.membershipLocked(s)
	s.mu.Unlock()

	s.runDVBStreamRuntimeActionsUnderGate([]dvbStreamRuntimeAction{{ID: id, Action: action, Stream: cloneStream(stream)}})
	s.broadcast()
	if !s.disableRuntime && s.scheduler != nil {
		return s.streamByID(id)
	}
	return cloneStream(result), nil
}

func (s *Store) AddDVBStream(in model.Stream) (model.Stream, error) {
	return s.AddDVBStreamContext(context.Background(), in)
}

func (s *Store) AddDVBStreamContext(ctx context.Context, in model.Stream) (model.Stream, error) {
	ctx, endRuntime, admissionErr := s.admitDVBMutation(ctx)
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	stream := normalizeDVBStreamInput(in)
	var err error
	stream, err = normalizeDVBDescrambling(stream)
	if err != nil {
		return model.Stream{}, err
	}
	stream.ID = ""
	stream.UpdatedAt = time.Time{}

	var id string
	var release func()
	for {
		id = newID()
		release, err = s.lockStructuredIDsContext(ctx, []string{id})
		if err != nil {
			return model.Stream{}, err
		}
		if err := s.mu.LockContext(ctx); err != nil {
			release()
			return model.Stream{}, err
		}
		if _, exists := s.streamIndexByID[id]; !exists {
			break
		}
		s.mu.Unlock()
		release()
	}
	defer release()
	stream.ID = id
	now := s.now().UTC()
	stream.UpdatedAt = now
	if err := s.validateDVBStreamLocked(stream); err != nil {
		s.mu.Unlock()
		return model.Stream{}, err
	}
	if s.testHookBeforeStreamMutationLocked != nil {
		s.testHookBeforeStreamMutationLocked()
	}
	snapshot := s.snapshotDVBStreamMutationLocked()
	s.config.Streams = append(s.config.Streams, cloneStream(stream))
	s.prepareStructuredRuntimeLocked(stream.ID, stream, now)
	s.rebuildDVBIndexesLocked()
	if err := s.saveStreamOutputContextLocked(ctx, stream); err != nil {
		s.restoreDVBStreamMutationLocked(snapshot)
		s.mu.Unlock()
		return model.Stream{}, err
	}
	s.bumpStructuredConfigLocked(stream.ID)
	s.appendLogLocked("info", fmt.Sprintf("DVB stream added: %s (%s)", stream.Name, stream.ID))
	result := cloneStream(s.config.Streams[s.streamIndexByID[stream.ID]])
	result.Runtime = cloneStreamRuntime(s.runtime[stream.ID])
	events.streamLocked(s, stream.ID)
	events.membershipLocked(s)
	s.mu.Unlock()

	actions := make([]dvbStreamRuntimeAction, 0, 1)
	if stream.Enabled {
		actions = append(actions, dvbStreamRuntimeAction{ID: stream.ID, Action: "reconcile", Stream: cloneStream(stream)})
	}
	s.runDVBStreamRuntimeActionsUnderGate(actions)
	s.broadcast()
	s.updateEPGChannels()
	if !s.disableRuntime && s.scheduler != nil {
		return s.streamByID(stream.ID)
	}
	return cloneStream(result), nil
}

func (s *Store) UpdateDVBStream(id string, in model.Stream) (model.Stream, error) {
	return s.UpdateDVBStreamContext(context.Background(), id, in)
}

func (s *Store) UpdateDVBStreamContext(ctx context.Context, id string, in model.Stream) (model.Stream, error) {
	ctx, endRuntime, admissionErr := s.admitDVBMutation(ctx)
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	id = strings.TrimSpace(id)
	release, err := s.lockStructuredIDsContext(ctx, []string{id})
	if err != nil {
		return model.Stream{}, err
	}
	defer release()
	stream := normalizeDVBStreamInput(in)
	stream, err = normalizeDVBDescrambling(stream)
	if err != nil {
		return model.Stream{}, err
	}
	stream.ID = id
	stream.UpdatedAt = time.Time{}

	if err := s.mu.LockContext(ctx); err != nil {
		return model.Stream{}, err
	}
	idx, exists := s.streamIndexByID[id]
	if !exists || idx < 0 || idx >= len(s.config.Streams) || s.config.Streams[idx].DVB == nil {
		s.mu.Unlock()
		return model.Stream{}, errors.New("DVB stream not found")
	}
	now := s.now().UTC()
	stream.UpdatedAt = now
	if err := s.validateDVBStreamLocked(stream); err != nil {
		s.mu.Unlock()
		return model.Stream{}, err
	}
	if s.testHookBeforeStreamMutationLocked != nil {
		s.testHookBeforeStreamMutationLocked()
	}
	snapshot := s.snapshotDVBStreamMutationLocked()
	s.config.Streams[idx] = cloneStream(stream)
	s.prepareStructuredRuntimeLocked(id, stream, now)
	s.rebuildDVBIndexesLocked()
	if err := s.saveStreamOutputContextLocked(ctx, stream); err != nil {
		s.restoreDVBStreamMutationLocked(snapshot)
		s.mu.Unlock()
		return model.Stream{}, err
	}
	s.bumpStructuredConfigLocked(id)
	s.appendLogLocked("info", fmt.Sprintf("DVB stream updated: %s (%s)", stream.Name, stream.ID))
	result := cloneStream(s.config.Streams[s.streamIndexByID[id]])
	result.Runtime = cloneStreamRuntime(s.runtime[id])
	events.streamLocked(s, id)
	events.membershipLocked(s)
	s.mu.Unlock()

	action := "stop"
	if stream.Enabled {
		action = "reconcile"
	}
	s.runDVBStreamRuntimeActionsUnderGate([]dvbStreamRuntimeAction{{ID: id, Action: action, Stream: cloneStream(stream)}})
	s.broadcast()
	s.updateEPGChannels()
	if !s.disableRuntime && s.scheduler != nil {
		return s.streamByID(id)
	}
	return cloneStream(result), nil
}

func (s *Store) DeleteDVBStream(id string) error {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return admissionErr
	}
	defer endRuntime()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	id = strings.TrimSpace(id)
	release := s.lockStructuredIDs([]string{id})
	defer release()
	s.mu.Lock()
	idx, exists := s.streamIndexByID[id]
	if !exists || idx < 0 || idx >= len(s.config.Streams) || s.config.Streams[idx].DVB == nil {
		s.mu.Unlock()
		return errors.New("DVB stream not found")
	}
	stream := cloneStream(s.config.Streams[idx])
	if s.testHookBeforeStreamMutationLocked != nil {
		s.testHookBeforeStreamMutationLocked()
	}
	snapshot := s.snapshotDVBStreamMutationLocked()
	s.config.Streams = append(s.config.Streams[:idx], s.config.Streams[idx+1:]...)
	delete(s.runtime, id)
	s.rebuildDVBIndexesLocked()
	if err := s.saveLocked(); err != nil {
		s.restoreDVBStreamMutationLocked(snapshot)
		s.mu.Unlock()
		return err
	}
	s.bumpStructuredConfigLocked(id)
	s.appendLogLocked("warn", fmt.Sprintf("DVB stream removed: %s (%s)", stream.Name, stream.ID))
	events.streamLocked(s, id)
	events.membershipLocked(s)
	s.mu.Unlock()

	s.runDVBStreamRuntimeActionsUnderGate([]dvbStreamRuntimeAction{{ID: id, Action: "delete", Stream: stream}})
	s.broadcast()
	s.updateEPGChannels()
	return nil
}

func normalizeBulkDVBAdapter(in *model.DVBAdapterPolicy) (model.DVBAdapterPolicy, error) {
	if in == nil {
		return model.DVBAdapterPolicy{}, errors.New("adapter is required")
	}
	probe := model.DVBStreamConfig{
		DeliverySystem: "dvbc",
		FrequencyKHz:   1,
		ServiceID:      1,
		Adapter:        *in,
	}
	probe.Normalize()
	if err := probe.Validate(); err != nil {
		return model.DVBAdapterPolicy{}, fmt.Errorf("invalid adapter: %w", err)
	}
	if probe.Adapter.Mode == "auto" && probe.Adapter.LastAddress == "0.0" {
		return model.DVBAdapterPolicy{}, errors.New("auto adapter cannot use LastAddress 0.0")
	}
	return probe.Adapter, nil
}

func finalizeBulkDVBStreamResult(result *model.BulkDVBStreamResult) {
	result.Succeeded = 0
	result.Failed = 0
	for _, item := range result.Results {
		if item.OK {
			result.Succeeded++
		} else {
			result.Failed++
		}
	}
}

func (s *Store) BulkDVBStreams(request model.BulkDVBStreamRequest) (model.BulkDVBStreamResult, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.BulkDVBStreamResult{}, admissionErr
	}
	defer endRuntime()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	action := strings.ToLower(strings.TrimSpace(request.Action))
	switch action {
	case "start", "stop", "restart", "move_group", "assign_adapter", "delete":
	default:
		return model.BulkDVBStreamResult{}, fmt.Errorf("unknown DVB stream bulk action %q", request.Action)
	}
	groupID := strings.TrimSpace(request.GroupID)
	var adapter model.DVBAdapterPolicy
	var err error
	if action == "assign_adapter" {
		adapter, err = normalizeBulkDVBAdapter(request.Adapter)
		if err != nil {
			return model.BulkDVBStreamResult{}, err
		}
	}

	ids := make([]string, len(request.IDs))
	for i, id := range request.IDs {
		ids[i] = strings.TrimSpace(id)
	}
	release := s.lockStructuredIDs(ids)
	defer release()
	result := model.BulkDVBStreamResult{Results: make([]model.BulkDVBStreamItemResult, len(request.IDs))}
	s.mu.Lock()
	if action == "move_group" && groupID != "" && s.findDVBGroupIndexLocked(groupID) < 0 {
		s.mu.Unlock()
		return model.BulkDVBStreamResult{}, errors.New("dvb group not found")
	}
	snapshot := s.snapshotDVBStreamMutationLocked()
	now := s.now().UTC()
	seen := make(map[string]struct{}, len(request.IDs))
	validResultIndexes := make([]int, 0, len(request.IDs))
	actions := make([]dvbStreamRuntimeAction, 0, len(request.IDs))
	deleteIDs := make(map[string]struct{})

	for resultIndex, requestedID := range request.IDs {
		item := &result.Results[resultIndex]
		item.ID = requestedID
		id := strings.TrimSpace(requestedID)
		if _, duplicate := seen[id]; duplicate {
			item.Error = "duplicate DVB stream ID in request"
			continue
		}
		seen[id] = struct{}{}
		idx, exists := s.streamIndexByID[id]
		if !exists || idx < 0 || idx >= len(s.config.Streams) {
			item.Error = "DVB stream not found"
			continue
		}
		stream := cloneStream(s.config.Streams[idx])
		if stream.DVB == nil {
			item.Error = "stream is not a structured DVB stream"
			continue
		}
		if action == "start" || action == "restart" || action == "assign_adapter" {
			if err := s.validateDVBDescramblingLocked(stream); err != nil {
				item.Error = err.Error()
				continue
			}
		}

		switch action {
		case "start":
			stream.Enabled = true
			stream.UpdatedAt = now
			s.config.Streams[idx] = cloneStream(stream)
			s.prepareStructuredRuntimeLocked(id, stream, now)
			actions = append(actions, dvbStreamRuntimeAction{ID: id, Action: action, Stream: cloneStream(stream)})
		case "stop":
			stream.Enabled = false
			stream.UpdatedAt = now
			s.config.Streams[idx] = cloneStream(stream)
			s.runtime[id] = model.StreamRuntime{State: "stopped", Since: now}
			actions = append(actions, dvbStreamRuntimeAction{ID: id, Action: action, Stream: cloneStream(stream)})
		case "restart":
			stream.Enabled = true
			stream.UpdatedAt = now
			s.config.Streams[idx] = cloneStream(stream)
			s.prepareStructuredRuntimeLocked(id, stream, now)
			actions = append(actions, dvbStreamRuntimeAction{ID: id, Action: action, Stream: cloneStream(stream)})
		case "move_group":
			stream.GroupID = groupID
			stream.UpdatedAt = now
			s.config.Streams[idx] = cloneStream(stream)
		case "assign_adapter":
			dvbConfig := cloneDVBStreamConfig(stream.DVB)
			dvbConfig.Adapter = adapter
			if err := dvbConfig.Validate(); err != nil {
				item.Error = fmt.Sprintf("validate assigned adapter: %v", err)
				continue
			}
			stream.DVB = dvbConfig
			stream.UpdatedAt = now
			s.config.Streams[idx] = cloneStream(stream)
			s.prepareStructuredRuntimeLocked(id, stream, now)
			if stream.Enabled {
				actions = append(actions, dvbStreamRuntimeAction{ID: id, Action: action, Stream: cloneStream(stream)})
			}
		case "delete":
			deleteIDs[id] = struct{}{}
			actions = append(actions, dvbStreamRuntimeAction{ID: id, Action: action, Stream: cloneStream(stream)})
		}
		item.OK = true
		validResultIndexes = append(validResultIndexes, resultIndex)
	}

	if len(validResultIndexes) == 0 {
		s.mu.Unlock()
		finalizeBulkDVBStreamResult(&result)
		return result, nil
	}
	if action == "delete" {
		kept := make([]model.Stream, 0, len(s.config.Streams)-len(deleteIDs))
		for _, stream := range s.config.Streams {
			if _, remove := deleteIDs[stream.ID]; remove {
				delete(s.runtime, stream.ID)
				continue
			}
			kept = append(kept, stream)
		}
		s.config.Streams = kept
	}
	s.rebuildDVBIndexesLocked()
	if err := s.saveLocked(); err != nil {
		s.restoreDVBStreamMutationLocked(snapshot)
		for _, resultIndex := range validResultIndexes {
			result.Results[resultIndex].OK = false
			result.Results[resultIndex].Error = err.Error()
		}
		s.mu.Unlock()
		finalizeBulkDVBStreamResult(&result)
		return result, err
	}
	for _, resultIndex := range validResultIndexes {
		id := strings.TrimSpace(result.Results[resultIndex].ID)
		s.bumpStructuredConfigLocked(id)
		s.appendLogLocked("info", fmt.Sprintf("DVB stream bulk %s: %s", action, id))
		events.streamLocked(s, id)
	}
	events.membershipLocked(s)
	s.mu.Unlock()

	s.runDVBStreamRuntimeActionsUnderGate(actions)
	s.broadcast()
	s.updateEPGChannels()
	finalizeBulkDVBStreamResult(&result)
	return result, nil
}

func (s *Store) runDVBStreamRuntimeActions(actions []dvbStreamRuntimeAction) {
	end, err := s.admitRuntime()
	if err != nil {
		return
	}
	defer end()
	for _, action := range actions {
		release := s.lockStructuredIDs([]string{action.ID})
		s.runDVBStreamRuntimeActionsUnderGate([]dvbStreamRuntimeAction{action})
		release()
	}
}
func (s *Store) runDVBStreamRuntimeActionsUnderGate(actions []dvbStreamRuntimeAction) {
	for _, action := range actions {
		action.Stream = cloneStream(action.Stream)
		if s.testHookDVBStreamRuntimeAction != nil {
			s.testHookDVBStreamRuntimeAction(action)
		}
		if s.disableRuntime {
			continue
		}
		if s.holdDescramblingActionUnderGate(action) {
			continue
		}
		if s.dvbStreamRuntimeActionExecutor != nil {
			s.dvbStreamRuntimeActionExecutor(action)
			continue
		}
		s.executeStructuredActionUnderGate(action)
	}
}
