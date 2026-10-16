// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"astrax/internal/model"
	"golang.org/x/text/cases"
)

func normalizeDVBGroupName(name string) (string, string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", "", errors.New("name is required")
	}
	return trimmed, cases.Fold().String(trimmed), nil
}

func (s *Store) findDVBGroupIndexLocked(id string) int {
	for i, group := range s.config.DVBGroups {
		if group.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) hasDVBGroupNameLocked(foldedName, exceptID string) bool {
	for _, group := range s.config.DVBGroups {
		if group.ID == exceptID {
			continue
		}
		_, currentFolded, err := normalizeDVBGroupName(group.Name)
		if err == nil && currentFolded == foldedName {
			return true
		}
	}
	return false
}

func (s *Store) ListDVBGroups() []model.DVBGroup {
	s.mu.RLock()
	groups := slices.Clone(s.config.DVBGroups)
	s.mu.RUnlock()

	slices.SortFunc(groups, func(a, b model.DVBGroup) int {
		if a.SortOrder < b.SortOrder {
			return -1
		}
		if a.SortOrder > b.SortOrder {
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	return groups
}

func (s *Store) AddDVBGroup(in model.DVBGroup) (model.DVBGroup, error) {
	end, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.DVBGroup{}, admissionErr
	}
	defer end()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	name, foldedName, err := normalizeDVBGroupName(in.Name)
	if err != nil {
		return model.DVBGroup{}, err
	}

	s.mu.Lock()
	if s.hasDVBGroupNameLocked(foldedName, "") {
		s.mu.Unlock()
		return model.DVBGroup{}, errors.New("dvb group name already exists")
	}

	sortOrder := 0
	if len(s.config.DVBGroups) > 0 {
		maxSortOrder := s.config.DVBGroups[0].SortOrder
		for _, group := range s.config.DVBGroups[1:] {
			if group.SortOrder > maxSortOrder {
				maxSortOrder = group.SortOrder
			}
		}
		sortOrder = maxSortOrder + 1
	}

	id := newID()
	for s.findDVBGroupIndexLocked(id) >= 0 {
		id = newID()
	}
	now := s.now().UTC()
	group := model.DVBGroup{
		ID:        id,
		Name:      name,
		SortOrder: sortOrder,
		CreatedAt: now,
		UpdatedAt: now,
	}
	previousGroups := slices.Clone(s.config.DVBGroups)
	s.config.DVBGroups = append(s.config.DVBGroups, group)
	if err := s.saveLocked(); err != nil {
		s.config.DVBGroups = previousGroups
		s.mu.Unlock()
		return model.DVBGroup{}, err
	}
	s.groupStreamIDs[group.ID] = []string{}
	s.appendLogLocked("info", fmt.Sprintf("DVB group added: %s (%s)", group.Name, group.ID))
	events.add(s, "dvb.group.changed", group.ID, group)
	events.membershipLocked(s)
	s.mu.Unlock()

	s.broadcast()
	return group, nil
}

func (s *Store) UpdateDVBGroup(id string, in model.DVBGroup) (model.DVBGroup, error) {
	end, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.DVBGroup{}, admissionErr
	}
	defer end()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	name, foldedName, err := normalizeDVBGroupName(in.Name)
	if err != nil {
		return model.DVBGroup{}, err
	}
	if id == "" {
		return model.DVBGroup{}, errors.New("dvb group not found")
	}

	s.mu.Lock()
	idx := s.findDVBGroupIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.DVBGroup{}, errors.New("dvb group not found")
	}
	if s.hasDVBGroupNameLocked(foldedName, id) {
		s.mu.Unlock()
		return model.DVBGroup{}, errors.New("dvb group name already exists")
	}

	group := s.config.DVBGroups[idx]
	group.Name = name
	group.UpdatedAt = s.now().UTC()
	previousGroups := slices.Clone(s.config.DVBGroups)
	s.config.DVBGroups[idx] = group
	if err := s.saveLocked(); err != nil {
		s.config.DVBGroups = previousGroups
		s.mu.Unlock()
		return model.DVBGroup{}, err
	}
	s.appendLogLocked("info", fmt.Sprintf("DVB group updated: %s (%s)", group.Name, group.ID))
	events.add(s, "dvb.group.changed", group.ID, group)
	events.membershipLocked(s)
	s.mu.Unlock()

	s.broadcast()
	return group, nil
}

func (s *Store) DeleteDVBGroup(id string) (int, error) {
	if id == "" {
		return 0, errors.New("dvb group not found")
	}

	end, err := s.admitRuntime()
	if err != nil {
		return 0, err
	}
	defer end()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	var release func()
	var affected []string
	for {
		s.mu.RLock()
		affected = nil
		for _, st := range s.config.Streams {
			if st.GroupID == id {
				affected = append(affected, st.ID)
			}
		}
		s.mu.RUnlock()
		if s.testHookBeforeDVBGroupDeleteGates != nil {
			s.testHookBeforeDVBGroupDeleteGates()
		}
		release = s.lockStructuredIDs(affected)
		s.mu.Lock()
		members := make(map[string]bool, len(affected))
		for _, member := range affected {
			members[member] = true
		}
		valid, count := true, 0
		for _, st := range s.config.Streams {
			if st.GroupID == id {
				count++
				if !members[st.ID] {
					valid = false
				}
			}
		}
		if valid && count == len(members) {
			break
		}
		s.mu.Unlock()
		release()
	}
	defer release()
	idx := s.findDVBGroupIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return 0, errors.New("dvb group not found")
	}

	group := s.config.DVBGroups[idx]
	previousGroups := slices.Clone(s.config.DVBGroups)
	previousStreams := cloneStreams(s.config.Streams)
	previousUpdatedAt := s.config.UpdatedAt
	if s.testHookBeforeDVBGroupDeleteMutationLocked != nil {
		s.testHookBeforeDVBGroupDeleteMutationLocked()
	}
	s.config.DVBGroups = append(s.config.DVBGroups[:idx], s.config.DVBGroups[idx+1:]...)
	now := s.now().UTC()
	moved := 0
	for i := range s.config.Streams {
		if s.config.Streams[i].GroupID != id {
			continue
		}
		s.config.Streams[i].GroupID = ""
		s.config.Streams[i].UpdatedAt = now
		moved++
	}
	s.rebuildDVBIndexesLocked()
	if err := s.saveLocked(); err != nil {
		s.config.DVBGroups = previousGroups
		s.config.Streams = previousStreams
		s.config.UpdatedAt = previousUpdatedAt
		s.rebuildDVBIndexesLocked()
		s.mu.Unlock()
		return 0, err
	}
	for _, streamID := range affected {
		if _, exists := s.currentStructuredLocked(streamID); exists {
			s.bumpStructuredConfigLocked(streamID)
		}
	}
	s.appendLogLocked("warn", fmt.Sprintf("DVB group removed: %s (%s); moved %d streams", group.Name, group.ID, moved))
	events.add(s, "dvb.group.removed", group.ID, nil)
	events.membershipLocked(s)
	s.mu.Unlock()

	s.broadcast()
	return moved, nil
}

func (s *Store) ReorderDVBGroups(ids []string) error {
	end, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return admissionErr
	}
	defer end()
	var events dvbEventBatch
	defer func() { events.emit(s) }()
	s.mu.Lock()
	if len(ids) != len(s.config.DVBGroups) {
		s.mu.Unlock()
		return errors.New("dvb group reorder must contain every group exactly once")
	}

	seen := make(map[string]struct{}, len(ids))
	reordered := make([]model.DVBGroup, len(ids))
	for i, id := range ids {
		if id == "" {
			s.mu.Unlock()
			return errors.New("dvb group reorder cannot contain Ungrouped")
		}
		if _, duplicate := seen[id]; duplicate {
			s.mu.Unlock()
			return errors.New("dvb group reorder contains a duplicate ID")
		}
		seen[id] = struct{}{}

		idx := s.findDVBGroupIndexLocked(id)
		if idx < 0 {
			s.mu.Unlock()
			return errors.New("dvb group reorder contains an unknown ID")
		}
		reordered[i] = s.config.DVBGroups[idx]
	}

	now := s.now().UTC()
	for i := range reordered {
		reordered[i].SortOrder = i
		reordered[i].UpdatedAt = now
	}
	previousGroups := slices.Clone(s.config.DVBGroups)
	s.config.DVBGroups = reordered
	if err := s.saveLocked(); err != nil {
		s.config.DVBGroups = previousGroups
		s.mu.Unlock()
		return err
	}
	s.appendLogLocked("info", "DVB groups reordered")
	events.membershipLocked(s)
	s.mu.Unlock()

	s.broadcast()
	return nil
}
