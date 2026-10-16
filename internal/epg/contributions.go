// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"time"
)

// DVBContributionKey identifies one scheduler lifetime, never just a frontend ID.
type DVBContributionKey struct {
	SessionID  string
	Generation uint64
}

var ErrDVBContributionRetired = errors.New("DVB contribution retired")

type dvbContribution struct {
	channels   []Channel
	programmes []Programme
}
type mergeSnapshot struct {
	revision    uint64
	tv          TV
	enabled     bool
	fetchOrigin *fetchSnapshotOrigin
}
type fetchSnapshotOrigin struct {
	settingsRevision uint64
	fetchRevision    uint64
}

func cloneChannels(in []Channel) []Channel {
	out := append([]Channel(nil), in...)
	for i := range out {
		out[i].DisplayName = append([]DisplayName(nil), in[i].DisplayName...)
		if in[i].Icon != nil {
			v := *in[i].Icon
			out[i].Icon = &v
		}
	}
	return out
}
func cloneProgrammes(in []Programme) []Programme {
	out := append([]Programme(nil), in...)
	for i := range out {
		out[i].Title = append([]Title(nil), in[i].Title...)
		out[i].Desc = append([]Desc(nil), in[i].Desc...)
		out[i].Category = append([]Category(nil), in[i].Category...)
	}
	return out
}
func validContribution(k DVBContributionKey) error {
	if k.SessionID == "" || k.Generation == 0 {
		return errors.New("DVB contribution requires session ID and nonzero generation")
	}
	return nil
}
func (a *Aggregator) UpsertDVBContribution(k DVBContributionKey, c []Channel, p []Programme) error {
	if err := validContribution(k); err != nil {
		return err
	}
	value := dvbContribution{cloneChannels(c), cloneProgrammes(p)}
	a.mu.Lock()
	if _, retired := a.retired[k]; retired {
		a.mu.Unlock()
		return ErrDVBContributionRetired
	}
	if a.contributions == nil {
		a.contributions = make(map[DVBContributionKey]dvbContribution)
	}
	a.contributions[k] = value
	snapshot := a.snapshotLocked()
	hook := a.testHookBeforeContributionApply
	a.mu.Unlock()
	if hook != nil {
		hook(snapshot.revision)
	}
	return a.applySnapshot(snapshot)
}
func (a *Aggregator) RemoveDVBContribution(k DVBContributionKey) error {
	if err := validContribution(k); err != nil {
		return err
	}
	a.mu.Lock()
	if _, retired := a.retired[k]; retired {
		a.mu.Unlock()
		return nil
	}
	if a.retired == nil {
		a.retired = make(map[DVBContributionKey]struct{})
	}
	a.retired[k] = struct{}{}
	delete(a.contributions, k)
	snapshot := a.snapshotLocked()
	hook := a.testHookBeforeContributionApply
	a.mu.Unlock()
	if hook != nil {
		hook(snapshot.revision)
	}
	return a.applySnapshot(snapshot)
}
func (a *Aggregator) snapshotLocked() mergeSnapshot {
	a.revision++
	tv := TV{GeneratorInfoName: "AstraX EPG Aggregator", GeneratorInfoURL: "https://github.com/Delitants/astrax"}
	keys := make([]DVBContributionKey, 0, len(a.contributions))
	for k := range a.contributions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SessionID != keys[j].SessionID {
			return keys[i].SessionID < keys[j].SessionID
		}
		return keys[i].Generation < keys[j].Generation
	})
	var ch []Channel
	var pr []Programme
	for _, k := range keys {
		v := a.contributions[k]
		ch = append(ch, v.channels...)
		pr = append(pr, v.programmes...)
	}
	pr = append(pr, a.dvbProgrammes...)
	tv.Channels = append(tv.Channels, a.external.Channels...)
	tv.Channels = append(tv.Channels, ch...)
	tv.Channels = append(tv.Channels, a.channels...)
	tv.Channels = append(tv.Channels, a.dvbChannels...)
	if a.dvbPriority {
		tv.Programmes = append(pr, a.external.Programmes...)
	} else {
		tv.Programmes = append(append([]Programme(nil), a.external.Programmes...), pr...)
	}
	seenCh := make(map[string]bool)
	channels := make([]Channel, 0, len(tv.Channels))
	for _, c := range tv.Channels {
		if !seenCh[c.ID] {
			seenCh[c.ID] = true
			channels = append(channels, c)
		}
	}
	type programmeKey struct{ channel, start string }
	seenPr := make(map[programmeKey]bool)
	programmes := make([]Programme, 0, len(tv.Programmes))
	for _, p := range tv.Programmes {
		key := programmeKey{p.Channel, p.Start}
		if !seenPr[key] {
			seenPr[key] = true
			programmes = append(programmes, p)
		}
	}
	tv.Channels = cloneChannels(channels)
	tv.Programmes = cloneProgrammes(programmes)
	return mergeSnapshot{revision: a.revision, tv: tv, enabled: a.enabled}
}
func (a *Aggregator) applySnapshot(s mergeSnapshot) error {
	var data []byte
	if s.enabled {
		out, err := xml.MarshalIndent(s.tv, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal merged epg: %w", err)
		}
		data = append([]byte(xml.Header), out...)
	}
	a.mu.Lock()
	// Fetch policy/generation can change without a merge revision change.
	// DVB snapshots remain fenced only by the existing merge revision.
	if s.revision != a.revision || (s.fetchOrigin != nil &&
		(s.fetchOrigin.settingsRevision != a.settingsRevision || s.fetchOrigin.fetchRevision != a.fetchRevision)) {
		a.mu.Unlock()
		return nil
	}
	a.data = data
	a.dataRevision = s.revision
	a.lastFetch = time.Time{}
	a.mergedChannels, a.mergedProgrammes = 0, 0
	if s.enabled {
		a.lastFetch = a.now().UTC()
		a.mergedChannels, a.mergedProgrammes = len(s.tv.Channels), len(s.tv.Programmes)
	}
	a.mu.Unlock()
	return nil
}

func (a *Aggregator) applyFetchSnapshot(s mergeSnapshot, settingsRevision, fetchRevision uint64) error {
	s.fetchOrigin = &fetchSnapshotOrigin{settingsRevision: settingsRevision, fetchRevision: fetchRevision}
	return a.applySnapshot(s)
}
