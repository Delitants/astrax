// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Aggregator fetches XMLTV data from configured sources and serves a merged feed.
type Aggregator struct {
	testHookBeforeContributionApply func(uint64)
	testHookBeforeOutputRename      func()
	mu                              sync.RWMutex
	sources                         []string
	channels                        []Channel
	enabled                         bool
	client                          *http.Client
	fetchLimits                     FetchLimits
	fetchCancel                     context.CancelFunc
	data                            []byte
	dataRevision                    uint64
	lastFetch                       time.Time
	refreshSec                      int
	dvbProgrammes                   []Programme
	dvbChannels                     []Channel
	dvbPriority                     bool
	contributions                   map[DVBContributionKey]dvbContribution
	retired                         map[DVBContributionKey]struct{}
	revision                        uint64
	settingsRevision                uint64
	fetchRevision                   uint64
	sourceCache                     map[string]sourceSnapshot
	sourceAttempts                  map[string]sourceAttempt
	retention                       time.Duration
	mergedChannels                  int
	mergedProgrammes                int
	outputAttempt                   outputAttempt
	outputSettingsRevision          uint64
	now                             func() time.Time
	external                        TV
	outputMu                        sync.Mutex
	localPath                       string
}

// New creates an EPG aggregator.
func New(sources []string, enabled bool) *Aggregator {
	return &Aggregator{
		sources:     append([]string(nil), sources...),
		enabled:     enabled,
		client:      &http.Client{Timeout: 30 * time.Second},
		fetchLimits: DefaultFetchLimits(),
		refreshSec:  3600,
		retention:   sourceRetention,
		now:         time.Now,
	}
}

// SetSources updates the source URLs and enabled state.
func (a *Aggregator) SetSources(sources []string, enabled bool) {
	a.mu.Lock()
	a.sources = append([]string(nil), sources...)
	a.cancelFetchLocked()
	a.settingsRevision++
	a.enabled = enabled
	a.pruneSourceAttemptsLocked()
	a.pruneSourceCacheLocked()
	a.external = a.mergeSourceCacheLocked()
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	_ = a.applySnapshot(snapshot)
}

// SetChannels updates the injected channel list (from configured streams).
func (a *Aggregator) SetChannels(channels []Channel) {
	a.mu.Lock()
	a.channels = cloneChannels(channels)
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	_ = a.applySnapshot(snapshot)
}

func (a *Aggregator) SetDVBProgrammes(programmes []Programme) {
	a.mu.Lock()
	a.dvbProgrammes = cloneProgrammes(programmes)
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	_ = a.applySnapshot(snapshot)
}

func (a *Aggregator) SetDVBChannels(channels []Channel) {
	a.mu.Lock()
	a.dvbChannels = cloneChannels(channels)
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	_ = a.applySnapshot(snapshot)
}

func (a *Aggregator) SetDVBPriority(priority bool) {
	a.mu.Lock()
	a.dvbPriority = priority
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	_ = a.applySnapshot(snapshot)
}

func (a *Aggregator) SetLocalPath(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.localPath != path {
		a.outputSettingsRevision++
		a.outputAttempt = outputAttempt{}
	}
	a.localPath = path
}

// Data returns the latest merged bytes and merge time, not source-fetch health.
func (a *Aggregator) Data() ([]byte, time.Time) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]byte(nil), a.data...), a.lastFetch
}

// Fetch downloads sources, retaining unexpired last-good data on failure.
// A nonnil error can accompany a usable feed when a source or output is degraded.
func (a *Aggregator) Fetch() error {
	a.mu.Lock()
	a.cancelFetchLocked()
	ctx, cancel := context.WithCancel(context.Background())
	a.fetchCancel = cancel
	defer cancel()
	sources := append([]string(nil), a.sources...)
	limits, client := a.fetchLimits, *a.client
	enabled, revision := a.enabled, a.settingsRevision
	a.fetchRevision++
	fetchRevision := a.fetchRevision
	a.mu.Unlock()
	updates := make(map[string]sourceSnapshot)
	outcomes := make(map[string]string)
	var failures []error
	if enabled {
		for index, src := range sources {
			if ctx.Err() != nil {
				break
			}
			if src == "" {
				continue
			}
			a.mu.Lock()
			if revision != a.settingsRevision || fetchRevision != a.fetchRevision {
				a.mu.Unlock()
				break
			}
			if a.sourceAttempts == nil {
				a.sourceAttempts = make(map[string]sourceAttempt)
			}
			attempt := a.sourceAttempts[src]
			attempt.lastAttempt = a.now().UTC()
			attempt.unfinished = true
			attempt.fetchRevision = fetchRevision
			a.sourceAttempts[src] = attempt
			a.mu.Unlock()
			tv, code, err := fetchSource(ctx, &client, src, limits)
			if err != nil {
				if ctx.Err() != nil && errors.Is(err, context.Canceled) {
					break
				}
				outcomes[src] = code
				failures = append(failures, fmt.Errorf("source %d fetch: %w", index+1, err))
				continue
			}
			updates[src] = sourceSnapshot{tv: tv, fetchedAt: a.now().UTC()}
			outcomes[src] = ""
		}
	}
	a.mu.Lock()
	if revision != a.settingsRevision || fetchRevision != a.fetchRevision {
		// Discard results, but retire only markers owned by this fetch. A
		// newer fetch may already be using the same configured source.
		for src, attempt := range a.sourceAttempts {
			if attempt.unfinished && attempt.fetchRevision == fetchRevision {
				attempt.unfinished = false
				a.sourceAttempts[src] = attempt
			}
		}
		a.mu.Unlock()
		return errors.Join(failures...)
	}
	if a.sourceCache == nil {
		a.sourceCache = make(map[string]sourceSnapshot)
	}
	for src, value := range updates {
		a.sourceCache[src] = value
	}
	for src, code := range outcomes {
		attempt := a.sourceAttempts[src]
		attempt.errorCode = code
		attempt.unfinished = false
		if value, ok := updates[src]; ok {
			attempt.lastSuccess = value.fetchedAt
		}
		a.sourceAttempts[src] = attempt
	}
	a.pruneSourceCacheLocked()
	a.external = a.mergeSourceCacheLocked()
	snapshot := a.snapshotLocked()
	a.mu.Unlock()
	if err := a.applyFetchSnapshot(snapshot, revision, fetchRevision); err != nil {
		return errors.Join(append(failures, err)...)
	}
	// Bulk file I/O is serialized separately from contribution updates.
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	a.mu.Lock()
	path := a.localPath
	outputSettingsRevision := a.outputSettingsRevision
	enabled = a.enabled
	data := append([]byte(nil), a.data...)
	dataRevision := a.dataRevision
	current := revision == a.settingsRevision && fetchRevision == a.fetchRevision && dataRevision == a.revision
	if current && snapshot.enabled && enabled && path != "" {
		a.outputAttempt.lastAttempt, a.outputAttempt.errorCode = a.now().UTC(), ""
	}
	a.mu.Unlock()
	if current && snapshot.enabled && enabled && path != "" {
		if err := writeLocalAtomic(path, data, func(temporary, target string) error {
			if a.testHookBeforeOutputRename != nil {
				a.testHookBeforeOutputRename()
			}
			// Only the commit is fenced; bulk writes and sync do not block DVB
			// contribution updates. Revalidate after the temporary file is ready.
			a.mu.Lock()
			defer a.mu.Unlock()
			if revision != a.settingsRevision || fetchRevision != a.fetchRevision || dataRevision != a.revision || !a.enabled || outputSettingsRevision != a.outputSettingsRevision {
				return errOutputSuperseded
			}
			if err := os.Rename(temporary, target); err != nil {
				return err
			}
			a.outputAttempt.lastSuccess = a.now().UTC()
			a.outputAttempt.dataRevision = dataRevision
			return nil
		}); err != nil {
			a.mu.Lock()
			if revision == a.settingsRevision && fetchRevision == a.fetchRevision && dataRevision == a.revision && a.enabled && outputSettingsRevision == a.outputSettingsRevision {
				a.outputAttempt.errorCode = "write_failed"
			}
			a.mu.Unlock()
			failures = append(failures, fmt.Errorf("local EPG output: %w", err))
		}
	}
	return errors.Join(failures...)
}

// Run starts a background refresh loop.
func (a *Aggregator) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(a.refreshSec) * time.Second)
	defer ticker.Stop()

	if err := a.Fetch(); err != nil {
		log.Printf("epg: refresh failed: %v", err)
	}

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := a.Fetch(); err != nil {
				log.Printf("epg: refresh failed: %v", err)
			}
		}
	}
}

// TV represents the root XMLTV element.
type TV struct {
	XMLName           xml.Name    `xml:"tv"`
	GeneratorInfoName string      `xml:"generator-info-name,attr,omitempty"`
	GeneratorInfoURL  string      `xml:"generator-info-url,attr,omitempty"`
	Channels          []Channel   `xml:"channel"`
	Programmes        []Programme `xml:"programme"`
}

// Channel represents an XMLTV channel.
type Channel struct {
	ID          string        `xml:"id,attr"`
	DisplayName []DisplayName `xml:"display-name"`
	Icon        *Icon         `xml:"icon,omitempty"`
}

// DisplayName is the channel name in XMLTV.
type DisplayName struct {
	Lang  string `xml:"lang,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Programme represents a single EPG entry.
type Programme struct {
	Channel  string     `xml:"channel,attr"`
	Start    string     `xml:"start,attr"`
	Stop     string     `xml:"stop,attr,omitempty"`
	Title    []Title    `xml:"title"`
	Desc     []Desc     `xml:"desc,omitempty"`
	Category []Category `xml:"category,omitempty"`
}

// Title is the programme title.
type Title struct {
	Lang  string `xml:"lang,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Desc is the programme description.
type Desc struct {
	Lang  string `xml:"lang,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Category is the programme category.
type Category struct {
	Lang  string `xml:"lang,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Icon is a channel icon reference.
type Icon struct {
	Src string `xml:"src,attr"`
}
