// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"astrax/internal/adapters"
	"astrax/internal/adminauth"
	"astrax/internal/dvb"
	"astrax/internal/engine"
	"astrax/internal/epg"
	"astrax/internal/model"
	"astrax/internal/softcam"
	"astrax/internal/streamer"
)

type contextRWMutex struct {
	stateMu         sync.Mutex
	readers         int
	writer          bool
	waitingWriters  int
	nextWriter      uint64
	servingWriter   uint64
	canceledWriters map[uint64]struct{}
	waitingReaders  int
	nextReader      uint64
	readerPhase     bool
	readerCutoff    uint64
	readerRemaining int
	notify          chan struct{}

	// Test hooks observe admission after it is established and run without stateMu.
	testHookWriterQueued func()
	testHookReaderQueued func()
}

func (m *contextRWMutex) Lock() {
	_ = m.LockContext(context.Background())
}

func (m *contextRWMutex) LockContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	m.stateMu.Lock()
	ticket := m.nextWriter
	m.nextWriter++
	m.waitingWriters++
	hook := m.testHookWriterQueued
	m.stateMu.Unlock()
	if hook != nil {
		hook()
	}
	m.stateMu.Lock()
	for {
		if err := ctx.Err(); err != nil {
			m.cancelWriterLocked(ticket)
			m.stateMu.Unlock()
			return err
		}
		if !m.writer && m.readers == 0 && !m.readerPhase && ticket == m.servingWriter {
			m.waitingWriters--
			m.writer = true
			m.stateMu.Unlock()
			return nil
		}

		notify := m.waitChannelLocked()
		m.stateMu.Unlock()
		select {
		case <-ctx.Done():
		case <-notify:
		}
		m.stateMu.Lock()
	}
}

func (m *contextRWMutex) Unlock() {
	m.stateMu.Lock()
	if !m.writer {
		m.stateMu.Unlock()
		panic("store: unlock of unlocked contextRWMutex")
	}
	m.writer = false
	m.servingWriter++
	m.advanceServingWriterLocked()
	m.startReaderPhaseLocked()
	m.notifyWaitersLocked()
	m.stateMu.Unlock()
}

func (m *contextRWMutex) RLock() {
	m.stateMu.Lock()
	queued := false
	var ticket uint64
	reportedWaiting := false
	for !m.readerCanAcquireLocked(queued, ticket) {
		if !queued {
			ticket = m.nextReader
			m.nextReader++
			m.waitingReaders++
			queued = true
		}
		notify := m.waitChannelLocked()
		hook := m.testHookReaderQueued
		if reportedWaiting {
			hook = nil
		} else {
			reportedWaiting = true
		}
		m.stateMu.Unlock()
		if hook != nil {
			hook()
		}
		<-notify
		m.stateMu.Lock()
	}
	m.readers++
	if queued {
		m.waitingReaders--
		if m.readerPhase && ticket < m.readerCutoff {
			m.readerRemaining--
			if m.readerRemaining == 0 {
				m.readerPhase = false
			}
		}
	}
	m.stateMu.Unlock()
}

func (m *contextRWMutex) RUnlock() {
	m.stateMu.Lock()
	if m.readers == 0 {
		m.stateMu.Unlock()
		panic("store: RUnlock of unlocked contextRWMutex")
	}
	m.readers--
	if m.readers == 0 {
		m.notifyWaitersLocked()
	}
	m.stateMu.Unlock()
}

func (m *contextRWMutex) waitChannelLocked() <-chan struct{} {
	if m.notify == nil {
		m.notify = make(chan struct{})
	}
	return m.notify
}

func (m *contextRWMutex) notifyWaitersLocked() {
	if m.notify != nil {
		close(m.notify)
		m.notify = nil
	}
}

func (m *contextRWMutex) cancelWriterLocked(ticket uint64) {
	wasServing := ticket == m.servingWriter
	m.waitingWriters--
	if m.canceledWriters == nil {
		m.canceledWriters = make(map[uint64]struct{})
	}
	m.canceledWriters[ticket] = struct{}{}
	m.advanceServingWriterLocked()
	if wasServing && !m.writer {
		m.startReaderPhaseLocked()
	}
	m.notifyWaitersLocked()
}

func (m *contextRWMutex) readerCanAcquireLocked(queued bool, ticket uint64) bool {
	if m.writer {
		return false
	}
	if queued && m.readerPhase && ticket < m.readerCutoff {
		return true
	}
	return m.waitingWriters == 0
}

func (m *contextRWMutex) startReaderPhaseLocked() {
	if m.readerPhase || m.waitingReaders == 0 {
		return
	}
	// Freeze the cohort so later readers cannot extend this handoff past the next writer.
	m.readerPhase = true
	m.readerCutoff = m.nextReader
	m.readerRemaining = m.waitingReaders
}

func (m *contextRWMutex) advanceServingWriterLocked() {
	for {
		if _, canceled := m.canceledWriters[m.servingWriter]; !canceled {
			return
		}
		delete(m.canceledWriters, m.servingWriter)
		m.servingWriter++
		if len(m.canceledWriters) == 0 {
			m.canceledWriters = nil
		}
	}
}

type streamLifecycleGates struct {
	mu      sync.Mutex
	entries map[string]*streamLifecycleGate
}

type streamLifecycleGate struct {
	mu   contextRWMutex
	refs int
}

// Lock serializes one stream lifecycle while allowing unrelated IDs to proceed.
func (g *streamLifecycleGates) Lock(id string) func() {
	release, _ := g.LockContext(context.Background(), id)
	return release
}

func (g *streamLifecycleGates) LockContext(ctx context.Context, id string) (func(), error) {
	g.mu.Lock()
	if g.entries == nil {
		g.entries = make(map[string]*streamLifecycleGate)
	}
	entry := g.entries[id]
	if entry == nil {
		entry = &streamLifecycleGate{}
		g.entries[id] = entry
	}
	entry.refs++
	g.mu.Unlock()

	if err := entry.mu.LockContext(ctx); err != nil {
		g.mu.Lock()
		entry.refs--
		if entry.refs == 0 && g.entries[id] == entry {
			delete(g.entries, id)
		}
		g.mu.Unlock()
		return nil, err
	}
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			g.mu.Lock()
			entry.refs--
			entry.mu.Unlock()
			if entry.refs == 0 && g.entries[id] == entry {
				delete(g.entries, id)
			}
			g.mu.Unlock()
		})
	}, nil
}

type Store struct {
	apiTokens                               apiTokenPersistence
	cardPublicationMu                       contextRWMutex
	cardApplicationGates                    streamLifecycleGates
	cardApplications                        map[string]dvbCardApplicationUpdate
	dvbOperations                           storeDVBOperations
	events                                  storeEventBus
	testHookBeforeDVBGroupDeleteGates       func()
	legacyWorkers                           sync.WaitGroup
	settingsRuntimeMu                       sync.Mutex
	testHookBeforeStructuredReservation     func(string)
	adapterLifecycleGates                   streamLifecycleGates
	legacyGeneration, epgSettingsGeneration uint64
	sessionWorkers                          sessionRuntimeWorkers
	testHookBroadcastCaptured               func()
	structured                              structuredRuntimeState
	runtimeLifecycle                        storeRuntimeLifecycle
	runtimeOptions                          Options
	runtimeDeps                             RuntimeDependencies
	runtimeSink                             storeStreamSink
	scheduler                               *dvbScheduler
	epgDone, updaterDone                    chan struct{}
	mu                                      contextRWMutex
	path                                    string
	started                                 time.Time
	config                                  model.Config
	logs                                    []model.LogEntry

	streamIndexByID map[string]int
	dvbStreamIDs    []string
	groupStreamIDs  map[string][]string

	dvbRefreshGate          chan struct{}
	dvbRefreshSequenceMu    sync.Mutex
	dvbRefreshStateMu       sync.Mutex
	dvbRefreshNext          uint64
	dvbRefreshPublished     uint64
	dvbDetected             []model.DVBCard
	dvbOwnership            map[string]dvbCardOwnership
	dvbRefreshedAt          time.Time
	dvbRefreshError         string
	dvbStale                bool
	dvbLastSummary          model.DVBCardSummary
	dvbStreamLifecycleGates streamLifecycleGates

	now             func() time.Time
	dvbOpener       dvb.SessionOpener
	adapterDetector adapters.Detector
	disableRuntime  bool

	// Locked test hooks are nil in production and run only while mu is held.
	testHookBeforeStreamMutationLocked         func()
	testHookBeforeDVBGroupDeleteMutationLocked func()
	testHookBeforeDVBStreamQueryCopyLocked     func()
	testHookDVBStreamQueryCandidatesLocked     func([]string)
	testHookSaveLocked                         func()
	testHookConfigWrite                        *atomicWriteHooks
	// This hook observes contention without taking the global Store mutex.
	testHookDVBRefreshWaiting func()
	// Runtime action hooks and executors run after the Store mutex is released.
	testHookDVBStreamRuntimeAction      func(dvbStreamRuntimeAction)
	testHookBeforeDVBOnDemandRevalidate func(string, string)
	testHookAfterStreamPersisted        func(string)
	testHookAfterDVBSourceAccepted      func(string, model.PacketSource)
	testHookAfterDVBPacketSample        func(string, uint64)
	dvbStreamRuntimeActionExecutor      func(dvbStreamRuntimeAction)

	engine          *engine.Engine
	streamer        *streamer.Streamer
	runtime         map[string]model.StreamRuntime
	softcam         *softcam.Manager
	softRuntime     map[string]model.SoftcamRuntime
	softGenerations map[string]uint64
	softcamTester   func(context.Context, model.Softcam) (*model.SoftcamTestResult, error)
	adapterWork     map[string]*adapterMonitorWorker
	adapterRT       map[string]model.AdapterProfileRuntime
	subscribers     map[int]chan model.StateSnapshot
	nextSubID       int
	epg             *epg.Aggregator
	epgStop         chan struct{}
}

func New(path string) (*Store, error) {
	return NewWithOptions(path, Options{})
}

func NewWithOptions(path string, opts Options) (*Store, error) {
	s, err := NewDormant(path, opts)
	if err != nil {
		return nil, err
	}
	if err := s.StartRuntime(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewDormant loads persistent configuration without creating runtime dependencies.
// The caller must complete preflight before calling StartRuntime.
func NewDormant(path string, opts Options) (*Store, error) {
	opts = opts.withDefaults()
	s := &Store{
		path:             path,
		runtimeLifecycle: storeRuntimeLifecycle{dormant: true},
		runtimeOptions:   opts,
		started:          opts.Now().UTC(),
		now:              opts.Now,
		dvbOpener:        opts.DVBOpener,
		adapterDetector:  opts.AdapterDetector,
		disableRuntime:   opts.DisableRuntime,
		dvbRefreshGate:   make(chan struct{}, 1),
		dvbDetected:      make([]model.DVBCard, 0),
		dvbOwnership:     make(map[string]dvbCardOwnership),
		dvbStale:         true,
		streamIndexByID:  make(map[string]int),
		dvbStreamIDs:     make([]string, 0),
		groupStreamIDs:   map[string][]string{"": {}},
		runtime:          make(map[string]model.StreamRuntime),
		softRuntime:      make(map[string]model.SoftcamRuntime),
		softGenerations:  make(map[string]uint64),
		softcamTester:    opts.SoftcamTester,
		adapterWork:      make(map[string]*adapterMonitorWorker),
		adapterRT:        make(map[string]model.AdapterProfileRuntime),
		subscribers:      make(map[int]chan model.StateSnapshot),
	}
	s.dvbRefreshGate <- struct{}{}
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}
	s.rebuildDVBIndexesLocked()
	s.dvbLastSummary = summarizeDVBCards(s.mergeDVBCardsLocked())
	return s, nil
}

func (s *Store) startRuntime() error {
	activateDescramblingBuildBackend()
	s.mu.Lock()
	for _, stream := range s.config.Streams {
		if stream.Enabled && descramblingEnabled(stream) {
			rt := newDVBStreamRuntime(stream, s.now().UTC())
			if err := s.validateDVBDescramblingLocked(stream); err != nil {
				rt.State, rt.LastError = "error", err.Error()
			}
			s.runtime[stream.ID] = rt
		}
	}
	s.mu.Unlock()

	if !s.runtimeOptions.DisableRuntime {
		if err := s.initializeRuntime(s.runtimeOptions); err != nil {
			// initializeRuntime consumes partial dependencies on every failure path.
			s.runtimeDeps, s.scheduler, s.engine, s.softcam = nil, nil, nil, nil
			s.runtimeSink, s.streamer, s.epg = nil, nil, nil
			return fmt.Errorf("initialize runtime: %w", err)
		}
	}
	s.mu.Lock()
	s.appendLogLocked("info", "store initialized")
	streams := slices.Clone(s.config.Streams)
	softcams := slices.Clone(s.config.Softcams)
	s.mu.Unlock()

	if !s.disableRuntime {
		s.reconcileSoftcamWorkers(softcams)
		s.reconcileWorkers(streams)
	}
	s.broadcast()
	return nil
}

func (s *Store) SetStreamerTLSConfig(cfg any) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if s.streamer != nil {
		if tlsCfg, ok := cfg.(*tls.Config); ok {
			s.streamer.SetTLSConfig(tlsCfg)
		}
	}
}

func (s *Store) loadOrInit() error {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		now := s.now().UTC()
		s.config = model.Config{
			SchemaVersion:   model.CurrentSchemaVersion,
			Version:         model.DefaultVersion,
			CreatedAt:       now,
			UpdatedAt:       now,
			Streams:         make([]model.Stream, 0),
			DVBGroups:       make([]model.DVBGroup, 0),
			DVBCards:        make([]model.DVBCardConfig, 0),
			Softcams:        make([]model.Softcam, 0),
			AdapterProfiles: make([]model.AdapterProfile, 0),
			Settings:        model.DefaultSettings(),
		}
		return s.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("stat config: %w", err)
	}
	if err := validateExistingConfigPath(s.path, info); err != nil {
		return err
	}

	cfg, migration, err := loadConfig(s.path, s.now().UTC())
	if err != nil {
		return err
	}
	if err := persistMigratedConfig(s.path, cfg, migration, s.now().UTC(), defaultMigrationFileOps()); err != nil {
		return err
	}
	s.config = cfg
	return nil
}

func (s *Store) saveLocked() error {
	return s.saveContextLocked(context.Background())
}

func (s *Store) saveContextLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.testHookSaveLocked != nil {
		s.testHookSaveLocked()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	persist := s.config
	persist.UpdatedAt = s.now().UTC()
	persist.Streams = cloneStreams(s.config.Streams)
	persist.DVBGroups = slices.Clone(s.config.DVBGroups)
	persist.DVBCards = slices.Clone(s.config.DVBCards)
	persist.Softcams = slices.Clone(s.config.Softcams)
	persist.AdapterProfiles = slices.Clone(s.config.AdapterProfiles)
	for i := range persist.Streams {
		persist.Streams[i].Runtime = model.StreamRuntime{}
	}
	for i := range persist.Softcams {
		persist.Softcams[i].Runtime = model.SoftcamRuntime{}
	}
	for i := range persist.AdapterProfiles {
		persist.AdapterProfiles[i].Runtime = model.AdapterProfileRuntime{}
	}

	write := writeConfigAtomic
	if s.testHookConfigWrite != nil || ctx.Done() != nil {
		var hooks atomicWriteHooks
		if s.testHookConfigWrite != nil {
			hooks = *s.testHookConfigWrite
		}
		if ctx.Done() != nil {
			beforeRename := hooks.beforeRename
			hooks.beforeRename = func(temp, destination string) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if beforeRename != nil {
					if err := beforeRename(temp, destination); err != nil {
						return err
					}
				}
				return ctx.Err()
			}
		}
		write = func(path string, cfg model.Config) error {
			return writeConfigAtomicWithHooks(path, cfg, hooks)
		}
	}
	if err := write(s.path, persist); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	s.config.UpdatedAt = persist.UpdatedAt
	s.apiTokens.dirty = false
	s.apiTokens.pendingRevocation = nil
	if s.streamer != nil {
		s.streamer.SetConfiguredOutputs(persist.Streams)
	}
	return nil
}

// Reuse the existing checked output reservation, with cancellation fenced
// before durable replacement. Once replacement succeeds, runtime must follow it.
func (s *Store) saveStreamOutputContextLocked(ctx context.Context, stream model.Stream) error {
	if s.streamer != nil {
		release, err := s.streamer.ReserveConfiguredOutput(stream)
		if err != nil {
			if errors.Is(err, streamer.ErrStreamPathConflict) {
				return fmt.Errorf("output route duplicates runtime claim: %w", err)
			}
			return err
		}
		defer release()
	}
	return s.saveContextLocked(ctx)
}

func (s *Store) appendLogLocked(level, message string) {
	minimum, _ := logSeverity(s.config.Settings.LogLevel)
	severity, _ := logSeverity(level)
	if severity < minimum {
		return
	}
	s.logs = append(s.logs, model.LogEntry{
		Timestamp: s.now().UTC(),
		Level:     level,
		Message:   message,
	})
	if len(s.logs) > 500 {
		s.logs = s.logs[len(s.logs)-500:]
	}
}

func (s *Store) statusLocked(now time.Time) model.Status {
	enabled := 0
	running := 0
	for _, stream := range s.config.Streams {
		if stream.Enabled {
			enabled++
		}
		if rt, ok := s.runtime[stream.ID]; ok && rt.State == "running" {
			running++
		}
	}

	softEnabled := 0
	softOnline := 0
	for _, profile := range s.config.Softcams {
		if profile.Enabled {
			softEnabled++
		}
		if rt, ok := s.softRuntime[profile.ID]; ok && rt.Connected && rt.State == "running" {
			softOnline++
		}
	}

	return model.Status{
		Version:         s.config.Version,
		StartedAt:       s.started,
		Now:             now,
		UptimeSeconds:   int64(now.Sub(s.started).Seconds()),
		TotalStreams:    len(s.config.Streams),
		EnabledStreams:  enabled,
		RunningStreams:  running,
		TotalSoftcams:   len(s.config.Softcams),
		EnabledSoftcams: softEnabled,
		OnlineSoftcams:  softOnline,
		ControlEndpoint: s.config.Settings.ControlListen,
	}
}

func (s *Store) listStreamsLocked() []model.Stream {
	streams := cloneStreams(s.config.Streams)
	for i := range streams {
		rt, ok := s.runtime[streams[i].ID]
		if ok {
			streams[i].Runtime = cloneStreamRuntime(rt)
			projectDescramblingRuntime(&streams[i])
			continue
		}

		if streams[i].Enabled {
			streams[i].Runtime = model.StreamRuntime{State: "starting"}
		} else {
			streams[i].Runtime = model.StreamRuntime{State: "stopped"}
		}
		projectDescramblingRuntime(&streams[i])
	}
	return streams
}

func (s *Store) listSoftcamsLocked() []model.Softcam {
	softcams := slices.Clone(s.config.Softcams)
	for i := range softcams {
		rt, ok := s.softRuntime[softcams[i].ID]
		if ok {
			softcams[i].Runtime = rt.Clone()
		} else if softcams[i].Enabled {
			softcams[i].Runtime = initialSoftcamRuntime(softcams[i], "starting")
			softcams[i].Runtime.Since = s.now().UTC()
		} else {
			softcams[i].Runtime = initialSoftcamRuntime(softcams[i], "stopped")
			softcams[i].Runtime.Since = s.now().UTC()
		}
		softcams[i].Password = ""
	}
	return softcams
}

func (s *Store) listAdapterProfilesLocked() []model.AdapterProfile {
	profiles := slices.Clone(s.config.AdapterProfiles)
	for i := range profiles {
		applyAdapterProfileDefaults(&profiles[i])
		if rt, ok := s.adapterRT[profiles[i].ID]; ok {
			profiles[i].Runtime = rt
		} else {
			profiles[i].Runtime = model.AdapterProfileRuntime{State: "stopped", Since: s.now().UTC()}
		}
	}
	return profiles
}

func (s *Store) snapshotLocked(logLimit int) model.StateSnapshot {
	logs := make([]model.LogEntry, 0)
	if len(s.logs) > 0 {
		if logLimit <= 0 || logLimit > len(s.logs) {
			logLimit = len(s.logs)
		}
		logs = append(logs, s.logs[len(s.logs)-logLimit:]...)
	}

	now := s.now().UTC()
	return model.StateSnapshot{
		At:              now,
		Status:          s.statusLocked(now),
		Streams:         s.listStreamsLocked(),
		Softcams:        s.listSoftcamsLocked(),
		AdapterProfiles: s.listAdapterProfilesLocked(),
		Logs:            logs,
	}
}

func (s *Store) Snapshot(logLimit int) model.StateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked(logLimit)
}

func (s *Store) broadcast() {
	endRuntime, admissionErr := s.admitRuntimeStarting()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	s.mu.RLock()
	if len(s.subscribers) == 0 {
		s.mu.RUnlock()
		return
	}
	snapshot := s.snapshotLocked(120)
	subs := make([]chan model.StateSnapshot, 0, len(s.subscribers))
	for _, ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.RUnlock()

	if s.testHookBroadcastCaptured != nil {
		s.testHookBroadcastCaptured()
	}
	for _, ch := range subs {
		select {
		case ch <- cloneSoftcamSnapshot(snapshot):
		default:
		}
	}
}

func (s *Store) Subscribe(buffer int) (int, <-chan model.StateSnapshot) {
	if buffer <= 0 {
		buffer = 8
	}
	ch := make(chan model.StateSnapshot, buffer)

	endRuntime, err := s.admitRuntime()
	if err != nil {
		close(ch)
		return -1, ch
	}
	defer endRuntime()
	s.mu.Lock()
	id := s.nextSubID
	s.nextSubID++
	s.subscribers[id] = ch
	s.mu.Unlock()

	return id, ch
}

func (s *Store) Unsubscribe(id int) {
	s.mu.Lock()
	delete(s.subscribers, id)
	s.mu.Unlock()
}

func (s *Store) Status() model.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.statusLocked(s.now().UTC())
}

func (s *Store) ListStreams() []model.Stream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listStreamsLocked()
}

func (s *Store) ListSoftcams() []model.Softcam {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listSoftcamsLocked()
}

func (s *Store) ListAdapterProfiles() []model.AdapterProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listAdapterProfilesLocked()
}

func (s *Store) AddStream(in model.Stream) (model.Stream, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	if isStructuredDVBStream(in) {
		return s.AddDVBStream(in)
	}
	if in.Name == "" {
		return model.Stream{}, errors.New("name is required")
	}
	if in.InputURL == "" {
		return model.Stream{}, errors.New("input_url is required")
	}
	if in.OutputURL == "" {
		return model.Stream{}, errors.New("output_url is required")
	}

	var err error
	in, err = normalizeDVBDescrambling(in)
	if err != nil {
		return model.Stream{}, err
	}
	if in.Protocol == "" {
		in.Protocol = "mpegts"
	}

	var releaseLifecycle func()
	var postPersistHook func(string)
	for {
		candidate := newID()
		release := s.dvbStreamLifecycleGates.Lock(candidate)
		s.mu.Lock()
		if _, exists := s.streamIndexByID[candidate]; exists {
			s.mu.Unlock()
			release()
			continue
		}

		in.ID = candidate
		in.UpdatedAt = s.now().UTC()
		if in.GroupID != "" && s.findDVBGroupIndexLocked(in.GroupID) < 0 {
			s.mu.Unlock()
			release()
			return model.Stream{}, errors.New("dvb group not found")
		}
		if err := s.validateDVBDescramblingLocked(in); err != nil {
			s.mu.Unlock()
			release()
			return model.Stream{}, err
		}
		if in.SoftcamID != "" && s.findSoftcamIndexLocked(in.SoftcamID) < 0 {
			s.mu.Unlock()
			release()
			return model.Stream{}, errors.New("softcam not found")
		}
		if err := s.validateConfiguredOutputLocked(in); err != nil {
			s.mu.Unlock()
			release()
			return model.Stream{}, err
		}
		if s.testHookBeforeStreamMutationLocked != nil {
			s.testHookBeforeStreamMutationLocked()
		}
		snapshot := s.snapshotDVBStreamMutationLocked()
		s.config.Streams = append(s.config.Streams, cloneStream(in))
		s.rebuildDVBIndexesLocked()
		if err := s.saveStreamOutputLocked(in); err != nil {
			s.restoreDVBStreamMutationLocked(snapshot)
			s.mu.Unlock()
			release()
			return model.Stream{}, err
		}
		s.appendLogLocked("info", fmt.Sprintf("stream added: %s (%s)", in.Name, in.ID))
		if in.Enabled {
			s.runtime[in.ID] = model.StreamRuntime{State: "starting", Since: s.now().UTC()}
		} else {
			s.runtime[in.ID] = model.StreamRuntime{State: "stopped", Since: s.now().UTC()}
		}
		postPersistHook = s.testHookAfterStreamPersisted
		s.mu.Unlock()
		releaseLifecycle = release
		break
	}

	if postPersistHook != nil {
		postPersistHook(in.ID)
	}
	if !s.disableRuntime && s.streamSnapshotIsCurrent(in) {
		switch {
		case !in.Enabled:
			s.engine.Stop(in.ID)
			if s.streamer != nil {
				s.streamer.UnregisterStream(in.ID)
			}
		case isLegacyDVBStream(in) && in.OnDemand:
			s.registerLegacyDVBPlaceholderUnderGate(in)
		case isLegacyDVBStream(in):
			if in.AdapterProfileID != "" {
				log.Printf("AddStream DVB: %s input_url=%s", in.Name, in.InputURL)
				s.StartAdapterProfileMonitor(in.AdapterProfileID)
				_ = s.startDVBStreamUnderGate(in)
			}
		case in.OnDemand:
			s.registerGenericPlaceholderUnderGate(in)
		default:
			s.startGenericStreamUnderGate(in, false)
		}
	}

	result, err := s.streamByID(in.ID)
	releaseLifecycle()
	s.broadcast()
	s.updateEPGChannels()
	return result, err
}

func (s *Store) UpdateStream(id string, in model.Stream) (model.Stream, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	if isStructuredDVBStream(in) {
		return s.UpdateDVBStream(id, in)
	}
	s.mu.RLock()
	idx, exists := s.streamIndexByID[id]
	currentStructured := exists && idx >= 0 && idx < len(s.config.Streams) && isStructuredDVBStream(s.config.Streams[idx])
	s.mu.RUnlock()
	if currentStructured {
		return model.Stream{}, errors.New("structured DVB updates require a DVB configuration")
	}
	if in.Name == "" {
		return model.Stream{}, errors.New("name is required")
	}
	if in.InputURL == "" {
		return model.Stream{}, errors.New("input_url is required")
	}
	if in.OutputURL == "" {
		return model.Stream{}, errors.New("output_url is required")
	}

	releaseLifecycle := s.dvbStreamLifecycleGates.Lock(id)
	defer releaseLifecycle()

	var err error
	in, err = normalizeDVBDescrambling(in)
	if err != nil {
		return model.Stream{}, err
	}
	s.mu.Lock()
	if in.GroupID != "" && s.findDVBGroupIndexLocked(in.GroupID) < 0 {
		s.mu.Unlock()
		return model.Stream{}, errors.New("dvb group not found")
	}
	if err := s.validateDVBDescramblingLocked(in); err != nil {
		s.mu.Unlock()
		return model.Stream{}, err
	}
	if in.SoftcamID != "" && s.findSoftcamIndexLocked(in.SoftcamID) < 0 {
		s.mu.Unlock()
		return model.Stream{}, errors.New("softcam not found")
	}
	found := false
	for i, stream := range s.config.Streams {
		if stream.ID != id {
			continue
		}
		if isStructuredDVBStream(stream) {
			s.mu.Unlock()
			return model.Stream{}, errors.New("structured DVB updates require a DVB configuration")
		}
		stream = cloneStream(stream)
		found = true
		if in.Protocol == "" {
			in.Protocol = stream.Protocol
			if in.Protocol == "" {
				in.Protocol = "mpegts"
			}
		}
		if in.AdapterProfileID == "" {
			in.AdapterProfileID = stream.AdapterProfileID
		}
		// Preserve scramble metadata if not explicitly changed
		if !in.Scrambled && stream.Scrambled {
			in.Scrambled = stream.Scrambled
		}
		if len(in.CAIDs) == 0 && len(stream.CAIDs) > 0 {
			in.CAIDs = slices.Clone(stream.CAIDs)
		}

		in.ID = id
		if err := s.validateConfiguredOutputLocked(in); err != nil {
			s.mu.Unlock()
			return model.Stream{}, err
		}
		in.UpdatedAt = s.now().UTC()
		if s.testHookBeforeStreamMutationLocked != nil {
			s.testHookBeforeStreamMutationLocked()
		}
		snapshot := s.snapshotDVBStreamMutationLocked()
		s.config.Streams[i] = cloneStream(in)
		s.rebuildDVBIndexesLocked()

		if err := s.saveStreamOutputLocked(in); err != nil {
			s.restoreDVBStreamMutationLocked(snapshot)
			s.mu.Unlock()
			return model.Stream{}, err
		}
		s.appendLogLocked("info", fmt.Sprintf("stream updated: %s (%s)", in.Name, in.ID))
		if in.Enabled {
			s.runtime[id] = model.StreamRuntime{State: "starting", Since: s.now().UTC()}
		} else {
			s.runtime[id] = model.StreamRuntime{State: "stopped", Since: s.now().UTC()}
		}
		break
	}
	s.mu.Unlock()

	if !found {
		return model.Stream{}, errors.New("stream not found")
	}

	if !s.disableRuntime {
		if in.Enabled {
			if !isLegacyDVBStream(in) {
				if in.OnDemand {
					s.registerGenericPlaceholderUnderGate(in)
				} else {
					s.startGenericStreamUnderGate(in, false)
				}
			} else if in.OnDemand {
				s.registerLegacyDVBPlaceholderUnderGate(in)
			} else {
				s.quiesceEngineOwnership(id)
				if s.streamer != nil {
					s.streamer.UnregisterStream(id)
				}
				if in.AdapterProfileID != "" {
					s.StartAdapterProfileMonitor(in.AdapterProfileID)
					_ = s.startDVBStreamUnderGate(in)
				}
			}
		} else {
			s.engine.Stop(id)
			if s.streamer != nil {
				s.streamer.UnregisterStream(id)
			}
		}
	}

	s.broadcast()
	s.updateEPGChannels()
	return s.streamByID(id)
}

func (s *Store) DeleteStream(id string) error {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return admissionErr
	}
	defer endRuntime()
	s.mu.RLock()
	idx, exists := s.streamIndexByID[id]
	structured := exists && idx >= 0 && idx < len(s.config.Streams) && isStructuredDVBStream(s.config.Streams[idx])
	s.mu.RUnlock()
	if structured {
		return s.DeleteDVBStream(id)
	}

	releaseLifecycle := s.dvbStreamLifecycleGates.Lock(id)
	defer releaseLifecycle()

	s.mu.Lock()
	found := false
	for i, stream := range s.config.Streams {
		if stream.ID != id {
			continue
		}
		if isStructuredDVBStream(stream) {
			s.mu.Unlock()
			return s.DeleteDVBStream(id)
		}
		found = true
		stream = cloneStream(stream)
		snapshot := s.snapshotDVBStreamMutationLocked()
		s.config.Streams = append(s.config.Streams[:i], s.config.Streams[i+1:]...)
		s.rebuildDVBIndexesLocked()
		if err := s.saveLocked(); err != nil {
			s.restoreDVBStreamMutationLocked(snapshot)
			s.mu.Unlock()
			return err
		}
		s.appendLogLocked("warn", fmt.Sprintf("stream removed: %s (%s)", stream.Name, stream.ID))
		delete(s.runtime, id)
		break
	}
	s.mu.Unlock()

	if !found {
		return errors.New("stream not found")
	}

	if !s.disableRuntime {
		s.engine.Remove(id)
		s.streamer.UnregisterStream(id)
	}
	s.broadcast()
	s.updateEPGChannels()
	return nil
}

func (s *Store) StartStream(id string) (model.Stream, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	s.mu.RLock()
	idx, exists := s.streamIndexByID[id]
	structured := exists && idx >= 0 && idx < len(s.config.Streams) && isStructuredDVBStream(s.config.Streams[idx])
	s.mu.RUnlock()
	if structured {
		return s.setStructuredDVBStreamEnabled(id, true, "start")
	}

	releaseLifecycle := s.dvbStreamLifecycleGates.Lock(id)
	defer releaseLifecycle()

	s.mu.Lock()
	idx = s.findStreamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Stream{}, errors.New("stream not found")
	}

	stream := s.config.Streams[idx]
	if isStructuredDVBStream(stream) {
		s.mu.Unlock()
		return s.setStructuredDVBStreamEnabled(id, true, "start")
	}
	if err := s.validateDVBDescramblingLocked(stream); err != nil {
		s.mu.Unlock()
		return model.Stream{}, err
	}
	if !stream.Enabled {
		stream.Enabled = true
		stream.UpdatedAt = s.now().UTC()
		s.config.Streams[idx] = stream
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return model.Stream{}, err
		}
	}
	if stream.OnDemand {
		s.runtime[id] = model.StreamRuntime{State: "on-demand", Since: s.now().UTC()}
		s.appendLogLocked("info", fmt.Sprintf("stream on-demand enabled: %s (%s)", stream.Name, stream.ID))
		s.mu.Unlock()
		if !s.disableRuntime {
			if isLegacyDVBStream(stream) {
				s.registerLegacyDVBPlaceholderUnderGate(stream)
			} else {
				s.registerGenericPlaceholderUnderGate(stream)
			}
		}
		s.broadcast()
		return s.streamByID(id)
	}
	s.runtime[id] = model.StreamRuntime{State: "starting", Since: s.now().UTC()}
	s.appendLogLocked("info", fmt.Sprintf("stream start requested: %s (%s)", stream.Name, stream.ID))
	stream.Enabled = true
	s.mu.Unlock()

	if !s.disableRuntime {
		if isLegacyDVBStream(stream) {
			s.quiesceEngineOwnership(stream.ID)
			if stream.AdapterProfileID != "" {
				s.StartAdapterProfileMonitor(stream.AdapterProfileID)
			}
			s.streamer.UnregisterStream(stream.ID)
			_ = s.startDVBStreamUnderGate(stream)
		} else {
			s.startGenericStreamUnderGate(stream, false)
		}
	}
	s.broadcast()
	return s.streamByID(id)
}

func (s *Store) StopStream(id string) (model.Stream, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	s.mu.RLock()
	idx, exists := s.streamIndexByID[id]
	structured := exists && idx >= 0 && idx < len(s.config.Streams) && isStructuredDVBStream(s.config.Streams[idx])
	s.mu.RUnlock()
	if structured {
		return s.setStructuredDVBStreamEnabled(id, false, "stop")
	}

	releaseLifecycle := s.dvbStreamLifecycleGates.Lock(id)
	defer releaseLifecycle()

	s.mu.Lock()
	idx = s.findStreamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Stream{}, errors.New("stream not found")
	}

	stream := s.config.Streams[idx]
	if isStructuredDVBStream(stream) {
		s.mu.Unlock()
		return s.setStructuredDVBStreamEnabled(id, false, "stop")
	}
	if stream.Enabled {
		stream.Enabled = false
		stream.UpdatedAt = s.now().UTC()
		s.config.Streams[idx] = stream
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return model.Stream{}, err
		}
	}
	s.runtime[id] = model.StreamRuntime{State: "stopped", Since: s.now().UTC()}
	s.appendLogLocked("warn", fmt.Sprintf("stream stop requested: %s (%s)", stream.Name, stream.ID))
	s.mu.Unlock()

	if !s.disableRuntime {
		s.engine.Stop(id)
		s.streamer.UnregisterStream(id)
	}
	s.broadcast()
	return s.streamByID(id)
}

func (s *Store) onDemandStart(id string) {
	s.onDemandStartExpected(id, nil)
}

func (s *Store) onDemandStartChecked(token streamer.RegistrationToken) {
	s.onDemandStartExpected(token.StreamID, &token)
}

func (s *Store) onDemandStartExpected(id string, expected *streamer.RegistrationToken) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if s.disableRuntime {
		return
	}
	if s.testHookBeforeDVBOnDemandRevalidate != nil {
		s.testHookBeforeDVBOnDemandRevalidate(id, "start")
	}

	releaseLifecycle := s.lockStructuredIDs([]string{id})
	defer releaseLifecycle()
	if expected != nil && !s.onDemandCallbackCurrent(*expected, true) {
		return
	}

	s.mu.Lock()
	idx := s.findStreamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return
	}
	stream := cloneStream(s.config.Streams[idx])
	if !stream.Enabled || !stream.OnDemand {
		s.mu.Unlock()
		return
	}
	if descramblingEnabled(stream) {
		s.mu.Unlock()
		if isStructuredDVBStream(stream) {
			if !s.holdDescramblingActionUnderGate(dvbStreamRuntimeAction{ID: id, Stream: stream}) {
				s.structuredOnDemandUnderGate(stream, expected, true)
			}
		} else {
			s.blockDescramblingRuntimeUnderGate(stream)
		}
		s.broadcast()
		return
	}
	if isStructuredDVBStream(stream) {
		if s.scheduler != nil {
			s.mu.Unlock()
			s.structuredOnDemandUnderGate(stream, expected, true)
			s.broadcast()
			return
		}
		s.runtime[id] = newDVBStreamRuntime(stream, s.now().UTC())
		s.mu.Unlock()
		s.broadcast()
		return
	}
	if expected == nil || isLegacyDVBStream(stream) {
		s.runtime[id] = model.StreamRuntime{State: "starting", Since: s.now().UTC()}
	}
	s.mu.Unlock()

	if isLegacyDVBStream(stream) {
		if stream.AdapterProfileID != "" {
			s.StartAdapterProfileMonitor(stream.AdapterProfileID)
		}
		_ = s.startDVBStreamExpectedUnderGate(stream, expected)
	} else if expected != nil {
		if s.engine != nil && s.genericStreamSnapshotIsCurrent(stream) {
			s.engine.StartOnDemand(stream, *expected)
		}
	} else {
		s.startGenericStreamUnderGate(stream, false)
	}
	s.broadcast()
}

func (s *Store) onDemandStop(id string) {
	s.onDemandStopExpected(id, nil)
}

func (s *Store) onDemandStopChecked(token streamer.RegistrationToken) {
	s.onDemandStopExpected(token.StreamID, &token)
}

func (s *Store) onDemandStopExpected(id string, expected *streamer.RegistrationToken) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if s.disableRuntime {
		return
	}
	if s.testHookBeforeDVBOnDemandRevalidate != nil {
		s.testHookBeforeDVBOnDemandRevalidate(id, "stop")
	}

	releaseLifecycle := s.lockStructuredIDs([]string{id})
	defer releaseLifecycle()
	if expected != nil && !s.onDemandCallbackCurrent(*expected, false) {
		return
	}

	s.mu.Lock()
	idx := s.findStreamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return
	}
	stream := cloneStream(s.config.Streams[idx])
	if !stream.Enabled || !stream.OnDemand {
		s.mu.Unlock()
		return
	}
	if descramblingEnabled(stream) {
		s.mu.Unlock()
		if isStructuredDVBStream(stream) {
			if !s.holdDescramblingActionUnderGate(dvbStreamRuntimeAction{ID: id, Stream: stream}) {
				s.structuredOnDemandUnderGate(stream, expected, false)
			}
		} else {
			s.blockDescramblingRuntimeUnderGate(stream)
		}
		s.broadcast()
		return
	}
	if isStructuredDVBStream(stream) {
		if s.scheduler != nil {
			s.mu.Unlock()
			s.structuredOnDemandUnderGate(stream, expected, false)
			s.broadcast()
			return
		}
		s.runtime[id] = newDVBStreamRuntime(stream, s.now().UTC())
		s.mu.Unlock()
		s.broadcast()
		return
	}
	s.mu.Unlock()

	if expected != nil {
		var placeholder *streamer.RegistrationToken
		var resultErr error
		if s.engine != nil {
			placeholder, resultErr = s.engine.StopOnDemand(*expected)
		} else {
			placeholder, resultErr = s.streamer.DemoteOnDemandChecked(*expected)
		}
		diagnostic := ""
		if !streamer.IsBenignLifecycleError(resultErr) {
			diagnostic = resultErr.Error()
		}
		s.mu.Lock()
		if diagnostic != "" {
			s.appendLogLocked("error", fmt.Sprintf("on-demand stop for %s: %v", id, resultErr))
		}
		if s.streamSnapshotIsCurrentLocked(stream) {
			switch {
			case placeholder != nil && s.streamer.IsCurrentRegistration(*placeholder):
				s.runtime[id] = model.StreamRuntime{State: "on-demand", Since: s.now().UTC(), LastError: diagnostic}
			case placeholder == nil && diagnostic != "" && s.streamer.IsCurrentRegistration(*expected):
				runtime := s.runtime[id]
				runtime.LastError = diagnostic
				s.runtime[id] = runtime
			}
		}
		s.mu.Unlock()
	} else if isLegacyDVBStream(stream) {
		s.registerLegacyDVBPlaceholderUnderGate(stream)
	} else {
		s.registerGenericPlaceholderUnderGate(stream)
	}
	s.broadcast()
}

func (s *Store) RestartStream(id string) (model.Stream, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Stream{}, admissionErr
	}
	defer endRuntime()
	s.mu.RLock()
	idx, exists := s.streamIndexByID[id]
	structured := exists && idx >= 0 && idx < len(s.config.Streams) && isStructuredDVBStream(s.config.Streams[idx])
	s.mu.RUnlock()
	if structured {
		return s.setStructuredDVBStreamEnabled(id, true, "restart")
	}

	releaseLifecycle := s.dvbStreamLifecycleGates.Lock(id)
	defer releaseLifecycle()

	s.mu.Lock()
	idx = s.findStreamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Stream{}, errors.New("stream not found")
	}

	stream := s.config.Streams[idx]
	if isStructuredDVBStream(stream) {
		s.mu.Unlock()
		return s.setStructuredDVBStreamEnabled(id, true, "restart")
	}
	if err := s.validateDVBDescramblingLocked(stream); err != nil {
		s.mu.Unlock()
		return model.Stream{}, err
	}
	changed := false
	if !stream.Enabled {
		stream.Enabled = true
		stream.UpdatedAt = s.now().UTC()
		changed = true
	}
	s.config.Streams[idx] = stream
	if changed {
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return model.Stream{}, err
		}
	}
	if stream.OnDemand {
		s.runtime[id] = model.StreamRuntime{State: "on-demand", Since: s.now().UTC()}
		s.appendLogLocked("info", fmt.Sprintf("stream on-demand restart: %s (%s)", stream.Name, stream.ID))
		s.mu.Unlock()
		if !s.disableRuntime {
			if isLegacyDVBStream(stream) {
				s.registerLegacyDVBPlaceholderUnderGate(stream)
			} else {
				s.registerGenericPlaceholderUnderGate(stream)
			}
		}
		s.broadcast()
		return s.streamByID(id)
	}
	s.runtime[id] = model.StreamRuntime{State: "starting", Since: s.now().UTC()}
	s.appendLogLocked("warn", fmt.Sprintf("stream restart requested: %s (%s)", stream.Name, stream.ID))
	s.mu.Unlock()

	if !s.disableRuntime {
		if isLegacyDVBStream(stream) {
			s.quiesceEngineOwnership(id)
			s.streamer.UnregisterStream(id)
			_ = s.startDVBStreamUnderGate(stream)
		} else {
			s.startGenericStreamUnderGate(stream, true)
		}
	}
	s.broadcast()
	return s.streamByID(id)
}

func (s *Store) AddSoftcam(in model.Softcam) (model.Softcam, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Softcam{}, admissionErr
	}
	defer endRuntime()
	if strings.TrimSpace(in.Name) == "" {
		return model.Softcam{}, errors.New("name is required")
	}
	if strings.TrimSpace(in.Host) == "" {
		return model.Softcam{}, errors.New("host is required")
	}
	if in.Port <= 0 || in.Port > 65535 {
		return model.Softcam{}, errors.New("port must be between 1 and 65535")
	}
	if strings.TrimSpace(in.Username) == "" {
		return model.Softcam{}, errors.New("username is required")
	}
	if strings.TrimSpace(in.Password) == "" {
		return model.Softcam{}, errors.New("password is required")
	}

	in.ID = newID()
	in.Type = normalizeSoftcamType(in.Type)
	if in.Type == "" {
		in.Type = "newcamd"
	}
	if !isSupportedSoftcamType(in.Type) {
		return model.Softcam{}, fmt.Errorf("unsupported softcam type: %s", in.Type)
	}
	if softcamRequiresDES(in.Type) {
		if strings.TrimSpace(in.DESKey) == "" {
			return model.Softcam{}, errors.New("des_key is required for newcamd")
		}
	} else {
		in.DESKey = ""
	}
	if in.Type == "cccam" && (in.ConnectTimeoutSec < 0 || in.ConnectTimeoutSec > 120) {
		return model.Softcam{}, errors.New("CCcam connect timeout must be zero or between 1 and 120")
	}
	in.Runtime = model.SoftcamRuntime{}
	in.ConnectTimeoutSec = normalizeSoftcamTimeout(in.ConnectTimeoutSec)
	in.UpdatedAt = s.now().UTC()

	s.mu.Lock()
	previous := s.config.Softcams
	s.config.Softcams = append(slices.Clone(previous), in)
	if err := s.saveLocked(); err != nil {
		s.config.Softcams = previous
		s.mu.Unlock()
		return model.Softcam{}, err
	}
	command, prepareErr := s.prepareSoftcamStateLocked(in, softcam.ActionStart, false)
	s.appendLogLocked("info", fmt.Sprintf("softcam added: %s (%s)", in.Name, in.ID))
	s.mu.Unlock()

	if err := s.applySoftcamCommand(in, command, false, prepareErr); err != nil {
		return model.Softcam{}, err
	}

	s.broadcast()
	return s.softcamByID(in.ID)
}

func (s *Store) UpdateSoftcam(id string, in model.Softcam) (model.Softcam, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Softcam{}, admissionErr
	}
	defer endRuntime()
	if strings.TrimSpace(in.Name) == "" {
		return model.Softcam{}, errors.New("name is required")
	}
	if strings.TrimSpace(in.Host) == "" {
		return model.Softcam{}, errors.New("host is required")
	}
	if in.Port <= 0 || in.Port > 65535 {
		return model.Softcam{}, errors.New("port must be between 1 and 65535")
	}
	if strings.TrimSpace(in.Username) == "" {
		return model.Softcam{}, errors.New("username is required")
	}

	s.mu.Lock()
	idx := s.findSoftcamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Softcam{}, errors.New("softcam not found")
	}

	current := s.config.Softcams[idx]
	in.ID = id
	in.Type = normalizeSoftcamType(in.Type)
	if in.Type == "" {
		in.Type = normalizeSoftcamType(current.Type)
		if in.Type == "" {
			in.Type = "newcamd"
		}
	}
	if !isSupportedSoftcamType(in.Type) {
		s.mu.Unlock()
		return model.Softcam{}, fmt.Errorf("unsupported softcam type: %s", in.Type)
	}
	if strings.TrimSpace(in.Password) == "" {
		in.Password = current.Password
	}
	if strings.TrimSpace(in.Password) == "" {
		s.mu.Unlock()
		return model.Softcam{}, errors.New("password is required")
	}
	if softcamRequiresDES(in.Type) {
		if strings.TrimSpace(in.DESKey) == "" {
			in.DESKey = current.DESKey
		}
		if strings.TrimSpace(in.DESKey) == "" {
			s.mu.Unlock()
			return model.Softcam{}, errors.New("des_key is required for newcamd")
		}
	} else {
		in.DESKey = ""
	}

	if in.Type == "cccam" && (in.ConnectTimeoutSec < 0 || in.ConnectTimeoutSec > 120) {
		s.mu.Unlock()
		return model.Softcam{}, errors.New("CCcam connect timeout must be zero or between 1 and 120")
	}
	in.Runtime = model.SoftcamRuntime{}
	in.ConnectTimeoutSec = normalizeSoftcamTimeout(in.ConnectTimeoutSec)
	in.UpdatedAt = s.now().UTC()
	previous := s.config.Softcams
	s.config.Softcams = slices.Clone(previous)
	s.config.Softcams[idx] = in
	if err := s.saveLocked(); err != nil {
		s.config.Softcams = previous
		s.mu.Unlock()
		return model.Softcam{}, err
	}
	command, prepareErr := s.prepareSoftcamStateLocked(in, softcam.ActionStart, false)
	s.appendLogLocked("info", fmt.Sprintf("softcam updated: %s (%s)", in.Name, in.ID))
	s.mu.Unlock()

	if err := s.applySoftcamCommand(in, command, false, prepareErr); err != nil {
		return model.Softcam{}, err
	}

	s.broadcast()
	return s.softcamByID(id)
}

func (s *Store) DeleteSoftcam(id string) error {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	idx := s.findSoftcamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return errors.New("softcam not found")
	}
	for _, stream := range s.config.Streams {
		if stream.SoftcamID == id {
			s.mu.Unlock()
			return errors.New("softcam is used by a stream")
		}
	}

	profile := s.config.Softcams[idx]
	previous := s.config.Softcams
	candidate := slices.Clone(previous)
	s.config.Softcams = append(candidate[:idx], candidate[idx+1:]...)
	if err := s.saveLocked(); err != nil {
		s.config.Softcams = previous
		s.mu.Unlock()
		return err
	}
	command, prepareErr := s.prepareSoftcamStateLocked(profile, softcam.ActionRemove, true)
	delete(s.softRuntime, id)
	s.appendLogLocked("warn", fmt.Sprintf("softcam removed: %s (%s)", profile.Name, profile.ID))
	s.mu.Unlock()

	if err := s.applySoftcamCommand(profile, command, true, prepareErr); err != nil {
		return err
	}
	s.broadcast()
	return nil
}

func (s *Store) StartSoftcam(id string) (model.Softcam, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Softcam{}, admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	idx := s.findSoftcamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Softcam{}, errors.New("softcam not found")
	}

	profile := s.config.Softcams[idx]
	if !profile.Enabled {
		profile.Enabled = true
		profile.UpdatedAt = s.now().UTC()
		previous := s.config.Softcams
		s.config.Softcams = slices.Clone(previous)
		s.config.Softcams[idx] = profile
		if err := s.saveLocked(); err != nil {
			s.config.Softcams = previous
			s.mu.Unlock()
			return model.Softcam{}, err
		}
	}
	command, prepareErr := s.prepareSoftcamStateLocked(profile, softcam.ActionStart, false)
	s.appendLogLocked("info", fmt.Sprintf("softcam start requested: %s (%s)", profile.Name, profile.ID))
	s.mu.Unlock()

	if err := s.applySoftcamCommand(profile, command, false, prepareErr); err != nil {
		return model.Softcam{}, err
	}
	s.broadcast()
	return s.softcamByID(id)
}

func (s *Store) StopSoftcam(id string) (model.Softcam, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Softcam{}, admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	idx := s.findSoftcamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Softcam{}, errors.New("softcam not found")
	}

	profile := s.config.Softcams[idx]
	if profile.Enabled {
		profile.Enabled = false
		profile.UpdatedAt = s.now().UTC()
		previous := s.config.Softcams
		s.config.Softcams = slices.Clone(previous)
		s.config.Softcams[idx] = profile
		if err := s.saveLocked(); err != nil {
			s.config.Softcams = previous
			s.mu.Unlock()
			return model.Softcam{}, err
		}
	}
	command, prepareErr := s.prepareSoftcamStateLocked(profile, softcam.ActionStop, false)
	s.appendLogLocked("warn", fmt.Sprintf("softcam stop requested: %s (%s)", profile.Name, profile.ID))
	s.mu.Unlock()

	if err := s.applySoftcamCommand(profile, command, false, prepareErr); err != nil {
		return model.Softcam{}, err
	}
	s.broadcast()
	return s.softcamByID(id)
}

func (s *Store) RestartSoftcam(id string) (model.Softcam, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Softcam{}, admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	idx := s.findSoftcamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.Softcam{}, errors.New("softcam not found")
	}

	profile := s.config.Softcams[idx]
	if !profile.Enabled {
		profile.Enabled = true
	}
	profile.UpdatedAt = s.now().UTC()
	previous := s.config.Softcams
	s.config.Softcams = slices.Clone(previous)
	s.config.Softcams[idx] = profile
	if err := s.saveLocked(); err != nil {
		s.config.Softcams = previous
		s.mu.Unlock()
		return model.Softcam{}, err
	}
	command, prepareErr := s.prepareSoftcamStateLocked(profile, softcam.ActionRestart, false)
	s.appendLogLocked("warn", fmt.Sprintf("softcam restart requested: %s (%s)", profile.Name, profile.ID))
	s.mu.Unlock()

	if err := s.applySoftcamCommand(profile, command, false, prepareErr); err != nil {
		return model.Softcam{}, err
	}
	s.broadcast()
	return s.softcamByID(id)
}

func (s *Store) AddAdapterProfile(in model.AdapterProfile) (model.AdapterProfile, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.AdapterProfile{}, admissionErr
	}
	defer endRuntime()
	if strings.TrimSpace(in.Name) == "" {
		return model.AdapterProfile{}, errors.New("name is required")
	}
	in.ID = newID()
	applyAdapterProfileDefaults(&in)
	in.UpdatedAt = s.now().UTC()

	s.mu.Lock()
	s.config.AdapterProfiles = append(s.config.AdapterProfiles, in)
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.AdapterProfile{}, err
	}
	s.appendLogLocked("info", fmt.Sprintf("adapter profile added: %s (%s)", in.Name, in.ID))
	s.mu.Unlock()

	s.broadcast()
	return s.adapterProfileByID(in.ID)
}

func (s *Store) UpdateAdapterProfile(id string, in model.AdapterProfile) (model.AdapterProfile, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.AdapterProfile{}, admissionErr
	}
	defer endRuntime()
	if strings.TrimSpace(in.Name) == "" {
		return model.AdapterProfile{}, errors.New("name is required")
	}

	s.mu.Lock()
	idx := s.findAdapterProfileIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.AdapterProfile{}, errors.New("adapter profile not found")
	}

	current := s.config.AdapterProfiles[idx]
	_, monitorRunning := s.adapterWork[id]
	in.ID = id
	applyAdapterProfileDefaults(&in)
	if in.InternalID == "" {
		in.InternalID = current.InternalID
	}
	in.UpdatedAt = s.now().UTC()
	s.config.AdapterProfiles[idx] = in
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return model.AdapterProfile{}, err
	}
	s.appendLogLocked("info", fmt.Sprintf("adapter profile updated: %s (%s)", in.Name, in.ID))
	s.mu.Unlock()

	if !s.disableRuntime {
		if monitorRunning && in.Enable {
			s.startAdapterMonitor(in, true)
		} else if monitorRunning && !in.Enable {
			s.stopAdapterMonitor(id, false)
		}
	}

	s.broadcast()
	return s.adapterProfileByID(id)
}

func (s *Store) DeleteAdapterProfile(id string) error {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	idx := s.findAdapterProfileIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return errors.New("adapter profile not found")
	}

	profile := s.config.AdapterProfiles[idx]
	s.config.AdapterProfiles = append(s.config.AdapterProfiles[:idx], s.config.AdapterProfiles[idx+1:]...)
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	worker := s.adapterWork[id]
	delete(s.adapterWork, id)
	delete(s.adapterRT, id)
	s.appendLogLocked("warn", fmt.Sprintf("adapter profile removed: %s (%s)", profile.Name, profile.ID))
	s.mu.Unlock()

	if worker != nil {
		worker.cancel()
	}
	s.broadcast()
	return nil
}

func (s *Store) StartAdapterProfileMonitor(id string) (model.AdapterProfile, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.AdapterProfile{}, admissionErr
	}
	defer endRuntime()
	return s.startAdapterProfileMonitor(id)
}

func (s *Store) startAdapterProfileMonitor(id string) (model.AdapterProfile, error) {
	s.mu.Lock()
	idx := s.findAdapterProfileIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.AdapterProfile{}, errors.New("adapter profile not found")
	}

	profile := s.config.AdapterProfiles[idx]
	if !profile.Enable {
		profile.Enable = true
		profile.UpdatedAt = s.now().UTC()
		s.config.AdapterProfiles[idx] = profile
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return model.AdapterProfile{}, err
		}
	}
	s.mu.Unlock()

	if !s.disableRuntime {
		s.startAdapterMonitor(profile, false)
	}
	s.broadcast()
	return s.adapterProfileByID(id)
}

func (s *Store) StopAdapterProfileMonitor(id string) (model.AdapterProfile, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.AdapterProfile{}, admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	if s.findAdapterProfileIndexLocked(id) < 0 {
		s.mu.Unlock()
		return model.AdapterProfile{}, errors.New("adapter profile not found")
	}
	s.mu.Unlock()

	if !s.disableRuntime {
		s.stopAdapterMonitor(id, true)
	}
	s.broadcast()
	return s.adapterProfileByID(id)
}

func (s *Store) RestartAdapterProfileMonitor(id string) (model.AdapterProfile, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.AdapterProfile{}, admissionErr
	}
	defer endRuntime()
	s.mu.Lock()
	idx := s.findAdapterProfileIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return model.AdapterProfile{}, errors.New("adapter profile not found")
	}
	profile := s.config.AdapterProfiles[idx]
	s.mu.Unlock()

	if !s.disableRuntime {
		s.startAdapterMonitor(profile, true)
	}
	s.broadcast()
	return s.adapterProfileByID(id)
}

func (s *Store) streamByID(id string) (model.Stream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx, ok := s.streamIndexByID[id]
	if !ok || idx < 0 || idx >= len(s.config.Streams) {
		return model.Stream{}, errors.New("stream not found")
	}
	stream := cloneStream(s.config.Streams[idx])
	if runtime, ok := s.runtime[id]; ok {
		stream.Runtime = cloneStreamRuntime(runtime)
	} else if stream.Enabled {
		stream.Runtime = model.StreamRuntime{State: "starting"}
	} else {
		stream.Runtime = model.StreamRuntime{State: "stopped"}
	}
	projectDescramblingRuntime(&stream)
	return stream, nil
}

func (s *Store) softcamByID(id string) (model.Softcam, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, profile := range s.listSoftcamsLocked() {
		if profile.ID == id {
			return profile, nil
		}
	}
	return model.Softcam{}, errors.New("softcam not found")
}

func (s *Store) adapterProfileByID(id string) (model.AdapterProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, profile := range s.listAdapterProfilesLocked() {
		if profile.ID == id {
			return profile, nil
		}
	}
	return model.AdapterProfile{}, errors.New("adapter profile not found")
}

func (s *Store) findStreamIndexLocked(id string) int {
	idx, ok := s.streamIndexByID[id]
	if !ok || idx < 0 || idx >= len(s.config.Streams) || s.config.Streams[idx].ID != id {
		return -1
	}
	return idx
}

func (s *Store) findSoftcamIndexLocked(id string) int {
	for i, profile := range s.config.Softcams {
		if profile.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) findAdapterProfileIndexLocked(id string) int {
	for i, profile := range s.config.AdapterProfiles {
		if profile.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) Settings() model.Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings := s.config.Settings
	settings.ExternalAPI.AllowedOrigins = slices.Clone(settings.ExternalAPI.AllowedOrigins)
	settings.EPGSourceURLs = slices.Clone(settings.EPGSourceURLs)
	return settings
}

func (s *Store) SetSettings(in model.Settings) (model.Settings, error) {
	return s.setSettings(in, nil, nil)
}

// SetSettingsWithValidation checks the normalized candidate under the settings
// gate before persistence. The management API supplies its startup admission
// check here; direct Store callers still receive the plaintext safety check.
func (s *Store) SetSettingsWithValidation(in model.Settings, validate func(model.Settings) error) (model.Settings, error) {
	return s.setSettings(in, nil, validate)
}

func (s *Store) setSettings(in model.Settings, patch map[string]json.RawMessage, validate func(model.Settings) error) (model.Settings, error) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return model.Settings{}, admissionErr
	}
	defer endRuntime()
	s.settingsRuntimeMu.Lock()
	defer s.settingsRuntimeMu.Unlock()
	if patch != nil {
		var err error
		in, err = applySettingsPatch(s.Settings(), patch)
		if err != nil {
			return model.Settings{}, err
		}
	}
	if in.HTTPPlayPort <= 0 || in.HTTPPlayPort > 65535 {
		return model.Settings{}, errors.New("http_play_port must be between 1 and 65535")
	}
	if in.SRTPlayPort <= 0 {
		in.SRTPlayPort = model.DefaultSettings().SRTPlayPort
	}
	if in.SRTPlayPort > 65535 {
		return model.Settings{}, errors.New("srt_play_port must be between 1 and 65535")
	}
	if in.ControlListen == "" {
		in.ControlListen = model.DefaultSettings().ControlListen
	}
	if in.PlaylistName == "" {
		in.PlaylistName = "playlist"
	}
	if in.LogLevel == "" {
		in.LogLevel = "info"
	}
	if _, valid := logSeverity(in.LogLevel); !valid {
		return model.Settings{}, errors.New("log_level must be debug, info, warn or error")
	}
	normalizeEPGFetchLimits(&in)
	if err := validateEPGFetchLimits(in, false); err != nil {
		return model.Settings{}, err
	}
	if in.EPGSourceRetentionHours == 0 {
		in.EPGSourceRetentionHours = model.DefaultSettings().EPGSourceRetentionHours
	}
	if in.EPGSourceRetentionHours < 1 || in.EPGSourceRetentionHours > 168 {
		return model.Settings{}, errors.New("epg_source_retention_hours must be between 1 and 168")
	}
	if in.TLSMinVersion != "" && in.TLSMinVersion != "1.2" && in.TLSMinVersion != "1.3" {
		return model.Settings{}, errors.New("management tls_min_version must be 1.2 or 1.3")
	}
	if _, err := adminauth.AdmitManagement(in.ControlListen, "", false, nil, false); err != nil {
		return model.Settings{}, err
	}
	if validate != nil {
		if err := validate(in); err != nil {
			return model.Settings{}, err
		}
	}

	s.mu.Lock()
	existing := s.config.Settings
	if existing.ExternalAPI.Enabled {
		if err := externalAPIPortConflict(existing.ExternalAPI.Port, in); err != nil {
			s.mu.Unlock()
			return model.Settings{}, err
		}
	}
	needsEITRestart := existing.EPGFromDVB != in.EPGFromDVB ||
		existing.EPGDVBIntervalSec != in.EPGDVBIntervalSec ||
		existing.EPGDVBDepth != in.EPGDVBDepth
	needsEPGRefresh := existing.EPGEnabled != in.EPGEnabled ||
		!slices.Equal(existing.EPGSourceURLs, in.EPGSourceURLs) ||
		existing.EPGLocalPath != in.EPGLocalPath || existing.EPGDVBPriority != in.EPGDVBPriority
	needsLimitsUpdate := existing.EPGMaxSourceMiB != in.EPGMaxSourceMiB || existing.EPGSourceTimeoutSec != in.EPGSourceTimeoutSec || existing.EPGMaxProgrammes != in.EPGMaxProgrammes
	needsRetentionUpdate := existing.EPGSourceRetentionHours != in.EPGSourceRetentionHours
	previous := existing
	existing.HTTPPlayPort = in.HTTPPlayPort
	existing.HTTPPlayLoopback = in.HTTPPlayLoopback
	existing.SRTPlayPort = in.SRTPlayPort
	existing.PlaylistName = in.PlaylistName
	existing.ControlListen = in.ControlListen
	existing.ControlListenHTTPS = in.ControlListenHTTPS
	existing.RedirectHTTPS = in.RedirectHTTPS
	existing.TLSMinVersion = in.TLSMinVersion
	existing.LogLevel = in.LogLevel
	existing.EPGEnabled = in.EPGEnabled
	existing.EPGSourceURLs = slices.Clone(in.EPGSourceURLs)
	existing.EPGFromDVB = in.EPGFromDVB
	existing.EPGDVBIntervalSec = in.EPGDVBIntervalSec
	existing.EPGDVBDepth = in.EPGDVBDepth
	existing.EPGDVBPriority = in.EPGDVBPriority
	existing.EPGLocalPath = in.EPGLocalPath
	existing.EPGMaxSourceMiB, existing.EPGSourceTimeoutSec, existing.EPGMaxProgrammes = in.EPGMaxSourceMiB, in.EPGSourceTimeoutSec, in.EPGMaxProgrammes
	existing.EPGSourceRetentionHours = in.EPGSourceRetentionHours
	s.config.Settings = existing
	if err := s.saveLocked(); err != nil {
		s.config.Settings = previous
		s.mu.Unlock()
		return model.Settings{}, err
	}
	if needsEITRestart {
		s.epgSettingsGeneration++
	}
	s.appendLogLocked("info", "settings updated")
	// General settings cannot reconfigure the independent API listener. Return
	// its actual saved values, not the possibly absent fields from a legacy UI.
	saved := s.config.Settings
	saved.ExternalAPI.AllowedOrigins = slices.Clone(saved.ExternalAPI.AllowedOrigins)
	saved.EPGSourceURLs = slices.Clone(saved.EPGSourceURLs)
	s.mu.Unlock()

	if s.epg != nil && needsLimitsUpdate {
		_ = s.epg.SetFetchLimits(runtimeEPGFetchLimits(in))
	}
	if s.epg != nil && needsRetentionUpdate {
		// Retention changes remerge cached data without fetching or restarting EIT.
		_ = s.epg.SetRetentionHours(in.EPGSourceRetentionHours)
	}
	if s.epg != nil && needsEPGRefresh {
		s.epg.SetSources(in.EPGSourceURLs, in.EPGEnabled)
		s.epg.SetLocalPath(in.EPGLocalPath)
		s.updateEPGChannels()
		s.epg.SetDVBPriority(in.EPGDVBPriority)
		if s.runtimeDeps != nil {
			if err := s.runtimeDeps.RefreshEPG(); err != nil {
				s.AddLog("error", "EPG refresh: "+err.Error())
			}
		}
	}

	// Restart EIT collectors if DVB EPG settings changed
	if needsEITRestart && !s.disableRuntime {
		s.restartEITCollectors()
		if !in.EPGFromDVB {
			s.clearDisabledDVBContributions()
		}
	}

	s.broadcast()
	return saved, nil
}

func (s *Store) ListAdapters() []model.Adapter {
	if err := s.requireActivated(); err != nil {
		return nil
	}
	end, err := s.admitRuntime()
	if err != nil {
		return nil
	}
	defer end()
	detected := s.adapterDetector.DetectRuntime()

	s.mu.RLock()
	usage := s.dvbUsageLocked()
	s.mu.RUnlock()

	if len(usage) == 0 {
		return detected
	}

	out := make([]model.Adapter, 0, len(detected))
	for _, item := range detected {
		if item.Type != "dvb" {
			out = append(out, item)
			continue
		}

		key := strings.TrimSpace(item.Address)
		if key == "" {
			key = strings.TrimPrefix(item.ID, "dvb")
		}
		count := usage[key]
		if count > 0 {
			item.InUse = true
			item.UsageCount += count
			if item.Status == "" || item.Status == "available" || item.Status == "idle" {
				item.Status = "in_use"
			}
		}
		out = append(out, item)
	}
	return out
}

func (s *Store) EPGData() ([]byte, time.Time, bool) {
	if s.epg == nil {
		return nil, time.Time{}, false
	}
	data, when := s.epg.Data()
	return data, when, len(data) > 0
}

func (s *Store) updateEPGChannels() {
	if s.epg == nil {
		return
	}
	s.mu.RLock()
	channels := make([]epg.Channel, 0, len(s.config.Streams))
	for _, st := range s.config.Streams {
		if st.XMLTVChannelID == "" {
			continue
		}
		channels = append(channels, epg.Channel{
			ID:          st.XMLTVChannelID,
			DisplayName: []epg.DisplayName{{Value: st.Name}},
		})
	}
	s.mu.RUnlock()
	s.epg.SetChannels(channels)
}

func (s *Store) restartEITCollectors() {
	s.mu.RLock()
	workers := make([]*adapterMonitorWorker, 0, len(s.adapterWork))
	for _, w := range s.adapterWork {
		workers = append(workers, w)
	}
	s.mu.RUnlock()
	for _, w := range workers {
		select {
		case w.eitWake <- struct{}{}:
		default:
		}
	}
	s.sessionWorkers.mu.Lock()
	for _, job := range s.sessionWorkers.jobs {
		job.nextEIT = time.Time{}
	}
	s.sessionWorkers.mu.Unlock()
}

func (s *Store) ListLogs(limit int) []model.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.logs) {
		limit = len(s.logs)
	}
	out := make([]model.LogEntry, limit)
	copy(out, s.logs[len(s.logs)-limit:])
	return out
}

func (s *Store) AddLog(level, message string) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if level == "" {
		level = "info"
	}

	s.mu.Lock()
	s.appendLogLocked(level, message)
	s.mu.Unlock()
	s.broadcast()
}

func (s *Store) reconcileWorkers(streams []model.Stream) {
	endRuntime, admissionErr := s.admitRuntimeStarting()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if s.disableRuntime {
		return
	}
	if s.scheduler != nil {
		s.reconcileStructuredRuntime()
	}
	for _, stream := range streams {
		if isStructuredDVBStream(stream) {
			if s.scheduler != nil {
				if descramblingEnabled(stream) {
					release := s.lockStructuredIDs([]string{stream.ID})
					s.holdDescramblingActionUnderGate(dvbStreamRuntimeAction{ID: stream.ID, Stream: stream})
					release()
				}
				continue
			}
			s.mu.Lock()
			idx := s.findStreamIndexLocked(stream.ID)
			if idx < 0 || !isStructuredDVBStream(s.config.Streams[idx]) {
				s.mu.Unlock()
				continue
			}
			stream = cloneStream(s.config.Streams[idx])
			s.runtime[stream.ID] = newDVBStreamRuntime(stream, s.now().UTC())
			s.mu.Unlock()
			action := "stop"
			if stream.Enabled {
				action = "reconcile"
			}
			s.runDVBStreamRuntimeActions([]dvbStreamRuntimeAction{{ID: stream.ID, Action: action, Stream: stream}})
			continue
		}
		if isLegacyDVBStream(stream) {
			s.reconcileLegacyDVBStream(stream)
			continue
		}
		s.reconcileGenericStream(stream)
	}
}

func (s *Store) reconcileGenericStream(stream model.Stream) {
	release := s.dvbStreamLifecycleGates.Lock(stream.ID)
	defer release()

	s.mu.RLock()
	idx := s.findStreamIndexLocked(stream.ID)
	if idx < 0 || isStructuredDVBStream(s.config.Streams[idx]) ||
		isLegacyDVBStream(s.config.Streams[idx]) ||
		!legacyDVBStreamSnapshotsEqual(s.config.Streams[idx], stream) {
		s.mu.RUnlock()
		return
	}
	current := cloneStream(s.config.Streams[idx])
	s.mu.RUnlock()

	if !current.Enabled {
		s.engine.Stop(current.ID)
		if s.streamer != nil {
			s.streamer.UnregisterStream(current.ID)
		}
		return
	}
	if current.OnDemand {
		s.registerGenericPlaceholderUnderGate(current)
		return
	}
	s.startGenericStreamUnderGate(current, false)
}

func (s *Store) reconcileLegacyDVBStream(stream model.Stream) {
	s.withLegacyDVBStreamLifecycle(stream.ID, func() {
		if !s.streamSnapshotIsCurrent(stream) {
			return
		}
		if s.blockDescramblingRuntimeUnderGate(stream) {
			return
		}
		if !stream.Enabled {
			s.engine.Stop(stream.ID)
			s.streamer.UnregisterStream(stream.ID)
			return
		}
		if stream.OnDemand {
			s.engine.Stop(stream.ID)
			s.registerLegacyDVBPlaceholderUnderGate(stream)
			return
		}

		s.engine.Stop(stream.ID)
		if stream.AdapterProfileID != "" {
			s.startAdapterProfileMonitor(stream.AdapterProfileID)
		}
		s.mu.RLock()
		runtime, exists := s.runtime[stream.ID]
		s.mu.RUnlock()
		if !exists || (runtime.State != "starting" && runtime.State != "running") {
			s.restartLegacyDVBStreamUnderGate(stream)
		}
	})
}

func isStructuredDVBStream(stream model.Stream) bool {
	return stream.DVB != nil
}

func isLegacyDVBStream(stream model.Stream) bool {
	if isStructuredDVBStream(stream) {
		return false
	}
	protocol := strings.TrimSpace(stream.Protocol)
	inputURL := strings.ToLower(strings.TrimSpace(stream.InputURL))
	return strings.EqualFold(protocol, "dvb") || strings.HasPrefix(inputURL, "dvb://")
}

func (s *Store) adapterSessionLocked(profileID string) dvb.Session {
	worker, ok := s.adapterWork[profileID]
	if !ok || worker == nil {
		return nil
	}
	return worker.session
}

var errLegacyDVBStreamSuperseded = errors.New("legacy DVB stream lifecycle superseded")

type legacyDVBStreamSupersededError struct {
	StreamID string
	Reason   string
}

func (e *legacyDVBStreamSupersededError) Error() string {
	return fmt.Sprintf("%s: stream %s %s", errLegacyDVBStreamSuperseded, e.StreamID, e.Reason)
}

func (e *legacyDVBStreamSupersededError) Unwrap() error {
	return errLegacyDVBStreamSuperseded
}

func (e *legacyDVBStreamSupersededError) Superseded() bool {
	return true
}

func legacyDVBStreamSnapshotsEqual(left, right model.Stream) bool {
	left = cloneStream(left)
	right = cloneStream(right)
	left.UpdatedAt = time.Time{}
	right.UpdatedAt = time.Time{}
	left.Runtime = model.StreamRuntime{}
	right.Runtime = model.StreamRuntime{}
	return reflect.DeepEqual(left, right)
}

func (s *Store) legacyDVBStreamSnapshotErrorLocked(expected model.Stream) error {
	idx := s.findStreamIndexLocked(expected.ID)
	if idx < 0 {
		return &legacyDVBStreamSupersededError{StreamID: expected.ID, Reason: "was deleted"}
	}
	current := s.config.Streams[idx]
	if !current.Enabled {
		return &legacyDVBStreamSupersededError{StreamID: expected.ID, Reason: "was disabled"}
	}
	if !isLegacyDVBStream(current) {
		return &legacyDVBStreamSupersededError{StreamID: expected.ID, Reason: "is no longer legacy DVB"}
	}
	if !legacyDVBStreamSnapshotsEqual(current, expected) {
		return &legacyDVBStreamSupersededError{StreamID: expected.ID, Reason: "configuration changed"}
	}
	return nil
}

func (s *Store) legacyDVBStreamSnapshotError(expected model.Stream) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.legacyDVBStreamSnapshotErrorLocked(expected)
}

func (s *Store) streamSnapshotIsCurrentLocked(expected model.Stream) bool {
	idx := s.findStreamIndexLocked(expected.ID)
	return idx >= 0 && legacyDVBStreamSnapshotsEqual(s.config.Streams[idx], expected)
}

func (s *Store) streamSnapshotIsCurrent(expected model.Stream) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streamSnapshotIsCurrentLocked(expected)
}

func (s *Store) withLegacyDVBStreamLifecycle(id string, operation func()) {
	release := s.dvbStreamLifecycleGates.Lock(id)
	defer release()
	operation()
}

func (s *Store) quiesceEngineOwnership(id string) {
	if s.engine != nil {
		s.recordRuntimeCleanup(s.engine.QuiesceWithError(id))
	}
}

func (s *Store) genericStreamSnapshotIsCurrentLocked(expected model.Stream) bool {
	idx := s.findStreamIndexLocked(expected.ID)
	return idx >= 0 &&
		!isStructuredDVBStream(s.config.Streams[idx]) &&
		!isLegacyDVBStream(s.config.Streams[idx]) &&
		legacyDVBStreamSnapshotsEqual(s.config.Streams[idx], expected)
}

func (s *Store) genericStreamSnapshotIsCurrent(expected model.Stream) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.genericStreamSnapshotIsCurrentLocked(expected)
}

func (s *Store) startGenericStreamUnderGate(stream model.Stream, restart bool) {
	if s.blockDescramblingRuntimeUnderGate(stream) {
		return
	}
	if !stream.Enabled || !s.genericStreamSnapshotIsCurrent(stream) {
		return
	}
	s.quiesceEngineOwnership(stream.ID)
	if !s.genericStreamSnapshotIsCurrent(stream) || s.engine == nil {
		return
	}
	if !stream.OnDemand && s.streamer != nil {
		s.streamer.UnregisterStream(stream.ID)
		if !s.genericStreamSnapshotIsCurrent(stream) {
			return
		}
	}
	if restart {
		s.engine.Restart(stream)
		return
	}
	s.engine.Start(stream)
}

func (s *Store) registerGenericPlaceholderUnderGate(stream model.Stream) {
	if s.blockDescramblingRuntimeUnderGate(stream) {
		return
	}
	if !stream.Enabled || !stream.OnDemand || !s.genericStreamSnapshotIsCurrent(stream) {
		return
	}
	s.quiesceEngineOwnership(stream.ID)
	if !s.genericStreamSnapshotIsCurrent(stream) {
		return
	}
	if s.streamer != nil {
		s.streamer.UnregisterStream(stream.ID)
		if !s.genericStreamSnapshotIsCurrent(stream) {
			return
		}
		s.streamer.RegisterStream(stream, nil)
		if !s.genericStreamSnapshotIsCurrent(stream) {
			s.streamer.UnregisterStream(stream.ID)
			return
		}
	}
	s.mu.Lock()
	if s.genericStreamSnapshotIsCurrentLocked(stream) {
		s.runtime[stream.ID] = model.StreamRuntime{State: "on-demand", Since: s.now().UTC()}
	}
	s.mu.Unlock()
}

func (s *Store) startDVBStream(stream model.Stream) {
	if s.disableRuntime {
		return
	}
	s.withLegacyDVBStreamLifecycle(stream.ID, func() {
		_ = s.startDVBStreamUnderGate(stream)
	})
}

func (s *Store) registerLegacyDVBPlaceholder(stream model.Stream) {
	if s.disableRuntime {
		return
	}
	s.withLegacyDVBStreamLifecycle(stream.ID, func() {
		s.registerLegacyDVBPlaceholderUnderGate(stream)
	})
}

func (s *Store) registerLegacyDVBPlaceholderUnderGate(stream model.Stream) {
	if s.blockDescramblingRuntimeUnderGate(stream) {
		return
	}
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil || !stream.OnDemand {
		return
	}
	s.quiesceEngineOwnership(stream.ID)
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil || !stream.OnDemand {
		return
	}
	if s.streamer == nil {
		return
	}
	s.streamer.UnregisterStream(stream.ID)
	s.streamer.RegisterStream(stream, nil)
	s.mu.Lock()
	if s.streamSnapshotIsCurrentLocked(stream) {
		s.runtime[stream.ID] = model.StreamRuntime{State: "on-demand", Since: s.now().UTC()}
	}
	s.mu.Unlock()
}

func (s *Store) restartLegacyDVBStream(stream model.Stream) {
	if s.disableRuntime {
		return
	}
	s.withLegacyDVBStreamLifecycle(stream.ID, func() {
		s.restartLegacyDVBStreamUnderGate(stream)
	})
}

func (s *Store) restartLegacyDVBStreamUnderGate(stream model.Stream) {
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
		return
	}
	s.quiesceEngineOwnership(stream.ID)
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
		return
	}
	if s.streamer != nil {
		s.streamer.UnregisterStream(stream.ID)
	}
	_ = s.startDVBStreamUnderGate(stream)
}

func (s *Store) autoRestartLegacyDVBStream(stream model.Stream) {
	s.restartLegacyDVBStream(stream)
}

func (s *Store) autoRestartLegacyDVBStreamUnderGate(stream model.Stream) {
	s.restartLegacyDVBStreamUnderGate(stream)
}

func (s *Store) setLegacyDVBStartRuntime(stream model.Stream, runtime model.StreamRuntime, level, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.legacyDVBStreamSnapshotErrorLocked(stream); err != nil {
		return err
	}
	s.runtime[stream.ID] = runtime
	if message != "" {
		s.appendLogLocked(level, message)
	}
	return nil
}

func (s *Store) startDVBStreamUnderGate(stream model.Stream) error {
	return s.startDVBStreamExpectedUnderGate(stream, nil)
}

func (s *Store) startDVBStreamExpectedUnderGate(stream model.Stream, expected *streamer.RegistrationToken) error {
	if s.disableRuntime {
		return nil
	}
	if s.blockDescramblingRuntimeUnderGate(stream) {
		return descramblingRuntimeGate(stream)
	}
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
		return err
	}
	s.quiesceEngineOwnership(stream.ID)
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
		return err
	}
	if expected != nil && (s.streamer == nil || !s.streamer.IsCurrentRegistration(*expected)) {
		return errLegacyDVBStreamSuperseded
	}
	log.Printf("startDVBStream: %s (id=%s adapter=%s)", stream.Name, stream.ID, stream.AdapterProfileID)
	if stream.AdapterProfileID == "" {
		err := errors.New("adapter profile not assigned")
		if snapshotErr := s.setLegacyDVBStartRuntime(stream, model.StreamRuntime{
			State:     "error",
			Since:     s.now().UTC(),
			LastError: err.Error(),
		}, "error", fmt.Sprintf("stream %s: %v", stream.Name, err)); snapshotErr != nil {
			return snapshotErr
		}
		return err
	}

	s.mu.Lock()
	if err := s.legacyDVBStreamSnapshotErrorLocked(stream); err != nil {
		s.mu.Unlock()
		return err
	}

	if art, ok := s.adapterRT[stream.AdapterProfileID]; ok && art.State == "error" {
		err := fmt.Errorf("adapter error: %s", art.LastError)
		s.runtime[stream.ID] = model.StreamRuntime{
			State:     "error",
			Since:     s.now().UTC(),
			LastError: err.Error(),
		}
		s.appendLogLocked("error", fmt.Sprintf("stream %s: %v", stream.Name, err))
		s.mu.Unlock()
		return err
	}

	session := s.adapterSessionLocked(stream.AdapterProfileID)
	if session == nil {
		s.runtime[stream.ID] = model.StreamRuntime{
			State:     "starting",
			Since:     s.now().UTC(),
			LastError: "waiting for adapter",
		}
		log.Printf("startDVBStream: %s no session yet, waiting for adapter", stream.Name)
		s.mu.Unlock()
		return nil
	}
	log.Printf("startDVBStream: %s session found, proceeding", stream.Name)

	worker, ok := s.adapterWork[stream.AdapterProfileID]
	if !ok || worker == nil {
		err := errors.New("adapter worker not found")
		s.runtime[stream.ID] = model.StreamRuntime{
			State:     "error",
			Since:     s.now().UTC(),
			LastError: err.Error(),
		}
		s.appendLogLocked("error", fmt.Sprintf("stream %s: %v", stream.Name, err))
		s.mu.Unlock()
		return err
	}
	shared := worker.sharedDemux
	releaseCall, leaseErr := s.leaseAdapterWorkerLocked(worker)
	s.mu.Unlock()
	if leaseErr != nil {
		return leaseErr
	}
	defer releaseCall()

	if shared == nil {
		// Some DVB drivers need a moment to clean up the old demux filter.
		time.Sleep(time.Second)
		if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
			return err
		}

		demux, err := session.OpenDemux(0, 0, 0)
		if err != nil {
			wrapped := fmt.Errorf("open shared demux: %w", err)
			if snapshotErr := s.setLegacyDVBStartRuntime(stream, model.StreamRuntime{
				State:     "error",
				Since:     s.now().UTC(),
				LastError: wrapped.Error(),
			}, "error", fmt.Sprintf("stream %s: %v", stream.Name, wrapped)); snapshotErr != nil {
				return snapshotErr
			}
			return wrapped
		}

		var closeDemux bool
		s.mu.Lock()
		if snapshotErr := s.legacyDVBStreamSnapshotErrorLocked(stream); snapshotErr != nil {
			s.mu.Unlock()
			if !nilPacketSource(demux) {
				_ = demux.Close()
			}
			return snapshotErr
		}
		worker, ok = s.adapterWork[stream.AdapterProfileID]
		if !ok || worker == nil {
			s.mu.Unlock()
			if !nilPacketSource(demux) {
				_ = demux.Close()
			}
			return errors.New("adapter worker not found")
		}
		if worker.sharedDemux == nil {
			created, sharedErr := newSharedDemux(demux)
			if sharedErr != nil {
				wrapped := fmt.Errorf("initialize shared demux: %w", sharedErr)
				s.runtime[stream.ID] = model.StreamRuntime{
					State:     "error",
					Since:     s.now().UTC(),
					LastError: wrapped.Error(),
				}
				s.appendLogLocked("error", fmt.Sprintf("stream %s: %v", stream.Name, wrapped))
				s.mu.Unlock()
				if !nilPacketSource(demux) {
					_ = demux.Close()
				}
				return wrapped
			}
			worker.sharedDemux = created
			shared = created
			s.appendLogLocked("info", fmt.Sprintf("adapter %s: shared demux opened", stream.AdapterProfileID))
		} else {
			shared = worker.sharedDemux
			closeDemux = true
		}
		s.mu.Unlock()
		if closeDemux && !nilPacketSource(demux) {
			_ = demux.Close()
		}
	}

	cfg, err := dvb.ParseConfig(stream.InputURL)
	if err != nil {
		wrapped := fmt.Errorf("parse dvb url: %w", err)
		if snapshotErr := s.setLegacyDVBStartRuntime(stream, model.StreamRuntime{
			State:     "error",
			Since:     s.now().UTC(),
			LastError: wrapped.Error(),
		}, "error", fmt.Sprintf("stream %s: %v", stream.Name, wrapped)); snapshotErr != nil {
			return snapshotErr
		}
		return wrapped
	}

	pids := legacyDVBServicePIDs(cfg.PCR_PID, cfg.VideoPID, cfg.AudioPID)
	err = s.registerAndPublishDVBStreamExpectedUnderGate(stream, shared, pids, expected)
	if err == nil {
		s.mu.Lock()
		if snapshotErr := s.legacyDVBStreamSnapshotErrorLocked(stream); snapshotErr == nil {
			s.appendLogLocked("info", fmt.Sprintf("stream %s: registered with shared demux pids=%v", stream.Name, pids))
		}
		s.mu.Unlock()
		return nil
	}
	if errors.Is(err, errLegacyDVBStreamSuperseded) {
		return err
	}
	if snapshotErr := s.setLegacyDVBStartRuntime(stream, model.StreamRuntime{
		State:     "error",
		Since:     s.now().UTC(),
		LastError: fmt.Sprintf("register shared demux: %v", err),
	}, "error", fmt.Sprintf("stream %s: register shared demux: %v", stream.Name, err)); snapshotErr != nil {
		return snapshotErr
	}
	return err
}

func (s *Store) registerAndPublishDVBStream(stream model.Stream, shared *sharedDemux, pids []int) error {
	var result error
	s.withLegacyDVBStreamLifecycle(stream.ID, func() {
		result = s.registerAndPublishDVBStreamUnderGate(stream, shared, pids)
	})
	return result
}

func (s *Store) registerAndPublishDVBStreamUnderGate(stream model.Stream, shared *sharedDemux, pids []int) error {
	return s.registerAndPublishDVBStreamExpectedUnderGate(stream, shared, pids, nil)
}

func (s *Store) registerAndPublishDVBStreamExpectedUnderGate(stream model.Stream, shared *sharedDemux, pids []int, expected *streamer.RegistrationToken) error {
	if s.blockDescramblingRuntimeUnderGate(stream) {
		return descramblingRuntimeGate(stream)
	}
	if shared == nil {
		return errors.New("shared demux is unavailable")
	}
	s.quiesceEngineOwnership(stream.ID)
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
		return err
	}
	if expected != nil && (s.streamer == nil || !s.streamer.IsCurrentRegistration(*expected)) {
		return errLegacyDVBStreamSuperseded
	}
	source, err := shared.RegisterStream(stream.ID, pids)
	if err != nil {
		if source != nil {
			_ = source.Close()
		}
		return err
	}
	if source == nil {
		return errors.New("shared demux returned a nil packet source")
	}
	if s.testHookAfterDVBSourceAccepted != nil {
		s.testHookAfterDVBSourceAccepted(stream.ID, source)
	}
	if err := s.legacyDVBStreamSnapshotError(stream); err != nil {
		_ = source.Close()
		return err
	}
	if s.streamer == nil {
		_ = source.Close()
		return errors.New("streamer is unavailable")
	}

	if expected != nil {
		token, err := s.streamer.RegisterChecked(stream, source, expected)
		if token.Generation == 0 {
			_ = source.Close()
			if !s.streamer.IsCurrentRegistration(*expected) {
				return errLegacyDVBStreamSuperseded
			}
		}
		return err
	}
	s.streamer.RegisterStream(stream, source)
	return nil
}

func legacyDVBServicePIDs(pcrPID, videoPID, audioPID int) []int {
	pids := make([]int, 0, 3)
	seen := make(map[int]struct{}, 3)
	for _, pid := range []int{pcrPID, videoPID, audioPID} {
		if pid <= 0 || pid > 0x1fff {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		pids = append(pids, pid)
	}
	return pids
}

func (s *Store) startDVBStreamsForAdapter(profileID string) {
	if s.disableRuntime {
		return
	}
	s.mu.RLock()
	var streams []model.Stream
	for _, st := range s.config.Streams {
		if st.Enabled && isLegacyDVBStream(st) && st.AdapterProfileID == profileID {
			streams = append(streams, st)
		}
	}
	s.mu.RUnlock()
	if len(streams) > 0 {
		log.Printf("startDVBStreamsForAdapter: found %d streams to start for profile %s", len(streams), profileID)
	}
	for _, st := range streams {
		s.restartLegacyDVBStream(st)
	}
}

func (s *Store) updateDVBStreamRuntimesOnce(prevPackets map[string]uint64) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	s.mu.RLock()
	streams := make([]model.Stream, 0, len(s.config.Streams))
	for _, st := range s.config.Streams {
		if st.Enabled && isLegacyDVBStream(st) {
			streams = append(streams, cloneStream(st))
		}
	}
	s.mu.RUnlock()

	for _, st := range streams {
		s.updateLegacyDVBStreamRuntime(st, prevPackets)
	}
}

func (s *Store) updateLegacyDVBStreamRuntime(expected model.Stream, prevPackets map[string]uint64) {
	release := s.dvbStreamLifecycleGates.Lock(expected.ID)
	defer release()

	s.mu.RLock()
	if err := s.legacyDVBStreamSnapshotErrorLocked(expected); err != nil {
		s.mu.RUnlock()
		return
	}
	idx := s.findStreamIndexLocked(expected.ID)
	current := cloneStream(s.config.Streams[idx])
	_, runtimeExists := s.runtime[expected.ID]
	s.mu.RUnlock()
	if !runtimeExists || s.streamer == nil {
		return
	}

	packets := s.streamer.StreamPackets(current.ID)
	if s.testHookAfterDVBPacketSample != nil {
		s.testHookAfterDVBPacketSample(current.ID, packets)
	}

	s.mu.Lock()
	if err := s.legacyDVBStreamSnapshotErrorLocked(current); err != nil {
		s.mu.Unlock()
		return
	}
	rt, ok := s.runtime[current.ID]
	if !ok {
		s.mu.Unlock()
		return
	}
	// Only auto-restart streams that hit a real error.
	// "stopped" is a user-initiated state and must not be overridden.
	wasError := rt.State == "error"

	// Guard against uint64 underflow when the streamer was unregistered and
	// re-registered and its packet counter reset to zero.
	var delta uint64
	if packets >= prevPackets[current.ID] {
		delta = packets - prevPackets[current.ID]
	}
	rt.Packets = packets
	if packets == 0 {
		rt.BitrateKbps = 0
	} else {
		rt.BitrateKbps = int(delta * 188 * 8 / 1000)
	}
	if packets > 0 {
		if rt.State != "running" {
			rt.Since = s.now().UTC()
			rt.UptimeSeconds = 0
		} else {
			rt.UptimeSeconds = int64(s.now().UTC().Sub(rt.Since).Seconds())
		}
		rt.State = "running"
		rt.LastError = ""
	}
	prevPackets[current.ID] = packets
	s.runtime[current.ID] = rt
	s.mu.Unlock()

	if wasError && packets == 0 {
		s.autoRestartLegacyDVBStreamUnderGate(current)
	}
}

func (s *Store) reconcileSoftcamWorkers(_ []model.Softcam) {
	end, err := s.admitRuntimeStarting()
	if err != nil {
		return
	}
	defer end()
	if s.disableRuntime {
		return
	}
	s.mu.Lock()
	type pending struct {
		profile model.Softcam
		command *softcam.RuntimeCommand
		err     error
	}
	commands := make([]pending, 0, len(s.config.Softcams))
	for _, profile := range s.config.Softcams {
		command, err := s.prepareSoftcamStateLocked(profile, softcam.ActionStart, false)
		commands = append(commands, pending{profile, command, err})
	}
	s.mu.Unlock()
	for _, item := range commands {
		_ = s.applySoftcamCommand(item.profile, item.command, false, item.err)
	}
}

func (s *Store) handleEngineEvent(ev engine.Event) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if s.disableRuntime {
		return
	}
	release := s.dvbStreamLifecycleGates.Lock(ev.StreamID)
	defer release()

	s.mu.Lock()
	idx := s.findStreamIndexLocked(ev.StreamID)
	if idx < 0 {
		s.mu.Unlock()
		return
	}
	stream := s.config.Streams[idx]
	// Persisted DVB rows are Store/scheduler-owned. Generic events also need
	// the exact still-current Engine worker generation before publication.
	if !stream.Enabled || isStructuredDVBStream(stream) || isLegacyDVBStream(stream) ||
		s.engine == nil || !s.engine.IsCurrentGeneration(ev.StreamID, ev.Generation) {
		s.mu.Unlock()
		return
	}
	s.runtime[ev.StreamID] = ev.Runtime
	if ev.Message != "" {
		level := ev.Level
		if level == "" {
			level = "info"
		}
		s.appendLogLocked(level, ev.Message)
	}
	s.mu.Unlock()
	s.broadcast()
}

func (s *Store) handleSoftcamEvent(ev softcam.Event) {
	endRuntime, admissionErr := s.admitRuntime()
	if admissionErr != nil {
		return
	}
	defer endRuntime()
	if s.disableRuntime {
		return
	}
	s.mu.Lock()
	exists := false
	readyTransition := false
	for _, profile := range s.config.Softcams {
		if profile.ID == ev.SoftcamID && ev.Generation != 0 && s.softGenerations[ev.SoftcamID] == ev.Generation {
			exists = true
			break
		}
	}
	if exists {
		previous := s.softRuntime[ev.SoftcamID]
		readyTransition = ev.Runtime.State == "running" && ev.Runtime.Connected && (previous.State != "running" || !previous.Since.Equal(ev.Runtime.Since))
		s.softRuntime[ev.SoftcamID] = ev.Runtime.Clone()
		if ev.Message != "" {
			level := ev.Level
			if level == "" {
				level = "info"
			}
			s.appendLogLocked(level, ev.Message)
		}
	}
	s.mu.Unlock()

	if exists {
		if ev.Runtime.State == "error" || ev.Runtime.State == "stopped" || ev.Runtime.State == "starting" {
			if s.scheduler != nil {
				s.scheduler.revokeStaleDescramblingProfile(ev.SoftcamID)
			}
		}
		if readyTransition {
			s.recoverDescramblingProfile(ev.SoftcamID, ev.Generation)
		}
		s.broadcast()
	}
}

func (s *Store) dvbUsageLocked() map[string]int {
	usage := make(map[string]int)

	for _, stream := range s.config.Streams {
		if !stream.Enabled {
			continue
		}
		if !isLegacyDVBStream(stream) {
			continue
		}
		cfg, err := dvb.ParseConfig(stream.InputURL)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d.%d", cfg.Adapter, cfg.Frontend)
		usage[key]++
	}

	for profileID := range s.adapterWork {
		if idx := s.findAdapterProfileIndexLocked(profileID); idx >= 0 {
			adapter, frontend := parseAdapterFrontend(s.config.AdapterProfiles[idx].Adapter)
			key := fmt.Sprintf("%d.%d", adapter, frontend)
			usage[key]++
		}
	}

	return usage
}

func normalizeSoftcamType(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "", "newcamd":
		return "newcamd"
	case "cccam", "cccam232", "cccam 2.3.2", "cccam2.3.2":
		return "cccam"
	default:
		return v
	}
}

func isSupportedSoftcamType(raw string) bool {
	switch normalizeSoftcamType(raw) {
	case "newcamd", "cccam":
		return true
	default:
		return false
	}
}

func softcamRequiresDES(raw string) bool {
	return normalizeSoftcamType(raw) == "newcamd"
}

func normalizeSoftcamTimeout(v int) int {
	if v <= 0 {
		return 6
	}
	if v > 120 {
		return 120
	}
	return v
}

func applyAdapterProfileDefaults(profile *model.AdapterProfile) {
	if profile.Name == "" {
		profile.Name = "DVB Adapter"
	}
	if profile.InternalID == "" {
		profile.InternalID = profile.ID
	}
	if profile.Adapter == "" {
		profile.Adapter = "auto"
	}
	if profile.Type == "" {
		profile.Type = "DVB-S2"
	}
	if profile.Frequency == 0 {
		profile.Frequency = 11568
	}
	if profile.Polarization == "" {
		profile.Polarization = "H"
	}
	if profile.SymbolRate == 0 {
		profile.SymbolRate = 27500
	}
	if profile.LNB == (model.AdapterLNBConfig{}) {
		profile.LNB = model.DefaultAdapterLNB()
	}
	if profile.Advanced == (model.AdapterAdvancedConfig{}) {
		profile.Advanced = model.DefaultAdapterAdvanced()
	}
	if profile.LNB.Mode == "" {
		profile.LNB.Mode = model.DefaultAdapterLNB().Mode
	}
	if profile.LNB.SlotPosition == "" {
		profile.LNB.SlotPosition = model.DefaultAdapterLNB().SlotPosition
	}
	if profile.LNB.LOF1 == 0 {
		profile.LNB.LOF1 = model.DefaultAdapterLNB().LOF1
	}
	if profile.LNB.LOF2 == 0 {
		profile.LNB.LOF2 = model.DefaultAdapterLNB().LOF2
	}
	if profile.LNB.SLOF == 0 {
		profile.LNB.SLOF = model.DefaultAdapterLNB().SLOF
	}
	if profile.LNB.SlotFrequency == 0 {
		profile.LNB.SlotFrequency = model.DefaultAdapterLNB().SlotFrequency
	}
	if profile.Advanced.Modulation == "" {
		profile.Advanced.Modulation = model.DefaultAdapterAdvanced().Modulation
	}
	if profile.Advanced.FEC == "" {
		profile.Advanced.FEC = model.DefaultAdapterAdvanced().FEC
	}
	if profile.Advanced.RollOff == "" {
		profile.Advanced.RollOff = model.DefaultAdapterAdvanced().RollOff
	}
	if profile.Advanced.TimeoutSec == 0 {
		profile.Advanced.TimeoutSec = model.DefaultAdapterAdvanced().TimeoutSec
	}
}

func newID() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return fmt.Sprintf("st-%d", time.Now().UnixNano())
	}
	return "st-" + hex.EncodeToString(buf)
}
