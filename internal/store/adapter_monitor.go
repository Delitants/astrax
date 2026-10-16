// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"astrax/internal/dvb"
	"astrax/internal/model"
)

type adapterMonitorWorker struct {
	epgPublishMu sync.Mutex
	callMu       sync.Mutex
	callCond     *sync.Cond
	stopping     bool
	calls        int
	generation   uint64
	eitWake      chan struct{}
	closeErr     error
	profile      model.AdapterProfile
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	restartCount int
	session      dvb.Session
	sharedDemux  *sharedDemux
	eitCancel    context.CancelFunc
	eitDone      chan struct{}
}

var (
	adapterFrontendPattern = regexp.MustCompile(`(\d+)\.(\d+)`)
	adapterDigitPattern    = regexp.MustCompile(`\d+`)
)

// Used only by idempotent legacy monitor admission, not stream ownership gates.
func (g *streamLifecycleGates) tryLockUncontended(id string) (func(), bool) {
	g.mu.Lock()
	if g.entries[id] != nil {
		g.mu.Unlock()
		return nil, false
	}
	if g.entries == nil {
		g.entries = make(map[string]*streamLifecycleGate)
	}
	entry := &streamLifecycleGate{refs: 1}
	entry.mu.Lock()
	g.entries[id] = entry
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			entry.refs--
			entry.mu.Unlock()
			if entry.refs == 0 && g.entries[id] == entry {
				delete(g.entries, id)
			}
			g.mu.Unlock()
		})
	}, true
}

func (s *Store) startAdapterMonitor(profile model.AdapterProfile, force bool) {
	if profile.ID == "" || s.disableRuntime {
		return
	}
	end, err := s.admitRuntime()
	if err != nil {
		return
	}
	defer end()
	var release func()
	if force {
		release = s.adapterLifecycleGates.Lock(profile.ID)
	} else {
		// Stream actions may own a stream gate needed by a retiring monitor.
		// An idempotent ensure linearizes before an overlapping stop/restart;
		// it must never wait for that operation's joined worker cleanup.
		var acquired bool
		release, acquired = s.adapterLifecycleGates.tryLockUncontended(profile.ID)
		if !acquired {
			return
		}
	}
	defer release()
	s.mu.Lock()
	previous := s.adapterWork[profile.ID]
	if previous != nil && !force {
		s.mu.Unlock()
		return
	}
	count := s.adapterRT[profile.ID].RestartCount
	if previous != nil {
		count++
	}
	s.mu.Unlock()
	if previous != nil {
		previous.cancel()
		if previous.done != nil {
			<-previous.done
		}
	}
	if s.runtimeClosing() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	worker := &adapterMonitorWorker{profile: profile, ctx: ctx, cancel: cancel, done: make(chan struct{}), restartCount: count, eitWake: make(chan struct{}, 1)}
	s.mu.Lock()
	s.legacyWorkers.Add(1)
	s.adapterWork[profile.ID] = worker
	s.adapterRT[profile.ID] = model.AdapterProfileRuntime{State: "starting", Since: s.now().UTC(), RestartCount: count}
	s.mu.Unlock()
	go s.runAdapterMonitor(worker)
	s.broadcast()
}
func (s *Store) stopAdapterMonitor(id string, addLog bool) {
	release := s.adapterLifecycleGates.Lock(id)
	defer release()
	s.mu.Lock()
	worker := s.adapterWork[id]
	delete(s.adapterWork, id)
	prev := s.adapterRT[id]
	s.adapterRT[id] = model.AdapterProfileRuntime{State: "stopped", Since: s.now().UTC(), RestartCount: prev.RestartCount}
	if addLog {
		s.appendLogLocked("warn", fmt.Sprintf("adapter monitor stop requested: %s", id))
	}
	s.mu.Unlock()
	if worker != nil {
		if worker.cancel != nil {
			worker.cancel()
		}
		if worker.done != nil {
			<-worker.done
		} else {
			s.recordRuntimeCleanup(s.closeLegacyResources(worker))
		}
	}
}
func waitLegacyContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (s *Store) runAdapterMonitor(worker *adapterMonitorWorker) {
	defer s.legacyWorkers.Done()
	defer func() { s.detachAdapterWorker(worker); s.recordRuntimeCleanup(worker.closeErr); close(worker.done) }()
	cfg, err := dvbConfigFromAdapterProfile(worker.profile)
	if err != nil {
		s.setAdapterRuntime(worker, model.AdapterProfileRuntime{State: "error", Since: s.now().UTC(), LastError: err.Error()}, "error", err.Error())
		return
	}
	for worker.ctx.Err() == nil {
		if s.dvbOpener == nil {
			worker.closeErr = errors.New("legacy session opener unavailable")
			return
		}
		session, err := s.dvbOpener.OpenSession(cfg)
		if err != nil {
			if !nilDVBSession(session) {
				worker.closeErr = errors.Join(worker.closeErr, session.Close())
			}
			s.setAdapterRuntime(worker, model.AdapterProfileRuntime{State: "error", Since: s.now().UTC(), LastError: err.Error()}, "error", err.Error())
			if errors.Is(err, os.ErrNotExist) || !waitLegacyContext(worker.ctx, 5*time.Second) {
				return
			}
			continue
		}
		if nilDVBSession(session) {
			worker.closeErr = errors.New("legacy opener returned nil session")
			return
		}
		s.mu.Lock()
		worker.session = session
		s.legacyGeneration++
		worker.generation = s.legacyGeneration
		s.mu.Unlock()
		worker.callMu.Lock()
		worker.stopping = false
		worker.callMu.Unlock()
		restart := s.runLegacySession(worker, session)
		worker.closeErr = errors.Join(worker.closeErr, s.closeLegacyResources(worker))
		if !restart || !waitLegacyContext(worker.ctx, 2*time.Second) {
			return
		}
		worker.restartCount++
	}
}
func (s *Store) runLegacySession(worker *adapterMonitorWorker, session dvb.Session) bool {
	ctx, cancel := context.WithCancel(worker.ctx)
	worker.eitCancel = cancel
	worker.eitDone = make(chan struct{})
	lockReady := make(chan struct{})
	go s.runEITCollector(ctx, worker, lockReady, worker.eitDone)
	var tasks sync.WaitGroup
	defer func() { cancel(); tasks.Wait(); <-worker.eitDone }()
	startedAt := s.now().UTC()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	type scanResult struct {
		services []dvb.Service
		err      error
	}
	scanned := make(chan scanResult, 1)
	var services []model.Service
	started := false
	var noLockSince time.Time
	for {
		select {
		case <-ctx.Done():
			return false
		case result := <-scanned:
			if result.err == nil {
				services = make([]model.Service, 0, len(result.services))
				for _, v := range result.services {
					services = append(services, model.Service{SID: v.SID, Name: v.Name, VideoPID: v.VideoPID, AudioPID: v.AudioPID, PCR_PID: v.PCR_PID, Type: v.Type, Provider: v.Provider, Scrambled: v.Scrambled, HasEPG: v.HasEPG, AudioLanguages: v.AudioLanguages, CAIDs: v.CAIDs})
				}
			}
		case <-ticker.C:
			if ctx.Err() != nil {
				return false
			}
			sig, err := session.Poll()
			if ctx.Err() != nil {
				return false
			}
			rt := model.AdapterProfileRuntime{State: "running", Since: startedAt, RestartCount: worker.restartCount, Services: services}
			if err != nil {
				rt.State = "error"
				rt.LastError = err.Error()
			} else {
				rt.Signal = &model.DVBSignal{Locked: sig.Locked, SignalPercent: sig.SignalPercent, SNRPercent: sig.SNRPercent, BER: sig.BER, UncorrectedBlocks: sig.UncorrectedBlocks, StatusBits: sig.StatusBits}
				if !sig.Locked {
					rt.State = "no_lock"
					rt.LastError = "frontend has no lock"
				}
			}
			s.setAdapterRuntime(worker, rt, "", "")
			if sig.Locked && err == nil && !started {
				started = true
				close(lockReady)
				tasks.Add(2)
				go func() {
					defer tasks.Done()
					if ctx.Err() != nil {
						return
					}
					svcs, e := session.ScanServices()
					select {
					case scanned <- scanResult{svcs, e}:
					case <-ctx.Done():
					}
				}()
				go func() {
					defer tasks.Done()
					if ctx.Err() == nil {
						s.startDVBStreamsForAdapter(worker.profile.ID)
					}
				}()
			}
			if rt.State == "running" {
				noLockSince = time.Time{}
			} else if noLockSince.IsZero() {
				noLockSince = s.now()
			} else if s.now().Sub(noLockSince) >= 30*time.Second {
				return true
			}
		}
	}
}

// A legacy source setup lease prevents terminal frontend close while OpenDemux
// or checked source publication is entered by a Store action.
func (s *Store) leaseAdapterWorkerLocked(worker *adapterMonitorWorker) (func(), error) {
	worker.callMu.Lock()
	if worker.stopping {
		worker.callMu.Unlock()
		return nil, errLegacyDVBStreamSuperseded
	}
	if worker.callCond == nil {
		worker.callCond = sync.NewCond(&worker.callMu)
	}
	worker.calls++
	worker.callMu.Unlock()
	return func() {
		worker.callMu.Lock()
		worker.calls--
		if worker.calls == 0 {
			worker.callCond.Broadcast()
		}
		worker.callMu.Unlock()
	}, nil
}
func (s *Store) closeLegacyResources(worker *adapterMonitorWorker) error {
	worker.callMu.Lock()
	worker.stopping = true
	if worker.callCond == nil {
		worker.callCond = sync.NewCond(&worker.callMu)
	}
	for worker.calls != 0 {
		worker.callCond.Wait()
	}
	worker.callMu.Unlock()
	s.mu.Lock()
	session, shared := worker.session, worker.sharedDemux
	worker.session = nil
	worker.sharedDemux = nil
	ids := make([]string, 0)
	for _, st := range s.config.Streams {
		if isLegacyDVBStream(st) && st.AdapterProfileID == worker.profile.ID {
			ids = append(ids, st.ID)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range ids {
		release := s.dvbStreamLifecycleGates.Lock(id)
		s.mu.RLock()
		idx := s.findStreamIndexLocked(id)
		same := idx >= 0 && isLegacyDVBStream(s.config.Streams[idx]) && s.config.Streams[idx].AdapterProfileID == worker.profile.ID
		s.mu.RUnlock()
		if same {
			s.quiesceEngineOwnership(id)
			if s.streamer != nil {
				errs = append(errs, s.streamer.UnregisterStreamWithError(id))
			}
		}
		release()
	}
	if worker.generation != 0 && s.runtimeDeps != nil {
		errs = append(errs, s.runtimeDeps.RemoveDVBContribution(dvbEPGContributionKey{SessionID: "legacy:" + worker.profile.ID, Generation: worker.generation}))
	}
	if shared != nil {
		errs = append(errs, shared.Close())
	}
	if !nilDVBSession(session) {
		errs = append(errs, session.Close())
	}
	return errors.Join(errs...)
}
func (s *Store) detachAdapterWorker(worker *adapterMonitorWorker) {
	s.mu.Lock()
	if s.adapterWork[worker.profile.ID] == worker {
		delete(s.adapterWork, worker.profile.ID)
	}
	s.mu.Unlock()
}
func (s *Store) runEITCollector(ctx context.Context, worker *adapterMonitorWorker, lockReady <-chan struct{}, done chan struct{}) {
	defer close(done)
	// Pre-lock demux filters can interfere with tuning on legacy drivers. Each
	// opened session must confirm its own first lock, even on settings wakeups.
	select {
	case <-ctx.Done():
		return
	case <-lockReady:
	}
	// The first collection reads current settings, including pre-lock changes.
	select {
	case <-worker.eitWake:
	default:
	}
	for ctx.Err() == nil {
		s.mu.RLock()
		settings := s.config.Settings
		s.mu.RUnlock()
		if settings.EPGFromDVB {
			s.collectEIT(worker, settings.EPGDVBDepth)
		}
		interval := time.Duration(settings.EPGDVBIntervalSec) * time.Second
		if interval <= 0 {
			interval = 15 * time.Minute
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-worker.eitWake:
			timer.Stop()
		case <-timer.C:
		}
	}
}
func (s *Store) collectEIT(worker *adapterMonitorWorker, depth string) {
	s.mu.RLock()
	settings := s.config.Settings
	session := worker.session
	generation := worker.generation
	settingsGeneration := s.epgSettingsGeneration
	var streams []model.Stream
	for _, st := range s.config.Streams {
		if st.Enabled && isLegacyDVBStream(st) && st.AdapterProfileID == worker.profile.ID {
			streams = append(streams, cloneStream(st))
		}
	}
	s.mu.RUnlock()
	if !settings.EPGFromDVB || nilDVBSession(session) || s.runtimeDeps == nil {
		return
	}
	if depth == "" {
		depth = "present_following"
	}
	programmes, err := s.runtimeDeps.CollectEIT(session, depth)
	if err != nil {
		s.AddLog("error", fmt.Sprintf("legacy EIT: %v", err))
		return
	}
	samples := make([]storeAttachmentSample, 0, len(streams))
	for _, st := range streams {
		cfg, err := dvb.ParseConfig(st.InputURL)
		if err != nil {
			continue
		}
		st.DVB = &model.DVBStreamConfig{ServiceID: cfg.ServiceID}
		samples = append(samples, storeAttachmentSample{stream: st})
	}
	channels, mapped := mapSessionEPG(samples, programmes)
	worker.epgPublishMu.Lock()
	defer worker.epgPublishMu.Unlock()
	s.mu.RLock()
	current := s.adapterWork[worker.profile.ID] == worker && worker.session == session && s.epgSettingsGeneration == settingsGeneration && s.config.Settings.EPGFromDVB
	s.mu.RUnlock()
	if current && generation != 0 {
		if err := s.runtimeDeps.UpsertDVBContribution(dvbEPGContributionKey{SessionID: "legacy:" + worker.profile.ID, Generation: generation}, channels, mapped); err != nil {
			s.AddLog("error", fmt.Sprintf("legacy EIT publication: %v", err))
		}
	}
}

func (s *Store) setAdapterRuntime(worker *adapterMonitorWorker, rt model.AdapterProfileRuntime, logLevel, logMessage string) {
	s.mu.Lock()
	current, ok := s.adapterWork[worker.profile.ID]
	if !ok || current != worker {
		s.mu.Unlock()
		return
	}
	s.adapterRT[worker.profile.ID] = rt
	if logMessage != "" {
		if logLevel == "" {
			logLevel = "info"
		}
		s.appendLogLocked(logLevel, logMessage)
	}

	// Sync adapter signal to enabled DVB stream runtimes only.
	// Stopped streams keep their "stopped" state so the UI reflects
	// the user's explicit stop action.
	for _, stream := range s.config.Streams {
		if !stream.Enabled {
			continue
		}
		if isLegacyDVBStream(stream) && stream.AdapterProfileID == worker.profile.ID {
			if prev, exists := s.runtime[stream.ID]; exists {
				s.runtime[stream.ID] = model.StreamRuntime{
					State:         rt.State,
					Since:         prev.Since,
					UptimeSeconds: prev.UptimeSeconds,
					RestartCount:  prev.RestartCount,
					LastError:     rt.LastError,
					Packets:       prev.Packets,
					BitrateKbps:   prev.BitrateKbps,
					Signal:        rt.Signal,
				}
			} else {
				s.runtime[stream.ID] = model.StreamRuntime{
					State:        rt.State,
					Since:        time.Now().UTC(),
					RestartCount: 0,
					Signal:       rt.Signal,
				}
			}
		}
	}

	s.mu.Unlock()
	s.broadcast()
}

func dvbConfigFromAdapterProfile(profile model.AdapterProfile) (dvb.Config, error) {
	copyProfile := profile
	applyAdapterProfileDefaults(&copyProfile)

	adapter, frontend := parseAdapterFrontend(copyProfile.Adapter)
	delivery := "dvbs"
	if strings.Contains(strings.ToLower(copyProfile.Type), "s2") {
		delivery = "dvbs2"
	}

	symbolRate := copyProfile.SymbolRate
	if symbolRate > 0 && symbolRate < 1_000_000 {
		symbolRate = symbolRate * 1000
	}
	if symbolRate == 0 {
		symbolRate = 27500000
	}

	frequencyKHz := normalizeFrequencyKHz(copyProfile.Frequency)
	if frequencyKHz == 0 {
		return dvb.Config{}, fmt.Errorf("frequency must be > 0")
	}

	polarization := strings.ToUpper(strings.TrimSpace(copyProfile.Polarization))
	if polarization != "V" {
		polarization = "H"
	}

	diseqcPort := 0
	if strings.EqualFold(strings.TrimSpace(copyProfile.LNB.SlotPosition), "B") {
		diseqcPort = 1
	}

	unicableType := 0
	switch strings.ToLower(strings.TrimSpace(copyProfile.LNB.Mode)) {
	case "unicable1":
		unicableType = 1
	case "unicable2":
		unicableType = 2
	}

	cfg := dvb.Config{
		Adapter:      adapter,
		Frontend:     frontend,
		Delivery:     delivery,
		FrequencyKHz: frequencyKHz,
		SymbolRate:   symbolRate,
		Polarization: polarization,
		DiseqcPort:   diseqcPort,
		UnicableType: unicableType,
		UnicableSlot: copyProfile.LNB.UnicableSlot,
		UnicableFreq: copyProfile.LNB.SlotFrequency,
		UnicablePIN:  -1,
		LnbLowMHz:    copyProfile.LNB.LOF1,
		LnbHighMHz:   copyProfile.LNB.LOF2,
		LnbSwitchMHz: copyProfile.LNB.SLOF,
		ForceTone:    copyProfile.LNB.ForceTone,
		DVBAPI:       copyProfile.Advanced.DVBAPI,
		DVBAPIV3:     copyProfile.Advanced.DVBAPI == "v3" || copyProfile.Advanced.DVBAPIV3,
		Modulation:   copyProfile.Advanced.Modulation,
		FEC:          copyProfile.Advanced.FEC,
		RollOff:      copyProfile.Advanced.RollOff,
	}

	if cfg.UnicableFreq <= 0 {
		cfg.UnicableFreq = 1210
	}

	if cfg.UnicableType == 0 {
		cfg.UnicableSlot = 0
	}
	return cfg, nil
}

func parseAdapterFrontend(raw string) (int, int) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "auto") {
		return 0, 0
	}

	if match := adapterFrontendPattern.FindStringSubmatch(trimmed); len(match) == 3 {
		adapter, err1 := strconv.Atoi(match[1])
		frontend, err2 := strconv.Atoi(match[2])
		if err1 == nil && err2 == nil {
			return adapter, frontend
		}
	}

	digits := adapterDigitPattern.FindAllString(trimmed, -1)
	if len(digits) >= 2 {
		adapter, err1 := strconv.Atoi(digits[0])
		frontend, err2 := strconv.Atoi(digits[1])
		if err1 == nil && err2 == nil {
			return adapter, frontend
		}
	}
	if len(digits) == 1 {
		adapter, err := strconv.Atoi(digits[0])
		if err == nil {
			return adapter, 0
		}
	}

	return 0, 0
}

func normalizeFrequencyKHz(value uint32) uint32 {
	switch {
	case value >= 1_000_000_000:
		return value / 1000
	case value >= 1_000_000:
		return value
	default:
		return value * 1000
	}
}
