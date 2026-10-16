// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"astrax/internal/csa"
	"astrax/internal/dvb"
	"astrax/internal/engine"
	"astrax/internal/epg"
	"astrax/internal/model"
	"astrax/internal/packetbudget"
	"astrax/internal/softcam"
	"astrax/internal/streamer"
)

type dvbEPGContributionKey = epg.DVBContributionKey

// RuntimeDependencies is a complete boundary: an injected factory must supply
// every method. Store never fills missing injected behavior with live defaults.
type RuntimeDependencies interface {
	Start() error
	Shutdown(context.Context) error
	Sink() storeStreamSink
	Streamer() *streamer.Streamer
	NewEngine(func(engine.Event)) (*engine.Engine, error)
	NewSoftcam(func(softcam.Event)) (*softcam.Manager, error)
	NewScheduler(dvb.SessionOpener) (*dvbScheduler, error)
	SetOnDemandCallbacks(func(streamer.RegistrationToken), func(streamer.RegistrationToken))
	OnDemandCallbackCurrent(streamer.RegistrationToken, bool) bool
	Aggregator() *epg.Aggregator
	RefreshEPG() error
	RunEPG(<-chan struct{})
	RunUpdater(<-chan struct{}, func())
	CollectEIT(dvb.Session, string) ([]epg.Programme, error)
	UpsertDVBContribution(dvbEPGContributionKey, []epg.Channel, []epg.Programme) error
	RemoveDVBContribution(dvbEPGContributionKey) error
	Emit(model.ResourceEvent)
}

type productionRuntime struct {
	st              *streamer.Streamer
	epg             *epg.Aggregator
	packetBudget    *packetbudget.Budget
	backend         csa.Backend
	backendErr      error
	backendOwned    bool
	backendClose    sync.Once
	backendCloseErr error
}

var _ RuntimeDependencies = (*productionRuntime)(nil)

func newProductionRuntime(settings model.Settings) (RuntimeDependencies, error) {
	return newProductionRuntimeWithOptions(settings, Options{})
}

func newProductionRuntimeWithOptions(settings model.Settings, opts Options) (RuntimeDependencies, error) {
	normalizeEPGFetchLimits(&settings)
	if err := validateEPGFetchLimits(settings, false); err != nil {
		return nil, err
	}
	a := epg.New(settings.EPGSourceURLs, settings.EPGEnabled)
	if err := a.SetFetchLimits(runtimeEPGFetchLimits(settings)); err != nil {
		return nil, err
	}
	hours := settings.EPGSourceRetentionHours
	if hours == 0 {
		hours = model.DefaultSettings().EPGSourceRetentionHours
	}
	if err := a.SetRetentionHours(hours); err != nil {
		return nil, err
	}
	a.SetLocalPath(settings.EPGLocalPath)
	a.SetDVBPriority(settings.EPGDVBPriority)
	budget := opts.PacketBudget
	if budget == nil {
		budget = processSharedDemuxDependencies.packets
	}
	resources, err := streamer.NewStageCResources(budget)
	if err != nil {
		return nil, err
	}
	st, err := streamer.NewWithStageCResources(settings, resources)
	if err != nil {
		return nil, err
	}
	r := &productionRuntime{st: st, epg: a, packetBudget: budget, backend: opts.DescramblingBackend}
	if r.backend == nil {
		r.backend, r.backendErr = csa.New()
		r.backendOwned = r.backend != nil
	}
	return r, nil
}
func (r *productionRuntime) Start() error { return r.st.Start() }
func (r *productionRuntime) Shutdown(ctx context.Context) error {
	err := r.st.Shutdown(ctx)
	r.backendClose.Do(func() {
		if r.backendOwned {
			r.backendCloseErr = r.backend.Close()
		}
	})
	return errors.Join(err, r.backendCloseErr)
}
func (r *productionRuntime) DescramblingResources() (*packetbudget.Budget, csa.Backend, error) {
	return r.packetBudget, r.backend, r.backendErr
}
func (r *productionRuntime) Sink() storeStreamSink        { return newStreamerSinkAdapter(r.st) }
func (r *productionRuntime) Streamer() *streamer.Streamer { return r.st }
func (r *productionRuntime) Aggregator() *epg.Aggregator  { return r.epg }
func (r *productionRuntime) NewEngine(h func(engine.Event)) (*engine.Engine, error) {
	return engine.New(h), nil
}
func (r *productionRuntime) NewSoftcam(h func(softcam.Event)) (*softcam.Manager, error) {
	return softcam.New(h), nil
}
func (r *productionRuntime) NewScheduler(o dvb.SessionOpener) (*dvbScheduler, error) {
	s := newDVBScheduler(o, r.Sink(), r.Emit)
	s.packetBudget = r.packetBudget
	return s, nil
}
func (r *productionRuntime) SetOnDemandCallbacks(a, b func(streamer.RegistrationToken)) {
	r.st.SetOnDemandCallbacks(a, b)
}
func (r *productionRuntime) OnDemandCallbackCurrent(t streamer.RegistrationToken, b bool) bool {
	return r.st.OnDemandCallbackCurrent(t, b)
}
func (r *productionRuntime) RefreshEPG() error           { return r.epg.Fetch() }
func (r *productionRuntime) RunEPG(stop <-chan struct{}) { r.epg.Run(stop) }
func (r *productionRuntime) RunUpdater(stop <-chan struct{}, tick func()) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			select {
			case <-stop:
				return
			default:
			}
			tick()
		}
	}
}
func (r *productionRuntime) CollectEIT(s dvb.Session, d string) ([]epg.Programme, error) {
	return dvb.CollectEIT(s, d)
}
func (r *productionRuntime) UpsertDVBContribution(k dvbEPGContributionKey, c []epg.Channel, p []epg.Programme) error {
	return r.epg.UpsertDVBContribution(k, c, p)
}
func (r *productionRuntime) RemoveDVBContribution(k dvbEPGContributionKey) error {
	return r.epg.RemoveDVBContribution(k)
}

// Store.PublishEvent owns production delivery; Emit is only an optional observer.
func (r *productionRuntime) Emit(model.ResourceEvent) {}

func (s *Store) initializeRuntime(opts Options) error {
	factory := opts.RuntimeFactory
	if factory == nil {
		factory = func(settings model.Settings) (RuntimeDependencies, error) {
			return newProductionRuntimeWithOptions(settings, opts)
		}
	}
	deps, err := factory(s.config.Settings)
	if err != nil {
		if deps != nil {
			err = errors.Join(err, deps.Shutdown(context.Background()))
		}
		return err
	}
	if deps == nil {
		return errors.New("runtime factory returned nil dependencies")
	}
	s.runtimeDeps = deps
	fail := func(err error) error {
		if s.scheduler != nil {
			err = errors.Join(err, s.scheduler.Close())
		}
		if s.engine != nil {
			err = errors.Join(err, s.engine.ShutdownWithError())
		}
		if s.softcam != nil {
			err = errors.Join(err, s.softcam.ShutdownWithError())
		}
		return errors.Join(err, deps.Shutdown(context.Background()))
	}
	if err := deps.Start(); err != nil {
		return fail(err)
	}
	scheduler, err := deps.NewScheduler(s.dvbOpener)
	s.scheduler = scheduler
	if err != nil {
		return fail(err)
	}
	if scheduler == nil || deps.Sink() == nil || deps.Streamer() == nil || deps.Aggregator() == nil {
		return fail(errors.New("incomplete runtime dependencies"))
	}
	s.scheduler = scheduler
	scheduler.removePublication = s.removeSessionPublication
	s.runtimeSink = deps.Sink()
	s.streamer = deps.Streamer()
	s.streamer.SetConfiguredOutputs(s.config.Streams)
	s.epg = deps.Aggregator()
	cards, err := s.adapterDetector.DetectDVB(context.Background())
	if err != nil {
		return fail(err)
	}
	s.dvbDetected = make([]model.DVBCard, len(cards))
	for i := range cards {
		s.dvbDetected[i] = cloneDVBCard(cards[i])
	}
	inventory := cardSelectionInventory(s.dvbDetected, s.config.DVBCards)
	if err := scheduler.ReplaceCards(inventory); err != nil {
		return fail(err)
	}
	scheduler.cardApplicationChanged = s.installCardApplications
	s.cardApplications = make(map[string]dvbCardApplicationUpdate)
	scheduler.mu.Lock()
	for _, card := range inventory {
		s.cardApplications[card.ID] = scheduler.cardApplicationLocked(card.ID)
	}
	scheduler.mu.Unlock()
	// Startup discovery completed an inventory read before runtime workers start.
	s.dvbRefreshedAt = s.now().UTC()
	s.dvbStale = false
	s.dvbLastSummary = summarizeDVBCards(s.mergeDVBCardsLocked())
	s.engine, err = deps.NewEngine(s.handleEngineEvent)
	if err != nil {
		return fail(err)
	}
	if s.engine == nil {
		return fail(errors.New("runtime factory returned nil Engine"))
	}
	s.engine.SetStreamer(s.streamer)
	s.softcam, err = deps.NewSoftcam(s.handleSoftcamEvent)
	if err != nil {
		return fail(err)
	}
	if s.softcam == nil {
		return fail(errors.New("runtime factory returned nil Softcam manager"))
	}
	var budget *packetbudget.Budget
	var backend csa.Backend
	var resourceErr error
	if resources, ok := deps.(descramblingRuntimeResources); ok {
		budget, backend, resourceErr = resources.DescramblingResources()
	}
	if opts.PacketBudget != nil {
		budget = opts.PacketBudget
	}
	if opts.DescramblingBackend != nil {
		backend, resourceErr = opts.DescramblingBackend, nil
	}
	// Missing cipher support leaves ordinary streams usable. Enabled streams
	// remain behind the explicit admission gate, never an FTA fallback.
	if resourceErr == nil && budget != nil && backend != nil {
		if deps.Streamer().StageCPacketBudget() != budget {
			return fail(errors.New("descrambling and sink packet budgets differ"))
		}
		if err := scheduler.configureDescrambling(s.softcam, budget, backend); err != nil {
			return fail(err)
		}
	}
	deps.SetOnDemandCallbacks(s.onDemandStartChecked, s.onDemandStopChecked)
	s.updateEPGChannels()
	s.epgStop = make(chan struct{})
	s.epgDone = make(chan struct{})
	s.updaterDone = make(chan struct{})
	go func() { defer close(s.epgDone); deps.RunEPG(s.epgStop) }()
	prev := make(map[string]uint64)
	go func() {
		defer close(s.updaterDone)
		deps.RunUpdater(s.epgStop, func() { s.updateDVBStreamRuntimesOnce(prev); s.updateStructuredSessionWorkers() })
	}()
	return nil
}
