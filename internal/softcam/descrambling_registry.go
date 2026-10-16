// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"astrax/internal/csa"
	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
)

type DescramblingServiceKey struct {
	InputID               string
	InputGeneration       uint64
	ONID, TSID, ServiceID uint16
	ProfileID             string
}

type DescramblingRegistryConfig struct {
	Manager *Manager
	Backend csa.Backend
	Budget  *packetbudget.Budget
	Workers int
	Now     func() time.Time
	Manual  bool
}

var errDescramblingPolicyConflict error = ecmFixedError{code: "ca_policy_conflict"}

// Counts include constructors waiting for a manager bind and outputs waiting
// for their close to join. Separate registries cannot bypass process limits.
var descramblingProcess = struct {
	sync.Mutex
	contexts, outputs int
	inputs            map[string]int
	profiles          map[string]int
}{inputs: make(map[string]int), profiles: make(map[string]int)}

var descramblingRegistrySequence atomic.Uint64

type DescramblingRegistry struct {
	mu          sync.Mutex
	services    map[DescramblingServiceKey]*DescramblingService
	cfg         DescramblingRegistryConfig
	refresh     *ECMRefreshCoordinator
	bindService func(string, ECMServiceIdentity) (*ECMClient, error)
	jobs        chan *DescramblingService
	stop        chan struct{}
	done        chan struct{}
	wg          sync.WaitGroup
	once        sync.Once
	closing     atomic.Bool
	id, next    uint64
}

type DescramblingService struct {
	registry          *DescramblingRegistry
	key               DescramblingServiceKey
	id                string
	route             mpegts.ResolvedRoute
	algorithm         string
	catalog           mpegts.Service
	binding           ECMBindingInfo
	client            *ECMClient
	pipeline          *DescramblingPipeline
	ready, done       chan struct{}
	initErr, closeErr error
	closing           atomic.Bool
	scheduled         atomic.Bool
	closeOnce         sync.Once
	mu                sync.Mutex
	outputs           map[string]*descramblingRegistrySource
	retiring          map[*descramblingRegistrySource]struct{}
}

type descramblingRegistrySource struct {
	owner    *DescramblingService
	id       string
	source   *DescramblingOutput
	closed   atomic.Bool
	once     sync.Once
	slotOnce sync.Once
	err      error
}

// Revoked is lifecycle metadata only, never a publication capability.
func (s *DescramblingService) Revoked() bool { return s == nil || s.closing.Load() }

func NewDescramblingRegistry(cfg DescramblingRegistryConfig) (*DescramblingRegistry, error) {
	if cfg.Manager == nil || cfg.Backend == nil || cfg.Budget == nil || cfg.Workers < 1 {
		return nil, ecmInvalidRequestError
	}
	v := reflect.ValueOf(cfg.Backend)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, ecmInvalidRequestError
	}
	if size := cfg.Backend.BatchSize(); size < 1 || size > 128 {
		return nil, ecmInvalidRequestError
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	workers := min(cfg.Workers, 8)
	refresh, err := NewECMRefreshCoordinator(workers)
	if err != nil {
		return nil, err
	}
	r := &DescramblingRegistry{cfg: cfg, refresh: refresh,
		services: make(map[DescramblingServiceKey]*DescramblingService),
		jobs:     make(chan *DescramblingService, 512), stop: make(chan struct{}), done: make(chan struct{}),
		bindService: cfg.Manager.BindService, id: descramblingRegistrySequence.Add(1)}
	for range workers {
		r.wg.Add(1)
		go r.mediaWorker()
	}
	if !cfg.Manual {
		r.wg.Add(1)
		go r.runTicker()
	}
	return r, nil
}

func reserveDescramblingContext(key DescramblingServiceKey) bool {
	descramblingProcess.Lock()
	defer descramblingProcess.Unlock()
	if descramblingProcess.contexts >= 512 || descramblingProcess.inputs[key.InputID] >= 64 ||
		descramblingProcess.profiles[key.ProfileID] >= 64 {
		return false
	}
	descramblingProcess.contexts++
	descramblingProcess.inputs[key.InputID]++
	descramblingProcess.profiles[key.ProfileID]++
	return true
}

func releaseDescramblingContext(key DescramblingServiceKey) {
	descramblingProcess.Lock()
	defer descramblingProcess.Unlock()
	descramblingProcess.contexts--
	descramblingProcess.inputs[key.InputID]--
	if descramblingProcess.inputs[key.InputID] == 0 {
		delete(descramblingProcess.inputs, key.InputID)
	}
	descramblingProcess.profiles[key.ProfileID]--
	if descramblingProcess.profiles[key.ProfileID] == 0 {
		delete(descramblingProcess.profiles, key.ProfileID)
	}
}

func (r *DescramblingRegistry) Acquire(key DescramblingServiceKey, service mpegts.Service, policy model.DVBDescramblingConfig) (*DescramblingService, error) {
	if r == nil {
		return nil, ecmInvalidRequestError
	}
	// Resolve and retain the same independent snapshot, including the optional
	// policy PID. A caller may reuse its catalog storage while a bind is waiting.
	service = service.Clone()
	policy = *policy.Clone()
	if key.InputID == "" || key.ProfileID == "" || key.InputGeneration == 0 ||
		len(key.InputID) > ecmMaxIDBytes || len(key.ProfileID) > ecmMaxIDBytes ||
		key.ONID != service.ONID || key.TSID != service.TSID || key.ServiceID != service.SID {
		return nil, ecmInvalidRequestError
	}
	route, routeErr := mpegts.ResolveRoute(service, policy)
	for {
		r.mu.Lock()
		if r.closing.Load() {
			r.mu.Unlock()
			return nil, io.EOF
		}
		if s := r.services[key]; s != nil {
			if s.closing.Load() {
				done := s.done
				r.mu.Unlock()
				<-done
				continue
			}
			if s.algorithm != policy.Algorithm {
				r.mu.Unlock()
				return nil, errDescramblingPolicyConflict
			}
			r.mu.Unlock()
			<-s.ready
			if s.initErr != nil {
				return nil, s.initErr
			}
			if s.closing.Load() {
				<-s.done
				continue
			}
			// Resolve viewer policy against the owner's retained catalog. A
			// conflicting viewer must not retire siblings; a changed catalog
			// with the same canonical policy instead requires owner replacement.
			requested, err := mpegts.ResolveRoute(s.catalog, policy)
			if err != nil || requested != s.route {
				return nil, errDescramblingPolicyConflict
			}
			binding, err := s.client.BindingInfo()
			if err != nil || binding != s.binding {
				_ = s.Close()
				if err == nil {
					err = ecmStaleError
				}
				return nil, err
			}
			if err := s.UpdateCatalog(service); err != nil {
				return nil, err
			}
			if s.closing.Load() {
				<-s.done
				continue
			}
			return s, nil
		}
		if routeErr != nil {
			r.mu.Unlock()
			return nil, routeErr
		}
		if !reserveDescramblingContext(key) {
			r.mu.Unlock()
			return nil, ecmCapacityError
		}
		r.next++
		s := &DescramblingService{registry: r, key: key,
			id: fmt.Sprintf("descrambling-%d-%d", r.id, r.next), route: route, algorithm: policy.Algorithm, catalog: service,
			ready: make(chan struct{}), done: make(chan struct{}), outputs: make(map[string]*descramblingRegistrySource),
			retiring: make(map[*descramblingRegistrySource]struct{})}
		r.services[key] = s
		r.mu.Unlock()
		// Only the provisional owner constructs. All waiters observe ready/done;
		// manager/native ownership and allocations never run under the map lock.
		s.initErr = s.initialize(policy)
		close(s.ready)
		if s.initErr != nil {
			_ = s.Close()
			return nil, s.initErr
		}
		if s.closing.Load() || r.closing.Load() {
			_ = s.Close()
			return nil, io.EOF
		}
		return s, nil
	}
}

func (s *DescramblingService) initialize(policy model.DVBDescramblingConfig) error {
	r := s.registry
	if s.closing.Load() || r.closing.Load() {
		return io.EOF
	}
	id := ECMServiceIdentity{InputID: s.key.InputID, InputGeneration: s.key.InputGeneration,
		ONID: s.key.ONID, TSID: s.key.TSID, ServiceID: s.key.ServiceID}
	client, err := r.bindService(s.key.ProfileID, id)
	s.client = client
	if err != nil {
		return err
	}
	if client == nil {
		return ecmInvalidRequestError
	}
	if s.closing.Load() || r.closing.Load() {
		return io.EOF
	}
	s.binding, err = client.BindingInfo()
	if err != nil {
		return err
	}
	if s.binding.Identity != id {
		return ecmInvalidRequestError
	}
	pids := make([]uint16, 0, len(s.catalog.ElementaryStreams))
	for _, es := range s.catalog.ElementaryStreams {
		pids = append(pids, es.PID)
	}
	s.pipeline, err = NewDescramblingPipeline(DescramblingPipelineConfig{
		Client: client, Backend: r.cfg.Backend, Budget: r.cfg.Budget,
		Service: s.catalog, Policy: policy, Selection: mpegts.Selection{PIDs: pids, PCRPID: s.catalog.PCRPID},
		Generation: s.key.InputGeneration, Now: r.cfg.Now, Shared: true,
	})
	if err != nil {
		return err
	}
	if s.closing.Load() || r.closing.Load() {
		return io.EOF
	}
	return r.refresh.Add(s.id, s.key.ProfileID, client, s.pipeline)
}

func (s *DescramblingService) Subscribe(outputID string, selection mpegts.Selection) (model.PacketSource, error) {
	if s == nil {
		return nil, io.EOF
	}
	<-s.ready
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() || s.registry.closing.Load() || s.initErr != nil {
		return nil, io.EOF
	}
	if outputID == "" || len(outputID) > ecmMaxIDBytes || s.outputs[outputID] != nil {
		return nil, ecmInvalidRequestError
	}
	if len(s.outputs) >= 64 {
		return nil, ecmCapacityError
	}
	descramblingProcess.Lock()
	if descramblingProcess.outputs >= 4096 {
		descramblingProcess.Unlock()
		return nil, ecmCapacityError
	}
	descramblingProcess.outputs++
	descramblingProcess.Unlock()
	out := &descramblingRegistrySource{owner: s, id: outputID}
	source, err := s.pipeline.Subscribe(outputID, selection)
	if err != nil {
		out.releaseSlot()
		return nil, err
	}
	out.source = source
	if s.closing.Load() || s.registry.closing.Load() {
		_ = source.Close()
		out.releaseSlot()
		return nil, io.EOF
	}
	s.outputs[outputID] = out
	return out, nil
}

func (s *DescramblingService) Unsubscribe(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	out := s.outputs[id]
	s.mu.Unlock()
	if out != nil {
		_ = out.Close()
	}
}

func (s *DescramblingService) Push(packet mpegts.Packet, at time.Time) error {
	if s == nil || s.closing.Load() || s.registry.closing.Load() {
		return io.EOF
	}
	select {
	case <-s.ready:
	default:
		return ecmCapacityError
	}
	if s.initErr != nil {
		return s.initErr
	}
	sections, err := s.pipeline.TryPush(packet, at)
	if err != nil {
		return err
	}
	if len(sections) != 0 {
		return s.registry.refresh.Offer(s.id, sections)
	}
	return nil
}

// Catalog replacement is deliberately conservative: even an SDT-only change
// retires the owner and requires explicit reacquisition. No tuning, new binding
// or speculative in-place SPTS/route update happens here.
func (s *DescramblingService) UpdateCatalog(service mpegts.Service) error {
	if s == nil {
		return ecmStaleError
	}
	service = service.Clone()
	<-s.ready
	if s.initErr != nil {
		return s.initErr
	}
	if s.closing.Load() || s.registry.closing.Load() {
		return ecmStaleError
	}
	if reflect.DeepEqual(s.catalog, service) {
		return nil
	}
	_ = s.Close()
	return ecmStaleError
}

func (out *descramblingRegistrySource) ReadPacket() ([]byte, error) {
	if out.closed.Load() || out.owner.closing.Load() {
		return nil, io.EOF
	}
	packet, err := out.source.ReadPacket()
	if out.closed.Load() || out.owner.closing.Load() {
		clear(packet)
		return nil, io.EOF
	}
	return packet, err
}

func (out *descramblingRegistrySource) releaseSlot() {
	out.slotOnce.Do(func() {
		descramblingProcess.Lock()
		descramblingProcess.outputs--
		descramblingProcess.Unlock()
	})
}

func (out *descramblingRegistrySource) Close() error {
	if out == nil {
		return nil
	}
	out.once.Do(func() {
		out.closed.Store(true)
		s := out.owner
		s.mu.Lock()
		current := s.outputs[out.id] == out
		if current {
			delete(s.outputs, out.id)
			s.retiring[out] = struct{}{}
		}
		last := current && len(s.outputs) == 0
		if last {
			s.closing.Store(true)
		}
		s.mu.Unlock()
		// Close the service first for the final subscriber: pipeline.Close must
		// fence publication before waiting for an in-flight cipher to return.
		if last {
			out.err = s.Close()
		}
		out.err = errors.Join(out.err, out.source.Close())
		out.releaseSlot()
		s.mu.Lock()
		delete(s.retiring, out)
		s.mu.Unlock()
	})
	return out.err
}

func (s *DescramblingService) Close() error {
	if s == nil {
		return nil
	}
	s.closing.Store(true)
	s.closeOnce.Do(func() {
		<-s.ready
		r := s.registry
		r.refresh.Remove(s.id)
		if s.pipeline != nil {
			s.closeErr = errors.Join(s.closeErr, s.pipeline.Close())
		}
		if s.client != nil {
			s.closeErr = errors.Join(s.closeErr, s.client.Release())
		}
		s.mu.Lock()
		for id, out := range s.outputs {
			out.closed.Store(true)
			out.releaseSlot()
			delete(s.outputs, id)
		}
		for out := range s.retiring {
			out.closed.Store(true)
			out.releaseSlot()
			delete(s.retiring, out)
		}
		s.mu.Unlock()
		r.mu.Lock()
		if r.services[s.key] == s {
			delete(r.services, s.key)
			releaseDescramblingContext(s.key)
		}
		close(s.done)
		r.mu.Unlock()
	})
	return s.closeErr
}

// Revocation is safe on the single native demux reader: publication is fenced
// immediately, while the fixed registry workers perform terminal cleanup.
func (s *DescramblingService) Revoke() {
	if s != nil {
		s.closing.Store(true)
	}
}

// Tick snapshots only ready owners. No pipeline mutex, binding metadata call,
// cipher or worker join is on this scheduling path.
func (r *DescramblingRegistry) Tick(now time.Time) {
	if r == nil || r.closing.Load() {
		return
	}
	r.refresh.Tick(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing.Load() {
		return
	}
	for _, s := range r.services {
		select {
		case <-s.ready:
		default:
			continue
		}
		if s.initErr != nil || (!s.closing.Load() && !s.pipeline.HasPackets()) || !s.scheduled.CompareAndSwap(false, true) {
			continue
		}
		select {
		case r.jobs <- s:
		default:
			s.scheduled.Store(false)
		}
	}
}

func (r *DescramblingRegistry) mediaWorker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.stop:
			return
		case s := <-r.jobs:
			if s.closing.Load() {
				_ = s.Close()
			} else {
				_ = s.pipeline.Flush(false)
			}
			s.scheduled.Store(false)
		}
	}
}

func (r *DescramblingRegistry) runTicker() {
	defer r.wg.Done()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.Tick(r.cfg.Now())
		}
	}
}

// Delayed commands/events may arrive after a replacement session is healthy.
// Retire exact stale native bindings, never all owners sharing a profile name.
// Provisional owners cannot publish before their own native admission checks.
func (r *DescramblingRegistry) RevokeStaleProfile(profileID string) {
	if r == nil || r.closing.Load() {
		return
	}
	r.mu.Lock()
	var owners []*DescramblingService
	for key, s := range r.services {
		if key.ProfileID == profileID {
			select {
			case <-s.ready:
				owners = append(owners, s)
			default:
			}
		}
	}
	r.mu.Unlock()
	var stale []*DescramblingService
	for _, s := range owners {
		if s.initErr != nil || s.client == nil {
			continue
		}
		binding, err := s.client.BindingInfo()
		if err != nil || binding != s.binding {
			s.Revoke()
			stale = append(stale, s)
		}
	}
	for _, s := range stale {
		_ = s.Close()
	}
}

func (r *DescramblingRegistry) ProfileChanged(profileID string) {
	if r == nil || r.closing.Load() {
		return
	}
	r.mu.Lock()
	var owners []*DescramblingService
	for key, s := range r.services {
		if key.ProfileID == profileID {
			s.closing.Store(true)
			owners = append(owners, s)
		}
	}
	r.mu.Unlock()
	for _, s := range owners {
		_ = s.Close()
	}
}

func (r *DescramblingRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.closing.Store(true)
	r.once.Do(func() {
		close(r.stop)
		r.mu.Lock()
		owners := make([]*DescramblingService, 0, len(r.services))
		for _, s := range r.services {
			s.closing.Store(true)
			owners = append(owners, s)
		}
		r.mu.Unlock()
		for _, s := range owners {
			_ = s.Close()
		}
		r.refresh.Close()
		r.wg.Wait()
		for {
			select {
			case s := <-r.jobs:
				s.scheduled.Store(false)
			default:
				close(r.done)
				return
			}
		}
	})
	<-r.done
	return nil
}

var _ model.PacketSource = (*descramblingRegistrySource)(nil)
