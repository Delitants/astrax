// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"runtime"

	"astrax/internal/csa"
	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
	"astrax/internal/softcam"
)

// Optional for injected runtimes: absence never falls back to live resources.
type descramblingRuntimeResources interface {
	DescramblingResources() (*packetbudget.Budget, csa.Backend, error)
}

// Only a complete registry and the exact guarded sink budget admit the native
// path. Missing resources never fall back to an ordinary FTA attachment.
func (s *dvbScheduler) configureDescrambling(manager *softcam.Manager, budget *packetbudget.Budget, backend csa.Backend) error {
	end, err := s.admit()
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	if s.descrambling != nil || s.descramblingPreparing || len(s.ownedSessions) != 0 {
		s.mu.Unlock()
		return schedulerError(ErrDVBSchedulerOwnership, "descrambling resources must be installed before native sessions")
	}
	s.descramblingPreparing = true
	s.mu.Unlock()
	registry, err := softcam.NewDescramblingRegistry(softcam.DescramblingRegistryConfig{
		Manager: manager, Backend: backend, Budget: budget, Workers: min(8, max(1, runtime.NumCPU())),
	})
	s.mu.Lock()
	s.descramblingPreparing = false
	if err == nil && s.isClosing() {
		err = ErrDVBSchedulerClosed
	}
	if err == nil {
		s.descrambling = registry
		s.acquireDescrambling = func(key softcam.DescramblingServiceKey, service mpegts.Service, policy model.DVBDescramblingConfig) (descramblingService, error) {
			return registry.Acquire(key, service, policy)
		}
		s.packetBudget = budget
		if sink, ok := s.sink.(descramblingSinkResources); ok {
			s.descramblingHookup = sink.DescramblingPacketBudget() == budget
		}
	}
	s.mu.Unlock()
	if err != nil && registry != nil {
		err = errors.Join(err, registry.Close())
	}
	return err
}
