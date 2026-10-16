// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"log"
	"sync"

	"astrax/internal/model"
)

var ErrStoreClosed = errors.New("Store runtime closed")

type storeRuntimeLifecycle struct {
	context       context.Context
	cancel        context.CancelFunc
	cleanupErrors []error
	mu            sync.Mutex
	cond          *sync.Cond
	active        int
	closing       bool
	done          chan struct{}
	result        error
}

func (l *storeRuntimeLifecycle) initLocked() {
	if l.done == nil {
		l.context, l.cancel = context.WithCancel(context.Background())
		l.done = make(chan struct{})
		l.cond = sync.NewCond(&l.mu)
	}
}
func (s *Store) admitRuntime() (func(), error) {
	l := &s.runtimeLifecycle
	l.mu.Lock()
	l.initLocked()
	if l.closing {
		l.mu.Unlock()
		return nil, ErrStoreClosed
	}
	l.active++
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.active--
		if l.active == 0 {
			l.cond.Broadcast()
		}
		l.mu.Unlock()
	}, nil
}
func (s *Store) runtimeClosing() bool {
	l := &s.runtimeLifecycle
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closing
}

// CloseWithError is terminal: context-free owners are joined, never abandoned on
// a timeout. All callers receive the same stored aggregate, including failures.
func (s *Store) CloseWithError() error {
	l := &s.runtimeLifecycle
	l.mu.Lock()
	l.initLocked()
	if l.closing {
		done := l.done
		l.mu.Unlock()
		<-done
		return l.result
	}
	l.closing = true
	l.cancel()
	l.mu.Unlock()
	s.cancelDVBOperations()
	if s.epgStop != nil {
		close(s.epgStop)
	}
	l.mu.Lock()
	for l.active != 0 {
		l.cond.Wait()
	}
	l.mu.Unlock()
	var errs []error
	s.mu.Lock()
	errs = append(errs, s.flushAPITokensLocked())
	s.mu.Unlock()
	if s.scheduler != nil {
		errs = append(errs, s.scheduler.Close())
	}
	s.mu.Lock()
	idle := make([]sinkRegistrationToken, 0)
	for _, owner := range s.structured.owners {
		if owner.idle != nil {
			idle = append(idle, *owner.idle)
		}
	}
	s.structured.owners = make(map[string]structuredRuntime)
	s.mu.Unlock()
	if s.runtimeSink != nil {
		for _, token := range idle {
			errs = append(errs, s.runtimeSink.RemoveStream(token))
		}
	}
	s.mu.Lock()
	workers := make([]*adapterMonitorWorker, 0, len(s.adapterWork))
	for _, w := range s.adapterWork {
		workers = append(workers, w)
	}
	s.mu.Unlock()
	for _, w := range workers {
		if w.cancel != nil {
			w.cancel()
		}
	}
	for _, w := range workers {
		if w.done != nil {
			<-w.done
		}
	}
	s.legacyWorkers.Wait()
	if s.engine != nil {
		errs = append(errs, s.engine.ShutdownWithError())
	}
	if s.softcam != nil {
		errs = append(errs, s.softcam.ShutdownWithError())
	}
	if s.epgDone != nil {
		<-s.epgDone
	}
	if s.updaterDone != nil {
		<-s.updaterDone
	}
	if s.runtimeDeps != nil {
		errs = append(errs, s.runtimeDeps.Shutdown(context.Background()))
	} else if s.streamer != nil {
		errs = append(errs, s.streamer.Shutdown(context.Background()))
	}
	s.mu.Lock()
	subs := make([]chan model.StateSnapshot, 0, len(s.subscribers))
	for _, ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.subscribers = make(map[int]chan model.StateSnapshot)
	s.adapterWork = make(map[string]*adapterMonitorWorker)
	s.mu.Unlock()
	for _, ch := range subs {
		close(ch)
	}
	s.closeEvents()
	l.mu.Lock()
	errs = append(errs, l.cleanupErrors...)
	l.result = errors.Join(errs...)
	close(l.done)
	l.mu.Unlock()
	return l.result
}
func (s *Store) Close() {
	if err := s.CloseWithError(); err != nil {
		log.Printf("store terminal shutdown: %v", err)
	}
}

func (s *Store) recordRuntimeCleanup(err error) {
	if err != nil {
		s.runtimeLifecycle.mu.Lock()
		s.runtimeLifecycle.cleanupErrors = append(s.runtimeLifecycle.cleanupErrors, err)
		s.runtimeLifecycle.mu.Unlock()
	}
}

func (s *Store) cardRefreshContext(ctx context.Context) (context.Context, context.CancelFunc) {
	l := &s.runtimeLifecycle
	l.mu.Lock()
	l.initLocked()
	stop := l.context
	l.mu.Unlock()
	work, cancel := context.WithCancel(ctx)
	detach := context.AfterFunc(stop, cancel)
	return work, func() { detach(); cancel() }
}

func (s *Store) softcamTestContext(ctx context.Context) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	l := &s.runtimeLifecycle
	l.mu.Lock()
	l.initLocked()
	terminal := l.context
	l.mu.Unlock()
	work, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(terminal, func() { defer close(joined); cancel() })
	return work, func() {
		if !stop() {
			<-joined
		}
		cancel()
	}
}
