// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/mpegts"
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrDVBSchedulerClosed     = errors.New("DVB scheduler closed")
	ErrDVBSchedulerCorrupt    = errors.New("DVB scheduler corrupt")
	ErrDVBSchedulerSuperseded = errors.New("DVB scheduler operation superseded")
	ErrDVBSchedulerOwnership  = errors.New("incompatible DVB ownership")
	ErrDVBSchedulerBackend    = errors.New("DVB backend failure")
	ErrDVBSchedulerSink       = errors.New("DVB sink failure")
)

type DVBSchedulerError struct {
	Kind  error
	Cause error
}

func (e *DVBSchedulerError) Error() string   { return fmt.Sprintf("%v: %v", e.Kind, e.Cause) }
func (e *DVBSchedulerError) Unwrap() []error { return []error{e.Kind, e.Cause} }
func schedulerError(kind error, message string) error {
	return &DVBSchedulerError{kind, errors.New(message)}
}
func schedulerWrap(kind, errorCause error) error {
	if errorCause == nil {
		return nil
	}
	return &DVBSchedulerError{kind, errorCause}
}
func (s *dvbScheduler) latchCorruptLocked(cause error) error {
	if s.health == nil {
		s.health = schedulerWrap(ErrDVBSchedulerCorrupt, cause)
	}
	return s.health
}

// Counters are optional diagnostics; every access is protected by scheduler.mu.
type dvbSchedulerCounters struct {
	FullAudits, SessionClones, IndexClones                uint64
	ExactBucketVisits, OffKeyBucketVisits, CardCandidates uint64
	AttachmentVisits, ReverseVisits, TargetedMutations    uint64
	Sorts, Comparisons                                    uint64
}
type dvbStreamGate struct {
	mu   sync.Mutex
	refs int
}
type dvbSchedulerLifecycle struct {
	mu              sync.Mutex
	cond            *sync.Cond
	closing, closed bool
	active          int
	gates           map[string]*dvbStreamGate
	stopping, done  chan struct{}
	result          error
}

func newSchedulerLifecycle() *dvbSchedulerLifecycle {
	l := &dvbSchedulerLifecycle{gates: make(map[string]*dvbStreamGate), stopping: make(chan struct{}), done: make(chan struct{})}
	l.cond = sync.NewCond(&l.mu)
	return l
}
func (s *dvbScheduler) admit() (func(), error) {
	l := s.lifecycle
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return nil, ErrDVBSchedulerClosed
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

// Callers are admitted before waiting. References cover both gate owners and waiters.
func (s *dvbScheduler) gate(id string) (func(), error) {
	l := s.lifecycle
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return nil, ErrDVBSchedulerClosed
	}
	g := l.gates[id]
	if g == nil {
		g = &dvbStreamGate{}
		l.gates[id] = g
	}
	g.refs++
	l.mu.Unlock()
	g.mu.Lock()
	release := func() {
		g.mu.Unlock()
		l.mu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(l.gates, id)
		}
		l.mu.Unlock()
	}
	if s.isClosing() {
		release()
		return nil, ErrDVBSchedulerClosed
	}
	return release, nil
}
func (s *dvbScheduler) isClosing() bool {
	l := s.lifecycle
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closing
}
func (s *dvbScheduler) begin(id string) (func(), error) {
	end, err := s.admit()
	if err != nil {
		return nil, err
	}
	unlock, err := s.gate(id)
	if err != nil {
		end()
		return nil, err
	}
	return func() { unlock(); end() }, nil
}

type dvbStreamReservation struct {
	recoveryLease  *dvbCardOperationLease
	recoveryEpoch  uint64
	admissionEpoch uint64
	session        *tuningSession
	generation     uint64
}

type streamAttachment struct {
	retiring     bool
	id           string
	generation   uint64
	session      *tuningSession
	stream       model.Stream
	pipeline     tuningKey
	policy       model.DVBAdapterPolicy
	subscription string
	sinkToken    sinkRegistrationToken
	source       model.PacketSource
	baseSource   *streamPacketSource
	outputSource model.PacketSource
}

// The resource state belongs only to its authoritative tuningSession pointer.
// Its handles have terminal Close semantics: success or error consumes the handle.
type dvbSessionRuntime struct {
	generation, cardRevision uint64
	inputGeneration          uint64
	catalog                  *mpegts.Catalog
	physical                 physicalFrontendKey
	frontend                 dvb.Session
	demux                    *sharedDemux
	attachments              map[string]*streamAttachment
	pending                  int
	ready, retiring, closing bool
	changed                  chan struct{}
	ctx                      context.Context
	cancel                   context.CancelFunc
	workMu                   sync.Mutex
	workCond                 *sync.Cond
	workStopped              bool
	workCalls                int
	workers                  sync.WaitGroup
	publicationMu            sync.Mutex
	publicationRefs          int
	transport                *model.DVBStreamConfig
}

func (s *dvbScheduler) initRuntimeState() {
	s.lifecycle = newSchedulerLifecycle()
	s.cardsByAddress = make(map[string][]string)
	s.sessionOrderByKey = make(map[tuningKey][]string)
	s.cardRevisions = make(map[string]uint64)
	s.cardFingerprints = make(map[string]tuningKey)
	s.streamReservations = make(map[string]dvbStreamReservation)
	s.sessionByPhysical = make(map[physicalFrontendKey]*tuningSession)
	s.physicalReservations = make(map[physicalFrontendKey]*tuningSession)
	s.ownedSessions = make(map[string]*tuningSession)
	s.attachments = make(map[string]*streamAttachment)
	s.subscriptions = make(map[string]*streamAttachment)
	s.sinkTokens = make(map[sinkRegistrationToken]*streamAttachment)
}
