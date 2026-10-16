// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"astrax/internal/model"
)

const (
	defaultConnectTimeoutSec = 6
	reconnectDelay           = 3 * time.Second
	keepAliveInterval        = 10 * time.Second
	keepAliveTimeout         = 4 * time.Second
)

type Event struct {
	SoftcamID  string
	Generation uint64
	Runtime    model.SoftcamRuntime
	Level      string
	Message    string
}

type RuntimeSession = session

type Manager struct {
	nativeNewcamdFactory bool
	nextECMSessionEpoch  uint64
	ecmQuota             *ecmQuota
	ecmClock             ecmClock
	closing              bool
	nextGeneration       uint64
	intents              map[string]*RuntimeCommand
	owned                map[string]map[*worker]struct{}
	contextOpener        func(context.Context, model.Softcam) (RuntimeSession, time.Duration, error)
	workerLifetimes      sync.WaitGroup
	dispatchDone         chan struct{}
	terminalErrors       []error
	shutdownErr          error
	opener               func(model.Softcam) (RuntimeSession, time.Duration, error)
	mu                   sync.RWMutex
	workers              map[string]*worker
	runtimes             map[string]model.SoftcamRuntime
	events               chan Event
	closed               chan struct{}
	once                 sync.Once
}

type worker struct {
	ecmOwner        *ecmOwner
	ecmBroker       *ecmBroker
	profile         model.Softcam
	generation      uint64
	native          bool
	newcamd         bool
	returnedSession bool
	done            chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	restartCount    int
}

func New(handler func(Event)) *Manager {
	m := NewWithContextSessionOpener(handler, openProfileSessionContext)
	m.nativeNewcamdFactory = true
	return m
}

// NewWithSessionOpener supplies the complete context-free session boundary.
func NewWithSessionOpener(handler func(Event), opener func(model.Softcam) (RuntimeSession, time.Duration, error)) *Manager {
	m := newManagerWithECMOptions(handler, nil, processECMQuota, realECMClock{})
	m.opener = opener
	return m
}

func (m *Manager) dispatch(handler func(Event)) {
	defer close(m.dispatchDone)
	for {
		select {
		case <-m.closed:
			return
		case ev := <-m.events:
			select {
			case <-m.closed:
				return
			default:
			}
			if handler != nil {
				handler(ev)
			}
		}
	}
}

func NewWithContextSessionOpener(handler func(Event), opener func(context.Context, model.Softcam) (RuntimeSession, time.Duration, error)) *Manager {
	return newManagerWithECMOptions(handler, opener, processECMQuota, realECMClock{})
}

func (m *Manager) Start(profile model.Softcam)   { m.applyCompatibility(profile, ActionStart) }
func (m *Manager) Restart(profile model.Softcam) { m.applyCompatibility(profile, ActionRestart) }
func (m *Manager) Stop(id string)                { m.applyCompatibility(model.Softcam{ID: id}, ActionStop) }
func (m *Manager) Remove(id string)              { m.applyCompatibility(model.Softcam{ID: id}, ActionRemove) }
func (m *Manager) applyCompatibility(profile model.Softcam, action RuntimeAction) {
	if command, err := m.Prepare(profile, action); err == nil {
		_ = command.Apply()
	}
}

func (m *Manager) Runtimes() map[string]model.SoftcamRuntime {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]model.SoftcamRuntime, len(m.runtimes))
	for k, v := range m.runtimes {
		if intent := m.intents[k]; intent != nil && m.intentNativeProjection(intent) && v.Authenticated == nil {
			v.Authenticated, v.DescramblingSupported, v.CardsObserved = cccamMetadata(SessionStatus{})
		}
		out[k] = v.Clone()
	}
	return out
}

func (m *Manager) Shutdown() {
	if err := m.ShutdownWithError(); err != nil {
		log.Printf("softcam terminal shutdown: %v", err)
	}
}

// ShutdownWithError is terminal and must not be called by this manager's event
// callback. Context-free opens/probes/cleanup remain owned until they return.
func (m *Manager) ShutdownWithError() error {
	m.once.Do(func() {
		m.mu.Lock()
		m.closing = true
		close(m.closed)
		workers := make([]*worker, 0)
		for _, group := range m.owned {
			for w := range group {
				m.revokeWorkerECMLocked(w)
				workers = append(workers, w)
			}
		}
		m.workers = make(map[string]*worker)
		m.intents = make(map[string]*RuntimeCommand)
		m.mu.Unlock()
		for _, w := range workers {
			w.cancel()
		}
		m.workerLifetimes.Wait()
		<-m.dispatchDone
		m.mu.Lock()
		m.shutdownErr = errors.Join(m.terminalErrors...)
		m.mu.Unlock()
	})
	return m.shutdownErr
}
func (m *Manager) closeSession(s RuntimeSession) {
	err := s.Close()
	if err != nil {
		m.mu.Lock()
		m.terminalErrors = append(m.terminalErrors, err)
		m.mu.Unlock()
	}
}

func (m *Manager) runWorker(w *worker) {
	defer m.finishWorker(w)
	restartCount := w.restartCount

	for {
		select {
		case <-w.ctx.Done():
			stopped := model.SoftcamRuntime{
				State:         "stopped",
				Since:         time.Now().UTC(),
				UptimeSeconds: 0,
				RestartCount:  restartCount,
				Connected:     false,
				LatencyMS:     0,
			}
			m.publishWorker(w, stopped, "warn", "softcam stopped: "+w.profile.Name)
			return
		default:
		}

		starting := model.SoftcamRuntime{
			State:         "starting",
			Since:         time.Now().UTC(),
			UptimeSeconds: 0,
			RestartCount:  restartCount,
			Connected:     false,
			LatencyMS:     0,
		}
		// Publication is also the current-generation admission fence for a new
		// open. A held replacement intent must not reopen an obsolete worker.
		if !m.publishWorker(w, starting, "", "") {
			return
		}

		var session RuntimeSession
		var latency time.Duration
		var err error
		if m.contextOpener != nil {
			session, latency, err = m.contextOpener(w.ctx, w.profile)
		} else if m.opener == nil {
			err = errors.New("softcam session opener unavailable")
		} else {
			session, latency, err = m.opener(w.profile)
		}
		m.classifyWorkerSession(w, session)
		if err == nil && session == nil {
			err = errors.New("softcam session opener returned nil session")
		}
		if err != nil {
			if session != nil {
				m.closeWorkerSession(w, session)
			}
			runtime := model.SoftcamRuntime{
				State:         "error",
				Since:         time.Now().UTC(),
				UptimeSeconds: 0,
				RestartCount:  restartCount,
				Connected:     false,
				LastError:     err.Error(),
				LatencyMS:     0,
			}
			if normalizeSoftcamType(w.profile.Type) == "cccam" || m.workerNewcamdProjection(w) {
				runtime.LastError, runtime.ErrorCode = m.safeWorkerError(w, err)
			}
			m.publishWorker(w, runtime, "error", "softcam connect failed: "+w.profile.Name+" ("+runtime.LastError+")")
			restartCount++
			if m.workerCurrent(w) && sleepContext(w.ctx, reconnectDelay) {
				continue
			}
			return
		}

		if w.ctx.Err() != nil {
			m.closeWorkerSession(w, session)
			return
		}

		err = m.attachECMSession(w, session)
		// Admission-only attachment may leave authentication alive, but it must
		// never let a superseded worker enter the running lifetime.
		if err == nil && !m.workerCurrent(w) {
			err = ecmStaleError
		}
		if err != nil {
			m.closeWorkerSession(w, session)
			message, code := m.safeWorkerError(w, err)
			notice := "CCcam runtime unavailable (" + message + ")"
			if m.workerNewcamdProjection(w) {
				notice = "Newcamd runtime unavailable (" + message + ")"
			}
			m.publishWorker(w, model.SoftcamRuntime{State: "error", Since: time.Now().UTC(), RestartCount: restartCount, LastError: message, ErrorCode: code}, "warn", notice)
			var ownership *ECMError
			if errors.As(err, &ownership) && ownership.Code == "ecm_stale" {
				return
			}
			restartCount++
			if m.workerCurrent(w) && sleepContext(w.ctx, reconnectDelay) {
				continue
			}
			return
		}

		startedAt := time.Now().UTC()
		running := model.SoftcamRuntime{
			State:         "running",
			Since:         startedAt,
			UptimeSeconds: 0,
			RestartCount:  restartCount,
			Connected:     true,
			LatencyMS:     latency.Milliseconds(),
		}
		if err := m.publishSessionWorker(w, session, running, "info", "softcam connected: "+w.profile.Name); err != nil {
			m.closeWorkerSession(w, session)
			restartCount++
			if m.workerCurrent(w) && sleepContext(w.ctx, reconnectDelay) {
				continue
			}
			return
		}

		uptimeTicker := time.NewTicker(1 * time.Second)
		probeTicker := time.NewTicker(keepAliveInterval)

		retry := false
		for !retry {
			select {
			case <-w.ctx.Done():
				uptimeTicker.Stop()
				probeTicker.Stop()
				m.closeWorkerSession(w, session)
				stopped := model.SoftcamRuntime{
					State:         "stopped",
					Since:         time.Now().UTC(),
					UptimeSeconds: 0,
					RestartCount:  restartCount,
					Connected:     false,
					LatencyMS:     0,
				}
				m.publishWorker(w, stopped, "warn", "softcam stopped: "+w.profile.Name)
				return
			case now := <-uptimeTicker.C:
				runtime := model.SoftcamRuntime{
					State:         "running",
					Since:         startedAt,
					UptimeSeconds: int64(now.Sub(startedAt).Seconds()),
					RestartCount:  restartCount,
					Connected:     true,
					LatencyMS:     running.LatencyMS,
				}
				if err := m.publishSessionWorker(w, session, runtime, "", ""); err != nil {
					m.closeWorkerSession(w, session)
					uptimeTicker.Stop()
					probeTicker.Stop()
					restartCount++
					retry = true
				}
			case <-probeTicker.C:
				probeLatency, err := session.KeepAlive(keepAliveTimeout)
				if err != nil {
					runtime := model.SoftcamRuntime{
						State:         "error",
						Since:         time.Now().UTC(),
						UptimeSeconds: 0,
						RestartCount:  restartCount,
						Connected:     false,
						LastError:     err.Error(),
						LatencyMS:     0,
					}
					if normalizeSoftcamType(w.profile.Type) == "cccam" || m.workerNewcamdProjection(w) {
						runtime.LastError, runtime.ErrorCode = m.safeWorkerError(w, err)
					}
					m.publishWorker(w, runtime, "warn", "softcam connection dropped: "+w.profile.Name+" ("+runtime.LastError+")")
					m.closeWorkerSession(w, session)
					uptimeTicker.Stop()
					probeTicker.Stop()
					restartCount++
					retry = true
					break
				}
				// Native CCcam keepalive completion measures only a write. Keep
				// its original connection latency instead of inventing a peer RTT.
				if _, nativeCCcam := session.(*cccamSession); !nativeCCcam {
					running.LatencyMS = probeLatency.Milliseconds()
				}
			}
		}

		if m.workerCurrent(w) && sleepContext(w.ctx, reconnectDelay) {
			continue
		}
		return
	}
}

// Runtime mutation and nonblocking event admission share the ownership check.
// Handler invocation remains on the dispatcher, never under m.mu. Already
// admitted events retain their generation for the downstream Task 5 fence.
func (m *Manager) publishWorker(w *worker, rt model.SoftcamRuntime, level, message string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.workers[w.profile.ID] != w {
		return false
	}
	intent := m.intents[w.profile.ID]
	if intent == nil || intent.generation != w.generation {
		return false
	}
	if normalizeSoftcamType(w.profile.Type) == "cccam" || m.workerNewcamdProjection(w) {
		if rt.Authenticated == nil {
			rt.Authenticated, rt.DescramblingSupported, rt.CardsObserved = cccamMetadata(SessionStatus{})
		}
		if rt.LastError != "" && rt.ErrorCode == "" {
			rt.LastError, rt.ErrorCode = m.safeWorkerError(w, errors.New(rt.LastError))
			message = "CCcam runtime unavailable"
			if m.workerNewcamdProjection(w) {
				message = "Newcamd runtime unavailable"
			}
		}
	}
	m.runtimes[w.profile.ID] = rt.Clone()
	m.emit(Event{SoftcamID: w.profile.ID, Generation: w.generation, Runtime: rt, Level: level, Message: message})
	return true
}

func (m *Manager) finishWorker(w *worker) {
	m.mu.Lock()
	group := m.owned[w.profile.ID]
	delete(group, w)
	if len(group) == 0 {
		delete(m.owned, w.profile.ID)
	}
	close(w.done)
	m.mu.Unlock()
	m.workerLifetimes.Done()
}

func (m *Manager) emit(ev Event) {
	if ev.SoftcamID != "" {
		if intent := m.intents[ev.SoftcamID]; intent != nil && m.intentNativeProjection(intent) && ev.Runtime.Authenticated == nil {
			ev.Runtime.Authenticated, ev.Runtime.DescramblingSupported, ev.Runtime.CardsObserved = cccamMetadata(SessionStatus{})
		}
	}
	ev.Runtime = ev.Runtime.Clone()
	select {
	case <-m.closed:
		return
	default:
	}

	select {
	case m.events <- ev:
	default:
	}
}

func validateProfile(profile model.Softcam) error {
	profile.Type = normalizeSoftcamType(profile.Type)
	if profile.Name == "" {
		return fmt.Errorf("name is required")
	}
	if profile.Type == "" {
		profile.Type = "newcamd"
	}
	if profile.Type != "newcamd" && profile.Type != "cccam" {
		return fmt.Errorf("unsupported softcam type: %s", profile.Type)
	}
	if profile.Host == "" {
		return fmt.Errorf("host is required")
	}
	if profile.Port <= 0 || profile.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if profile.Username == "" {
		return fmt.Errorf("username is required")
	}
	if profile.Password == "" {
		return fmt.Errorf("password is required")
	}
	if profile.Type == "newcamd" {
		if _, err := parseDESKey(profile.DESKey); err != nil {
			return err
		}
	}
	return nil
}

func sameConfig(a, b model.Softcam) bool {
	return a.Name == b.Name &&
		a.Type == b.Type &&
		a.Host == b.Host &&
		a.Port == b.Port &&
		a.Username == b.Username &&
		a.Password == b.Password &&
		a.DESKey == b.DESKey &&
		a.ConnectTimeoutSec == b.ConnectTimeoutSec &&
		a.Enabled == b.Enabled
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (m *Manager) publishSessionWorker(w *worker, s RuntimeSession, rt model.SoftcamRuntime, level, message string) error {
	var terminal error
	newcamd := normalizeSoftcamType(w.profile.Type) == "newcamd" && isNativeNewcamd(s)
	if normalizeSoftcamType(w.profile.Type) == "cccam" || newcamd {
		status := SessionStatus{}
		if provider, ok := s.(sessionStateProvider); ok {
			status, terminal = provider.sessionState()
		} else if provider, ok := s.(sessionStatusProvider); ok {
			status = provider.SessionStatus()
		}
		if terminal != nil || !status.Authenticated {
			failure := terminal
			if failure == nil {
				if newcamd {
					failure = newcamdError("session_closed", nil)
					terminal = failure
				} else {
					failure = protocolError("session_closed", nil)
					terminal = failure
				}
			}
			status = SessionStatus{}
			rt.State, rt.Connected, rt.UptimeSeconds, rt.LatencyMS = "error", false, 0, 0
			rt.LastError, rt.ErrorCode = m.safeWorkerError(w, failure)
			level, message = "warn", "CCcam runtime unavailable ("+rt.LastError+")"
			if newcamd {
				message = "Newcamd runtime unavailable (" + rt.LastError + ")"
			}
		}
		rt.Authenticated, rt.DescramblingSupported, rt.CardsObserved = cccamMetadata(status)
	}
	m.publishWorker(w, rt, level, message)
	return terminal
}

// Default-factory tags project failed opens, never grant successful native
// ownership. Opened sessions are classified from their actual private marker.
func (m *Manager) workerNewcamdProjection(w *worker) bool {
	return normalizeSoftcamType(w.profile.Type) == "newcamd" && (w.newcamd || (m.nativeNewcamdFactory && !w.returnedSession))
}

func (m *Manager) intentNativeProjection(intent *RuntimeCommand) bool {
	protocol := normalizeSoftcamType(intent.profile.Type)
	return protocol == "cccam" || (protocol == "newcamd" && m.nativeNewcamdFactory)
}

func (m *Manager) safeWorkerError(w *worker, err error) (string, string) {
	if m.workerNewcamdProjection(w) {
		return safeNewcamdError(err)
	}
	return safeCCcamError(err)
}
