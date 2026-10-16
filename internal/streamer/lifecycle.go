// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"astrax/internal/packetbudget"
)

type httpServer interface {
	Serve(net.Listener) error
	ServeTLS(net.Listener, string, string) error
	Shutdown(context.Context) error
	Close() error
}

type udpOutput interface {
	Write([]byte) (int, error)
	Close() error
}

type srtOutput interface {
	Start()
	Write([]byte)
	Close() error
	Done() <-chan struct{}
}

// Optional Stage C capability seams; ordinary transport interfaces stay intact.
type stageCUDPOutput interface {
	udpOutput
	SetWriteDeadline(time.Time) error
}
type stageCSRTOutput interface {
	srtOutput
	SetWriteDeadline(time.Time) error
	WritePacket([]byte) error
}

type timerHandle interface {
	Stop() bool
}

type dependencies struct {
	now           func() time.Time
	listenTCP     func(string, string) (net.Listener, error)
	newHTTPServer func(http.Handler, *tls.Config) (httpServer, error)
	setupUDP      func(string) (udpOutput, error)
	setupSRT      func(string, *packetbudget.Budget) (srtOutput, error)
	afterFunc     func(time.Duration, func()) timerHandle
}

func (deps dependencies) withDefaults() dependencies {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.listenTCP == nil {
		deps.listenTCP = net.Listen
	}
	if deps.newHTTPServer == nil {
		deps.newHTTPServer = func(handler http.Handler, tlsConfig *tls.Config) (httpServer, error) {
			return &http.Server{
				Handler:      handler,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 0,
				TLSConfig:    tlsConfig,
			}, nil
		}
	}
	if deps.setupUDP == nil {
		deps.setupUDP = setupUDPOutput
	}
	if deps.setupSRT == nil {
		deps.setupSRT = func(outputURL string, budget *packetbudget.Budget) (srtOutput, error) {
			listener, err := setupSRTListener(outputURL, budget)
			if listener == nil {
				return nil, err
			}
			return listener, err
		}
	}
	if deps.afterFunc == nil {
		deps.afterFunc = func(delay time.Duration, callback func()) timerHandle {
			return time.AfterFunc(delay, callback)
		}
	}
	return deps
}

type streamOperationGate struct {
	mu   sync.Mutex
	refs int
}

func (st *Streamer) beginOperation() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closing || st.closed {
		return ErrStreamerClosed
	}
	if st.activeOps == 0 {
		st.activeDone = make(chan struct{})
	}
	st.activeOps++
	return nil
}

func (st *Streamer) endOperation() {
	st.mu.Lock()
	st.endOperationLocked()
	st.mu.Unlock()
}

func (st *Streamer) endOperationLocked() {
	st.activeOps--
	if st.activeOps < 0 {
		panic("streamer active operation count became negative")
	}
	if st.activeOps == 0 {
		close(st.activeDone)
	}
}

func (st *Streamer) beginStreamOperation(id string) (func(), error) {
	if err := st.beginOperation(); err != nil {
		return nil, err
	}

	st.mu.Lock()
	gate := st.streamGates[id]
	if gate == nil {
		gate = &streamOperationGate{}
		st.streamGates[id] = gate
	}
	gate.refs++
	st.mu.Unlock()

	gate.mu.Lock()
	st.mu.Lock()
	closed := st.closing || st.closed
	st.mu.Unlock()
	if closed {
		gate.mu.Unlock()
		st.releaseStreamGate(id, gate)
		st.endOperation()
		return nil, ErrStreamerClosed
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			gate.mu.Unlock()
			st.releaseStreamGate(id, gate)
			st.endOperation()
		})
	}, nil
}

func (st *Streamer) releaseStreamGate(id string, gate *streamOperationGate) {
	st.mu.Lock()
	gate.refs--
	if gate.refs == 0 && st.streamGates[id] == gate {
		delete(st.streamGates, id)
	}
	st.mu.Unlock()
}

func (st *Streamer) Start() error {
	if err := st.beginOperation(); err != nil {
		return err
	}
	defer st.endOperation()

	st.mu.Lock()
	if st.startCalled {
		st.mu.Unlock()
		return ErrStreamerAlreadyStarted
	}
	st.startCalled = true
	st.startPending = true
	tlsConfig := st.tlsConfig
	st.mu.Unlock()

	port := st.settings.HTTPPlayPort
	if port <= 0 {
		port = 8000
	}
	var listener net.Listener
	var lastErr error
	for offset := 0; offset < 10; offset++ {
		tryPort := port + offset
		candidate, listenErr := st.deps.listenTCP("tcp", fmt.Sprintf(":%d", tryPort))
		if listenErr == nil && candidate != nil {
			listener = candidate
			break
		}
		if listenErr == nil {
			listenErr = errors.New("listener factory returned nil")
		}
		lastErr = listenErr
		if candidate != nil {
			if closeErr := candidate.Close(); closeErr != nil && !isTerminalCloseError(closeErr) {
				st.mu.Lock()
				st.startPending = false
				st.mu.Unlock()
				return errors.Join(
					fmt.Errorf("listen on port %d: %w", tryPort, listenErr),
					wrapError("close partial listener", closeErr),
				)
			}
		}
		st.mu.Lock()
		closed := st.closing || st.closed || !st.startPending
		st.mu.Unlock()
		if closed {
			return ErrStreamerClosed
		}
	}
	if listener == nil {
		st.mu.Lock()
		st.startPending = false
		st.mu.Unlock()
		return fmt.Errorf("streamer could not bind to any port in range %d-%d: %w", port, port+9, lastErr)
	}

	st.mu.Lock()
	publishable := !st.closing && st.startPending
	st.mu.Unlock()
	if !publishable {
		return errors.Join(ErrStreamerClosed, wrapError("close unpublished listener", listener.Close()))
	}

	server, err := st.deps.newHTTPServer(st, tlsConfig)
	if err != nil || server == nil {
		st.mu.Lock()
		st.startPending = false
		st.mu.Unlock()
		if err == nil {
			err = errors.New("HTTP server factory returned nil")
		}
		var serverCloseErr error
		if server != nil {
			serverCloseErr = wrapError("close unpublished HTTP server", server.Close())
		}
		return errors.Join(
			wrapError("create HTTP server", err),
			serverCloseErr,
			wrapError("close unpublished listener", listener.Close()),
		)
	}

	st.mu.Lock()
	if st.closing || !st.startPending {
		st.mu.Unlock()
		return errors.Join(
			ErrStreamerClosed,
			wrapError("close unpublished HTTP server", server.Close()),
			wrapError("close unpublished listener", listener.Close()),
		)
	}
	serveDone := make(chan struct{})
	st.server = server
	st.listener = listener
	st.serveDone = serveDone
	st.startPending = false
	st.mu.Unlock()

	go st.serve(server, listener, tlsConfig != nil, serveDone)
	return nil
}

func (st *Streamer) serve(server httpServer, listener net.Listener, tlsEnabled bool, done chan struct{}) {
	var err error
	if tlsEnabled {
		err = server.ServeTLS(listener, "", "")
	} else {
		err = server.Serve(listener)
	}
	st.mu.Lock()
	st.serveErr = err
	st.mu.Unlock()
	close(done)
}

func (st *Streamer) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	st.mu.Lock()
	if st.shutdownStarted {
		done := st.shutdownDone
		st.mu.Unlock()
		<-done
		st.mu.Lock()
		err := st.shutdownErr
		st.mu.Unlock()
		return err
	}
	st.shutdownStarted = true
	st.closing = true
	close(st.stageCStop)
	st.startPending = false
	for _, reservation := range st.reservations {
		reservation.valid = false
	}
	st.pathReservations = make(map[string]*registrationReservation)
	st.reservedPaths = pathNamespace{}
	server := st.server
	listener := st.listener
	serveDone := st.serveDone
	activeDone := st.activeDone
	var stageCRequests []*stageCHTTPRequest
	for _, state := range st.streams {
		state.mu.RLock()
		for request := range state.stageCRequests {
			stageCRequests = append(stageCRequests, request)
		}
		state.mu.RUnlock()
	}
	st.mu.Unlock()
	for _, request := range stageCRequests {
		request.cancel()
	}

	var shutdownErrors []error
	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			shutdownErrors = append(shutdownErrors, wrapError("graceful HTTP shutdown", err))
			if closeErr := server.Close(); closeErr != nil && !isTerminalCloseError(closeErr) {
				shutdownErrors = append(shutdownErrors, wrapError("force-close HTTP server", closeErr))
			}
			if listener != nil {
				if closeErr := listener.Close(); closeErr != nil && !isTerminalCloseError(closeErr) {
					shutdownErrors = append(shutdownErrors, wrapError("force-close HTTP listener", closeErr))
				}
			}
		}
	}
	if serveDone != nil {
		<-serveDone
	}
	<-activeDone

	st.mu.Lock()
	ids := make([]string, 0, len(st.streams))
	for id := range st.streams {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	resources := make([]detachedResources, 0, len(ids))
	for _, id := range ids {
		state := st.streams[id]
		resources = append(resources, st.detachStateLocked(state, true))
		delete(st.streams, id)
	}
	st.customPaths = make(map[string]pathPublication)
	st.publishedPaths = pathNamespace{}
	st.reservations = make(map[string]*registrationReservation)
	st.pathReservations = make(map[string]*registrationReservation)
	st.reservedPaths = pathNamespace{}
	st.tombstones = make(map[string]uint64)
	st.configuredOutputs = nil
	serveErr := st.serveErr
	st.mu.Unlock()

	for _, resource := range resources {
		if err := cleanupDetached(resource); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !isTerminalCloseError(serveErr) {
		shutdownErrors = append(shutdownErrors, wrapError("HTTP Serve", serveErr))
	}

	terminalErr := errors.Join(shutdownErrors...)
	st.mu.Lock()
	st.closed = true
	st.shutdownErr = terminalErr
	close(st.shutdownDone)
	st.mu.Unlock()
	return terminalErr
}

func isTerminalCloseError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)
}
