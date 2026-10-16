// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"astrax/internal/cert"
	"astrax/internal/model"
	"astrax/internal/store"
)

type externalHandlerValue struct{ handler http.Handler }
type externalHandlerSlot struct {
	current atomic.Pointer[externalHandlerValue]
}

func (h *externalHandlerSlot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.current.Load().handler.ServeHTTP(w, r)
}
func (h *externalHandlerSlot) set(handler http.Handler) {
	h.current.Store(&externalHandlerValue{handler: handler})
}

type externalListener struct {
	listener  net.Listener
	server    *http.Server
	handler   *externalHandlerSlot
	settings  model.ExternalAPISettings
	tlsConfig *tls.Config
	retiring  atomic.Bool
}

// ExternalAPIManager serializes changes independently of request handling.
// Status reads never wait for graceful drains or network binds.
type ExternalAPIManager struct {
	operations      chan struct{}
	mu              sync.RWMutex
	factory         func(model.ExternalAPISettings) http.Handler
	listen          func(context.Context, string, string) (net.Listener, error)
	persistSettings func(model.ExternalAPISettings) error
	certMgr         *cert.Manager
	store           *store.Store
	reserved        []string
	active          *externalListener
	pending         *externalListener
	status          model.ExternalAPIStatus
	closed          atomic.Bool
	lifetime        context.Context
	cancel          context.CancelFunc
}

// reserved contains actual management addresses, including command-line overrides.
func NewExternalAPIManager(factory func(model.ExternalAPISettings) http.Handler, certMgr *cert.Manager, st *store.Store, reserved ...string) *ExternalAPIManager {
	lifetime, cancel := context.WithCancel(context.Background())
	return &ExternalAPIManager{operations: make(chan struct{}, 1), lifetime: lifetime, cancel: cancel, factory: factory, listen: (&net.ListenConfig{}).Listen, persistSettings: st.SetExternalAPISettings, certMgr: certMgr, store: st, reserved: append([]string(nil), reserved...), status: externalStatus(st.ExternalAPISettings(), false)}
}

func externalStatus(cfg model.ExternalAPISettings, running bool) model.ExternalAPIStatus {
	status := model.ExternalAPIStatus{Enabled: cfg.Enabled, Running: running, ListenAddress: cfg.ListenAddress, Port: cfg.Port, TLS: cfg.TLS}
	if running {
		scheme := "http"
		if cfg.TLS {
			scheme = "https"
		}
		status.BaseURL = scheme + "://" + net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port))
	}
	return status
}

func (m *ExternalAPIManager) Status() model.ExternalAPIStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *ExternalAPIManager) StartConfigured(ctx context.Context) error {
	ctx, release, err := m.begin(ctx)
	if err != nil {
		return m.failure(err)
	}
	defer release()
	cfg := m.store.ExternalAPISettings()
	m.mu.Lock()
	if m.active == nil && !m.closed.Load() {
		m.status = externalStatus(cfg, false)
	}
	m.mu.Unlock()
	return m.apply(ctx, cfg, false)
}

func (m *ExternalAPIManager) Apply(ctx context.Context, in model.ExternalAPISettings) error {
	ctx, release, err := m.begin(ctx)
	if err != nil {
		return m.failure(err)
	}
	defer release()
	return m.apply(ctx, in, true)
}

// Operation admission, DNS resolution and binding have a deadline and can be
// interrupted by terminal Close. Disk persistence retains the store's semantics.
func (m *ExternalAPIManager) begin(parent context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	stop := context.AfterFunc(m.lifetime, cancel)
	cleanup := func() { stop(); cancel() }
	select {
	case m.operations <- struct{}{}:
		if m.closed.Load() || ctx.Err() != nil {
			<-m.operations
			cleanup()
			return nil, nil, context.Canceled
		}
		return ctx, func() { cleanup(); <-m.operations }, nil
	case <-ctx.Done():
		cleanup()
		return nil, nil, ctx.Err()
	}
}

func (m *ExternalAPIManager) failure(err error) error {
	m.mu.Lock()
	m.status.LastError = err.Error()
	m.mu.Unlock()
	m.store.AddLog("error", "external API listener transition failed")
	return err
}

func (m *ExternalAPIManager) apply(ctx context.Context, in model.ExternalAPISettings, persist bool) error {
	if m.closed.Load() {
		return errors.New("external API manager is closed")
	}
	defer func() {
		m.mu.Lock()
		pending := m.pending
		m.pending = nil
		m.mu.Unlock()
		if pending != nil {
			_ = pending.listener.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return m.failure(err)
	}
	cfg, err := in.Normalized()
	if err != nil {
		return m.failure(err)
	}
	if err = m.store.ValidateExternalAPISettings(cfg); err != nil {
		return m.failure(err)
	}
	if cfg.Enabled {
		for _, address := range m.reserved {
			_, port, e := net.SplitHostPort(address)
			number, lookupErr := net.LookupPort("tcp", port)
			if e == nil && lookupErr == nil && number == cfg.Port {
				return m.failure(errors.New("external API port conflicts with an active management address"))
			}
		}
	}
	var tlsConfig *tls.Config
	if cfg.Enabled && cfg.TLS {
		if m.certMgr == nil {
			return m.failure(errors.New("external API TLS requires a certificate"))
		}
		tlsConfig, err = m.certMgr.TLSConfigWithVersion(m.store.Settings().TLSMinVersion)
		if err != nil {
			return m.failure(err)
		}
		if tlsConfig == nil {
			return m.failure(errors.New("external API TLS requires a certificate"))
		}
	}
	save := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if persist {
			return m.persistSettings(cfg)
		}
		return m.store.ValidateExternalAPISettings(cfg)
	}
	m.mu.RLock()
	old := m.active
	m.mu.RUnlock()
	if !cfg.Enabled {
		if err := save(); err != nil {
			return m.failure(err)
		}
		if err := m.install(nil, cfg); err != nil {
			return m.failure(err)
		}
		stopExternal(ctx, old)
		return nil
	}
	sameAddress := old != nil && cfg.ListenAddress == old.settings.ListenAddress && cfg.Port == old.settings.Port
	if sameAddress && !cfg.TLS && !old.settings.TLS {
		handler := m.factory(cfg)
		m.mu.RLock()
		stillActive := m.active == old
		m.mu.RUnlock()
		if !stillActive {
			return m.failure(errors.New("external API listener stopped during apply"))
		}
		if err := save(); err != nil {
			return m.failure(err)
		}
		m.mu.Lock()
		if m.active != old || m.closed.Load() {
			m.mu.Unlock()
			return m.failure(errors.New("external API listener stopped during apply"))
		}
		old.handler.set(handler)
		old.settings = cfg
		m.status = externalStatus(cfg, true)
		m.mu.Unlock()
		return nil
	}
	// Same-address protocol/certificate changes cannot prebind. Keep the old
	// immutable handler and certificate for rollback, and bound the interruption.
	if sameAddress {
		old.retiring.Store(true)
		_ = old.listener.Close()
	}
	candidate, err := m.bind(ctx, cfg, tlsConfig, m.factory(cfg))
	if err == nil {
		err = save()
	}
	if err != nil {
		if candidate != nil {
			_ = candidate.listener.Close()
		}
		if sameAddress && !m.closed.Load() {
			rollbackCtx, cancel := context.WithTimeout(m.lifetime, 3*time.Second)
			restored, restoreErr := m.bind(rollbackCtx, old.settings, old.tlsConfig, old.handler.current.Load().handler)
			cancel()
			if restoreErr == nil {
				restoreErr = m.install(restored, old.settings)
				if restoreErr == nil {
					m.serve(restored)
				}
			} else {
				_ = m.install(nil, old.settings)
			}
			if restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore previous external listener: %w", restoreErr))
			}
			stopExternal(ctx, old)
		}
		return m.failure(err)
	}
	if err := m.install(candidate, cfg); err != nil {
		return m.failure(err)
	}
	m.serve(candidate)
	stopExternal(ctx, old)
	return nil
}

func (m *ExternalAPIManager) bind(ctx context.Context, cfg model.ExternalAPISettings, tlsConfig *tls.Config, handler http.Handler) (*externalListener, error) {
	address := net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port))
	listener, err := m.listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("bind external API: %w", err)
	}
	slot := &externalHandlerSlot{}
	slot.set(handler)
	server := &http.Server{Handler: slot, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	candidate := &externalListener{listener: listener, server: server, handler: slot, settings: cfg, tlsConfig: tlsConfig}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() || ctx.Err() != nil {
		_ = listener.Close()
		return nil, context.Canceled
	}
	m.pending = candidate
	return candidate, nil
}

func (m *ExternalAPIManager) install(active *externalListener, cfg model.ExternalAPISettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return errors.New("external API manager is closed")
	}
	if m.active != nil {
		m.active.retiring.Store(true)
	}
	m.active = active
	if m.pending == active {
		m.pending = nil
	}
	m.status = externalStatus(cfg, active != nil)
	return nil
}

func (m *ExternalAPIManager) serve(active *externalListener) {
	go func() {
		err := active.server.Serve(active.listener)
		if active.retiring.Load() {
			return
		}
		m.mu.Lock()
		if m.active == active {
			m.active = nil
			m.status.Running = false
			m.status.BaseURL = ""
			m.status.LastError = "external API listener stopped unexpectedly"
		}
		m.mu.Unlock()
		_ = active.server.Close()
		if err != nil {
			m.store.AddLog("error", "external API listener stopped unexpectedly")
		}
	}()
}

func stopExternal(ctx context.Context, active *externalListener) error {
	if active == nil {
		return nil
	}
	active.retiring.Store(true)
	drain, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := active.server.Shutdown(drain)
	// Shutdown before Serve begins must also close the prebound socket.
	_ = active.listener.Close()
	if err != nil {
		_ = active.server.Close()
	}
	return err
}

// Close is terminal; saved enablement is retained for the next process start.
func (m *ExternalAPIManager) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	m.closed.Store(true)
	m.cancel()
	m.mu.Lock()
	old := m.active
	pending := m.pending
	m.pending = nil
	if old != nil {
		old.retiring.Store(true)
	}
	m.active = nil
	m.status.Running = false
	m.status.BaseURL = ""
	m.mu.Unlock()
	if pending != nil {
		_ = pending.listener.Close()
	}
	err := stopExternal(ctx, old)
	// Join any admitted transition without waiting beyond the shutdown deadline.
	select {
	case m.operations <- struct{}{}:
		<-m.operations
		return err
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	}
}
