// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"astrax/internal/model"
)

var (
	ErrStreamerClosed         = errors.New("streamer is shutting down")
	ErrStreamerAlreadyStarted = errors.New("streamer Start is single-shot")
	ErrStreamExists           = errors.New("stream registration already exists")
	ErrStreamNotFound         = errors.New("stream registration not found")
	ErrStreamTokenMismatch    = errors.New("stream registration token mismatch")
	ErrStreamPathConflict     = errors.New("stream output path conflicts with another registration")
	ErrStreamReserved         = errors.New("stream registration is reserved")
	ErrInvalidRegistration    = errors.New("invalid stream registration")
	ErrRegistrationSuperseded = errors.New("stream registration was superseded")
	ErrGenerationExhausted    = errors.New("stream registration generation exhausted")
)

type RegistrationToken struct {
	StreamID   string
	Generation uint64
}

type DetachMode uint8

const (
	DetachRemove DetachMode = iota
	DetachPreservePlaceholder
)

type streamState uint8

const (
	streamStatePlaceholder streamState = iota + 1
	streamStateActive
)

type pathPublication struct {
	streamID   string
	generation uint64
}

type Streamer struct {
	mu sync.Mutex

	streams           map[string]*activeStream
	customPaths       map[string]pathPublication
	publishedPaths    pathNamespace
	reservedPaths     pathNamespace
	configuredOutputs map[string]string
	reservations      map[string]*registrationReservation
	pathReservations  map[string]*registrationReservation
	tombstones        map[string]uint64
	streamGates       map[string]*streamOperationGate
	nextGeneration    uint64
	routeLookupProbes *atomic.Uint64

	mux             *http.ServeMux
	settings        model.Settings
	tlsConfig       *tls.Config
	deps            dependencies
	stageCResources *StageCResources
	stageCStop      chan struct{}
	nextClient      atomic.Uint64

	onDemandStart func(RegistrationToken)
	onDemandStop  func(RegistrationToken)

	closing         bool
	closed          bool
	activeOps       int
	activeDone      chan struct{}
	startCalled     bool
	startPending    bool
	server          httpServer
	listener        net.Listener
	serveDone       chan struct{}
	serveErr        error
	shutdownStarted bool
	shutdownDone    chan struct{}
	shutdownErr     error
}

type activeStream struct {
	id         string
	generation uint64
	state      streamState
	terminal   bool // retains the exact cleanup token, but admits no new viewers
	path       string

	mu                  sync.RWMutex
	cfg                 model.Stream
	run                 *streamRun
	outputs             *preparedOutputs
	clients             map[string]*tsClient
	segments            *hlsBuffer
	packets             uint64
	clientCount         int
	ordinaryHTTPClients int
	activationTimer     timerHandle
	stopTimer           timerHandle
	stageCRequests      map[*stageCHTTPRequest]struct{}
}

type streamRun struct {
	generation    uint64
	ctx           context.Context
	cancel        context.CancelFunc
	src           model.PacketSource
	outputs       *preparedOutputs
	done          chan struct{}
	closeOnce     sync.Once
	closeErr      error
	retirementErr error // published by closing done
	guarded       bool
}

func (run *streamRun) closeSource() error {
	run.closeOnce.Do(func() { run.closeErr = run.src.Close() })
	return run.closeErr
}

type tsClient struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	closed  bool
	writer  *packetWriter
}

func New(settings model.Settings) *Streamer {
	initSRT()
	return newWithDependencies(settings, dependencies{})
}

func newWithDependencies(settings model.Settings, deps dependencies) *Streamer {
	deps = deps.withDefaults()
	activeDone := make(chan struct{})
	close(activeDone)
	st := &Streamer{
		streams:          make(map[string]*activeStream),
		customPaths:      make(map[string]pathPublication),
		reservations:     make(map[string]*registrationReservation),
		pathReservations: make(map[string]*registrationReservation),
		tombstones:       make(map[string]uint64),
		streamGates:      make(map[string]*streamOperationGate),
		settings:         settings,
		deps:             deps,
		mux:              http.NewServeMux(),
		activeDone:       activeDone,
		shutdownDone:     make(chan struct{}),
		stageCStop:       make(chan struct{}),
	}
	st.mux.HandleFunc("/stream/", st.handleStream)
	st.mux.HandleFunc("/hls/", st.handleHLS)
	st.mux.HandleFunc("/", st.handleCustomPath)
	return st
}

func (st *Streamer) SetOnDemandCallbacks(start, stop func(RegistrationToken)) {
	st.mu.Lock()
	st.onDemandStart = start
	st.onDemandStop = stop
	st.mu.Unlock()
}

func (st *Streamer) SetTLSConfig(cfg *tls.Config) {
	st.mu.Lock()
	st.tlsConfig = cfg
	st.mu.Unlock()
}

// ServeHTTP is a listener-free entry point that shares the production handler admission path.
func (st *Streamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := st.beginOperation(); err != nil {
		http.Error(w, "streamer unavailable", http.StatusServiceUnavailable)
		return
	}
	defer st.endOperation()
	st.mux.ServeHTTP(w, r)
}

func (st *Streamer) RegisterChecked(stream model.Stream, src model.PacketSource, expected *RegistrationToken) (RegistrationToken, error) {
	release, err := st.beginStreamOperation(stream.ID)
	if err != nil {
		return RegistrationToken{}, err
	}
	defer release()
	return st.register(stream, src, expected, registrationChecked)
}

func (st *Streamer) UnregisterChecked(token RegistrationToken, mode DetachMode) (*RegistrationToken, error) {
	release, err := st.beginStreamOperation(token.StreamID)
	if err != nil {
		return nil, err
	}
	defer release()
	return st.unregisterChecked(token, mode, false)
}

// DemoteOnDemandChecked revalidates idle state atomically with the transition.
func (st *Streamer) DemoteOnDemandChecked(token RegistrationToken) (*RegistrationToken, error) {
	release, err := st.beginStreamOperation(token.StreamID)
	if err != nil {
		return nil, err
	}
	defer release()
	return st.unregisterChecked(token, DetachPreservePlaceholder, true)
}

func (st *Streamer) IsCurrentRegistration(token RegistrationToken) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, err := st.publishedStateLocked(token, 0)
	return err == nil
}

// OnDemandCallbackCurrent is a read-only handoff check; mutations must still use
// the exact token, since no Streamer lock is held across the caller's action.
func (st *Streamer) OnDemandCallbackCurrent(token RegistrationToken, start bool) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	state, err := st.publishedStateLocked(token, 0)
	if err != nil {
		return false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.cfg.OnDemand && (start && state.state == streamStatePlaceholder && state.clientCount > 0 ||
		!start && state.state == streamStateActive && state.clientCount == 0)
}

func (st *Streamer) RemoveChecked(token RegistrationToken) error {
	release, err := st.beginStreamOperation(token.StreamID)
	if err != nil {
		return err
	}
	defer release()
	return st.removeChecked(token)
}

func (st *Streamer) ReplacePlaceholderChecked(token RegistrationToken, stream model.Stream) (RegistrationToken, error) {
	release, err := st.beginStreamOperation(token.StreamID)
	if err != nil {
		return RegistrationToken{}, err
	}
	defer release()
	return st.replacePlaceholderChecked(token, stream)
}

// RegisterStream preserves the legacy void API while using the transactional lifecycle.
func (st *Streamer) RegisterStream(stream model.Stream, src model.PacketSource) {
	if _, err := st.RegisterStreamWithToken(stream, src); err != nil {
		log.Printf("streamer: legacy registration for %s failed: %v", stream.ID, err)
	}
}

// RegisterStreamWithToken preserves legacy replacement/source-consumption rules
// while giving owners an exact token for subsequent cleanup.
func (st *Streamer) RegisterStreamWithToken(stream model.Stream, src model.PacketSource) (RegistrationToken, error) {
	release, err := st.beginStreamOperation(stream.ID)
	if err != nil {
		if !packetSourceIsNil(src) {
			err = errors.Join(err, src.Close())
		}
		return RegistrationToken{}, err
	}
	defer release()
	return st.register(stream, src, nil, registrationLegacy)
}

// UnregisterStream preserves the legacy ID-only API for existing Engine/Store callers.
func (st *Streamer) UnregisterStream(id string) {
	if err := st.UnregisterStreamWithError(id); err != nil && !errors.Is(err, ErrStreamerClosed) {
		log.Printf("streamer: legacy unregister for %s failed: %v", id, err)
	}
}

// UnregisterStreamWithError retains legacy ID-only ownership and admission.
// Structured owners must continue to use their exact checked token instead.
func (st *Streamer) UnregisterStreamWithError(id string) error {
	release, err := st.beginStreamOperation(id)
	if err != nil {
		return err
	}
	defer release()
	err = st.removeLegacy(id)
	if errors.Is(err, ErrStreamNotFound) {
		return nil
	}
	return err
}

func (st *Streamer) StreamCount() int {
	st.mu.Lock()
	count := len(st.streams)
	st.mu.Unlock()
	return count
}

func (st *Streamer) StreamPackets(id string) uint64 {
	st.mu.Lock()
	state := st.streams[id]
	if state == nil {
		st.mu.Unlock()
		return 0
	}
	state.mu.RLock()
	packets := state.packets
	state.mu.RUnlock()
	st.mu.Unlock()
	return packets
}

// PacketReader wraps an io.Reader to satisfy model.PacketSource by reading fixed MPEG-TS packets.
type PacketReader struct {
	r io.Reader
}

func NewPacketReader(r io.Reader) *PacketReader {
	return &PacketReader{r: r}
}

func (p *PacketReader) ReadPacket() ([]byte, error) {
	buf := make([]byte, 188)
	_, err := io.ReadFull(p.r, buf)
	return buf, err
}

func (p *PacketReader) Close() error {
	if closer, ok := p.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
