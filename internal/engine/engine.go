// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/streamer"
)

type Event struct {
	StreamID   string
	Generation uint64
	Runtime    model.StreamRuntime
	Level      string
	Message    string
}

type Engine struct {
	mu              sync.RWMutex
	workers         map[string]*worker
	runtimes        map[string]model.StreamRuntime
	publish         map[string]*streamPublication
	events          chan Event
	closed          chan struct{}
	once            sync.Once
	closing         bool
	workerLifetimes sync.WaitGroup
	dispatchDone    chan struct{}
	shutdownErr     error
	terminalErrors  []error
	streamer        *streamer.Streamer
	nextGeneration  uint64

	testHookBeforeStreamRegistration func(string)
	testHookAfterStreamRegistration  func(string)
	testHookBeforeStreamQuiescence   func(string)
	testHookWorkerCanceled           func(string)
	testPacketSourceFactory          func(model.Stream) model.PacketSource
	testRelayInput                   func(context.Context, model.Stream, *io.PipeWriter) error
}

type worker struct {
	stream              model.Stream
	ctx                 context.Context
	cancel              context.CancelFunc
	restartCount        int
	prevPackets         uint64
	generation          uint64
	publication         *streamPublication
	done                chan struct{}
	expectedPlaceholder *streamer.RegistrationToken
	registration        streamer.RegistrationToken
	registrationSink    *streamer.Streamer
	sinkError           string
}

type streamPublication struct {
	mu    sync.Mutex
	owner *streamOwner
}

type streamOwner struct {
	worker *worker
	sink   *streamer.Streamer
	token  streamer.RegistrationToken
}

func New(handler func(Event)) *Engine {
	e := &Engine{
		workers:      make(map[string]*worker),
		runtimes:     make(map[string]model.StreamRuntime),
		publish:      make(map[string]*streamPublication),
		events:       make(chan Event, 256),
		closed:       make(chan struct{}),
		dispatchDone: make(chan struct{}),
	}

	go e.dispatch(handler)
	return e
}

func (e *Engine) SetStreamer(strmr *streamer.Streamer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.streamer = strmr
}

func (e *Engine) SetTestHookBeforeStreamRegistration(hook func(string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.testHookBeforeStreamRegistration = hook
}

func (e *Engine) SetTestHookAfterStreamRegistration(hook func(string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.testHookAfterStreamRegistration = hook
}

func (e *Engine) SetTestHookBeforeStreamQuiescence(hook func(string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.testHookBeforeStreamQuiescence = hook
}

func (e *Engine) SetTestHookWorkerCanceled(hook func(string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.testHookWorkerCanceled = hook
}

func (e *Engine) SetTestPacketSourceFactory(factory func(model.Stream) model.PacketSource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.testPacketSourceFactory = factory
}

func (e *Engine) CurrentGeneration(id string) uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.closing {
		if current := e.workers[id]; current != nil && current.ctx.Err() == nil && e.registrationCurrentLocked(current) {
			return current.generation
		}
	}
	return 0
}

func (e *Engine) IsCurrentGeneration(id string, generation uint64) bool {
	if generation == 0 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.closing {
		if current := e.workers[id]; current != nil && current.generation == generation && current.ctx.Err() == nil && e.registrationCurrentLocked(current) {
			return true
		}
	}
	return false
}

func (e *Engine) dispatch(handler func(Event)) {
	defer close(e.dispatchDone)
	for {
		select {
		case <-e.closed:
			return
		case ev := <-e.events:
			select {
			case <-e.closed:
				return
			default:
			}
			if handler != nil {
				handler(ev)
			}
		}
	}
}

func (e *Engine) Start(stream model.Stream) {
	e.start(stream, false, nil)
}

func (e *Engine) Restart(stream model.Stream) {
	e.start(stream, true, nil)
}

// StartOnDemand retains the triggering placeholder through asynchronous source
// creation/publication. Store calls it while holding its same-ID lifecycle gate.
func (e *Engine) StartOnDemand(stream model.Stream, expected streamer.RegistrationToken) {
	if !stream.OnDemand || !stream.Enabled || expected.StreamID != stream.ID || expected.Generation == 0 {
		return
	}
	e.start(stream, false, &expected)
}

func (e *Engine) start(stream model.Stream, force bool, expected *streamer.RegistrationToken) {
	if stream.ID == "" {
		return
	}
	if !stream.Enabled {
		e.Stop(stream.ID)
		return
	}

	validationErr := validateStream(stream)
	for {
		e.mu.Lock()
		if e.closing {
			e.mu.Unlock()
			return
		}
		publication := e.publish[stream.ID]
		if publication == nil {
			publication = &streamPublication{}
			e.publish[stream.ID] = publication
		}
		e.mu.Unlock()

		publication.mu.Lock()
		e.mu.Lock()
		if e.closing || e.publish[stream.ID] != publication {
			if e.publish[stream.ID] == publication && e.workers[stream.ID] == nil && publication.owner == nil {
				delete(e.publish, stream.ID)
			}
			closing := e.closing
			e.mu.Unlock()
			publication.mu.Unlock()
			if closing {
				return
			}
			continue
		}

		if expected != nil && (e.streamer == nil || !e.streamer.IsCurrentRegistration(*expected)) {
			if e.workers[stream.ID] == nil && publication.owner == nil {
				delete(e.publish, stream.ID)
			}
			e.mu.Unlock()
			publication.mu.Unlock()
			return
		}
		previous := e.workers[stream.ID]
		if previous != nil && !force && sameConfig(previous.stream, stream) &&
			(expected == nil || previous.registration == *expected) {
			e.mu.Unlock()
			publication.mu.Unlock()
			return
		}

		restartCount := 0
		if prevRuntime, ok := e.runtimes[stream.ID]; ok {
			restartCount = prevRuntime.RestartCount + 1
		}
		ctx, cancel := context.WithCancel(context.Background())
		e.nextGeneration++
		if e.nextGeneration == 0 {
			e.nextGeneration++
		}
		w := &worker{
			stream:       stream,
			ctx:          ctx,
			cancel:       cancel,
			restartCount: restartCount,
			generation:   e.nextGeneration,
			publication:  publication,
			done:         make(chan struct{}),
		}
		if expected != nil {
			token := *expected
			w.expectedPlaceholder = &token
			w.registration = token
			w.registrationSink = e.streamer
		}
		// Admission and Add precede exposure under the same mutex that closes admission.
		e.workerLifetimes.Add(1)
		e.workers[stream.ID] = w
		owner := publication.owner
		publication.owner = nil
		e.mu.Unlock()

		if previous != nil {
			previous.cancel()
		}
		if owner != nil && owner.sink != nil {
			e.reportSinkError(owner.worker, "retire replaced source", e.terminalCleanup(owner.sink.RemoveChecked(owner.token)), false)
		}

		if validationErr != nil {
			runtime := model.StreamRuntime{
				State:         "error",
				Since:         time.Now().UTC(),
				UptimeSeconds: 0,
				RestartCount:  restartCount,
				LastError:     validationErr.Error(),
				Packets:       0,
				BitrateKbps:   0,
			}
			e.publishWorkerRuntime(w, runtime, "error", "stream worker error: "+stream.Name+" ("+validationErr.Error()+")", true)
			e.finishWorker(w)
			publication.mu.Unlock()
			return
		}

		publication.mu.Unlock()
		go e.runWorker(w)
		return
	}
}

func (e *Engine) Stop(id string) {
	e.Quiesce(id)
}

// Quiesce retires Engine ownership for id and waits only for an in-progress
// concrete publication, not for the worker relay lifetime.
func (e *Engine) Quiesce(id string) {
	logSinkError(id, "quiesce source", e.QuiesceWithError(id))
}

// StopOnDemand demotes only the callback's active generation, under the same
// publication barrier used by Quiesce, before retiring Engine ownership.
func (e *Engine) StopOnDemand(expected streamer.RegistrationToken) (*streamer.RegistrationToken, error) {
	placeholder, err := e.quiesce(expected.StreamID, false, &expected)
	logSinkError(expected.StreamID, "demote on-demand source", err)
	return placeholder, err
}

func (e *Engine) quiesce(id string, removeRuntime bool, expected *streamer.RegistrationToken) (*streamer.RegistrationToken, error) {
	if id == "" {
		return nil, nil
	}

	e.mu.Lock()
	publication := e.publish[id]
	if expected != nil && publication == nil && !e.closing {
		publication = &streamPublication{}
		e.publish[id] = publication
	}
	hook := e.testHookBeforeStreamQuiescence
	e.mu.Unlock()
	if publication == nil {
		if removeRuntime {
			e.mu.Lock()
			delete(e.runtimes, id)
			e.mu.Unlock()
		}
		return nil, nil
	}
	if hook != nil {
		hook(id)
	}

	for publication != nil {
		publication.mu.Lock()
		e.mu.Lock()
		if e.publish[id] != publication {
			nextPublication := e.publish[id]
			e.mu.Unlock()
			publication.mu.Unlock()
			publication = nextPublication
			continue
		}
		var placeholder *streamer.RegistrationToken
		var resultErr error
		var demotedSink *streamer.Streamer
		if expected != nil {
			sink := e.streamer
			closing := e.closing
			e.mu.Unlock()
			switch {
			case closing:
				resultErr = streamer.ErrStreamerClosed
			case sink == nil:
				resultErr = errors.New("streamer is unavailable")
			default:
				placeholder, resultErr = sink.DemoteOnDemandChecked(*expected)
				demotedSink = sink
			}
			if placeholder == nil {
				e.mu.Lock()
				if e.publish[id] == publication && e.workers[id] == nil && publication.owner == nil {
					delete(e.publish, id)
				}
				e.mu.Unlock()
				publication.mu.Unlock()
				return nil, resultErr
			}
			e.mu.Lock()
		}
		w, ok := e.workers[id]
		if ok {
			runtime := e.runtimes[id]
			runtime.State = "stopped"
			runtime.Since = time.Now().UTC()
			runtime.UptimeSeconds = 0
			runtime.RestartCount = w.restartCount
			runtime.BitrateKbps = 0
			runtime.LastError = ""
			if removeRuntime {
				delete(e.runtimes, id)
			} else {
				e.runtimes[id] = runtime
			}
			if !e.closing {
				e.enqueueEventLocked(Event{
					StreamID:   id,
					Generation: w.generation,
					Runtime:    runtime,
					Level:      "warn",
					Message:    "stream worker stopped: " + w.stream.Name,
				})
			}
			delete(e.workers, id)
		} else if removeRuntime {
			delete(e.runtimes, id)
		}
		owner := publication.owner
		publication.owner = nil
		e.mu.Unlock()

		if ok {
			w.cancel()
		}
		if owner != nil && owner.sink != nil &&
			!(placeholder != nil && owner.sink == demotedSink && owner.token == *expected) {
			cleanupErr := e.terminalCleanup(owner.sink.RemoveChecked(owner.token))
			if !streamer.IsBenignLifecycleError(cleanupErr) {
				resultErr = errors.Join(resultErr, cleanupErr)
			}
		}

		e.mu.Lock()
		if e.publish[id] == publication {
			if _, exists := e.workers[id]; !exists {
				delete(e.publish, id)
			}
		}
		e.mu.Unlock()
		publication.mu.Unlock()
		return placeholder, resultErr
	}
	return nil, nil
}

func (e *Engine) Remove(id string) {
	_, err := e.quiesce(id, true, nil)
	logSinkError(id, "remove source", err)
}

func (e *Engine) Runtimes() map[string]model.StreamRuntime {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make(map[string]model.StreamRuntime, len(e.runtimes))
	for k, v := range e.runtimes {
		out[k] = v
	}
	return out
}

func (e *Engine) Shutdown() {
	logSinkError("", "terminal shutdown", e.ShutdownWithError())
}

// ShutdownWithError joins dispatch and every admitted worker, including workers
// already retired by ordinary Quiesce. It must not be called from an Engine callback.
func (e *Engine) ShutdownWithError() error {
	e.once.Do(func() {
		e.mu.Lock()
		e.closing = true
		close(e.closed)
		ids := make([]string, 0, len(e.publish))
		for id := range e.publish {
			ids = append(ids, id)
		}
		e.mu.Unlock()
		sort.Strings(ids)
		for _, id := range ids {
			_ = e.QuiesceWithError(id)
		}
		e.workerLifetimes.Wait()
		<-e.dispatchDone
		e.mu.Lock()
		e.shutdownErr = errors.Join(e.terminalErrors...)
		e.mu.Unlock()
	})
	return e.shutdownErr
}

func (e *Engine) finishWorker(w *worker) {
	close(w.done)
	e.workerLifetimes.Done()
}

func (e *Engine) terminalCleanup(err error) error {
	if !streamer.IsBenignLifecycleError(err) {
		e.mu.Lock()
		if e.closing {
			e.terminalErrors = append(e.terminalErrors, err)
		}
		e.mu.Unlock()
	}
	return err
}

func (e *Engine) runWorker(w *worker) {
	defer e.finishWorker(w)
	if strings.EqualFold(w.stream.Protocol, "dvb") {
		e.runDVBWorker(w)
		return
	}

	now := time.Now().UTC()
	if !e.publishWorkerRuntime(w, model.StreamRuntime{
		State:         "starting",
		Since:         now,
		UptimeSeconds: 0,
		RestartCount:  w.restartCount,
		Packets:       0,
		BitrateKbps:   0,
	}, "", "", true) {
		return
	}

	timer := time.NewTimer(350 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-w.ctx.Done():
		e.notifyWorkerCanceled(w)
		return
	case <-timer.C:
	}

	startedAt := time.Now().UTC()
	packets := uint64(0)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	if !e.publishWorkerRuntime(w, model.StreamRuntime{
		State:         "running",
		Since:         startedAt,
		UptimeSeconds: 0,
		RestartCount:  w.restartCount,
		Packets:       0,
		BitrateKbps:   0,
	}, "info", "stream worker started: "+w.stream.Name, true) {
		return
	}

	var pr *io.PipeReader
	var relayDone chan struct{}
	relayCancel := context.CancelFunc(func() {})
	e.mu.RLock()
	testSourceFactory := e.testPacketSourceFactory
	relay := e.relayInput
	if e.testRelayInput != nil {
		relay = e.testRelayInput
	}
	e.mu.RUnlock()
	var source model.PacketSource
	if testSourceFactory != nil {
		source = testSourceFactory(w.stream)
	} else {
		// Create a pipe to relay input packets to the streamer.
		var pw *io.PipeWriter
		pr, pw = io.Pipe()
		var relayCtx context.Context
		relayCtx, relayCancel = context.WithCancel(w.ctx)
		relayDone = make(chan struct{})
		go func() {
			defer close(relayDone)
			defer pw.Close()
			_ = relay(relayCtx, w.stream, pw)
		}()
		source = streamer.NewPacketReader(pr)
	}
	defer func() {
		relayCancel()
		if pr != nil {
			_ = pr.Close()
		}
		if relayDone != nil {
			<-relayDone
		}
	}()

	// Register with streamer so HLS/HTTP/UDP outputs work.
	if !e.registerWorkerStream(w, source) {
		return
	}
	defer e.unregisterWorkerStream(w)

	for {
		select {
		case <-w.ctx.Done():
			e.notifyWorkerCanceled(w)
			return
		case now := <-ticker.C:
			packets = e.workerStreamPackets(w)
			var delta uint64
			if packets >= w.prevPackets {
				delta = packets - w.prevPackets
			}
			w.prevPackets = packets
			bitrate := int(delta * 188 * 8 / 1000)
			if packets == 0 {
				log.Printf("engine runWorker %s: no packets from streamer yet", w.stream.Name)
			}
			runtime := model.StreamRuntime{
				State:         "running",
				Since:         startedAt,
				UptimeSeconds: int64(now.Sub(startedAt).Seconds()),
				RestartCount:  w.restartCount,
				Packets:       packets,
				BitrateKbps:   bitrate,
			}
			if !e.publishWorkerRuntime(w, runtime, "", "", true) {
				return
			}
		}
	}
}

func (e *Engine) registerWorkerStream(w *worker, source model.PacketSource) bool {
	if w == nil || w.publication == nil || source == nil {
		err := errors.New("invalid stream publication or unavailable packet source")
		if source != nil {
			err = errors.Join(err, e.terminalCleanup(source.Close()))
		}
		e.reportSinkError(w, "register source", err, true)
		return false
	}

	publication := w.publication
	publication.mu.Lock()
	defer publication.mu.Unlock()

	e.mu.RLock()
	hook := e.testHookBeforeStreamRegistration
	e.mu.RUnlock()
	if hook != nil {
		hook(w.stream.ID)
	}

	e.mu.RLock()
	current := e.workers[w.stream.ID]
	strmr := e.streamer
	if w.expectedPlaceholder != nil {
		strmr = w.registrationSink
	}
	closing := e.closing
	e.mu.RUnlock()
	if closing || current != w || current.generation != w.generation || w.ctx.Err() != nil || strmr == nil {
		err := e.terminalCleanup(source.Close())
		if strmr == nil && !closing && current == w && w.ctx.Err() == nil {
			err = errors.Join(errors.New("streamer is unavailable"), err)
		}
		e.reportSinkError(w, "close unaccepted source", err, true)
		return false
	}

	var token streamer.RegistrationToken
	var registrationErr error
	if w.expectedPlaceholder != nil {
		token, registrationErr = strmr.RegisterChecked(w.stream, source, w.expectedPlaceholder)
		if token.Generation == 0 {
			registrationErr = errors.Join(registrationErr, e.terminalCleanup(source.Close()))
		}
	} else {
		tracked := &engineCleanupSource{PacketSource: source}
		token, registrationErr = strmr.RegisterStreamWithToken(w.stream, tracked)
		if token.Generation == 0 {
			e.terminalCleanup(tracked.closeError())
		}
	}
	if token.Generation != 0 {
		e.terminalCleanup(registrationErr)
	}
	if token.Generation == 0 {
		e.reportSinkError(w, "register source", registrationErr, true)
		return false
	}
	e.mu.Lock()
	current = e.workers[w.stream.ID]
	closing = e.closing
	if !closing && current == w && current.generation == w.generation && w.ctx.Err() == nil {
		w.registration = token
		w.registrationSink = strmr
	}
	e.mu.Unlock()
	if closing || current != w || current.generation != w.generation || w.ctx.Err() != nil {
		e.reportSinkError(w, "discard superseded publication", errors.Join(registrationErr, e.terminalCleanup(strmr.RemoveChecked(token))), false)
		return false
	}
	publication.owner = &streamOwner{worker: w, sink: strmr, token: token}
	e.reportSinkError(w, "accepted source cleanup", registrationErr, false)
	e.mu.RLock()
	afterHook := e.testHookAfterStreamRegistration
	e.mu.RUnlock()
	if afterHook != nil {
		afterHook(w.stream.ID)
	}
	return true
}

func (e *Engine) unregisterWorkerStream(w *worker) {
	if w == nil || w.publication == nil {
		return
	}

	publication := w.publication
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.owner == nil || publication.owner.worker != w {
		return
	}

	owner := publication.owner
	publication.owner = nil
	if owner.sink != nil {
		e.reportSinkError(owner.worker, "cleanup completed worker source", e.terminalCleanup(owner.sink.RemoveChecked(owner.token)), false)
	}
}

func (e *Engine) runDVBWorker(w *worker) {
	now := time.Now().UTC()
	if !e.publishWorkerRuntime(w, model.StreamRuntime{
		State:         "starting",
		Since:         now,
		UptimeSeconds: 0,
		RestartCount:  w.restartCount,
		Packets:       0,
		BitrateKbps:   0,
	}, "", "", true) {
		return
	}

	cfg, err := dvb.ParseConfig(w.stream.InputURL)
	if err != nil {
		runtime := model.StreamRuntime{
			State:         "error",
			Since:         time.Now().UTC(),
			UptimeSeconds: 0,
			RestartCount:  w.restartCount,
			LastError:     err.Error(),
			Packets:       0,
			BitrateKbps:   0,
		}
		e.publishWorkerRuntime(w, runtime, "error", "dvb config error: "+w.stream.Name+" ("+err.Error()+")", true)
		return
	}

	// Streams tied to an adapter profile are managed by the store's
	// adapter monitor (signal polling) and updateDVBStreamRuntimes
	// (packet counting). Opening a second frontend fd here can break
	// demux output on drivers that don't use reference counting.
	if w.stream.AdapterProfileID != "" {
		e.runDVBPassthroughWorker(w)
		return
	}

	session, err := dvb.OpenSession(cfg)
	if err != nil {
		runtime := model.StreamRuntime{
			State:         "error",
			Since:         time.Now().UTC(),
			UptimeSeconds: 0,
			RestartCount:  w.restartCount,
			LastError:     err.Error(),
			Packets:       0,
			BitrateKbps:   0,
		}
		e.publishWorkerRuntime(w, runtime, "error", "dvb tuner open failed: "+w.stream.Name+" ("+err.Error()+")", true)
		return
	}
	defer func() { e.terminalCleanup(session.Close()) }()

	startedAt := time.Now().UTC()
	packets := uint64(0)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	if !e.publishWorkerRuntime(w, model.StreamRuntime{
		State:         "starting",
		Since:         startedAt,
		UptimeSeconds: 0,
		RestartCount:  w.restartCount,
		Packets:       0,
		BitrateKbps:   0,
	}, "info", "dvb frontend opened: "+w.stream.Name, true) {
		return
	}

	for {
		select {
		case <-w.ctx.Done():
			e.notifyWorkerCanceled(w)
			return
		case now := <-ticker.C:
			sig, err := session.Poll()
			state := "running"
			lastErr := ""
			if err != nil {
				state = "error"
				lastErr = err.Error()
			} else if !sig.Locked {
				state = "no_lock"
				lastErr = "frontend has no lock"
			}
			packets = e.workerStreamPackets(w)
			// Compute delta-based bitrate (kbps) from packet count change.
			var delta uint64
			if packets >= w.prevPackets {
				delta = packets - w.prevPackets
			}
			w.prevPackets = packets
			currentBitrate := int(delta * 188 * 8 / 1000)

			runtime := model.StreamRuntime{
				State:         state,
				Since:         startedAt,
				UptimeSeconds: int64(now.Sub(startedAt).Seconds()),
				RestartCount:  w.restartCount,
				LastError:     lastErr,
				Packets:       packets,
				BitrateKbps:   currentBitrate,
				Signal: &model.DVBSignal{
					Locked:            sig.Locked,
					SignalPercent:     sig.SignalPercent,
					SNRPercent:        sig.SNRPercent,
					BER:               sig.BER,
					UncorrectedBlocks: sig.UncorrectedBlocks,
					StatusBits:        sig.StatusBits,
				},
			}

			if !e.publishWorkerRuntime(w, runtime, "", "", true) {
				return
			}
		}
	}
}

// runDVBPassthroughWorker is used for DVB streams backed by an adapter
// profile.  It does not open a frontend session — the adapter monitor owns
// the frontend and the store's updateDVBStreamRuntimes handles packet
// counting.  This avoids breaking demux output on drivers that power-down
// the frontend when any fd is closed.
func (e *Engine) runDVBPassthroughWorker(w *worker) {
	startedAt := time.Now().UTC()
	packets := uint64(0)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			e.notifyWorkerCanceled(w)
			return
		case <-ticker.C:
			packets = e.workerStreamPackets(w)
			var delta uint64
			if packets >= w.prevPackets {
				delta = packets - w.prevPackets
			}
			w.prevPackets = packets
			bitrate := int(delta * 188 * 8 / 1000)

			if !e.publishWorkerRuntime(w, model.StreamRuntime{
				State:         "running",
				Since:         startedAt,
				UptimeSeconds: int64(time.Since(startedAt).Seconds()),
				RestartCount:  w.restartCount,
				Packets:       packets,
				BitrateKbps:   bitrate,
			}, "", "", false) {
				return
			}
		}
	}
}

// e.mu protects the token update from placeholder to the concrete publication.
func (e *Engine) registrationCurrentLocked(w *worker) bool {
	return w.registration.Generation == 0 ||
		w.registrationSink != nil && w.registrationSink.IsCurrentRegistration(w.registration)
}

func (e *Engine) publishWorkerRuntime(w *worker, runtime model.StreamRuntime, level, message string, notify bool) bool {
	if w == nil || w.generation == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	current := e.workers[w.stream.ID]
	if e.closing || current != w || current.generation != w.generation || w.ctx.Err() != nil || !e.registrationCurrentLocked(w) {
		return false
	}
	if runtime.LastError == "" {
		runtime.LastError = w.sinkError
	}
	e.runtimes[w.stream.ID] = runtime
	if notify {
		e.enqueueEventLocked(Event{
			StreamID:   w.stream.ID,
			Generation: w.generation,
			Runtime:    runtime,
			Level:      level,
			Message:    message,
		})
	}
	return true
}

func (e *Engine) enqueueEventLocked(ev Event) {
	select {
	case e.events <- ev:
	default:
	}
}

func (e *Engine) workerStreamPackets(w *worker) uint64 {
	if w == nil || w.publication == nil {
		return 0
	}

	publication := w.publication
	publication.mu.Lock()
	var sink *streamer.Streamer
	if publication.owner != nil && publication.owner.worker == w {
		sink = publication.owner.sink
	}
	if sink == nil {
		e.mu.RLock()
		current := e.workers[w.stream.ID]
		if !e.closing && current == w && current.generation == w.generation {
			sink = e.streamer
		}
		e.mu.RUnlock()
	}
	publication.mu.Unlock()
	if sink == nil {
		return 0
	}
	return sink.StreamPackets(w.stream.ID)
}

func (e *Engine) notifyWorkerCanceled(w *worker) {
	e.mu.RLock()
	hook := e.testHookWorkerCanceled
	e.mu.RUnlock()
	if hook != nil {
		hook(w.stream.ID)
	}
}

func sameConfig(a, b model.Stream) bool {
	return a.Name == b.Name &&
		a.InputURL == b.InputURL &&
		a.OutputURL == b.OutputURL &&
		a.Protocol == b.Protocol &&
		a.SoftcamID == b.SoftcamID &&
		a.Enabled == b.Enabled
}

func packetsPerSecond(bitrateKbps int) uint64 {
	bytesPerSecond := (bitrateKbps * 1000) / 8
	if bytesPerSecond <= 0 {
		return 0
	}
	packets := bytesPerSecond / 188
	if packets <= 0 {
		return 1
	}
	return uint64(packets)
}

func validateStream(stream model.Stream) error {
	if stream.Name == "" {
		return errInvalid("name is required")
	}
	if stream.InputURL == "" {
		return errInvalid("input_url is required")
	}
	if stream.OutputURL == "" {
		return errInvalid("output_url is required")
	}

	if !supportedProtocol(stream.Protocol) {
		return errInvalid("unsupported protocol: " + stream.Protocol)
	}

	inputURL, err := url.Parse(stream.InputURL)
	if err != nil || inputURL.Scheme == "" {
		return errInvalid("invalid input_url")
	}
	if strings.EqualFold(stream.Protocol, "dvb") {
		if _, err := dvb.ParseConfig(stream.InputURL); err != nil {
			return errInvalid("invalid dvb input_url: " + err.Error())
		}
	}
	outputURL, err := url.Parse(stream.OutputURL)
	if err != nil || outputURL.Scheme == "" {
		return errInvalid("invalid output_url")
	}

	return nil
}

func supportedProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "mpegts", "mpegts-secure", "udp", "srt", "hls", "hls-secure", "http", "rtsp", "rtsp-secure", "dvb":
		return true
	default:
		return false
	}
}

func (e *Engine) relayInput(ctx context.Context, stream model.Stream, pw *io.PipeWriter) error {
	inputURL := stream.InputURL

	// HTTP/HTTPS input
	if strings.HasPrefix(inputURL, "http://") || strings.HasPrefix(inputURL, "https://") {
		transport := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          10,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			req, err := http.NewRequestWithContext(ctx, "GET", inputURL, nil)
			if err != nil {
				return fmt.Errorf("create request: %w", err)
			}
			req.Header.Set("User-Agent", "AstraX/1.0")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("relayInput %s: connect error: %v", stream.Name, err)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
					continue
				}
			}

			if resp.StatusCode != http.StatusOK {
				log.Printf("relayInput %s: HTTP %d", stream.Name, resp.StatusCode)
				resp.Body.Close()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
					continue
				}
			}

			log.Printf("relayInput %s: connected, streaming", stream.Name)
			_, err = io.Copy(pw, resp.Body)
			resp.Body.Close()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Printf("relayInput %s: stream error: %v", stream.Name, err)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
					continue
				}
			}
			log.Printf("relayInput %s: server closed connection, reconnecting", stream.Name)
		}
	}

	// UDP input
	if strings.HasPrefix(inputURL, "udp://") {
		u, err := url.Parse(inputURL)
		if err != nil {
			return fmt.Errorf("parse udp url: %w", err)
		}
		addr, err := net.ResolveUDPAddr("udp", u.Host)
		if err != nil {
			return fmt.Errorf("resolve udp addr: %w", err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("listen udp: %w", err)
		}
		defer conn.Close()

		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-ctx.Done():
			case <-stop:
			}
			_ = conn.Close()
		}()
		defer func() { close(stop); <-done }()

		_, err = io.Copy(pw, conn)
		return err
	}

	return fmt.Errorf("unsupported input protocol")
}

func errInvalid(message string) error {
	return &invalidStreamError{message: message}
}

type invalidStreamError struct {
	message string
}

func (e *invalidStreamError) Error() string {
	return e.message
}

func (e *Engine) QuiesceWithError(id string) error { _, err := e.quiesce(id, false, nil); return err }

// Registration's legacy wrapper consumes rejected sources. Keep its genuine
// cleanup failure separate from the returned setup diagnostic.
type engineCleanupSource struct {
	model.PacketSource
	mu  sync.Mutex
	err error
}

func (s *engineCleanupSource) Close() error {
	err := s.PacketSource.Close()
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	return err
}
func (s *engineCleanupSource) closeError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
