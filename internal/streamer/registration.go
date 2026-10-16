// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	pathpkg "path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"astrax/internal/model"
)

type registrationKind uint8

const (
	registrationChecked registrationKind = iota
	registrationLegacy
	registrationPlaceholderReplacement
)

type registrationReservation struct {
	id              string
	generation      uint64
	path            string
	prior           *activeStream
	priorGeneration uint64
	valid           bool
}

type preparedOutputs struct {
	udp       udpOutput
	srt       srtOutput
	udpWriter *packetWriter
	srtWriter *packetWriter
	closeOnce syncOnceWithError
}

type syncOnceWithError struct {
	once   sync.Once
	result error
}

type detachedResources struct {
	run             *streamRun
	outputs         *preparedOutputs
	activationTimer timerHandle
	stopTimer       timerHandle
	segments        *hlsBuffer
	requests        []*stageCHTTPRequest
}

func (st *Streamer) register(stream model.Stream, src model.PacketSource, expected *RegistrationToken, kind registrationKind) (RegistrationToken, error) {
	callerOwnsSource := !packetSourceIsNil(src)
	reservation, reuseOutputs, err := st.reserveRegistration(stream, src, expected, kind)
	if err != nil {
		if kind == registrationLegacy && callerOwnsSource {
			err = errors.Join(err, src.Close())
		}
		return RegistrationToken{}, err
	}

	var outputs *preparedOutputs
	if reuseOutputs != nil {
		outputs = reuseOutputs
	} else {
		outputs, err = st.prepareOutputs(stream)
		if err != nil {
			st.releaseRegistrationReservation(reservation)
			if kind == registrationLegacy && callerOwnsSource {
				err = errors.Join(err, src.Close())
			}
			return RegistrationToken{}, err
		}
	}

	token, state, oldResources, publishErr := st.publishRegistration(reservation, stream, src, outputs, reuseOutputs != nil)
	if publishErr != nil {
		st.releaseRegistrationReservation(reservation)
		if reuseOutputs == nil {
			publishErr = errors.Join(publishErr, cleanupDetached(detachedResources{outputs: outputs}))
		}
		if kind == registrationLegacy && callerOwnsSource {
			publishErr = errors.Join(publishErr, src.Close())
		}
		return RegistrationToken{}, publishErr
	}

	stopDetachedTimers(&oldResources)
	st.installPublishedOnDemandTimer(state, token.Generation)
	if reuseOutputs == nil {
		startOutputs(outputs)
	}
	if state.run != nil {
		go st.runStream(state, state.run)
	}
	cleanupErr := cleanupDetached(oldResources)
	if kind == registrationLegacy {
		if cleanupErr != nil {
			return token, cleanupErr
		}
		return token, nil
	}
	return token, cleanupErr
}

func (st *Streamer) reserveRegistration(stream model.Stream, src model.PacketSource, expected *RegistrationToken, kind registrationKind) (*registrationReservation, *preparedOutputs, error) {
	if stageCEnabled(stream) && !st.stageCResources.available() {
		return nil, nil, ErrStageCSinksUnavailable
	}
	if stream.ID == "" || stream.ID != strings.TrimSpace(stream.ID) {
		return nil, nil, fmt.Errorf("%w: stream ID must be non-empty and trimmed", ErrInvalidRegistration)
	}
	sourceNil := packetSourceIsNil(src)
	if kind == registrationChecked {
		switch {
		case expected == nil && sourceNil && !stream.OnDemand:
			return nil, nil, fmt.Errorf("%w: nil source requires an on-demand stream", ErrInvalidRegistration)
		case expected != nil && sourceNil:
			return nil, nil, fmt.Errorf("%w: placeholder promotion requires a source", ErrInvalidRegistration)
		}
	}
	path, err := ValidateOutputPath(stream.OutputURL)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidRegistration, err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closing || st.closed {
		return nil, nil, ErrStreamerClosed
	}
	if st.reservations[stream.ID] != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrStreamReserved, stream.ID)
	}
	prior := st.streams[stream.ID]
	var reuseOutputs *preparedOutputs
	if kind == registrationChecked {
		if expected == nil {
			if prior != nil {
				return nil, nil, fmt.Errorf("%w: %s", ErrStreamExists, stream.ID)
			}
		} else {
			if expected.StreamID != stream.ID || expected.Generation == 0 {
				return nil, nil, fmt.Errorf("%w: malformed expected placeholder", ErrStreamTokenMismatch)
			}
			if prior == nil {
				return nil, nil, fmt.Errorf("%w: %s", ErrStreamNotFound, stream.ID)
			}
			prior.mu.RLock()
			priorState := prior.state
			priorGeneration := prior.generation
			priorPath := prior.path
			priorOutputURL := prior.cfg.OutputURL
			priorOutputs := prior.outputs
			priorStageC := stageCEnabled(prior.cfg)
			prior.mu.RUnlock()
			if priorState != streamStatePlaceholder || priorGeneration != expected.Generation {
				return nil, nil, fmt.Errorf("%w: %s generation %d", ErrStreamTokenMismatch, stream.ID, expected.Generation)
			}
			if path != priorPath || stream.OutputURL != priorOutputURL {
				return nil, nil, fmt.Errorf("%w: placeholder output changes require ReplacePlaceholderChecked", ErrInvalidRegistration)
			}
			if priorOutputs != nil && priorStageC == stageCEnabled(stream) && priorOutputs.reusableFor(stream) {
				reuseOutputs = priorOutputs
			}
		}
	}
	if conflict := st.configuredOutputConflictLocked(path, stream.ID); conflict != "" {
		return nil, nil, fmt.Errorf("%w: %s is configured by %s", ErrStreamPathConflict, path, conflict)
	}
	if conflict := st.pathConflictLocked(path, prior); conflict != "" {
		return nil, nil, fmt.Errorf("%w: %s is owned by %s", ErrStreamPathConflict, path, conflict)
	}

	generation, err := st.allocateGenerationLocked(stream.ID)
	if err != nil {
		return nil, nil, err
	}
	reservation := &registrationReservation{
		id:         stream.ID,
		generation: generation,
		path:       path,
		prior:      prior,
		valid:      true,
	}
	if prior != nil {
		prior.mu.RLock()
		reservation.priorGeneration = prior.generation
		if (kind == registrationLegacy || kind == registrationPlaceholderReplacement) && prior.cfg.OutputURL == stream.OutputURL && prior.outputs != nil && stageCEnabled(prior.cfg) == stageCEnabled(stream) && prior.outputs.reusableFor(stream) {
			reuseOutputs = prior.outputs
		}
		prior.mu.RUnlock()
	}
	st.reservations[stream.ID] = reservation
	if path != "" {
		st.pathReservations[path] = reservation
		st.reservedPaths.add(path, pathPublication{streamID: stream.ID, generation: generation})
	}
	return reservation, reuseOutputs, nil
}

func (st *Streamer) pathConflictLocked(path string, prior *activeStream) string {
	if conflict := st.reservedPaths.conflict(path, pathPublication{}); conflict != "" {
		return conflict
	}
	var allowed pathPublication
	if prior != nil {
		allowed = pathPublication{streamID: prior.id, generation: prior.generation}
	}
	return st.publishedPaths.conflict(path, allowed)
}

func (st *Streamer) allocateGenerationLocked(id string) (uint64, error) {
	if st.nextGeneration == ^uint64(0) {
		return 0, ErrGenerationExhausted
	}
	st.nextGeneration++
	st.tombstones[id] = st.nextGeneration
	return st.nextGeneration, nil
}

func (st *Streamer) publishRegistration(reservation *registrationReservation, stream model.Stream, src model.PacketSource, outputs *preparedOutputs, reused bool) (RegistrationToken, *activeStream, detachedResources, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closing || st.closed {
		return RegistrationToken{}, nil, detachedResources{}, ErrStreamerClosed
	}
	if reservation == nil || !reservation.valid || st.reservations[reservation.id] != reservation {
		return RegistrationToken{}, nil, detachedResources{}, ErrRegistrationSuperseded
	}
	current := st.streams[reservation.id]
	if current != reservation.prior {
		return RegistrationToken{}, nil, detachedResources{}, ErrRegistrationSuperseded
	}
	if current != nil && current.generation != reservation.priorGeneration {
		return RegistrationToken{}, nil, detachedResources{}, ErrRegistrationSuperseded
	}
	if conflict := st.pathConflictForPublicationLocked(reservation); conflict != "" {
		return RegistrationToken{}, nil, detachedResources{}, fmt.Errorf("%w: %s is owned by %s", ErrStreamPathConflict, reservation.path, conflict)
	}

	state := current
	if stageCEnabled(stream) && current != nil {
		current.mu.RLock()
		if current.ordinaryHTTPClients != 0 {
			current.mu.RUnlock()
			return RegistrationToken{}, nil, detachedResources{}, ErrStageCSinksUnavailable
		}
		for _, client := range current.clients {
			if client.writer == nil {
				current.mu.RUnlock()
				return RegistrationToken{}, nil, detachedResources{}, ErrStageCSinksUnavailable
			}
		}
		current.mu.RUnlock()
	}
	if state == nil {
		state = &activeStream{
			id:       stream.ID,
			clients:  make(map[string]*tsClient),
			segments: newHLSBuffer(),
		}
		st.streams[stream.ID] = state
	}

	state.mu.Lock()
	// EOF may consume reserved reusable writers without changing the cleanup
	// token. Do not publish a successful replacement with those closed sinks.
	if reused && (state.terminal || state.outputs != outputs || !outputs.reusableFor(stream)) {
		state.mu.Unlock()
		return RegistrationToken{}, nil, detachedResources{}, ErrRegistrationSuperseded
	}
	var replacementSegments *hlsBuffer
	if stageCEnabled(stream) && (!stageCEnabled(state.cfg) || state.run != nil || state.segments == nil || state.segments.bounded == nil) {
		var err error
		var owner *hlsStreamBudget
		if stageCEnabled(state.cfg) && state.segments != nil && state.segments.bounded != nil {
			// A replacement must not reset capacity still held by old responses.
			owner = state.segments.bounded.owner
		}
		replacementSegments, err = newBoundedHLSBufferWithOwner(st.stageCResources.HLS, st.deps.now, owner)
		if err != nil {
			state.mu.Unlock()
			return RegistrationToken{}, nil, detachedResources{}, err
		}
	} else if !stageCEnabled(stream) && stageCEnabled(state.cfg) {
		replacementSegments = newHLSBuffer()
	}
	oldPath := state.path
	oldResources := detachedResources{
		run:             state.run,
		activationTimer: state.activationTimer,
		stopTimer:       state.stopTimer,
	}
	if replacementSegments != nil {
		if stageCEnabled(state.cfg) {
			oldResources.segments = state.segments
		}
		state.segments = replacementSegments
	}
	// A placeholder promotion must keep the waiting viewers that triggered
	// on-demand activation. Only an existing run/policy transition is detached.
	if stageCEnabled(state.cfg) && (state.run != nil || !stageCEnabled(stream)) {
		for request := range state.stageCRequests {
			oldResources.requests = append(oldResources.requests, request)
		}
		state.stageCRequests = nil
	}
	if !reused {
		oldResources.outputs = state.outputs
	}
	state.activationTimer = nil
	state.stopTimer = nil
	state.packets = 0
	state.cfg = stream
	state.terminal = false
	state.generation = reservation.generation
	state.path = reservation.path
	state.outputs = outputs
	if packetSourceIsNil(src) {
		state.state = streamStatePlaceholder
		state.run = nil
	} else {
		state.state = streamStateActive
		ctx, cancel := context.WithCancel(context.Background())
		state.run = &streamRun{
			guarded:    stageCEnabled(stream),
			generation: reservation.generation,
			ctx:        ctx,
			cancel:     cancel,
			src:        src,
			outputs:    outputs,
			done:       make(chan struct{}),
		}
	}
	state.mu.Unlock()

	st.removePathOwnerLocked(oldPath, RegistrationToken{StreamID: stream.ID, Generation: reservation.priorGeneration})
	st.publishPathLocked(reservation.path, pathPublication{streamID: stream.ID, generation: reservation.generation})
	st.finishReservationLocked(reservation)
	return RegistrationToken{StreamID: stream.ID, Generation: reservation.generation}, state, oldResources, nil
}

func (st *Streamer) pathConflictForPublicationLocked(reservation *registrationReservation) string {
	if conflict := st.configuredOutputConflictLocked(reservation.path, reservation.id); conflict != "" {
		return conflict
	}
	prior := pathPublication{streamID: reservation.id, generation: reservation.priorGeneration}
	if conflict := st.publishedPaths.conflict(reservation.path, prior); conflict != "" {
		return conflict
	}
	return st.reservedPaths.conflict(reservation.path, pathPublication{streamID: reservation.id, generation: reservation.generation})
}

func (st *Streamer) finishReservationLocked(reservation *registrationReservation) {
	reservation.valid = false
	st.reservedPaths.remove(reservation.path, pathPublication{streamID: reservation.id, generation: reservation.generation})
	if st.reservations[reservation.id] == reservation {
		delete(st.reservations, reservation.id)
	}
	if reservation.path != "" && st.pathReservations[reservation.path] == reservation {
		delete(st.pathReservations, reservation.path)
	}
}

func (st *Streamer) releaseRegistrationReservation(reservation *registrationReservation) {
	if reservation == nil {
		return
	}
	st.mu.Lock()
	st.finishReservationLocked(reservation)
	st.mu.Unlock()
}

func (st *Streamer) unregisterChecked(token RegistrationToken, mode DetachMode, requireIdle bool) (*RegistrationToken, error) {
	if mode != DetachRemove && mode != DetachPreservePlaceholder {
		return nil, fmt.Errorf("%w: unknown detach mode %d", ErrInvalidRegistration, mode)
	}
	st.mu.Lock()
	state, err := st.exactStateLocked(token, streamStateActive)
	if err != nil {
		st.mu.Unlock()
		return nil, err
	}
	if requireIdle {
		state.mu.RLock()
		idle := state.cfg.OnDemand && state.clientCount == 0
		state.mu.RUnlock()
		if !idle {
			st.mu.Unlock()
			return nil, ErrStreamTokenMismatch
		}
	}
	var next *RegistrationToken
	if mode == DetachPreservePlaceholder {
		generation, allocationErr := st.allocateGenerationLocked(token.StreamID)
		if allocationErr != nil {
			st.mu.Unlock()
			return nil, allocationErr
		}
		state.mu.Lock()
		resources := st.detachStateResourcesLocked(state, true)
		state.generation = generation
		state.state = streamStatePlaceholder
		state.terminal = false
		if stageCEnabled(state.cfg) {
			var owner *hlsStreamBudget
			if resources.segments != nil && resources.segments.bounded != nil {
				owner = resources.segments.bounded.owner
			}
			state.segments, _ = newBoundedHLSBufferWithOwner(st.stageCResources.HLS, st.deps.now, owner)
		}
		state.mu.Unlock()
		st.removePathOwnerLocked(state.path, token)
		st.publishPathLocked(state.path, pathPublication{streamID: state.id, generation: generation})
		value := RegistrationToken{StreamID: token.StreamID, Generation: generation}
		next = &value
		st.mu.Unlock()
		stopDetachedTimers(&resources)
		if stageCEnabled(state.cfg) {
			cleanupErr := cleanupDetached(resources)
			st.installPublishedOnDemandTimer(state, generation)
			return next, cleanupErr
		}
		st.installPublishedOnDemandTimer(state, generation)
		return next, cleanupDetached(resources)
	}
	resources := st.detachStateLocked(state, true)
	delete(st.streams, token.StreamID)
	st.removePathOwnerLocked(state.path, token)
	st.mu.Unlock()
	return nil, cleanupDetached(resources)
}

func (st *Streamer) removeChecked(token RegistrationToken) error {
	st.mu.Lock()
	state, err := st.exactStateLocked(token, 0)
	if err != nil {
		st.mu.Unlock()
		return err
	}
	resources := st.detachStateLocked(state, true)
	delete(st.streams, token.StreamID)
	st.removePathOwnerLocked(state.path, token)
	st.mu.Unlock()
	return cleanupDetached(resources)
}

func (st *Streamer) removeLegacy(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty stream ID", ErrInvalidRegistration)
	}
	st.mu.Lock()
	state := st.streams[id]
	if state == nil {
		st.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrStreamNotFound, id)
	}
	state.mu.RLock()
	token := RegistrationToken{StreamID: id, Generation: state.generation}
	state.mu.RUnlock()
	resources := st.detachStateLocked(state, true)
	delete(st.streams, id)
	st.removePathOwnerLocked(state.path, token)
	st.mu.Unlock()
	return cleanupDetached(resources)
}

func (st *Streamer) replacePlaceholderChecked(token RegistrationToken, stream model.Stream) (RegistrationToken, error) {
	if stream.ID != token.StreamID || !stream.OnDemand {
		return RegistrationToken{}, fmt.Errorf("%w: replacement must be the same on-demand stream", ErrInvalidRegistration)
	}
	st.mu.Lock()
	_, err := st.exactStateLocked(token, streamStatePlaceholder)
	if err != nil {
		st.mu.Unlock()
		return RegistrationToken{}, err
	}
	st.mu.Unlock()
	return st.register(stream, nil, &token, registrationPlaceholderReplacement)
}

func (st *Streamer) exactStateLocked(token RegistrationToken, required streamState) (*activeStream, error) {
	state, err := st.publishedStateLocked(token, required)
	if err != nil {
		return nil, err
	}
	if st.reservations[token.StreamID] != nil {
		return nil, fmt.Errorf("%w: %s", ErrStreamReserved, token.StreamID)
	}
	return state, nil
}

// Preparing a replacement does not supersede the still-published generation.
func (st *Streamer) publishedStateLocked(token RegistrationToken, required streamState) (*activeStream, error) {
	if token.StreamID == "" || token.Generation == 0 {
		return nil, fmt.Errorf("%w: malformed token", ErrStreamTokenMismatch)
	}
	if st.closing || st.closed {
		return nil, ErrStreamerClosed
	}
	state := st.streams[token.StreamID]
	if state == nil {
		return nil, fmt.Errorf("%w: %s", ErrStreamNotFound, token.StreamID)
	}
	state.mu.RLock()
	generation := state.generation
	kind := state.state
	state.mu.RUnlock()
	if generation != token.Generation || (required != 0 && kind != required) {
		return nil, fmt.Errorf("%w: %s generation %d", ErrStreamTokenMismatch, token.StreamID, token.Generation)
	}
	return state, nil
}

func (st *Streamer) detachStateLocked(state *activeStream, timers bool) detachedResources {
	state.mu.Lock()
	resources := st.detachStateResourcesLocked(state, timers)
	state.mu.Unlock()
	return resources
}

func (st *Streamer) detachStateResourcesLocked(state *activeStream, timers bool) detachedResources {
	resources := detachedResources{run: state.run, outputs: state.outputs}
	if stageCEnabled(state.cfg) {
		resources.segments = state.segments
		state.segments = nil
		for request := range state.stageCRequests {
			resources.requests = append(resources.requests, request)
		}
		state.stageCRequests = nil
	}
	state.run = nil
	state.outputs = nil
	state.packets = 0
	if timers {
		resources.activationTimer = state.activationTimer
		resources.stopTimer = state.stopTimer
		state.activationTimer = nil
		state.stopTimer = nil
	}
	return resources
}

func (st *Streamer) removePathOwnerLocked(path string, token RegistrationToken) {
	if path == "" {
		return
	}
	if owner := st.customPaths[path]; owner.streamID == token.StreamID && owner.generation == token.Generation {
		delete(st.customPaths, path)
		st.publishedPaths.remove(path, owner)
	}
}

func (st *Streamer) prepareOutputs(stream model.Stream) (*preparedOutputs, error) {
	outputs := &preparedOutputs{}
	lowerURL := strings.ToLower(strings.TrimSpace(stream.OutputURL))
	if strings.HasPrefix(lowerURL, "udp://") {
		output, err := st.deps.setupUDP(stream.OutputURL)
		if err != nil {
			if output != nil {
				outputs.udp = output
			}
			return nil, errors.Join(fmt.Errorf("setup UDP output for %s: %w", stream.ID, err), outputs.close())
		}
		if output == nil {
			return nil, fmt.Errorf("setup UDP output for %s: nil output", stream.ID)
		}
		outputs.udp = output
	}
	if strings.HasPrefix(lowerURL, "srt://") {
		budget := ordinarySRTBudget
		if stageCEnabled(stream) {
			budget = nil
			if st.stageCResources.available() {
				budget = st.stageCResources.PacketBudget
			}
		}
		output, err := st.deps.setupSRT(stream.OutputURL, budget)
		if err != nil {
			if output != nil {
				outputs.srt = output
			}
			return nil, errors.Join(fmt.Errorf("setup SRT output for %s: %w", stream.ID, err), outputs.close())
		}
		if output == nil {
			return nil, errors.Join(fmt.Errorf("setup SRT output for %s: nil output", stream.ID), outputs.close())
		}
		outputs.srt = output
	}
	if stageCEnabled(stream) {
		if !st.stageCResources.available() {
			return nil, errors.Join(ErrStageCSinksUnavailable, outputs.close())
		}
		if outputs.udp != nil {
			finite, ok := outputs.udp.(stageCUDPOutput)
			if !ok {
				return nil, errors.Join(ErrStageCSinksUnavailable, outputs.close())
			}
			if err := finite.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
				return nil, errors.Join(ErrStageCSinksUnavailable, outputs.close())
			}
			writer, err := newPacketWriter(func(packet []byte) error {
				if err := finite.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
					return err
				}
				n, err := finite.Write(packet)
				if err == nil && n != len(packet) {
					err = io.ErrShortWrite
				}
				return err
			}, finite.Close, st.stageCResources.PacketBudget)
			if err != nil {
				return nil, errors.Join(err, outputs.close())
			}
			outputs.udpWriter = writer
		}
		if outputs.srt != nil {
			// Native legacy listeners do not promise finite per-peer write/close
			// ownership. They remain explicitly unsupported for Stage C until a
			// verified adapter satisfies this interface; ordinary SRT is unchanged.
			finite, ok := outputs.srt.(stageCSRTOutput)
			if !ok {
				return nil, errors.Join(ErrStageCSinksUnavailable, outputs.close())
			}
			if err := finite.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
				return nil, errors.Join(ErrStageCSinksUnavailable, outputs.close())
			}
			writer, err := newPacketWriter(func(packet []byte) error {
				if err := finite.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
					return err
				}
				return finite.WritePacket(packet)
			}, finite.Close, st.stageCResources.PacketBudget)
			if err != nil {
				return nil, errors.Join(err, outputs.close())
			}
			outputs.srtWriter = writer
		}
	}
	return outputs, nil
}

func startOutputs(outputs *preparedOutputs) {
	if outputs != nil && outputs.srt != nil {
		outputs.srt.Start()
	}
}

func (outputs *preparedOutputs) reusableFor(stream model.Stream) bool {
	if !stageCEnabled(stream) {
		return true
	}
	if outputs.udp != nil && outputs.udpWriter == nil || outputs.srt != nil && outputs.srtWriter == nil {
		return false
	}
	for _, writer := range []*packetWriter{outputs.udpWriter, outputs.srtWriter} {
		if writer != nil {
			writer.mu.Lock()
			closed := writer.closed
			writer.mu.Unlock()
			if closed {
				return false
			}
		}
	}
	return true
}

func (outputs *preparedOutputs) close() error {
	if outputs == nil {
		return nil
	}
	outputs.closeOnce.once.Do(func() {
		var errs []error
		if outputs.udpWriter != nil {
			if err := outputs.udpWriter.Close(); err != nil {
				errs = append(errs, wrapError("close UDP writer", err))
			}
		} else if outputs.udp != nil {
			if err := outputs.udp.Close(); err != nil {
				errs = append(errs, wrapError("close UDP output", err))
			}
		}
		if outputs.srt != nil {
			var err error
			if outputs.srtWriter != nil {
				err = outputs.srtWriter.Close()
			} else {
				err = outputs.srt.Close()
			}
			if err != nil {
				errs = append(errs, wrapError("close SRT output", err))
			}
			<-outputs.srt.Done()
		}
		outputs.closeOnce.result = errors.Join(errs...)
	})
	return outputs.closeOnce.result
}

func stopDetachedTimers(resources *detachedResources) {
	if resources == nil {
		return
	}
	activationTimer := resources.activationTimer
	stopTimer := resources.stopTimer
	resources.activationTimer = nil
	resources.stopTimer = nil

	if activationTimer != nil {
		activationTimer.Stop()
	}
	if stopTimer != nil && stopTimer != activationTimer {
		stopTimer.Stop()
	}
}

func cleanupDetached(resources detachedResources) error {
	stopDetachedTimers(&resources)
	for _, request := range resources.requests {
		request.cancel()
	}
	var errs []error
	if resources.run != nil {
		resources.run.cancel()
		if err := resources.run.closeSource(); err != nil {
			errs = append(errs, wrapError("close packet source", err))
		}
	}
	if resources.outputs != nil {
		if err := resources.outputs.close(); err != nil {
			errs = append(errs, err)
		}
	}
	if resources.run != nil {
		<-resources.run.done
		errs = append(errs, resources.run.retirementErr)
	}
	if resources.segments != nil {
		if err := resources.segments.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, request := range resources.requests {
		<-request.done
	}
	return errors.Join(errs...)
}

func packetSourceIsNil(source model.PacketSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// ValidateOutputPath parses the output URL and returns its normalized custom route.
// It checks syntax and the static built-in namespace only; it does not reserve
// routes, resolve hosts, or prepare output resources.
func ValidateOutputPath(outputURL string) (string, error) {
	if strings.TrimSpace(outputURL) == "" {
		return "", nil
	}
	parsed, err := url.Parse(strings.TrimSpace(outputURL))
	if err != nil {
		return "", fmt.Errorf("parse output URL: %w", err)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return "", nil
	}
	cleaned := pathpkg.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	lower := strings.ToLower(cleaned)
	switch {
	case strings.HasSuffix(lower, ".m3u8"):
		cleaned = cleaned[:len(cleaned)-len(".m3u8")]
	case strings.HasSuffix(lower, ".ts"):
		cleaned = cleaned[:len(cleaned)-len(".ts")]
	}
	if cleaned == "" || cleaned == "/" {
		return "", nil
	}
	if cleaned == "/stream" || strings.HasPrefix(cleaned, "/stream/") ||
		cleaned == "/hls" || strings.HasPrefix(cleaned, "/hls/") {
		return "", fmt.Errorf("custom path overlaps built-in namespace")
	}
	return cleaned, nil
}

func setupUDPOutput(outputURL string) (udpOutput, error) {
	parsed, err := url.Parse(outputURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	if port <= 0 {
		port = 1234
	}
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	connection, err := net.DialUDP("udp", nil, address)
	if err != nil {
		return nil, err
	}
	_ = connection.SetWriteBuffer(2 * 1024 * 1024)
	return connection, nil
}

func isMulticastAddr(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsMulticast()
}
