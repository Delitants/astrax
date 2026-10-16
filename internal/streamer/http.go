// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"astrax/internal/mpegts"
)

func (st *Streamer) streamClientConnected(state *activeStream) bool {
	return st.streamClientConnectedPolicy(state, false)
}

func (st *Streamer) streamClientConnectedPolicy(state *activeStream, ordinary bool) bool {
	if state == nil {
		return false
	}

	st.mu.Lock()
	published := !st.closing && !st.closed && st.streams[state.id] == state
	state.mu.Lock()
	if !published || state.terminal || (ordinary && stageCEnabled(state.cfg)) {
		state.mu.Unlock()
		st.mu.Unlock()
		return false
	}
	state.clientCount++
	if ordinary {
		// Claim the selected ordinary policy before any Flush/Write or client
		// insertion. Publication uses the same locks to reject this owner.
		state.ordinaryHTTPClients++
	}
	firstClient := state.clientCount == 1
	generation := state.generation
	stateKind := state.state
	onDemand := state.cfg.OnDemand
	stopTimer := state.stopTimer
	state.stopTimer = nil
	var activationTimer timerHandle
	if firstClient && onDemand && stateKind == streamStatePlaceholder {
		activationTimer = state.activationTimer
		state.activationTimer = nil
	}
	state.mu.Unlock()
	st.mu.Unlock()

	if stopTimer != nil {
		stopTimer.Stop()
	}
	if activationTimer != nil {
		activationTimer.Stop()
	}
	if firstClient && onDemand && stateKind == streamStatePlaceholder {
		st.installOnDemandTimer(state, generation, true, 500*time.Millisecond)
	}
	return true
}

func (st *Streamer) streamClientDisconnected(state *activeStream) {
	st.streamClientDisconnectedPolicy(state, false)
}

func (st *Streamer) streamClientDisconnectedPolicy(state *activeStream, ordinary bool) {
	if state == nil {
		return
	}

	st.mu.Lock()
	published := !st.closing && !st.closed && st.streams[state.id] == state
	state.mu.Lock()
	if state.clientCount > 0 {
		state.clientCount--
	}
	if ordinary {
		state.ordinaryHTTPClients--
	}
	clientCount := state.clientCount
	generation := state.generation
	stateKind := state.state
	onDemand := state.cfg.OnDemand
	timeout := state.cfg.OnDemandTimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	var activationTimer timerHandle
	var stopTimer timerHandle
	if clientCount == 0 {
		if stateKind == streamStatePlaceholder {
			activationTimer = state.activationTimer
			state.activationTimer = nil
		}
		if stateKind == streamStateActive {
			stopTimer = state.stopTimer
			state.stopTimer = nil
		}
	}
	state.mu.Unlock()
	st.mu.Unlock()

	if activationTimer != nil {
		activationTimer.Stop()
	}
	if stopTimer != nil {
		stopTimer.Stop()
	}
	if published && clientCount == 0 && onDemand && stateKind == streamStateActive {
		st.installOnDemandTimer(state, generation, false, time.Duration(timeout)*time.Second)
	}
}

func (st *Streamer) installPublishedOnDemandTimer(state *activeStream, generation uint64) {
	if state == nil {
		return
	}

	st.mu.Lock()
	published := !st.closing && !st.closed && st.streams[state.id] == state
	state.mu.RLock()
	valid := published && state.generation == generation && state.cfg.OnDemand
	start := false
	delay := time.Duration(0)
	if valid {
		switch {
		case state.state == streamStatePlaceholder && state.clientCount > 0:
			start = true
			delay = 500 * time.Millisecond
		case state.state == streamStateActive && state.clientCount == 0:
			timeout := state.cfg.OnDemandTimeoutSec
			if timeout <= 0 {
				timeout = 30
			}
			delay = time.Duration(timeout) * time.Second
		default:
			valid = false
		}
	}
	state.mu.RUnlock()
	st.mu.Unlock()

	if valid {
		st.installOnDemandTimer(state, generation, start, delay)
	}
}

func (st *Streamer) installOnDemandTimer(state *activeStream, generation uint64, start bool, delay time.Duration) {
	timer := st.deps.afterFunc(delay, func() {
		st.dispatchOnDemandCallback(state, generation, start)
	})
	if timer == nil {
		return
	}

	st.mu.Lock()
	published := !st.closing && !st.closed && st.streams[state.id] == state
	state.mu.Lock()
	valid := published && state.generation == generation && state.cfg.OnDemand
	if start {
		valid = valid && state.state == streamStatePlaceholder && state.clientCount > 0
	} else {
		valid = valid && state.state == streamStateActive && state.clientCount == 0
	}
	var replaced timerHandle
	if valid {
		if start {
			replaced = state.activationTimer
			state.activationTimer = timer
		} else {
			replaced = state.stopTimer
			state.stopTimer = timer
		}
	}
	state.mu.Unlock()
	st.mu.Unlock()

	if !valid {
		timer.Stop()
		return
	}
	if replaced != nil && replaced != timer {
		replaced.Stop()
	}
}

func (st *Streamer) dispatchOnDemandCallback(state *activeStream, generation uint64, start bool) {
	if err := st.beginOperation(); err != nil {
		return
	}
	defer st.endOperation()

	st.mu.Lock()
	current := st.streams[state.id]
	var callback func(RegistrationToken)
	if start {
		callback = st.onDemandStart
	} else {
		callback = st.onDemandStop
	}
	if current != state || callback == nil {
		st.mu.Unlock()
		return
	}
	state.mu.RLock()
	valid := state.generation == generation && state.cfg.OnDemand
	if start {
		valid = valid && state.state == streamStatePlaceholder && state.clientCount > 0
	} else {
		valid = valid && state.state == streamStateActive && state.clientCount == 0
	}
	state.mu.RUnlock()
	st.mu.Unlock()
	if !valid {
		return
	}
	callback(RegistrationToken{StreamID: state.id, Generation: generation})
}

func (st *Streamer) runStream(state *activeStream, run *streamRun) {
	defer close(run.done)
	for {
		select {
		case <-run.ctx.Done():
			return
		default:
		}

		packet, err := run.src.ReadPacket()
		if err != nil {
			if run.ctx.Err() != nil {
				return
			}
			if run.guarded && errors.Is(err, io.EOF) {
				st.retireTerminalRun(state, run)
				return
			}
			select {
			case <-run.ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if run.ctx.Err() != nil {
			return
		}

		state.mu.Lock()
		if state.run != run || state.generation != run.generation || state.state != streamStateActive {
			state.mu.Unlock()
			return
		}
		state.packets++
		clients := make([]*tsClient, 0, len(state.clients))
		for _, client := range state.clients {
			clients = append(clients, client)
		}
		segments := state.segments
		state.mu.Unlock()

		for _, client := range clients {
			client.write(packet)
		}
		if run.outputs != nil && run.outputs.udpWriter != nil {
			if len(packet) == 188 {
				var p mpegts.Packet
				copy(p[:], packet)
				_ = run.outputs.udpWriter.TryEnqueue(p)
			}
		} else if run.outputs != nil && run.outputs.udp != nil {
			_, _ = run.outputs.udp.Write(packet)
		}
		if run.outputs != nil && run.outputs.srtWriter != nil {
			if len(packet) == 188 {
				var p mpegts.Packet
				copy(p[:], packet)
				_ = run.outputs.srtWriter.TryEnqueue(p)
			}
		} else if run.outputs != nil && run.outputs.srt != nil {
			run.outputs.srt.Write(packet)
		}
		if segments != nil {
			segments.WritePacket(packet)
		}
	}
}

// A terminal source cannot unregister itself: normal detach joins run.done.
// Retain its token and run for checked scheduler cleanup, while consuming only
// this generation's sinks here. Replacement and shutdown may join us safely.
func (st *Streamer) retireTerminalRun(state *activeStream, run *streamRun) {
	st.mu.Lock()
	state.mu.Lock()
	if st.streams[state.id] != state || state.run != run || state.generation != run.generation {
		state.mu.Unlock()
		st.mu.Unlock()
		return
	}
	state.terminal = true
	resources := st.detachStateResourcesLocked(state, true)
	state.run = run
	// Retain only the closed buffer's budget identity so a concurrent
	// replacement cannot reset its per-stream cap while old responses pin slabs.
	state.segments = resources.segments
	resources.run = nil
	state.mu.Unlock()
	st.mu.Unlock()
	run.cancel()
	run.retirementErr = errors.Join(run.closeSource(), cleanupDetached(resources))
}

func (client *tsClient) write(packet []byte) {
	if client.writer != nil {
		if len(packet) == 188 {
			var p mpegts.Packet
			copy(p[:], packet)
			_ = client.writer.TryEnqueue(p)
		}
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return
	}
	if _, err := client.w.Write(packet); err != nil {
		client.closed = true
		return
	}
	client.flusher.Flush()
}

func (st *Streamer) handleStream(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/stream/")
	parts := strings.Split(path, ".")
	if len(parts) < 2 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	st.serveStreamByID(w, r, parts[0])
}

func (st *Streamer) handleCustomPath(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	if st.routeLookupProbes != nil {
		st.routeLookupProbes.Add(1)
	}
	route, found := st.publishedPaths.aliases[r.URL.Path]
	segment := false
	if !found {
		if base, valid := numericSegmentBase(r.URL.Path); valid {
			if st.routeLookupProbes != nil {
				st.routeLookupProbes.Add(1)
			}
			route, found = st.publishedPaths.aliases[base]
			found = found && route.base == base
			segment = found
		}
	}
	st.mu.Unlock()
	switch {
	case !found:
		http.Error(w, "not found", http.StatusNotFound)
	case segment:
		st.serveHLSSegmentByPublication(w, r, route.publication, r.URL.Path)
	case route.playlist:
		st.serveHLSPlaylistByPublication(w, r, route.publication, route.base)
	default:
		st.serveStreamByPublication(w, r, route.publication)
	}
}

func (st *Streamer) serveHLSPlaylist(w http.ResponseWriter, r *http.Request, id, baseURL string) {
	st.serveHLSPlaylistState(w, r, st.streamByID(id), baseURL)
}

func (st *Streamer) serveHLSPlaylistByPublication(w http.ResponseWriter, r *http.Request, publication pathPublication, baseURL string) {
	st.serveHLSPlaylistState(w, r, st.streamByPublication(publication), baseURL)
}

func (st *Streamer) serveHLSPlaylistState(w http.ResponseWriter, r *http.Request, state *activeStream, baseURL string) {
	if state == nil {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	if stageCState(state) {
		st.serveStageCPlaylist(w, r, state, baseURL)
		return
	}
	if !st.streamClientConnectedPolicy(state, true) {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	defer st.streamClientDisconnectedPolicy(state, true)
	state.mu.RLock()
	segments := state.segments
	state.mu.RUnlock()
	playlist := segments.Playlist(baseURL)
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(playlist)
}

func (st *Streamer) serveHLSSegment(w http.ResponseWriter, r *http.Request, id, path string) {
	st.serveHLSSegmentState(w, r, st.streamByID(id), path)
}

func (st *Streamer) serveHLSSegmentByPublication(w http.ResponseWriter, r *http.Request, publication pathPublication, path string) {
	st.serveHLSSegmentState(w, r, st.streamByPublication(publication), path)
}

func (st *Streamer) serveHLSSegmentState(w http.ResponseWriter, r *http.Request, state *activeStream, path string) {
	if state == nil {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	if stageCState(state) {
		st.serveStageCSegment(w, r, state, path)
		return
	}
	if !st.streamClientConnectedPolicy(state, true) {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	defer st.streamClientDisconnectedPolicy(state, true)

	base := strings.TrimSuffix(path, ".ts")
	lastUnderscore := strings.LastIndex(base, "_")
	if lastUnderscore < 0 {
		http.Error(w, "invalid segment path", http.StatusBadRequest)
		return
	}
	index, err := strconv.Atoi(base[lastUnderscore+1:])
	if err != nil {
		http.Error(w, "invalid segment index", http.StatusBadRequest)
		return
	}
	state.mu.RLock()
	segments := state.segments
	state.mu.RUnlock()
	data, found := segments.Segment(index)
	if !found {
		http.Error(w, "segment not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Cache-Control", "max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (st *Streamer) serveStreamByID(w http.ResponseWriter, r *http.Request, id string) {
	st.serveStreamState(w, r, st.streamByID(id))
}

func (st *Streamer) serveStreamByPublication(w http.ResponseWriter, r *http.Request, publication pathPublication) {
	st.serveStreamState(w, r, st.streamByPublication(publication))
}

func (st *Streamer) serveStreamState(w http.ResponseWriter, r *http.Request, state *activeStream) {
	if state == nil {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	if stageCState(state) {
		st.serveStageCStream(w, r, state)
		return
	}
	if !st.streamClientConnectedPolicy(state, true) {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	defer st.streamClientDisconnectedPolicy(state, true)

	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()

	clientID := r.RemoteAddr + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	client := &tsClient{w: w, flusher: flusher}
	state.mu.Lock()
	state.clients[clientID] = client
	state.mu.Unlock()
	<-r.Context().Done()
	client.mu.Lock()
	client.closed = true
	client.mu.Unlock()
	state.mu.Lock()
	delete(state.clients, clientID)
	state.mu.Unlock()
}

func (st *Streamer) streamByID(id string) *activeStream {
	st.mu.Lock()
	state := st.streams[id]
	st.mu.Unlock()
	return state
}

func (st *Streamer) streamByPublication(publication pathPublication) *activeStream {
	st.mu.Lock()
	state := st.streams[publication.streamID]
	if state != nil {
		state.mu.RLock()
		valid := state.generation == publication.generation
		state.mu.RUnlock()
		if !valid {
			state = nil
		}
	}
	st.mu.Unlock()
	return state
}

func (st *Streamer) handleHLS(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/hls/")
	if strings.HasSuffix(path, ".ts") {
		st.handleHLSSegment(w, r, path)
		return
	}
	if !strings.HasSuffix(path, ".m3u8") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := strings.TrimSuffix(path, ".m3u8")
	st.serveHLSPlaylist(w, r, id, "/hls/"+id)
}

func (st *Streamer) handleHLSSegment(w http.ResponseWriter, r *http.Request, path string) {
	base := strings.TrimSuffix(path, ".ts")
	parts := strings.Split(base, "_")
	if len(parts) != 2 {
		http.Error(w, "invalid segment path", http.StatusBadRequest)
		return
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		http.Error(w, "invalid segment index", http.StatusBadRequest)
		return
	}
	st.serveHLSSegment(w, r, parts[0], "/hls/"+path)
}

type stageCHTTPRequest struct {
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	lease    *viewerLease
	state    *activeStream
	clientID string
}

func stageCState(state *activeStream) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return stageCEnabled(state.cfg)
}
func (st *Streamer) admitStageCHTTP(w http.ResponseWriter, r *http.Request, state *activeStream, kind viewerKind) (*stageCHTTPRequest, *http.ResponseController, error) {
	if !st.stageCResources.available() {
		return nil, nil, ErrStageCSinksUnavailable
	}
	lease, err := st.stageCResources.Viewers.Acquire(state.id, kind)
	if err != nil {
		return nil, nil, err
	}
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
		lease.Release()
		return nil, nil, ErrStageCSinksUnavailable
	}
	if !st.streamClientConnected(state) {
		lease.Release()
		return nil, nil, ErrStreamNotFound
	}
	ctx, cancel := context.WithCancel(r.Context())
	request := &stageCHTTPRequest{ctx: ctx, cancel: cancel, done: make(chan struct{}), lease: lease, state: state}
	st.mu.Lock()
	state.mu.Lock()
	valid := !st.closing && st.streams[state.id] == state && !state.terminal && stageCEnabled(state.cfg)
	if valid {
		if state.stageCRequests == nil {
			state.stageCRequests = make(map[*stageCHTTPRequest]struct{})
		}
		state.stageCRequests[request] = struct{}{}
	}
	state.mu.Unlock()
	st.mu.Unlock()
	if !valid {
		st.finishStageCHTTP(request)
		return nil, nil, ErrStageCSinksUnavailable
	}
	return request, controller, nil
}
func (st *Streamer) finishStageCHTTP(request *stageCHTTPRequest) {
	request.cancel()
	state := request.state
	state.mu.Lock()
	delete(state.stageCRequests, request)
	if request.clientID != "" {
		delete(state.clients, request.clientID)
	}
	state.mu.Unlock()
	request.lease.Release()
	st.streamClientDisconnected(state)
	close(request.done)
}
func stageCFlushAvailable(w http.ResponseWriter) bool {
	for depth := 0; depth < 32; depth++ {
		if _, ok := w.(interface{ FlushError() error }); ok {
			return true
		}
		if _, ok := w.(http.Flusher); ok {
			return true
		}
		wrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = wrapper.Unwrap()
	}
	return false
}
func (st *Streamer) serveStageCStream(w http.ResponseWriter, r *http.Request, state *activeStream) {
	request, controller, err := st.admitStageCHTTP(w, r, state, viewerTS)
	if err != nil {
		http.Error(w, "Stage C stream unavailable", http.StatusServiceUnavailable)
		return
	}
	defer st.finishStageCHTTP(request)
	if !stageCFlushAvailable(w) {
		http.Error(w, "Stage C flush unavailable", http.StatusServiceUnavailable)
		return
	}
	writer, err := newPacketWriter(func(packet []byte) error {
		if err := controller.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
			return err
		}
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
		return controller.Flush()
	}, func() error { return nil }, st.stageCResources.PacketBudget)
	if err != nil {
		http.Error(w, "Stage C packet capacity", http.StatusServiceUnavailable)
		return
	}
	defer writer.Close()
	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		return
	}
	request.clientID = strconv.FormatUint(st.nextClient.Add(1), 10)
	state.mu.Lock()
	state.clients[request.clientID] = &tsClient{writer: writer}
	state.mu.Unlock()
	select {
	case <-request.ctx.Done():
	case <-writer.Done():
	case <-st.stageCStop:
	}
	request.cancel()
}

// A request owns its bounded HTTP write until completion. Cancellation may
// shorten the deadline; joining the interrupter prevents a stale deadline
// update racing the next response on a reused HTTP connection.
func (st *Streamer) writeStageCResponse(w http.ResponseWriter, request *stageCHTTPRequest, controller *http.ResponseController, data []byte, contentType, cache string) {
	if request.ctx.Err() != nil {
		return
	}
	if err := controller.SetWriteDeadline(st.deps.now().Add(time.Second)); err != nil {
		http.Error(w, "Stage C deadline unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", cache)
	w.WriteHeader(http.StatusOK)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(request.ctx, func() { _ = controller.SetWriteDeadline(st.deps.now()); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	_, _ = w.Write(data)
}
func (st *Streamer) serveStageCPlaylist(w http.ResponseWriter, r *http.Request, state *activeStream, baseURL string) {
	request, controller, err := st.admitStageCHTTP(w, r, state, viewerHLS)
	if err != nil {
		http.Error(w, "Stage C HLS unavailable", http.StatusServiceUnavailable)
		return
	}
	defer st.finishStageCHTTP(request)
	state.mu.RLock()
	segments := state.segments
	state.mu.RUnlock()
	if segments == nil || segments.bounded == nil {
		http.Error(w, "Stage C HLS unavailable", http.StatusServiceUnavailable)
		return
	}
	if segments.CapacityError() != nil {
		http.Error(w, "Stage C HLS capacity", http.StatusServiceUnavailable)
		return
	}
	playlist, err := segments.acquirePlaylist(baseURL)
	if err != nil {
		http.Error(w, "Stage C HLS capacity", http.StatusServiceUnavailable)
		return
	}
	defer playlist.Release()
	st.writeStageCResponse(w, request, controller, playlist.Bytes(), "application/vnd.apple.mpegurl", "no-cache")
}
func (st *Streamer) serveStageCSegment(w http.ResponseWriter, r *http.Request, state *activeStream, path string) {
	request, controller, err := st.admitStageCHTTP(w, r, state, viewerHLS)
	if err != nil {
		http.Error(w, "Stage C HLS unavailable", http.StatusServiceUnavailable)
		return
	}
	defer st.finishStageCHTTP(request)
	base := strings.TrimSuffix(path, ".ts")
	separator := strings.LastIndex(base, "_")
	if separator < 0 {
		http.Error(w, "invalid segment path", http.StatusBadRequest)
		return
	}
	index, err := strconv.Atoi(base[separator+1:])
	if err != nil {
		http.Error(w, "invalid segment index", http.StatusBadRequest)
		return
	}
	state.mu.RLock()
	segments := state.segments
	state.mu.RUnlock()
	if segments == nil || segments.bounded == nil {
		http.Error(w, "Stage C HLS unavailable", http.StatusServiceUnavailable)
		return
	}
	lease, err := segments.AcquireSegment(index)
	if err != nil {
		if errors.Is(err, ErrHLSSegmentNotFound) {
			http.Error(w, "segment not found", http.StatusNotFound)
		} else {
			http.Error(w, "Stage C HLS unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	defer lease.Release()
	st.writeStageCResponse(w, request, controller, lease.Bytes(), "video/mp2t", "max-age=60")
}
