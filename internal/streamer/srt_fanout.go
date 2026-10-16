// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"errors"
	"io"
	"sync"
	"time"

	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
)

// Transport calls must return by their deadline; Close owns no active Send.
type srtPeerTransport interface {
	Send([]byte, time.Time) (int, error)
	Close() error
}

type srtAcceptTransport interface {
	Accept() (srtPeerTransport, error)
	Close() error
}

// Ordinary SRT has its own shared process ceiling. It is never substituted for
// the exact caller-owned Stage C budget; native Stage C admission remains held.
var ordinarySRTBudget = packetbudget.New(128 << 20)

type srtFanout struct {
	mu         sync.Mutex
	transport  srtAcceptTransport
	budget     *packetbudget.Budget
	now        func() time.Time
	clients    map[*packetWriter]struct{}
	started    bool
	closed     bool
	stop       chan struct{}
	acceptDone chan struct{}
	done       chan struct{}
	peers      sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
}

func newSRTFanout(transport srtAcceptTransport, budget *packetbudget.Budget, now func() time.Time) (*srtFanout, error) {
	if transport == nil || budget == nil || now == nil {
		return nil, ErrStageCSinksUnavailable
	}
	return &srtFanout{transport: transport, budget: budget, now: now, clients: make(map[*packetWriter]struct{}), stop: make(chan struct{}), acceptDone: make(chan struct{}), done: make(chan struct{})}, nil
}
func (h *srtFanout) Start() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started || h.closed {
		return
	}
	h.started = true
	go h.acceptLoop()
}
func (h *srtFanout) recordError(err error) {
	h.mu.Lock()
	// Retain one bounded diagnostic, not an unbounded error chain per peer.
	if h.closeErr == nil {
		h.closeErr = err
	}
	h.mu.Unlock()
}
func (h *srtFanout) acceptLoop() {
	defer close(h.acceptDone)
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		peer, err := h.transport.Accept()
		if err != nil || peer == nil {
			if peer != nil {
				h.recordError(peer.Close())
			}
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-h.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			h.recordError(peer.Close())
			return
		}
		writer, err := newPacketWriter(func(packet []byte) error {
			n, err := peer.Send(packet, h.now().Add(time.Second))
			if err == nil && n != len(packet) {
				err = io.ErrShortWrite
			}
			return err
		}, peer.Close, h.budget)
		if err != nil {
			h.mu.Unlock()
			h.recordError(peer.Close())
			continue
		}
		h.clients[writer] = struct{}{}
		h.peers.Add(1)
		h.mu.Unlock()
		go func() {
			defer h.peers.Done()
			<-writer.Done()
			err := writer.Close()
			h.mu.Lock()
			delete(h.clients, writer)
			if h.closeErr == nil {
				h.closeErr = err
			}
			h.mu.Unlock()
		}()
	}
}
func (h *srtFanout) Write(packet []byte) {
	if len(packet) != 188 {
		return
	}
	var owned mpegts.Packet
	copy(owned[:], packet)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	for writer := range h.clients {
		// Enqueue never performs transport I/O or waits for a slow peer.
		_ = writer.TryEnqueue(owned)
	}
}
func (h *srtFanout) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		close(h.stop)
		writers := make([]*packetWriter, 0, len(h.clients))
		for writer := range h.clients {
			writers = append(writers, writer)
		}
		if !h.started {
			close(h.acceptDone)
		}
		h.mu.Unlock()
		for _, writer := range writers {
			writer.requestStop()
		}
		err := h.transport.Close()
		<-h.acceptDone
		h.peers.Wait()
		h.mu.Lock()
		h.closeErr = errors.Join(h.closeErr, err)
		h.mu.Unlock()
		close(h.done)
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closeErr
}
func (h *srtFanout) Done() <-chan struct{} { return h.done }
