// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"errors"
	"sync"

	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
)

var (
	ErrPacketWriterOverflow = errors.New("stage_c_writer_overflow")
	ErrPacketWriterClosed   = errors.New("stage_c_writer_closed")
)

type packetWriter struct {
	mu             sync.Mutex
	queue          [64]mpegts.Packet
	head           int
	count          int
	closed         bool
	err            error
	wake           chan struct{}
	stop           chan struct{}
	done           chan struct{}
	write          func([]byte) error
	closeTransport func() error
	reservation    *packetbudget.Reservation
}

func newPacketWriter(write func([]byte) error, closeTransport func() error, budget *packetbudget.Budget) (*packetWriter, error) {
	if budget == nil || write == nil || closeTransport == nil {
		return nil, ErrStageCSinksUnavailable
	}
	// 64 queued packet values and one private in-flight packet value.
	reservation, err := budget.Reserve(65 * 188)
	if err != nil {
		return nil, err
	}
	w := &packetWriter{wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), write: write, closeTransport: closeTransport, reservation: reservation}
	go w.run()
	return w, nil
}
func (w *packetWriter) stopLocked() {
	if !w.closed {
		w.closed = true
		close(w.stop)
	}
}
func (w *packetWriter) TryEnqueue(packet mpegts.Packet) error {
	if w == nil {
		return ErrPacketWriterClosed
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrPacketWriterClosed
	}
	if w.count == len(w.queue) {
		w.stopLocked()
		return ErrPacketWriterOverflow
	}
	w.queue[(w.head+w.count)%len(w.queue)] = packet
	w.count++
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}
func (w *packetWriter) run() {
	defer func() {
		err := w.closeTransport()
		w.mu.Lock()
		w.stopLocked()
		w.err = err
		w.queue = [64]mpegts.Packet{}
		w.count = 0
		w.mu.Unlock()
		w.reservation.Release()
		close(w.done)
	}()
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return
		}
		if w.count == 0 {
			w.mu.Unlock()
			select {
			case <-w.stop:
				return
			case <-w.wake:
			}
			continue
		}
		packet := w.queue[w.head]
		w.queue[w.head] = mpegts.Packet{}
		w.head = (w.head + 1) % len(w.queue)
		w.count--
		w.mu.Unlock()
		// The callback owns a finite deadline. Neither callback runs under a
		// source/registration/broker mutex, and close never races an active write.
		if err := w.write(packet[:]); err != nil {
			return
		}
	}
}

// Signal every member of a fanout before joining any individual writer.
func (w *packetWriter) requestStop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.stopLocked()
	w.mu.Unlock()
}
func (w *packetWriter) Close() error {
	if w == nil {
		return nil
	}
	w.requestStop()
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
func (w *packetWriter) Done() <-chan struct{} { return w.done }
