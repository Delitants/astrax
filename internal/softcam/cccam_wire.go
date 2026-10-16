// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

type cccamFrame struct {
	Flags   byte
	Command byte
	Payload []byte
}

// readFrame has one owner, writeFrame has one other owner. Neither may be shared.
// The parent cancellation hook stays armed across login and session ownership.
type cccamWire struct {
	clientIdentity   [8]byte
	identityRetained bool
	conn             net.Conn
	receive          *cccamCipher
	send             *cccamCipher
	pending          []cccamFrame
	stopParent       func() bool
	parentClosed     <-chan struct{}
	closeOnce        sync.Once
	closeErr         error
	parentOnce       sync.Once
}

// Hooks close only the socket; owner cleanup separately disarms/joins them.
// Keeping the join outside the close owner prevents callback self-joining.
func (w *cccamWire) closeConn() error {
	w.closeOnce.Do(func() {
		w.closeErr = w.conn.Close()
	})
	return w.closeErr
}

func (w *cccamWire) Close() error {
	err := w.closeConn()
	w.parentOnce.Do(func() {
		if w.stopParent != nil && !w.stopParent() {
			<-w.parentClosed
		}
	})
	return err
}

func (w *cccamWire) readFrame() (cccamFrame, error) {
	if len(w.pending) > 0 {
		frame := w.pending[0]
		w.pending[0] = cccamFrame{}
		w.pending = w.pending[1:]
		return frame, nil
	}
	return w.readSocketFrame()
}

func (w *cccamWire) readSocketFrame() (cccamFrame, error) {
	var header [4]byte
	if _, err := io.ReadFull(w.conn, header[:]); err != nil {
		w.Close()
		return cccamFrame{}, protocolError("invalid_frame", err)
	}
	w.receive.decrypt(header[:])
	size := int(binary.BigEndian.Uint16(header[2:]))
	if size > cccamMaxPayload {
		w.Close()
		return cccamFrame{}, protocolError("invalid_frame", nil)
	}
	frame := cccamFrame{Flags: header[0], Command: header[1], Payload: make([]byte, size)}
	if _, err := io.ReadFull(w.conn, frame.Payload); err != nil {
		w.Close()
		return cccamFrame{}, protocolError("invalid_frame", err)
	}
	w.receive.decrypt(frame.Payload)
	return frame, nil
}

func (w *cccamWire) writeFrame(frame cccamFrame) error {
	if len(frame.Payload) > cccamMaxPayload {
		return protocolError("invalid_frame", nil)
	}
	packet := make([]byte, 4+len(frame.Payload))
	packet[0], packet[1] = frame.Flags, frame.Command
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(frame.Payload)))
	copy(packet[4:], frame.Payload)
	return w.writeEncrypted(packet)
}

func (w *cccamWire) writeEncrypted(packet []byte) error {
	w.send.encrypt(packet)
	// Encrypt once: partial writes retry only the remaining ciphertext.
	for len(packet) > 0 {
		n, err := w.conn.Write(packet)
		if n < 0 || n > len(packet) {
			err = io.ErrShortWrite
			n = 0
		}
		packet = packet[n:]
		if err != nil {
			w.Close()
			return err
		}
		if n == 0 {
			w.Close()
			return io.ErrShortWrite
		}
	}
	return nil
}
