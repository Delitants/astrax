// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"astrax/internal/model"
)

func validateCCcamProfile(p model.Softcam) (time.Duration, error) {
	if normalizeSoftcamType(p.Type) != "cccam" || strings.TrimSpace(p.Host) == "" || strings.ContainsAny(p.Host, "\x00\r\n") || p.Port < 1 || p.Port > 65535 ||
		len(p.Username) == 0 || len(p.Username) > 20 || strings.ContainsRune(p.Username, 0) ||
		len(p.Password) == 0 || len(p.Password) > 64 || strings.ContainsRune(p.Password, 0) ||
		p.ConnectTimeoutSec < 0 || p.ConnectTimeoutSec > 120 {
		return 0, protocolError("invalid_configuration", nil)
	}
	seconds := p.ConnectTimeoutSec
	if seconds == 0 {
		seconds = 6
	}
	return time.Duration(seconds) * time.Second, nil
}

func validateCCcamLoginAck(ack []byte) error {
	if len(ack) != 20 || !bytes.Equal(ack[:6], []byte("CCcam\x00")) {
		return protocolError("login_rejected", nil)
	}
	return nil
}

func cccamLoginError(parent, budget context.Context, code string, err error) error {
	if parent.Err() != nil {
		return protocolError("cancelled", parent.Err())
	}
	var timeout net.Error
	if budget.Err() != nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		return protocolError("login_timeout", context.DeadlineExceeded)
	}
	var protocol *ProtocolError
	if errors.As(err, &protocol) {
		return err
	}
	return protocolError(code, err)
}

func loginCCcam(parent context.Context, p model.Softcam, opts cccamOptions) (_ *cccamWire, _ time.Duration, resultErr error) {
	timeout, err := validateCCcamProfile(p)
	if err != nil {
		return nil, 0, err
	}
	if err := opts.validate(); err != nil {
		return nil, 0, err
	}
	start := time.Now()
	budget, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if parent.Err() != nil {
		return nil, 0, protocolError("cancelled", parent.Err())
	}
	conn, err := opts.dial(budget, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, 0, cccamLoginError(parent, budget, "dial_failed", err)
	}
	if conn == nil {
		return nil, 0, cccamLoginError(parent, budget, "dial_failed", nil)
	}
	wire := &cccamWire{conn: conn}
	parentClosed := make(chan struct{})
	wire.parentClosed = parentClosed
	wire.stopParent = context.AfterFunc(parent, func() { defer close(parentClosed); wire.closeConn() })
	budgetClosed := make(chan struct{})
	stopBudget := context.AfterFunc(budget, func() { defer close(budgetClosed); wire.closeConn() })
	budgetStopped := false
	defer func() {
		if !budgetStopped && !stopBudget() {
			<-budgetClosed
		}
		if resultErr != nil {
			wire.Close()
			clear(wire.clientIdentity[:])
			wire.identityRetained = false
		}
	}()
	deadline, _ := budget.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, cccamLoginError(parent, budget, "login_rejected", err)
	}
	if err := cccamHandshake(wire, p, opts); err != nil {
		return nil, 0, cccamLoginError(parent, budget, "login_rejected", err)
	}
	// Disarm/join only the temporary budget. The parent hook never stops here.
	budgetStopped = true
	if !stopBudget() {
		<-budgetClosed
		return nil, 0, cccamLoginError(parent, budget, "login_timeout", budget.Err())
	}
	if err := budget.Err(); err != nil {
		return nil, 0, cccamLoginError(parent, budget, "login_timeout", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, 0, cccamLoginError(parent, budget, "login_rejected", err)
	}
	// Check again at transfer; a concurrent cancellation still closes via the hook.
	if err := budget.Err(); err != nil {
		return nil, 0, cccamLoginError(parent, budget, "login_timeout", err)
	}
	if err := parent.Err(); err != nil {
		return nil, 0, protocolError("cancelled", err)
	}
	return wire, time.Since(start), nil
}

func cccamHandshake(w *cccamWire, p model.Softcam, opts cccamOptions) error {
	var seed [16]byte
	if _, err := io.ReadFull(w.conn, seed[:]); err != nil {
		return err
	}
	for index := 0; index < 8; index++ {
		seed[8+index] = byte(index) * seed[index]
	}
	for index, value := range []byte("CCcam\x00") {
		seed[index] ^= value
	}
	digest := sha1.Sum(seed[:])
	w.receive, _ = newCCcamCipher(digest[:])
	w.receive.decrypt(seed[:])
	w.send, _ = newCCcamCipher(seed[:])
	w.send.decrypt(digest[:])
	if err := w.writeEncrypted(digest[:]); err != nil {
		return err
	}
	username := make([]byte, 20)
	copy(username, p.Username)
	if err := w.writeEncrypted(username); err != nil {
		return err
	}
	// Password bytes advance only the outbound state; they are never transmitted.
	password := []byte(p.Password)
	w.send.encrypt(password)
	clear(password)
	if err := w.writeEncrypted([]byte("CCcam\x00")); err != nil {
		return err
	}
	var ack [20]byte
	if _, err := io.ReadFull(w.conn, ack[:]); err != nil {
		return err
	}
	w.receive.decrypt(ack[:])
	if err := validateCCcamLoginAck(ack[:]); err != nil {
		return err
	}
	info := make([]byte, 93)
	copy(info, p.Username)
	if _, err := io.ReadFull(opts.random, info[20:28]); err != nil {
		return err
	}
	copy(w.clientIdentity[:], info[20:28])
	w.identityRetained = true
	copy(info[29:], "2.3.2")
	copy(info[61:], "4000")
	if err := w.writeFrame(cccamFrame{Command: 0, Payload: info}); err != nil {
		return err
	}
	return w.awaitClientInfoAck()
}

func (w *cccamWire) awaitClientInfoAck() error {
	var control cccamControl
	var lastPeerReply time.Time
	for {
		frame, err := w.readSocketFrame()
		if err != nil {
			return err
		}
		if frame.Flags != 0 && frame.Command != 0 {
			return protocolError("unsupported_protocol", nil)
		}
		switch frame.Command {
		case 0:
			if frame.Flags != 0 || len(frame.Payload) != 0 {
				return protocolError("login_rejected", nil)
			}
			return nil
		case 7, 15:
			if _, err := parseCCcamCard(frame.Payload, frame.Command == 15); err != nil {
				return err
			}
		case 4:
			if _, err := parseCCcamRemoval(frame.Payload); err != nil {
				return err
			}
		case 6:
			if len(frame.Payload) != 0 {
				return protocolError("unsupported_protocol", nil)
			}
			if time.Since(lastPeerReply) < cccamLivenessBudget {
				continue
			}
			if len(w.pending) >= cccamControlQueue {
				return protocolError("inventory_limit", nil)
			}
			if err := w.writeFrame(cccamFrame{Command: 6}); err != nil {
				return err
			}
			lastPeerReply = time.Now()
			// Retain a handled-probe marker for handoff suppression, not liveness.
		default:
			reply, err := control.interpret(frame)
			if err != nil {
				return err
			}
			if reply != nil {
				// Login still exclusively owns I/O and its absolute socket budget.
				if err := w.writeFrame(*reply); err != nil {
					return err
				}
				continue
			}
		}
		if len(w.pending) >= cccamControlQueue {
			return protocolError("inventory_limit", nil)
		}
		w.pending = append(w.pending, frame)
	}
}
