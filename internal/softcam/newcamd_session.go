// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"astrax/internal/model"
)

const newcamdControlQueue = 32

type newcamdProbe struct {
	id                        uint16
	issued, written, received bool
	deadline                  time.Time
	notify                    chan struct{}
}
type newcamdOutbound struct {
	frame    newcamdFrame
	deadline time.Time
	probe    *newcamdProbe
}
type newcamdSession struct {
	ctx                   context.Context
	conn                  net.Conn
	cipher                cipher.Block
	random                io.Reader
	mu                    sync.Mutex
	msgID                 uint16
	card                  *newcamdCard
	cardID                uint32
	cardRevision          uint64
	authenticated, closed bool
	err, cleanupErr       error
	ecmEpoch              uint64
	ecmPending            *newcamdECMTransaction
	ecmRetiring           bool
	probe                 *newcamdProbe
	issuedProbeIDs        [1024]uint64 // Bounded lifetime history for all 16-bit IDs.
	outbound              []newcamdOutbound
	writerWake            chan struct{}
	done                  chan struct{}
	shutdownOnce          sync.Once
	loops                 sync.WaitGroup
}

var _ caidSession = (*newcamdSession)(nil)
var _ sessionStatusProvider = (*newcamdSession)(nil)

func (*newcamdSession) nativeNewcamd() {}

func openNewcamdSession(profile model.Softcam) (*newcamdSession, time.Duration, error) {
	return openNewcamdSessionContext(context.Background(), profile)
}
func openNewcamdSessionContext(ctx context.Context, profile model.Softcam) (*newcamdSession, time.Duration, error) {
	return openNewcamdSessionWithOptions(ctx, profile, defaultNewcamdOptions())
}
func openNewcamdSessionWithOptions(ctx context.Context, profile model.Softcam, opts newcamdOptions) (*newcamdSession, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e := ctx.Err(); e != nil {
		return nil, 0, newcamdError("cancelled", e)
	}
	// Validate the raw saved password before hashing, which would otherwise hide NUL.
	if opts.dial == nil || opts.random == nil || profile.Username == "" || profile.Password == "" || strings.ContainsRune(profile.Password, 0) {
		return nil, 0, newcamdError("invalid_configuration", nil)
	}
	keyBytes, e := parseDESKey(profile.DESKey)
	if e != nil {
		return nil, 0, newcamdError("invalid_configuration", e)
	}
	if len(profile.Username) > newcamdMaxFramePayload-5 || strings.ContainsRune(profile.Username, 0) {
		return nil, 0, newcamdError("invalid_configuration", nil)
	}
	password, e := md5Crypt(profile.Password, "abcdefgh")
	if e != nil {
		return nil, 0, newcamdError("invalid_configuration", e)
	}
	payload, e := newcamdLoginPayload(profile.Username, password)
	if e != nil {
		return nil, 0, e
	}
	var key [14]byte
	copy(key[:], keyBytes)
	timeout := time.Duration(profile.ConnectTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = defaultConnectTimeoutSec * time.Second
	}
	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, e := opts.dial(dialCtx, "tcp", net.JoinHostPort(profile.Host, fmt.Sprint(profile.Port)))
	cancel()
	if e != nil {
		if conn != nil {
			e = errors.Join(e, newcamdError("session_closed", conn.Close()))
		}
		if ctx.Err() != nil {
			e = errors.Join(ctx.Err(), e)
			return nil, 0, newcamdError("cancelled", e)
		}
		return nil, 0, newcamdError("dial_failed", e)
	}
	if conn == nil {
		return nil, 0, newcamdError("dial_failed", nil)
	}
	s := &newcamdSession{ctx: ctx, conn: conn, random: opts.random, writerWake: make(chan struct{}, 1), done: make(chan struct{})}
	// This joined watcher owns cancellation even while the opener is doing I/O.
	s.loops.Add(1)
	go func() {
		defer s.loops.Done()
		select {
		case <-ctx.Done():
			s.shutdown(newcamdError("cancelled", ctx.Err()))
		case <-s.done:
		}
	}()
	fail := func(e error) (*newcamdSession, time.Duration, error) {
		s.shutdown(e)
		cleanup := s.Close()
		return nil, 0, errors.Join(s.closedError(), cleanup)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(20 * time.Second)
	}
	loginDeadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(loginDeadline) {
		loginDeadline = d
	}
	if e = conn.SetDeadline(loginDeadline); e != nil {
		return fail(newcamdError("login_timeout", e))
	}
	var challenge [14]byte
	if _, e = io.ReadFull(conn, challenge[:]); e != nil {
		return fail(newcamdOpenError(e))
	}
	s.cipher, e = deriveNewcamdCipher(key, challenge[:])
	if e != nil {
		return fail(e)
	}
	if e = s.writeFrame(newcamdFrame{ServiceID: 0x8888, Payload: payload}, loginDeadline); e != nil {
		return fail(newcamdOpenError(e))
	}
	ack, e := readNewcamdFrame(conn, s.cipher)
	if e != nil {
		return fail(newcamdOpenError(e))
	}
	if ack.MessageID != 0 || len(ack.Payload) != 3 {
		return fail(newcamdError("invalid_frame", nil))
	}
	standardHeader := ack.ServiceID == 0 && ack.Reserved == ([6]byte{})
	// OSCam mgclient marks only LOGIN_ACK with SID "ns" and header byte 0x14.
	mgclientHeader := ack.Payload[0] == newcamdCmdLoginAck && ack.ServiceID == 0x6e73 && ack.Reserved == ([6]byte{0, 0, 0, 0, 0, 0x14})
	if !standardHeader && !mgclientHeader {
		return fail(newcamdError("invalid_frame", nil))
	}
	if ack.Payload[0] == newcamdCmdLoginNak {
		return fail(newcamdError("login_rejected", nil))
	}
	if ack.Payload[0] != newcamdCmdLoginAck {
		return fail(newcamdError("invalid_frame", nil))
	}
	s.mu.Lock()
	e = s.stateErrorLocked()
	if e == nil {
		s.authenticated = true
	}
	s.mu.Unlock()
	if e != nil {
		return fail(e)
	}
	s.cipher, e = deriveNewcamdCipher(key, []byte(password))
	if e != nil {
		return fail(e)
	}
	discovery := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(discovery) {
		discovery = d
	}
	if e = conn.SetDeadline(discovery); e != nil {
		return fail(newcamdOpenError(e))
	}
	s.mu.Lock()
	id, e := s.nextIDLocked()
	s.mu.Unlock()
	if e != nil {
		return fail(e)
	}
	if e = s.writeFrame(newcamdFrame{MessageID: id, Payload: []byte{newcamdCmdGetCAID, 0, 0}}, discovery); e != nil {
		return fail(newcamdOpenError(e))
	}
	f, e := readNewcamdFrame(conn, s.cipher)
	if e != nil {
		return fail(newcamdOpenError(e))
	}
	if f.MessageID != id || f.ServiceID != 0 || f.Reserved != ([6]byte{}) || f.Payload[0] != newcamdCmdCAIDAck {
		return fail(newcamdError("invalid_frame", nil))
	}
	card, e := decodeNewcamdCardData(f.Payload)
	if e != nil {
		return fail(e)
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return fail(newcamdOpenError(e))
	}
	s.mu.Lock()
	e = s.stateErrorLocked()
	if e == nil && card.CAID != 0 {
		s.card = &card
		s.cardID = 1
		s.cardRevision = 1
	}
	s.mu.Unlock()
	if e != nil {
		return fail(e)
	}
	s.loops.Add(2)
	go s.readLoop()
	go s.writeLoop()
	if e = ctx.Err(); e != nil {
		return fail(newcamdError("cancelled", e))
	}
	return s, time.Since(start), nil
}
func newcamdOpenError(e error) error {
	var n net.Error
	if errors.As(e, &n) && n.Timeout() {
		return newcamdError("login_timeout", e)
	}
	var p *newcamdProtocolError
	if errors.As(e, &p) {
		return e
	}
	return newcamdError("invalid_frame", e)
}
func readNewcamdFrame(r io.Reader, block cipher.Block) (newcamdFrame, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return newcamdFrame{}, newcamdError("invalid_frame", e)
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 16 || n > newcamdMaxWireLength || (n-8)%8 != 0 {
		return newcamdFrame{}, newcamdError("invalid_frame", nil)
	}
	wire := make([]byte, n+2)
	copy(wire, h[:])
	if _, e := io.ReadFull(r, wire[2:]); e != nil {
		return newcamdFrame{}, newcamdError("invalid_frame", e)
	}
	return decodeNewcamdFrame(block, wire)
}

// Only the opening I/O owner, then the single writer, calls this method.
func (s *newcamdSession) writeFrame(f newcamdFrame, deadline time.Time) error {
	if !time.Now().Before(deadline) {
		return newcamdError("keepalive_timeout", context.DeadlineExceeded)
	}
	if e := s.conn.SetWriteDeadline(deadline); e != nil {
		return e
	}
	s.mu.Lock()
	e := s.stateErrorLocked()
	if e == nil && !time.Now().Before(deadline) {
		e = newcamdError("keepalive_timeout", context.DeadlineExceeded)
	}
	// Allocation is not issue: early responses while preparing a deadline fail.
	if e == nil && f.MessageID != 0 && f.Payload[0] == newcamdCmdKeepAlive && s.probe != nil && s.probe.id == f.MessageID {
		s.probe.issued = true
		s.issuedProbeIDs[f.MessageID/64] |= uint64(1) << (f.MessageID % 64)
	}
	s.mu.Unlock()
	if e != nil {
		return e
	}
	wire, e := encodeNewcamdFrame(s.cipher, f, s.random)
	if e != nil {
		return e
	}
	if f.Payload[0] == 0x80 || f.Payload[0] == 0x81 {
		s.mu.Lock()
		tx := s.ecmPending
		if tx == nil || !tx.writerOwned || tx.id != f.MessageID || tx.err != nil {
			e = ecmError("ecm_stale", nil)
		} else {
			e = tx.validateLocked(time.Now())
			if e == nil {
				tx.issued = true
			}
		}
		s.mu.Unlock()
		if e != nil {
			clear(wire)
			return e
		}
	}
	defer clear(wire)
	n, e := s.conn.Write(wire)
	if e != nil {
		return e
	}
	if n != len(wire) {
		return io.ErrShortWrite
	}
	if !time.Now().Before(deadline) {
		return newcamdError("keepalive_timeout", context.DeadlineExceeded)
	}
	return nil
}
func (s *newcamdSession) stateErrorLocked() error {
	if s.closed {
		return s.err
	}
	if e := s.ctx.Err(); e != nil {
		return newcamdError("cancelled", e)
	}
	if s.ecmRetiring {
		return newcamdError("session_closed", nil)
	}
	return nil
}
func (s *newcamdSession) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.stateErrorLocked(); e != nil {
		return e
	}
	return newcamdError("session_closed", nil)
}
func (s *newcamdSession) SessionStatus() SessionStatus { st, _ := s.sessionState(); return st }
func (s *newcamdSession) sessionState() (SessionStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.stateErrorLocked(); e != nil {
		return SessionStatus{}, e
	}
	count := 0
	if s.card != nil {
		count = 1
	}
	return SessionStatus{Authenticated: s.authenticated, CardsObserved: count}, nil
}
func (s *newcamdSession) GetCAIDs() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.stateErrorLocked(); e != nil {
		return nil, e
	}
	if s.card == nil {
		return []string{}, nil
	}
	return []string{fmt.Sprintf("%04X", s.card.CAID)}, nil
}

// Signal/close once, without joining the caller's own reader/writer/watcher.
func (s *newcamdSession) shutdown(cause error) {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		if e := s.ctx.Err(); e != nil {
			cause = newcamdError("cancelled", errors.Join(e, cause))
		}
		if cause == nil {
			cause = newcamdError("session_closed", nil)
		}
		s.closed = true
		s.authenticated = false
		s.err = cause
		s.card = nil
		s.cardID = 0
		s.cardRevision = 0
		s.ecmRetiring = true
		if tx := s.ecmPending; tx != nil {
			if tx.err == nil {
				tx.err = ecmError("ecm_session_unavailable", cause)
			}
			tx.keys = ecmKeys{}
			tx.section = nil
			tx.notifyLocked()
		}
		clear(s.outbound)
		s.outbound = nil
		close(s.done)
		s.mu.Unlock()
		e := s.conn.Close()
		if e != nil {
			s.mu.Lock()
			s.cleanupErr = newcamdError("session_closed", e)
			s.mu.Unlock()
		}
	})
}
func (s *newcamdSession) Close() error {
	s.shutdown(nil)
	s.loops.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupErr
}
func (s *newcamdSession) wakeWriter() {
	select {
	case s.writerWake <- struct{}{}:
	default:
	}
}
func (s *newcamdSession) nextIDLocked() (uint16, error) {
	if e := s.stateErrorLocked(); e != nil {
		return 0, e
	}
	if s.msgID == 65535 {
		return 0, newcamdError("session_closed", nil)
	}
	s.msgID++
	return s.msgID, nil
}
func (s *newcamdSession) enqueueLocked(op newcamdOutbound) error {
	if e := s.stateErrorLocked(); e != nil {
		return e
	}
	if len(s.outbound) >= newcamdControlQueue {
		return newcamdError("invalid_frame", nil)
	}
	s.outbound = append(s.outbound, op)
	s.wakeWriter()
	return nil
}
func (s *newcamdSession) KeepAlive(timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = keepAliveTimeout
	}
	start := time.Now()
	p := &newcamdProbe{deadline: start.Add(timeout), notify: make(chan struct{}, 1)}
	s.mu.Lock()
	e := s.stateErrorLocked()
	if e == nil && s.probe != nil {
		e = newcamdError("probe_busy", nil)
	}
	if e == nil {
		s.probe = p
		e = s.enqueueLocked(newcamdOutbound{frame: newcamdFrame{Payload: []byte{newcamdCmdKeepAlive, 0, 0}}, deadline: p.deadline, probe: p})
	}
	s.mu.Unlock()
	if e != nil {
		if _, code := safeNewcamdError(e); code != "probe_busy" {
			s.shutdown(e)
		}
		return 0, e
	}
	timer := time.NewTimer(max(time.Until(p.deadline), 0))
	defer timer.Stop()
	for {
		s.mu.Lock()
		e = s.stateErrorLocked()
		ready := p.written && p.received
		if e == nil && ready {
			s.probe = nil
		}
		s.mu.Unlock()
		if e != nil {
			return 0, e
		}
		if ready {
			return time.Since(start), nil
		}
		select {
		case <-s.done:
			return 0, s.closedError()
		case <-p.notify:
		case <-timer.C:
			s.shutdown(newcamdError("keepalive_timeout", context.DeadlineExceeded))
			return 0, s.closedError()
		}
	}
}
func (s *newcamdSession) writeLoop() {
	defer s.loops.Done()
	for {
		s.mu.Lock()
		if s.stateErrorLocked() != nil {
			s.mu.Unlock()
			return
		}
		var op newcamdOutbound
		found := len(s.outbound) > 0
		if found {
			op = s.outbound[0]
			copy(s.outbound, s.outbound[1:])
			s.outbound[len(s.outbound)-1] = newcamdOutbound{}
			s.outbound = s.outbound[:len(s.outbound)-1]
		}
		var tx *newcamdECMTransaction
		if !found && s.ecmPending != nil && !s.ecmPending.selected && s.ecmPending.err == nil {
			tx = s.ecmPending
			tx.selected = true
		}
		var e error
		if found && op.probe != nil {
			op.frame.MessageID, e = s.nextIDLocked()
			if e == nil {
				op.probe.id = op.frame.MessageID
			}
		}
		s.mu.Unlock()
		if tx != nil {
			s.writeECM(tx)
			continue
		}
		if !found {
			select {
			case <-s.done:
				return
			case <-s.writerWake:
				continue
			}
		}
		if e == nil {
			e = s.writeFrame(op.frame, op.deadline)
		}
		if e != nil {
			s.shutdown(newcamdControlError(e))
			return
		}
		if op.probe != nil {
			s.mu.Lock()
			op.probe.written = true
			select {
			case op.probe.notify <- struct{}{}:
			default:
			}
			s.mu.Unlock()
		}
	}
}
func newcamdControlError(e error) error {
	var n net.Error
	if errors.As(e, &n) && n.Timeout() {
		return newcamdError("keepalive_timeout", e)
	}
	var p *newcamdProtocolError
	if errors.As(e, &p) {
		return e
	}
	return newcamdError("invalid_frame", e)
}
func (s *newcamdSession) readLoop() {
	defer s.loops.Done()
	for {
		f, e := readNewcamdFrame(s.conn, s.cipher)
		if e == nil {
			s.mu.Lock()
			correlated := s.ecmPending != nil && s.ecmPending.id != 0 && s.ecmPending.id == f.MessageID
			s.mu.Unlock()
			if correlated || f.Payload[0] == 0x80 || f.Payload[0] == 0x81 {
				e = s.handleECMResponse(f)
			} else {
				e = s.handleControl(f)
			}
		}
		if e != nil {
			s.shutdown(e)
			return
		}
	}
}
func (s *newcamdSession) handleControl(f newcamdFrame) error {
	if f.Reserved != ([6]byte{}) {
		return newcamdError("unsupported_protocol", nil)
	}
	if f.Payload[0] != newcamdCmdKeepAlive {
		if f.Payload[0] == 0x80 || f.Payload[0] == 0x81 {
			return newcamdError("unsupported_protocol", nil)
		}
		return newcamdError("invalid_frame", nil)
	}
	if len(f.Payload) != 3 {
		return newcamdError("invalid_frame", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.stateErrorLocked(); e != nil {
		return e
	}
	if p := s.probe; p != nil {
		if !p.issued || p.id != f.MessageID || p.received || !time.Now().Before(p.deadline) {
			return newcamdError("invalid_frame", nil)
		}
		p.received = true
		select {
		case p.notify <- struct{}{}:
		default:
		}
		return nil
	}
	// A completed client reply never becomes an unsolicited peer request.
	if s.issuedProbeIDs[f.MessageID/64]&(uint64(1)<<(f.MessageID%64)) != 0 {
		return newcamdError("invalid_frame", nil)
	}
	return s.enqueueLocked(newcamdOutbound{frame: f, deadline: time.Now().Add(keepAliveTimeout)})
}
