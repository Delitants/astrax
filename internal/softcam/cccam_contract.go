// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"crypto/rand"
	"io"
	"net"
)

const (
	cccamMaxPayload     = 32 * 1024
	cccamMaxCards       = 1024
	cccamMaxProviders   = 256
	cccamControlQueue   = 32
	softcamTestCapacity = 4
)

// ProtocolError preserves a private cause without reflecting it in public copy.
type ProtocolError struct {
	Code  string
	cause error
}

func (e *ProtocolError) Error() string {
	switch e.Code {
	case "invalid_configuration":
		return "CCcam invalid configuration"
	case "dial_failed":
		return "CCcam connection failed"
	case "login_rejected":
		return "CCcam login rejected"
	case "login_timeout":
		return "CCcam login timed out"
	case "unsupported_protocol":
		return "CCcam unsupported protocol"
	case "invalid_frame":
		return "CCcam invalid frame"
	case "inventory_limit":
		return "CCcam card inventory limit exceeded"
	case "keepalive_timeout":
		return "CCcam keepalive timed out"
	case "probe_busy":
		return "CCcam keepalive already pending"
	case "session_closed":
		return "CCcam session closed"
	case "cancelled":
		return "CCcam operation cancelled"
	default:
		return "CCcam protocol error"
	}
}

func (e *ProtocolError) Unwrap() error { return e.cause }

func protocolError(code string, cause error) error {
	return &ProtocolError{Code: code, cause: cause}
}

// Authentication and inventory do not imply media descrambling support.
type SessionStatus struct {
	Authenticated bool
	CardsObserved int
}

type sessionStatusProvider interface {
	SessionStatus() SessionStatus
}

// Runtime consumers sample the terminal cause and metadata under one lock.
// SessionStatus keeps its existing metadata-only contract for other callers.
type sessionStateProvider interface {
	sessionState() (SessionStatus, error)
}

type cccamOptions struct {
	dial   func(context.Context, string, string) (net.Conn, error)
	random io.Reader
}

func defaultCCcamOptions() cccamOptions {
	dialer := &net.Dialer{}
	return cccamOptions{dial: dialer.DialContext, random: rand.Reader}
}

func (o cccamOptions) validate() error {
	if o.dial == nil || o.random == nil {
		return protocolError("invalid_configuration", nil)
	}
	return nil
}
