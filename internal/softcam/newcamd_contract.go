// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
)

type newcamdFrame struct {
	MessageID, ServiceID uint16
	Reserved             [6]byte
	Payload              []byte
}

type newcamdCard struct {
	CAID      uint16
	Providers []uint32
}

type newcamdOptions struct {
	dial   func(context.Context, string, string) (net.Conn, error)
	random io.Reader
}

func defaultNewcamdOptions() newcamdOptions {
	dialer := &net.Dialer{}
	return newcamdOptions{dial: dialer.DialContext, random: rand.Reader}
}

// Causes remain available for ownership/cleanup, never for public formatting.
type newcamdProtocolError struct {
	Code  string
	cause error
}

func newcamdSafeCode(code string) string {
	switch code {
	case "invalid_configuration", "dial_failed", "login_rejected", "login_timeout",
		"unsupported_protocol", "invalid_frame", "inventory_limit", "keepalive_timeout",
		"probe_busy", "session_closed", "cancelled":
		return code
	default:
		return "protocol_error"
	}
}

func (e *newcamdProtocolError) Error() string {
	code := "protocol_error"
	if e != nil {
		code = newcamdSafeCode(e.Code)
	}
	switch code {
	case "invalid_configuration":
		return "Newcamd invalid configuration"
	case "dial_failed":
		return "Newcamd connection failed"
	case "login_rejected":
		return "Newcamd login rejected"
	case "login_timeout":
		return "Newcamd login timed out"
	case "unsupported_protocol":
		return "Newcamd unsupported protocol"
	case "invalid_frame":
		return "Newcamd invalid frame"
	case "inventory_limit":
		return "Newcamd card inventory limit exceeded"
	case "keepalive_timeout":
		return "Newcamd keepalive timed out"
	case "probe_busy":
		return "Newcamd keepalive already pending"
	case "session_closed":
		return "Newcamd session closed"
	case "cancelled":
		return "Newcamd operation cancelled"
	default:
		return "Newcamd protocol error"
	}
}

func (e *newcamdProtocolError) GoString() string { return e.Error() }

func (e *newcamdProtocolError) MarshalJSON() ([]byte, error) {
	code := "protocol_error"
	if e != nil {
		code = newcamdSafeCode(e.Code)
	}
	return json.Marshal(struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}{e.Error(), code})
}

func (e *newcamdProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func newcamdError(code string, cause error) error {
	return &newcamdProtocolError{Code: newcamdSafeCode(code), cause: cause}
}

func safeNewcamdError(err error) (message, code string) {
	if err == nil {
		return "", ""
	}
	code = "protocol_error"
	var pe *newcamdProtocolError
	if errors.As(err, &pe) && pe != nil {
		code = newcamdSafeCode(pe.Code)
	}
	if errors.Is(err, context.Canceled) {
		code = "cancelled"
	}
	return (&newcamdProtocolError{Code: code}).Error(), code
}
