// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package csa

// Backend decrypts a bounded batch of non-overlapping MPEG-TS payload slices
// using one control word. It never owns caller packets or retains their pointers.
// Decrypt and Close are safe to call concurrently; callers must not concurrently
// mutate or read the same payload slices while Decrypt is running.
type Backend interface {
	BatchSize() int
	Decrypt(cw [8]byte, payloads [][]byte) error
	Close() error
}

// Error contains a stable machine-readable code, never control words or packets.
type Error struct {
	Code string
}

func (e Error) Error() string {
	switch e.Code {
	case "backend_unavailable":
		return "CSA backend unavailable"
	case "backend_closed":
		return "CSA backend closed"
	case "unsupported_abi":
		return "CSA backend ABI unsupported"
	case "allocation_failed":
		return "CSA backend allocation failed"
	case "invalid_payload":
		return "CSA payload invalid"
	case "capacity":
		return "CSA batch capacity exceeded"
	default:
		return "CSA backend error"
	}
}

// New requires an explicitly enabled, supported native backend. Ordinary builds
// keep CSA unavailable; selecting a softcam profile does not enable a cipher.
func New() (Backend, error) { return newBackend() }

// Capability reports whether a CSA backend is available in this build.
func Capability() (available bool, reason string) {
	return backendCapability()
}
