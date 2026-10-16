//go:build dvbcsa && (!linux || !cgo)

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package csa

// Opt-in on an unsupported platform must not silently select the default stub.
var _ = dvbcsa_requires_linux_and_cgo__use_GOOS_linux_and_CGO_ENABLED_1

func newBackend() (Backend, error) {
	return nil, Error{Code: "backend_unavailable"}
}

func backendCapability() (bool, string) { return false, "backend_unavailable" }
