//go:build !dvbcsa

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package csa

func newBackend() (Backend, error) {
	return nil, Error{Code: "backend_unavailable"}
}

func backendCapability() (available bool, reason string) {
	return false, "backend_unavailable"
}
