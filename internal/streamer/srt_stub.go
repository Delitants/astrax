//go:build !cgo

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"errors"

	"astrax/internal/packetbudget"
)

var errSRTUnavailable = errors.New("SRT unavailable: requires CGo and native libsrt")

// SRTAvailable reports compiled native support, not a successful peer connection.
func SRTAvailable() bool { return false }

func initSRT() {}

type srtListener struct{}

func setupSRTListener(string, *packetbudget.Budget) (*srtListener, error) {
	return nil, errSRTUnavailable
}

// Setup never returns this listener; its methods only keep cleanup terminal.
func (*srtListener) Start()       {}
func (*srtListener) AcceptLoop()  {}
func (*srtListener) Write([]byte) {}
func (*srtListener) Close() error { return errSRTUnavailable }
func (*srtListener) Done() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
