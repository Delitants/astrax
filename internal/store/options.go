// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"time"

	"astrax/internal/adapters"
	"astrax/internal/csa"
	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/packetbudget"
)

type Options struct {
	// Injected cipher/budget resources are borrowed, never closed by Store.
	DescramblingBackend csa.Backend
	PacketBudget        *packetbudget.Budget

	// SoftcamTester supplies the complete explicit Test boundary. A nil value uses
	// the process-wide default tester; an injected runner never falls back to it.
	// Runners must join and close their temporary sessions before returning.
	SoftcamTester func(context.Context, model.Softcam) (*model.SoftcamTestResult, error)

	RuntimeFactory  func(model.Settings) (RuntimeDependencies, error)
	Now             func() time.Time
	DVBOpener       dvb.SessionOpener
	AdapterDetector adapters.Detector
	DisableRuntime  bool
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DVBOpener == nil {
		o.DVBOpener = dvb.SystemSessionOpener{}
	}
	if o.AdapterDetector == nil {
		o.AdapterDetector = adapters.SystemDetector{}
	}
	return o
}
