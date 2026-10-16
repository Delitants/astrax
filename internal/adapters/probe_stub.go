//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"

	"astrax/internal/model"
)

func linuxDVBCards(ctx context.Context) ([]model.DVBCard, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []model.DVBCard{}, nil
}

func linuxDVBAdapters() []model.Adapter {
	return nil
}
