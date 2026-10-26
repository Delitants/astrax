//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"
	"errors"
	"io"
)

func writeDVBOwnerSnapshot(context.Context, io.Writer) error {
	return errors.New("DVB ownership reader requires Linux")
}
