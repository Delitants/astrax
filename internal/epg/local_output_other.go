//go:build !unix

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import "os"

func preserveOutputOwner(_ *os.File, _ os.FileInfo) error { return nil }
