//go:build unix

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"fmt"
	"os"
	"syscall"
)

func preserveOutputOwner(f *os.File, original os.FileInfo) error {
	want, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unavailable original ownership")
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	got, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unavailable temporary file ownership")
	}
	if want.Uid == got.Uid && want.Gid == got.Gid {
		return nil
	}
	return f.Chown(int(want.Uid), int(want.Gid))
}
