// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var errOutputSuperseded = errors.New("EPG output superseded")

// The old feed remains visible until the complete, synced temporary file is
// renamed within the same directory. The caller fences only the final rename.
func writeLocalAtomic(path string, data []byte, replace func(string, string) error) (retErr error) {
	mode := os.FileMode(0644)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output target must be a regular file")
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create output temp: %w", err)
	}
	closed, renamed := false, false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, f.Close())
		}
		if !renamed {
			retErr = errors.Join(retErr, os.Remove(f.Name()))
		}
	}()
	if info != nil {
		if err := preserveOutputOwner(f, info); err != nil {
			return fmt.Errorf("preserve output owner: %w", err)
		}
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("output permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	err = f.Close()
	closed = true
	if err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if replace == nil {
		replace = os.Rename
	}
	if err := replace(f.Name(), path); err != nil {
		if errors.Is(err, errOutputSuperseded) {
			return nil
		}
		return fmt.Errorf("replace output: %w", err)
	}
	renamed = true
	return nil
}
