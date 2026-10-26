//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnershipEnumerationRejectsSymlinksBeforeOpening(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "frontend0"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := readOwnerDeviceDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory: %v, %v", entries, err)
	}
	link := filepath.Join(t.TempDir(), "adapter0")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerDeviceDir(link); err == nil {
		t.Fatal("symlink directory opened by privileged reader")
	}
	if _, err := readOwnerDeviceDir(filepath.Join(dir, "frontend0")); err == nil {
		t.Fatal("non-directory opened by privileged reader")
	}
}

func TestHelperOwnershipMissingAndUnknownRemainClosed(t *testing.T) {
	helper := helperFixture(t, "printf '%s' '"+validOwnerSnapshot+"'\n")
	paths := []string{"/dev/dvb/adapter0/frontend0", "/dev/dvb/adapter36/frontend0", "/dev/dvb/adapter59/frontend0"}
	owners, err := helperOwnerLookup(helper)(context.Background(), "/must-not-be-read", paths)
	if err != nil {
		t.Fatal(err)
	}
	if owners[paths[0]].pid != 7506 || owners[paths[0]].free {
		t.Fatalf("busy frontend admitted: %#v", owners[paths[0]])
	}
	if !owners[paths[1]].free || owners[paths[1]].warning != "" {
		t.Fatalf("conclusive free frontend lost: %#v", owners[paths[1]])
	}
	if owners[paths[2]].free || owners[paths[2]].warning == "" {
		t.Fatalf("missing frontend admitted: %#v", owners[paths[2]])
	}
}

func TestHelperFailureNeverFallsBackToUnprivilegedSnapshot(t *testing.T) {
	helper := helperFixture(t, "exit 2\n")
	if owners, err := helperOwnerLookup(helper)(context.Background(), "/proc", []string{"/dev/dvb/adapter0/frontend0"}); err == nil || owners != nil {
		t.Fatalf("failed helper accepted: %#v, %v", owners, err)
	}
}
