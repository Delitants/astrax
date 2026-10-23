// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"astrax/internal/model"
)

func TestAdminAuthMarkerAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := NewDormant(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.AdminAuthInitialized() {
		t.Fatal("new config starts initialized")
	}
	s.testHookConfigWrite = &atomicWriteHooks{beforeRename: func(_, _ string) error { return errors.New("injected failure") }}
	if err := s.MarkAdminAuthInitialized(); err == nil {
		t.Fatal("marker write failure not returned")
	}
	if s.AdminAuthInitialized() {
		t.Fatal("failed marker was published in memory")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _, err := loadConfig(path, s.now()); err != nil || cfg.AdminAuthInitialized {
		t.Fatalf("failed marker appeared on disk: %v, %s", err, data)
	}
	s.testHookConfigWrite = nil
	if err := s.MarkAdminAuthInitialized(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAdminAuthInitialized(); err != nil {
		t.Fatalf("idempotent marker failed: %v", err)
	}
	if !s.AdminAuthInitialized() {
		t.Fatal("marker not published")
	}
	var cfg model.Config
	if cfg, _, err = loadConfig(path, s.now()); err != nil || !cfg.AdminAuthInitialized {
		t.Fatalf("marker not durable: %v", err)
	}
}
