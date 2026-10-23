// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"astrax/internal/model"
)

func TestLegacyControlListenMigration(t *testing.T) {
	for _, tt := range []struct{ old, want string }{
		{"0.0.0.0:8080", "127.0.0.1:8080"},
		{":8080", "127.0.0.1:8080"},
		{"[::]:8080", "[::1]:8080"},
		{"0.0.0.0:18080", "127.0.0.1:18080"},
		{"127.0.0.1:8080", "127.0.0.1:8080"},
	} {
		t.Run(tt.old, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			original := []byte(`{"schema_version":` + "2" + `,"settings":{"control_listen":"` + tt.old + `","control_listen_https":"0.0.0.0:8443"}}`)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			s, err := NewDormant(path, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got := s.Settings()
			if got.ControlListen != tt.want || got.ControlListenHTTPS != "0.0.0.0:8443" {
				t.Fatalf("settings = %+v", got)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"control_listen": "`+tt.want+`"`) && !strings.Contains(string(data), `"control_listen":"`+tt.want+`"`) {
				t.Fatalf("migration not durable: %s", data)
			}
		})
	}
}

func TestManagementTransportNewInstallDefaultLoopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := NewDormant(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Settings().ControlListen; got != "127.0.0.1:8080" {
		t.Fatalf("new install HTTP management address = %q", got)
	}
}

func TestLegacyControlListenDoesNotMigrateMalformedWildcard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	original := []byte(`{"schema_version":2,"settings":{"control_listen":"0.0.0.0:bad"}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, result, err := loadConfig(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.migrated || cfg.Settings.ControlListen != "0.0.0.0:bad" {
		t.Fatalf("malformed address was rewritten: %+v %+v", cfg.Settings, result)
	}
}

func TestLegacyControlListenMigrationAtomicFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	original := []byte(`{"schema_version":2,"settings":{"control_listen":"0.0.0.0:8080"}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, result, err := loadConfig(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !result.migrated || cfg.Settings.ControlListen != "127.0.0.1:8080" {
		t.Fatalf("migration = %+v, %+v", cfg.Settings, result)
	}
	ops := defaultMigrationFileOps()
	ops.write = func(string, model.Config, []byte) error { return errors.New("injected atomic write failure") }
	if err := persistMigratedConfig(path, cfg, result, time.Now(), ops); err == nil {
		t.Fatal("failed write appeared successful")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("source changed after failed migration: %q, %v", got, err)
	}
}
