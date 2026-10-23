// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"astrax/internal/adminauth"
)

func TestDirectSettingsSaveDoesNotOpenAdministratorState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	st, err := NewWithOptions(path, Options{DisableRuntime: true})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	settings := st.Settings()
	settings.ControlListen = "0.0.0.0:18080"
	if _, err := st.SetSettings(settings); err != nil {
		t.Fatal(err)
	}
	if got := st.Settings().ControlListen; got != "0.0.0.0:18080" {
		t.Fatalf("default wildcard normalization changed persisted value: %q", got)
	}
	if _, err := st.PatchSettings(map[string]json.RawMessage{"control_listen": json.RawMessage(`"127.0.0.1:18080"`)}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	settings.ControlListen = "192.0.2.10:18080"
	if _, err := st.SetSettings(settings); err == nil {
		t.Fatal("plaintext LAN address accepted by direct Store setter")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) || st.Settings().ControlListen != "127.0.0.1:18080" {
		t.Fatal("rejected direct Store settings changed configuration")
	}
	for _, sidecar := range []string{adminauth.StatePath(path), adminauth.SetupSecretPath(path)} {
		if _, err := os.Stat(sidecar); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("settings save touched administrator sidecar %q: %v", sidecar, err)
		}
	}
}
