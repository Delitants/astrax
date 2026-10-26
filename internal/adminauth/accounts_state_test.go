// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func accountStateDocument(t *testing.T, config string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(StatePath(config))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func assertVersion2Admin(t *testing.T, config, salt, hash string) {
	t.Helper()
	doc := accountStateDocument(t, config)
	if string(doc["version"]) != "2" {
		t.Fatalf("durable version = %s, want 2", doc["version"])
	}
	if _, ok := doc["password_hash"]; ok {
		t.Fatal("version 2 retained a top-level password verifier")
	}
	var users []struct {
		Username     string `json:"username"`
		Role         string `json:"role"`
		Enabled      bool   `json:"enabled"`
		PasswordSalt string `json:"password_salt"`
		PasswordHash string `json:"password_hash"`
	}
	if err := json.Unmarshal(doc["users"], &users); err != nil || len(users) != 1 {
		t.Fatalf("initial users = %s, error = %v", doc["users"], err)
	}
	u := users[0]
	if u.Username != "admin" || u.Role != "administrator" || !u.Enabled {
		t.Fatalf("initial user = %+v", u)
	}
	if salt != "" && (u.PasswordSalt != salt || u.PasswordHash != hash) {
		t.Fatal("migration replaced the existing password verifier")
	}
	if !verifySecret(testPassword, u.PasswordSalt, u.PasswordHash) {
		t.Fatal("admin password no longer verifies")
	}
}

func TestAccountsEnrollmentWritesVersion2(t *testing.T) {
	config, m, secret := newTestManager(t)
	if string(accountStateDocument(t, config)["version"]) != "2" {
		t.Fatal("new pending setup is not version 2")
	}
	if err := m.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
	assertVersion2Admin(t, config, "", "")
}

func TestAccountsMigrateLegacyEnrolledVerifier(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(map[bool]string{false: "before marker", true: "after marker"}[initialized], func(t *testing.T) {
			config := filepath.Join(t.TempDir(), "legacy.json")
			salt := []byte("legacy-salt-1234")
			old := authState{Version: 1, Phase: "enrolled", PasswordSalt: encode(salt), PasswordHash: encode(hashSecret(testPassword, salt))}
			data, err := json.Marshal(old)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(StatePath(config), data, 0o600); err != nil {
				t.Fatal(err)
			}
			m, err := Open(config, initialized)
			if err != nil {
				t.Fatal(err)
			}
			assertVersion2Admin(t, config, old.PasswordSalt, old.PasswordHash)
			if _, err := m.Login("legacy", testPassword); err != nil {
				t.Fatal(err)
			}
			m.Close()
			before, _ := os.ReadFile(StatePath(config))
			reopened, err := Open(config, true)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			after, _ := os.ReadFile(StatePath(config))
			if !bytes.Equal(before, after) {
				t.Fatal("restart rewrote migrated verifiers")
			}
		})
	}
}

func TestAccountsMigrateLegacyPendingSetup(t *testing.T) {
	config, first, secret := newTestManager(t)
	old := first.state
	first.Close()
	old.Version = 1
	if err := persistState(config, old); err != nil {
		t.Fatal(err)
	}
	m, err := Open(config, true)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	doc := accountStateDocument(t, config)
	if string(doc["version"]) != "2" || string(doc["setup_salt"]) != `"`+old.SetupSalt+`"` || string(doc["setup_hash"]) != `"`+old.SetupHash+`"` {
		t.Fatal("pending migration did not preserve the existing setup verifier")
	}
	if err := m.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
	assertVersion2Admin(t, config, "", "")
}
