// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountsRejectAmbiguousJSONState(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "alice", RoleViewer)
	data, err := os.ReadFile(StatePath(m.configPath))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, tc := range []struct{ name, data string }{
		{"duplicate root field", strings.Replace(text, `"version":2`, `"version":1,"version":2`, 1)},
		{"duplicate user role", strings.Replace(text, `"role":"administrator"`, `"role":"viewer","role":"administrator"`, 1)},
		{"duplicate enabled", strings.Replace(text, `"enabled":true`, `"enabled":false,"enabled":true`, 1)},
		{"case alias root", strings.Replace(text, `"version":2`, `"Version":2`, 1)},
		{"case alias user", strings.Replace(text, `"username":"admin"`, `"Username":"admin"`, 1)},
		{"missing enabled", strings.Replace(text, `"username":"alice","role":"viewer","enabled":true,`, `"username":"alice","role":"viewer",`, 1)},
		{"null enabled", strings.Replace(text, `"username":"alice","role":"viewer","enabled":true`, `"username":"alice","role":"viewer","enabled":null`, 1)},
		{"null legacy field", strings.TrimSuffix(text, "}") + `,"password_salt":null}`},
		{"empty legacy field", strings.TrimSuffix(text, "}") + `,"password_hash":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseState([]byte(tc.data)); !errors.Is(err, errInvalidState) {
				t.Fatalf("ambiguous state accepted: %v", err)
			}
		})
	}
}

func TestAccountsRejectInvalidVersion2State(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "alice", RoleViewer)
	valid := m.state
	for _, tc := range []struct {
		name   string
		mutate func(*authState)
	}{
		{"future version", func(s *authState) { s.Version = 3 }},
		{"v1 with named users", func(s *authState) {
			s.Version = 1
			s.PasswordSalt = s.Users[0].PasswordSalt
			s.PasswordHash = s.Users[0].PasswordHash
		}},
		{"missing users", func(s *authState) { s.Users = nil }},
		{"no enabled administrator", func(s *authState) { s.Users[0].Enabled = false }},
		{"no administrator role", func(s *authState) { s.Users[0].Role = RoleOperator }},
		{"unknown role", func(s *authState) { s.Users[1].Role = "root" }},
		{"noncanonical username", func(s *authState) { s.Users[1].Username = "ALICE" }},
		{"unsafe username", func(s *authState) { s.Users[1].Username = "../alice" }},
		{"duplicate username", func(s *authState) { s.Users[1].Username = "admin" }},
		{"truncated salt", func(s *authState) { s.Users[1].PasswordSalt = "abc" }},
		{"truncated verifier", func(s *authState) { s.Users[1].PasswordHash = "abc" }},
		{"top-level verifier", func(s *authState) { s.PasswordSalt = s.Users[0].PasswordSalt; s.PasswordHash = s.Users[0].PasswordHash }},
		{"65 accounts", func(s *authState) { s.Users = append(s.Users, make([]userState, 63)...) }},
		{"pending with users", func(s *authState) {
			s.Phase = "pending"
			s.SetupSalt = s.Users[0].PasswordSalt
			s.SetupHash = s.Users[0].PasswordHash
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := valid
			next.Users = append([]userState(nil), valid.Users...)
			tc.mutate(&next)
			data, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseState(data); !errors.Is(err, errInvalidState) {
				t.Fatalf("invalid state accepted: %v", err)
			}
		})
	}
	data, _ := json.Marshal(valid)
	for _, suffix := range []string{`{}`, ` true`, strings.Repeat(" ", maxStateBytes)} {
		config := filepath.Join(t.TempDir(), "invalid.json")
		if err := os.WriteFile(StatePath(config), append(data, suffix...), 0o600); err != nil {
			t.Fatal(err)
		}
		if other, err := Open(config, true); err == nil {
			other.Close()
			t.Fatal("trailing/oversize state accepted on restart")
		}
	}
}

func TestAccountsTamperClosesAllSessionsPermanently(t *testing.T) {
	for _, kind := range []string{"valid role change", "malformed verifier", "deleted file", "permissions", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			m, admin := accountAdmin(t)
			accountCreate(t, m, admin, "alice", RoleViewer)
			alice := accountLogin(t, m, "alice", testPassword)
			path := StatePath(m.configPath)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "valid role change":
				err = os.WriteFile(path, bytes.Replace(original, []byte(`"role":"viewer"`), []byte(`"role":"operator"`), 1), 0o600)
			case "malformed verifier":
				err = os.WriteFile(path, []byte(`{"version":2,"phase":"enrolled","users":[]}`), 0o600)
			case "deleted file":
				err = os.Remove(path)
			case "permissions":
				err = os.Chmod(path, 0o644)
			case "symlink":
				target := path + ".target"
				if err := os.WriteFile(target, original, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(path, path+".linked")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Users(admin.Token); !errors.Is(err, ErrForbidden) {
				t.Fatalf("tamper did not deny administrator: %v", err)
			}
			accountSessions(t, m, false, admin, alice)
			if kind == "symlink" || kind == "hardlink" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.LoginUser("restored", "admin", testPassword); err == nil {
				t.Fatal("restoring state reopened a fail-closed manager")
			}
			if _, err := m.CreateUser(admin.Token, "after-tamper", testPassword, RoleViewer); !errors.Is(err, ErrForbidden) {
				t.Fatalf("closed manager mutated state: %v", err)
			}
			if err := m.ChangePassword(alice.Token, testPassword, accountNewPassword); err == nil {
				t.Fatal("closed manager accepted self password change")
			}
		})
	}
}

func TestAccountsStaleManagerCannotOverwriteAccounts(t *testing.T) {
	m, admin := accountAdmin(t)
	other, err := Open(m.configPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	stale := accountLogin(t, other, "admin", testPassword)
	accountCreate(t, m, admin, "alice", RoleViewer)
	before, _ := os.ReadFile(StatePath(m.configPath))
	if _, err := other.CreateUser(stale.Token, "stale-write", testPassword, RoleOperator); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stale manager error = %v", err)
	}
	after, _ := os.ReadFile(StatePath(m.configPath))
	if !bytes.Equal(before, after) {
		t.Fatal("stale manager overwrote newer accounts")
	}
	accountSessions(t, other, false, stale)
	accountSessions(t, m, true, admin)
}

func TestAccountsLegacyMigrationNeverChangesConfig(t *testing.T) {
	config := filepath.Join(t.TempDir(), "legacy.json")
	original := []byte("existing-main-config-must-not-change\n")
	if err := os.WriteFile(config, original, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("legacy-salt-1234")
	state := authState{Version: 1, Phase: "enrolled", PasswordSalt: encode(salt), PasswordHash: encode(hashSecret(testPassword, salt))}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(StatePath(config), data, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Open(config, true)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	assertVersion2Admin(t, config, state.PasswordSalt, state.PasswordHash)
	after, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(config)
	if !bytes.Equal(original, current) || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("migration modified the main config")
	}
	info, err := os.Stat(StatePath(config))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("migration did not preserve owner-only state")
	}
}

func TestAccountsLoginFailuresAreGenericAndShareLimits(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "disabled", RoleViewer)
	disabled := false
	if _, err := m.UpdateUser(admin.Token, "disabled", UserUpdate{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ username, password string }{
		{"missing", testPassword}, {"disabled", testPassword}, {"admin", "wrong"}, {"", testPassword},
		{strings.Repeat("a", 129), testPassword}, {"admin", strings.Repeat("p", 1025)},
	} {
		if session, err := m.LoginUser("generic-"+tc.username, tc.username, tc.password); err != errCredentials || session != (Session{}) {
			t.Fatalf("non-generic login failure: %+v, %v", session.User, err)
		}
	}
	for i := 0; i < sourceLoginLimit; i++ {
		if _, err := m.LoginUser("shared", "missing", testPassword); err != errCredentials {
			t.Fatalf("unknown user error = %v", err)
		}
	}
	if _, err := m.LoginUser("shared", "admin", testPassword); err != errCredentials {
		t.Fatal("switching username bypassed the shared source limit")
	}
}
