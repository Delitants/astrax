// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const testPassword = "A-strong-local-password_2026!"

func newTestManager(t *testing.T) (string, *Manager, string) {
	t.Helper()
	config := filepath.Join(t.TempDir(), "astrax.json")
	m, err := Open(config, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	secretBytes, err := os.ReadFile(SetupSecretPath(config))
	if err != nil {
		t.Fatal(err)
	}
	return config, m, strings.TrimSpace(string(secretBytes))
}

func TestAuthStateFirstSetupAndRestart(t *testing.T) {
	config, m, secret := newTestManager(t)
	if !m.SetupPending() || len(secret) < 32 {
		t.Fatal("first start did not create a strong pending setup secret")
	}
	state, err := os.ReadFile(StatePath(config))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, []byte(secret)) || !json.Valid(state) {
		t.Fatal("state is invalid or leaks the setup secret")
	}
	for _, path := range []string{StatePath(config), SetupSecretPath(config)} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not owner-only: %v, %v", path, info, err)
		}
	}
	if _, err := m.Login("local", testPassword); err == nil {
		t.Fatal("login succeeded before enrollment")
	}
	if err := m.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
	if m.SetupPending() {
		t.Fatal("setup still pending after enrollment")
	}
	if _, err := os.Lstat(SetupSecretPath(config)); !os.IsNotExist(err) {
		t.Fatalf("setup secret was not consumed: %v", err)
	}
	state, err = os.ReadFile(StatePath(config))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, []byte(secret)) || bytes.Contains(state, []byte(testPassword)) {
		t.Fatal("state contains a credential")
	}
	m.Close()
	restarted, err := Open(config, true)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.SetupPending() {
		t.Fatal("restart restored setup")
	}
	if _, err := restarted.Login("local", testPassword); err != nil {
		t.Fatalf("durable password did not verify: %v", err)
	}
	if err := restarted.Enroll(secret, testPassword); err == nil {
		t.Fatal("consumed secret re-enrolled")
	}
}

func TestAuthStateCrashBeforeMarkerReusesIdentity(t *testing.T) {
	config, first, secret := newTestManager(t)
	first.Close()
	recovered, err := Open(config, false)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	again, err := os.ReadFile(SetupSecretPath(config))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(again)) != secret {
		t.Fatal("interrupted initialization minted a second identity")
	}
	if err := recovered.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
}

func TestAuthStateRestartAfterEnrollmentBeforeSetupRemoval(t *testing.T) {
	config, first, secret := newTestManager(t)
	first.Close()
	salt, err := randomSalt()
	if err != nil {
		t.Fatal(err)
	}
	enrolled := authState{
		Version:      stateVersion,
		Phase:        "enrolled",
		PasswordSalt: encode(salt),
		PasswordHash: encode(hashSecret(testPassword, salt)),
	}
	if err := persistState(config, enrolled); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(SetupSecretPath(config)); err != nil {
		t.Fatalf("crash fixture lost the leftover setup file: %v", err)
	}
	restarted, err := Open(config, true)
	if err != nil {
		t.Fatalf("enrolled identity was not recovered: %v", err)
	}
	defer restarted.Close()
	if _, err := os.Lstat(SetupSecretPath(config)); !os.IsNotExist(err) {
		t.Fatalf("stale setup file survived recovery: %v", err)
	}
	if _, err := restarted.Login("local", testPassword); err != nil {
		t.Fatalf("durable enrolled password did not verify: %v", err)
	}
	if err := restarted.Enroll(secret, testPassword); err == nil {
		t.Fatal("consumed setup secret re-enrolled")
	}
}

func TestAuthStateMissingAfterInitializationFailsClosed(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	if _, err := Open(config, true); err == nil {
		t.Fatal("missing initialized sidecar was recreated")
	}
	if _, err := os.Lstat(StatePath(config)); !os.IsNotExist(err) {
		t.Fatal("missing initialized sidecar was written")
	}
}

func TestAuthStateRejectsUnsafeStateFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{"malformed", func(t *testing.T, path string) { t.Helper(); os.WriteFile(path, []byte("not json"), 0o600) }},
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			os.Remove(path)
			if err := os.Symlink("target", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		}},
		{"permissive", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, m, secret := newTestManager(t)
			m.Close()
			path := StatePath(config)
			tc.mutate(t, path)
			if _, err := Open(config, false); err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe state accepted or error leaked secret: %v", err)
			}
		})
	}
}

func TestAuthStateRejectsWrongOwner(t *testing.T) {
	config, m, _ := newTestManager(t)
	m.Close()
	path := StatePath(config)
	if err := os.Chown(path, os.Getuid()+1, -1); err != nil {
		t.Skipf("changing file owner requires local privilege: %v", err)
	}
	if _, err := Open(config, true); err == nil {
		t.Fatal("wrong-owner state accepted")
	}
}

func TestAuthStateRejectsInsecureStat(t *testing.T) {
	config, m, _ := newTestManager(t)
	m.Close()
	info, err := os.Lstat(StatePath(config))
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid = uint32(os.Getuid() + 1)
	if err := validateSecureStat(info.Mode(), &stat); err == nil {
		t.Fatal("wrong-owner metadata accepted")
	}
}

func TestAuthStateSetupFileWithoutSidecarReusesSecret(t *testing.T) {
	config, m, secret := newTestManager(t)
	m.Close()
	if err := os.Remove(StatePath(config)); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(config, false)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	again, err := os.ReadFile(SetupSecretPath(config))
	if err != nil || strings.TrimSpace(string(again)) != secret {
		t.Fatalf("setup-file recovery minted a second identity: %v", err)
	}
}

func TestAuthStateRecoversInterruptedCreateLink(t *testing.T) {
	for _, kind := range []string{"state", "setup"} {
		t.Run(kind, func(t *testing.T) {
			config, first, secret := newTestManager(t)
			first.Close()
			path := StatePath(config)
			if kind == "setup" {
				path = SetupSecretPath(config)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			temp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-crash")
			if err := os.Link(path, temp); err != nil {
				t.Fatal(err)
			}
			recovered, err := Open(config, false)
			if err != nil {
				t.Fatalf("interrupted %s creation did not recover: %v", kind, err)
			}
			defer recovered.Close()
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("%s identity changed during recovery: %v", kind, err)
			}
			if _, err := os.Lstat(temp); !os.IsNotExist(err) {
				t.Fatalf("interrupted temporary link remains: %v", err)
			}
			current, err := os.ReadFile(SetupSecretPath(config))
			if err != nil || strings.TrimSpace(string(current)) != secret {
				t.Fatalf("setup identity changed during recovery: %v", err)
			}
			if err := recovered.Enroll(secret, testPassword); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthStateRecoveryRejectsUnrecognizedAndInsecureLinks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   func(string) string
		mutate func(t *testing.T, path string)
	}{
		{"unrecognized state link", StatePath, func(t *testing.T, path string) {
			if err := os.Link(path, path+".unknown"); err != nil {
				t.Fatal(err)
			}
		}},
		{"unrecognized setup link", SetupSecretPath, func(t *testing.T, path string) {
			if err := os.Link(path, path+".unknown"); err != nil {
				t.Fatal(err)
			}
		}},
		{"permissive interrupted link", StatePath, func(t *testing.T, path string) {
			temp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-crash")
			if err := os.Link(path, temp); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked destination", StatePath, func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".elsewhere", path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, first, _ := newTestManager(t)
			first.Close()
			tc.mutate(t, tc.path(config))
			if _, err := Open(config, false); err == nil {
				t.Fatal("unsafe administrator file accepted")
			}
		})
	}
}

func TestAuthStateRejectsUnsafeSetupFile(t *testing.T) {
	config, m, _ := newTestManager(t)
	m.Close()
	if err := os.Chmod(SetupSecretPath(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config, false); err == nil {
		t.Fatal("permissive setup file accepted")
	}
}

func TestAuthStateRejectsSymlinkedLockFile(t *testing.T) {
	config, m, _ := newTestManager(t)
	m.Close()
	lock := StatePath(config) + ".lock"
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(StatePath(config), lock); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config, false); err == nil {
		t.Fatal("symlinked lock file accepted")
	}
}

func TestAuthStateRejectsSetupTamperAfterOpen(t *testing.T) {
	config, m, secret := newTestManager(t)
	if err := os.Chmod(SetupSecretPath(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Enroll(secret, testPassword); err == nil {
		t.Fatal("insecure setup secret was accepted after open")
	}
	if _, err := m.Login("source", testPassword); err == nil {
		t.Fatal("insecure setup file enrolled an administrator despite error")
	}
	if m.SetupPending() {
		t.Fatal("setup remained available after file tamper")
	}
}

func TestAuthStateRejectsStaleSecretAndWeakPasswords(t *testing.T) {
	_, m, secret := newTestManager(t)
	for _, password := range []string{"", "short", "admin", "admin/admin", "password123", "Password123!", "P@ssw0rd123!", "Admin123456!", "WELCOME12345!"} {
		if err := m.Enroll(secret, password); err == nil {
			t.Fatalf("weak/default password accepted: %q", password)
		}
	}
	if err := m.Enroll("wrong-secret", testPassword); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("stale secret accepted or leaked: %v", err)
	}
	if !m.SetupPending() {
		t.Fatal("bad enrollment consumed setup")
	}
	if err := m.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
}
