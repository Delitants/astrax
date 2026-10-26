// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const accountNewPassword = "Another-strong-password_2026!"

func accountAdmin(t *testing.T) (*Manager, Session) {
	t.Helper()
	m := enrolledTestManager(t)
	session, err := m.Login("administrator", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return m, session
}

func accountLogin(t *testing.T, m *Manager, username, password string) Session {
	t.Helper()
	session, err := m.LoginUser("client-"+username, username, password)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func accountCreate(t *testing.T, m *Manager, admin Session, name string, role Role) User {
	t.Helper()
	user, err := m.CreateUser(admin.Token, name, testPassword, role)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func accountSessions(t *testing.T, m *Manager, active bool, sessions ...Session) {
	t.Helper()
	for _, session := range sessions {
		if m.SessionActive(session.Token) != active || m.SessionValid(session.Token) != active {
			t.Fatalf("session for %s active != %t", session.User.Username, active)
		}
		if found, ok := m.VerifySession(session.Token); ok != active || (ok && found.User != session.User) {
			t.Fatalf("session identity/verification mismatch: %+v %t", found.User, ok)
		}
	}
}

func TestAccountsNamedSessionsAndPublicProjection(t *testing.T) {
	m, admin := accountAdmin(t)
	if admin.User != (User{Username: "admin", Role: RoleAdministrator, Enabled: true}) {
		t.Fatalf("legacy Login wrapper identity = %+v", admin.User)
	}
	accountCreate(t, m, admin, "zulu", RoleViewer)
	got := accountCreate(t, m, admin, " Alice ", RoleOperator)
	if got != (User{Username: "alice", Role: RoleOperator, Enabled: true}) {
		t.Fatalf("created user = %+v", got)
	}
	alice := accountLogin(t, m, " ALICE ", testPassword)
	if alice.User != got {
		t.Fatalf("session identity = %+v, want %+v", alice.User, got)
	}
	users, err := m.Users(admin.Token)
	want := []User{{Username: "admin", Role: RoleAdministrator, Enabled: true}, got, {Username: "zulu", Role: RoleViewer, Enabled: true}}
	if err != nil || !reflect.DeepEqual(users, want) {
		t.Fatalf("Users = %+v, %v; want %+v", users, err, want)
	}
	data, err := json.Marshal(users)
	if err != nil || strings.Contains(string(data), "password") || strings.Contains(string(data), "salt") || strings.Contains(string(data), "hash") {
		t.Fatalf("public users leak credential fields: %s %v", data, err)
	}
	sessionJSON, err := json.Marshal(alice)
	if err != nil || !bytes.Contains(sessionJSON, []byte(`"user":{"username":"alice","role":"operator","enabled":true}`)) {
		t.Fatalf("session has no public user: %s %v", sessionJSON, err)
	}
	users[0].Role = RoleViewer
	again, err := m.Users(admin.Token)
	if err != nil || again[0].Role != RoleAdministrator {
		t.Fatal("mutating a Users result changed the stored identity")
	}
	if m.state.Users[0].PasswordSalt == m.state.Users[1].PasswordSalt || m.state.Users[0].PasswordHash == m.state.Users[1].PasswordHash {
		t.Fatal("distinct accounts share a password verifier")
	}
	accountSessions(t, m, true, admin, alice)
}

func TestAccountsManagementRequiresActiveAdministrator(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "operator", RoleOperator)
	accountCreate(t, m, admin, "viewer", RoleViewer)
	operator := accountLogin(t, m, "operator", testPassword)
	viewer := accountLogin(t, m, "viewer", testPassword)
	revoked := accountLogin(t, m, "admin", testPassword)
	m.Logout(revoked.Token)
	for _, token := range []string{"", "not-a-token", revoked.Token, operator.Token, viewer.Token} {
		if _, err := m.Users(token); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Users error = %v", err)
		}
		if _, err := m.CreateUser(token, "bad/name", "weak", "invalid"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("CreateUser leaked validation or allowed non-admin: %v", err)
		}
		if _, err := m.UpdateUser(token, "missing", UserUpdate{}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("UpdateUser error = %v", err)
		}
		if err := m.DeleteUser(token, "missing"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("DeleteUser error = %v", err)
		}
	}
	accountSessions(t, m, true, admin, operator, viewer)
	base := time.Now().UTC()
	m.now = func() time.Time { return base.Add(sessionAbsoluteTTL + time.Second) }
	if _, err := m.Users(admin.Token); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired administrator accepted: %v", err)
	}
}

func TestAccountsInputValidationAndCaseDuplicates(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "Alice", RoleViewer)
	for _, name := range []string{"alice", "ALICE", " Alice ", " ADMIN "} {
		if _, err := m.CreateUser(admin.Token, name, testPassword, RoleViewer); !errors.Is(err, ErrUserExists) {
			t.Fatalf("case duplicate %q: %v", name, err)
		}
	}
	for _, name := range []string{"", "  ", ".hidden", "../admin", "two words", "a/b", "a\\b", "a\x00b", "a:b", "\u0430dmin", "\u212Aevin", strings.Repeat("a", 65)} {
		if _, err := m.CreateUser(admin.Token, name, testPassword, RoleViewer); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("invalid username %q: %v", name, err)
		}
		if _, err := m.UpdateUser(admin.Token, name, UserUpdate{}); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("invalid update username %q: %v", name, err)
		}
		if err := m.DeleteUser(admin.Token, name); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("invalid delete username %q: %v", name, err)
		}
	}
	for _, role := range []Role{"", "admin", "Administrator", "unknown"} {
		if _, err := m.CreateUser(admin.Token, "invalid-role", testPassword, role); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("invalid role %q: %v", role, err)
		}
		if _, err := m.UpdateUser(admin.Token, "alice", UserUpdate{Role: &role}); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("invalid update role %q: %v", role, err)
		}
	}
	if _, err := m.CreateUser(admin.Token, "weak", "short", RoleViewer); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("weak create password: %v", err)
	}
	if _, err := m.UpdateUser(admin.Token, "alice", UserUpdate{NewPassword: "short"}); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("weak reset password: %v", err)
	}
	if _, err := m.UpdateUser(admin.Token, "missing", UserUpdate{}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing update: %v", err)
	}
	if err := m.DeleteUser(admin.Token, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing delete: %v", err)
	}
	if session, err := m.LoginUser("unknown", "not-found", testPassword); err == nil || session.Token != "" {
		t.Fatal("unknown account logged in")
	}
	if _, err := m.LoginUser("wrong", "alice", accountNewPassword); err == nil {
		t.Fatal("wrong password accepted")
	}
	accountCreate(t, m, admin, strings.Repeat("a", 64), RoleViewer)
	accountSessions(t, m, true, admin)
}

func TestAccountsRoleAndEnabledChangesRevokeOnlyTarget(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "alice", RoleOperator)
	accountCreate(t, m, admin, "bob", RoleViewer)
	alice1 := accountLogin(t, m, "alice", testPassword)
	alice2 := accountLogin(t, m, "alice", testPassword)
	bob := accountLogin(t, m, "bob", testPassword)
	viewer := RoleViewer
	if _, err := m.UpdateUser(admin.Token, "ALICE", UserUpdate{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	accountSessions(t, m, false, alice1, alice2)
	accountSessions(t, m, true, admin, bob)
	alice := accountLogin(t, m, "alice", testPassword)
	if alice.User.Role != RoleViewer {
		t.Fatal("role update was not reflected in a new session")
	}
	if _, err := m.UpdateUser(admin.Token, "alice", UserUpdate{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	accountSessions(t, m, true, alice)
	disabled := false
	if user, err := m.UpdateUser(admin.Token, "alice", UserUpdate{Enabled: &disabled}); err != nil || user.Enabled {
		t.Fatalf("disable result = %+v, %v", user, err)
	}
	accountSessions(t, m, false, alice)
	if _, err := m.LoginUser("disabled", "alice", testPassword); err == nil {
		t.Fatal("disabled user logged in")
	}
	operator := RoleOperator
	if user, err := m.UpdateUser(admin.Token, "alice", UserUpdate{Role: &operator}); err != nil || user.Enabled {
		t.Fatal("role edit re-enabled a disabled user")
	}
	enabled := true
	if _, err := m.UpdateUser(admin.Token, "alice", UserUpdate{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	alice = accountLogin(t, m, "alice", testPassword)
	if alice.User.Role != RoleOperator {
		t.Fatal("re-enabled user lost the edited role")
	}
	if err := m.DeleteUser(admin.Token, "Alice"); err != nil {
		t.Fatal(err)
	}
	accountSessions(t, m, false, alice)
	accountSessions(t, m, true, admin, bob)
	if _, err := m.LoginUser("deleted", "alice", testPassword); err == nil {
		t.Fatal("deleted account logged in")
	}
}

func TestAccountsLastEnabledAdministratorInvariant(t *testing.T) {
	m, admin := accountAdmin(t)
	before, _ := os.ReadFile(StatePath(m.configPath))
	viewer, disabled := RoleViewer, false
	for _, update := range []UserUpdate{{Role: &viewer}, {Enabled: &disabled}, {Role: &viewer, Enabled: &disabled, NewPassword: accountNewPassword}} {
		if _, err := m.UpdateUser(admin.Token, "admin", update); !errors.Is(err, ErrLastAdministrator) {
			t.Fatalf("last administrator update: %v", err)
		}
	}
	if err := m.DeleteUser(admin.Token, "ADMIN"); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("last administrator delete: %v", err)
	}
	after, _ := os.ReadFile(StatePath(m.configPath))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected last-admin mutation changed the durable state")
	}
	accountSessions(t, m, true, admin)
	accountCreate(t, m, admin, "backup", RoleAdministrator)
	if _, err := m.UpdateUser(admin.Token, "backup", UserUpdate{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpdateUser(admin.Token, "admin", UserUpdate{Role: &viewer}); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("disabled backup counted as an enabled administrator: %v", err)
	}
	enabled := true
	if _, err := m.UpdateUser(admin.Token, "backup", UserUpdate{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	backup := accountLogin(t, m, "backup", testPassword)
	if _, err := m.UpdateUser(admin.Token, "admin", UserUpdate{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	accountSessions(t, m, false, admin)
	accountSessions(t, m, true, backup)
	if err := m.DeleteUser(backup.Token, "backup"); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("new last administrator could be deleted: %v", err)
	}
	if err := m.DeleteUser(backup.Token, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login("wrapper", testPassword); err == nil {
		t.Fatal("legacy Login wrapper authenticated a different administrator")
	}
}

func TestAccountsMultipleAdministratorsCanDeleteSelf(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "backup", RoleAdministrator)
	backup := accountLogin(t, m, "backup", testPassword)
	if err := m.DeleteUser(admin.Token, "admin"); err != nil {
		t.Fatal(err)
	}
	accountSessions(t, m, false, admin)
	accountSessions(t, m, true, backup)
	users, err := m.Users(backup.Token)
	if err != nil || len(users) != 1 || users[0].Username != "backup" {
		t.Fatalf("remaining administrator = %+v, %v", users, err)
	}
}

func TestAccountsPasswordResetAndSelfChangeAreScoped(t *testing.T) {
	for _, role := range []Role{RoleOperator, RoleViewer, RoleAdministrator} {
		t.Run(string(role), func(t *testing.T) {
			m, admin := accountAdmin(t)
			accountCreate(t, m, admin, "alice", role)
			accountCreate(t, m, admin, "bob", RoleViewer)
			alice1 := accountLogin(t, m, "alice", testPassword)
			alice2 := accountLogin(t, m, "alice", testPassword)
			bob := accountLogin(t, m, "bob", testPassword)
			if err := m.ChangePassword(alice1.Token, "wrong", accountNewPassword); err == nil {
				t.Fatal("self change accepted wrong old password")
			}
			if err := m.ChangePassword(alice1.Token, testPassword, "weak"); err == nil {
				t.Fatal("self change accepted weak new password")
			}
			accountSessions(t, m, true, alice1, alice2, admin, bob)
			if err := m.ChangePassword(alice1.Token, testPassword, accountNewPassword); err != nil {
				t.Fatal(err)
			}
			accountSessions(t, m, false, alice1, alice2)
			accountSessions(t, m, true, admin, bob)
			if _, err := m.LoginUser("old", "alice", testPassword); err == nil {
				t.Fatal("self-change retained the old password")
			}
			alice1 = accountLogin(t, m, "alice", accountNewPassword)
			alice2 = accountLogin(t, m, "alice", accountNewPassword)
			if _, err := m.UpdateUser(admin.Token, "alice", UserUpdate{NewPassword: testPassword}); err != nil {
				t.Fatal(err)
			}
			accountSessions(t, m, false, alice1, alice2)
			accountSessions(t, m, true, admin, bob)
			if _, err := m.LoginUser("reset-old", "alice", accountNewPassword); err == nil {
				t.Fatal("administrator reset retained the old password")
			}
			m.now = func() time.Time { return time.Now().Add(loginWindow + time.Second) }
			accountLogin(t, m, "alice", testPassword)
		})
	}
}

func TestAccountsLimitIncludesAdminAndDeletionFreesSlot(t *testing.T) {
	m, admin := accountAdmin(t)
	for i := 1; i < 64; i++ {
		accountCreate(t, m, admin, fmt.Sprintf("user-%02d", i), RoleViewer)
	}
	if _, err := m.CreateUser(admin.Token, "overflow", testPassword, RoleViewer); !errors.Is(err, ErrInvalidUser) {
		t.Fatalf("65th user error = %v", err)
	}
	users, err := m.Users(admin.Token)
	if err != nil || len(users) != 64 {
		t.Fatalf("user count = %d, error = %v", len(users), err)
	}
	if err := m.DeleteUser(admin.Token, "user-01"); err != nil {
		t.Fatal(err)
	}
	accountCreate(t, m, admin, "replacement", RoleOperator)
	m.Close()
	restarted, err := Open(m.configPath, true)
	if err != nil {
		t.Fatalf("full account state did not restart: %v", err)
	}
	defer restarted.Close()
	admin = accountLogin(t, restarted, "admin", testPassword)
	users, err = restarted.Users(admin.Token)
	if err != nil || len(users) != 64 {
		t.Fatalf("restarted user count = %d, error = %v", len(users), err)
	}
}

func TestAccountsConcurrentDuplicateAndLastAdminMutations(t *testing.T) {
	m, admin := accountAdmin(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"Alice", "ALICE"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_, err := m.CreateUser(admin.Token, name, testPassword, RoleAdministrator)
			results <- err
		}(name)
	}
	wg.Wait()
	close(results)
	success, duplicates := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrUserExists):
			duplicates++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || duplicates != 1 {
		t.Fatalf("concurrent duplicate result: %d success, %d duplicates", success, duplicates)
	}
	alice := accountLogin(t, m, "alice", testPassword)
	results = make(chan error, 2)
	viewer := RoleViewer
	for _, session := range []Session{admin, alice} {
		wg.Add(1)
		go func(session Session) {
			defer wg.Done()
			_, err := m.UpdateUser(session.Token, session.User.Username, UserUpdate{Role: &viewer})
			results <- err
		}(session)
	}
	wg.Wait()
	close(results)
	success, last := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLastAdministrator) {
			last++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || last != 1 {
		t.Fatalf("concurrent last-admin result: %d success, %d rejected", success, last)
	}
}

func TestAccountsRestartRetainsUsersAndRevokesMemorySessions(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "alice", RoleOperator)
	accountCreate(t, m, admin, "bob", RoleViewer)
	accountCreate(t, m, admin, "deleted", RoleViewer)
	disabled, viewer := false, RoleViewer
	if _, err := m.UpdateUser(admin.Token, "alice", UserUpdate{Role: &viewer, NewPassword: accountNewPassword}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpdateUser(admin.Token, "bob", UserUpdate{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteUser(admin.Token, "deleted"); err != nil {
		t.Fatal(err)
	}
	alice := accountLogin(t, m, "alice", accountNewPassword)
	m.Close()
	restarted, err := Open(m.configPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	accountSessions(t, restarted, false, admin, alice)
	admin = accountLogin(t, restarted, "admin", testPassword)
	users, err := restarted.Users(admin.Token)
	want := []User{{Username: "admin", Role: RoleAdministrator, Enabled: true}, {Username: "alice", Role: RoleViewer, Enabled: true}, {Username: "bob", Role: RoleViewer, Enabled: false}}
	if err != nil || !reflect.DeepEqual(users, want) {
		t.Fatalf("persisted users = %+v, %v", users, err)
	}
	if _, err := restarted.LoginUser("old", "alice", testPassword); err == nil {
		t.Fatal("old password returned after restart")
	}
	accountLogin(t, restarted, "alice", accountNewPassword)
	for _, name := range []string{"bob", "deleted"} {
		if _, err := restarted.LoginUser("disabled-or-deleted", name, testPassword); err == nil {
			t.Fatalf("%s logged in after restart", name)
		}
	}
}

func TestAccountsSessionAdmissionEvictsOnlySigningInUser(t *testing.T) {
	m, admin := accountAdmin(t)
	accountCreate(t, m, admin, "alice", RoleViewer)
	var first Session
	var retained []Session
	for i := 0; i <= maxSessions; i++ {
		session, err := m.LoginUser(fmt.Sprintf("alice-source-%d", i), "alice", testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = session
		} else {
			retained = append(retained, session)
		}
	}
	accountSessions(t, m, true, admin)
	accountSessions(t, m, false, first)
	accountSessions(t, m, true, retained...)
	if len(m.sessions) != 17 {
		t.Fatalf("session count = %d, want admin + 16 alice sessions", len(m.sessions))
	}
}

func TestAccountsSessionAdmissionAtTotalBound(t *testing.T) {
	m, _ := accountAdmin(t)
	// Seed valid durable identities and memory-only sessions to test full capacity
	// without 1,024 expensive password verifications or changing rate limits.
	next := m.state
	for i := 1; i < 64; i++ {
		user := next.Users[0]
		user.User = User{Username: fmt.Sprintf("user-%02d", i), Role: RoleViewer, Enabled: true}
		next.Users = append(next.Users, user)
	}
	if err := persistState(m.configPath, next); err != nil {
		t.Fatal(err)
	}
	m.state = next
	clear(m.sessions)
	now := m.now().UTC()
	var targetOldest, unrelatedOldest string
	for _, user := range next.Users {
		for i := 0; i < maxSessions; i++ {
			token, err := randomToken()
			if err != nil {
				t.Fatal(err)
			}
			m.nextSessionSeq++
			m.sessions[tokenDigest(token)] = sessionRecord{username: user.Username, sequence: m.nextSessionSeq, issuedAt: now, idleExpiresAt: now.Add(sessionIdleTTL), expiresAt: now.Add(sessionAbsoluteTTL)}
			if user.Username == "admin" && i == 0 {
				unrelatedOldest = token
			}
			if user.Username == "user-63" && i == 0 {
				targetOldest = token
			}
		}
	}
	if len(m.sessions) != 1024 {
		t.Fatal("full-capacity fixture is invalid")
	}
	issued := accountLogin(t, m, "user-63", testPassword)
	if !m.SessionActive(unrelatedOldest) || m.SessionActive(targetOldest) || !m.SessionActive(issued.Token) {
		t.Fatal("full-capacity login did not evict only the signing-in user's oldest session")
	}
	counts := make(map[string]int)
	for _, record := range m.sessions {
		counts[record.username]++
	}
	if len(m.sessions) != 1024 || len(counts) != 64 {
		t.Fatalf("full capacity = %d sessions for %d users", len(m.sessions), len(counts))
	}
	for username, count := range counts {
		if count != 16 {
			t.Fatalf("%s has %d sessions, want 16", username, count)
		}
	}
}
