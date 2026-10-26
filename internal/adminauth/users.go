// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"errors"
	"os"
	"slices"
	"strings"
)

// Role is a public management access tier.
type Role string

const (
	RoleAdministrator Role = "administrator"
	RoleOperator      Role = "operator"
	RoleViewer        Role = "viewer"
)

// User is the credential-free account projection exposed to management clients.
type User struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
	Enabled  bool   `json:"enabled"`
}

// UserUpdate leaves nil role/enabled fields and an empty password unchanged.
type UserUpdate struct {
	Role        *Role  `json:"role,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
	NewPassword string `json:"new_password,omitempty"`
}

var (
	ErrForbidden         = errors.New("administrator access required")
	ErrInvalidUser       = errors.New("invalid user")
	ErrUserExists        = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrLastAdministrator = errors.New("at least one enabled administrator is required")
)

func (m *Manager) administratorLocked(actorToken string) error {
	session, ok := m.verifySessionLocked(actorToken)
	if !ok || session.User.Role != RoleAdministrator {
		return ErrForbidden
	}
	return nil
}

// lockCurrentStateLocked prevents stale managers from overwriting a newer identity.
func (m *Manager) lockCurrentStateLocked() (*os.File, error) {
	lock, err := lockState(m.configPath)
	if err != nil {
		m.failClosedLocked()
		return nil, err
	}
	if !m.stateCurrentLocked() {
		unlockState(lock)
		return nil, errInvalidState
	}
	return lock, nil
}

// Users returns sorted public accounts, never their password verifiers.
func (m *Manager) Users(actorToken string) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.administratorLocked(actorToken); err != nil {
		return nil, err
	}
	users := make([]User, len(m.state.Users))
	for i, user := range m.state.Users {
		users[i] = user.User
	}
	slices.SortFunc(users, func(a, b User) int { return strings.Compare(a.Username, b.Username) })
	return users, nil
}

// CreateUser creates an enabled account with an independent salted verifier.
func (m *Manager) CreateUser(actorToken, username, password string, role Role) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.administratorLocked(actorToken); err != nil {
		return User{}, err
	}
	username, ok := normalizeUsername(username)
	if !ok || !validRole(role) || !strongPassword(password) {
		return User{}, ErrInvalidUser
	}
	if m.state.userIndex(username) >= 0 {
		return User{}, ErrUserExists
	}
	if len(m.state.Users) >= maxUsers {
		return User{}, ErrInvalidUser
	}
	lock, err := m.lockCurrentStateLocked()
	if err != nil {
		return User{}, err
	}
	defer unlockState(lock)
	salt, err := randomSalt()
	if err != nil {
		return User{}, err
	}
	user := userState{User: User{Username: username, Role: role, Enabled: true}, PasswordSalt: encode(salt), PasswordHash: encode(hashSecret(password, salt))}
	next := m.state
	next.Users = append(slices.Clone(m.state.Users), user)
	if err := m.persistUsersLocked(next, username); err != nil {
		return User{}, err
	}
	return user.User, nil
}

// UpdateUser atomically edits an account, then revokes only its sessions.
func (m *Manager) UpdateUser(actorToken, username string, update UserUpdate) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.administratorLocked(actorToken); err != nil {
		return User{}, err
	}
	username, ok := normalizeUsername(username)
	if !ok || (update.Role != nil && !validRole(*update.Role)) || (update.NewPassword != "" && !strongPassword(update.NewPassword)) {
		return User{}, ErrInvalidUser
	}
	index := m.state.userIndex(username)
	if index < 0 {
		return User{}, ErrUserNotFound
	}
	lock, err := m.lockCurrentStateLocked()
	if err != nil {
		return User{}, err
	}
	defer unlockState(lock)
	next := m.state
	next.Users = slices.Clone(m.state.Users)
	user := &next.Users[index]
	if update.Role != nil {
		user.Role = *update.Role
	}
	if update.Enabled != nil {
		user.Enabled = *update.Enabled
	}
	if !hasEnabledAdministrator(next.Users) {
		return User{}, ErrLastAdministrator
	}
	if update.NewPassword != "" {
		salt, err := randomSalt()
		if err != nil {
			return User{}, err
		}
		user.PasswordSalt, user.PasswordHash = encode(salt), encode(hashSecret(update.NewPassword, salt))
	}
	if *user == m.state.Users[index] {
		return user.User, nil
	}
	if err := m.persistUsersLocked(next, username); err != nil {
		return User{}, err
	}
	return user.User, nil
}

// DeleteUser cannot remove the last enabled administrator.
func (m *Manager) DeleteUser(actorToken, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.administratorLocked(actorToken); err != nil {
		return err
	}
	username, ok := normalizeUsername(username)
	if !ok {
		return ErrInvalidUser
	}
	index := m.state.userIndex(username)
	if index < 0 {
		return ErrUserNotFound
	}
	lock, err := m.lockCurrentStateLocked()
	if err != nil {
		return err
	}
	defer unlockState(lock)
	next := m.state
	next.Users = slices.Delete(slices.Clone(m.state.Users), index, index+1)
	if !hasEnabledAdministrator(next.Users) {
		return ErrLastAdministrator
	}
	return m.persistUsersLocked(next, username)
}

func hasEnabledAdministrator(users []userState) bool {
	for _, user := range users {
		if user.Enabled && user.Role == RoleAdministrator {
			return true
		}
	}
	return false
}

func (m *Manager) persistUsersLocked(next authState, username string) error {
	if err := persistState(m.configPath, next); err != nil {
		// A rename may have succeeded even if the directory sync failed.
		m.failClosedLocked()
		return err
	}
	m.state = next
	for key, record := range m.sessions {
		if record.username == username {
			delete(m.sessions, key)
		}
	}
	return nil
}

func validRole(role Role) bool {
	return role == RoleAdministrator || role == RoleOperator || role == RoleViewer
}

func normalizeUsername(username string) (string, bool) {
	username = strings.TrimSpace(username)
	if len(username) < 1 || len(username) > 64 {
		return "", false
	}
	for i, c := range username {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '_' || c == '-')) {
			continue
		}
		return "", false
	}
	return strings.ToLower(username), true
}
