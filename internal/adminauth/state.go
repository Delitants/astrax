// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	stateVersion   = 2
	argonTime      = 2
	argonMemoryKiB = 64 * 1024
	argonThreads   = 1
	argonKeyLen    = 32
	maxStateBytes  = 32 * 1024
	maxUsers       = 64
)

var (
	errInvalidState = errors.New("invalid administrator state")
	errCredentials  = errors.New("invalid credentials")
)

type authState struct {
	Version      int         `json:"version"`
	Phase        string      `json:"phase"`
	SetupSalt    string      `json:"setup_salt,omitempty"`
	SetupHash    string      `json:"setup_hash,omitempty"`
	PasswordSalt string      `json:"password_salt,omitempty"`
	PasswordHash string      `json:"password_hash,omitempty"`
	Users        []userState `json:"users,omitempty"`
}

type userState struct {
	User
	PasswordSalt string `json:"password_salt"`
	PasswordHash string `json:"password_hash"`
}

func sameState(a, b authState) bool {
	return a.Version == b.Version && a.Phase == b.Phase && a.SetupSalt == b.SetupSalt && a.SetupHash == b.SetupHash &&
		a.PasswordSalt == b.PasswordSalt && a.PasswordHash == b.PasswordHash && slices.Equal(a.Users, b.Users)
}

func (s authState) userIndex(username string) int {
	for i, user := range s.Users {
		if user.Username == username {
			return i
		}
	}
	return -1
}

// Manager owns durable named identities and ephemeral browser sessions.
type Manager struct {
	mu             sync.Mutex
	configPath     string
	state          authState
	now            func() time.Time
	csrfKey        [32]byte
	sessions       map[[32]byte]sessionRecord
	nextSessionSeq uint64
	sourceAttempts map[string]int
	globalAttempts int
	windowStart    time.Time
	setupSources   map[string]int
	setupAttempts  int
	setupWindow    time.Time
	closed         bool
}

// StatePath is the owner-only administrator identity sidecar.
func StatePath(configPath string) string { return configPath + ".admin-auth.json" }

// SetupSecretPath is the local owner-only, one-use setup credential file.
func SetupSecretPath(configPath string) string { return configPath + ".admin-setup" }

// Open never creates a replacement identity after the main-config marker is set.
func Open(configPath string, initialized bool) (*Manager, error) {
	if configPath == "" {
		return nil, errInvalidState
	}
	lock, err := lockState(configPath)
	if err != nil {
		return nil, err
	}
	defer unlockState(lock)

	statePath := StatePath(configPath)
	if err := recoverInterruptedCreate(SetupSecretPath(configPath)); err != nil {
		return nil, err
	}
	if err := recoverInterruptedCreate(statePath); err != nil {
		return nil, err
	}
	data, exists, err := readSecureFile(statePath, maxStateBytes)
	if err != nil {
		return nil, err
	}
	if !exists {
		if initialized {
			return nil, fmt.Errorf("administrator state missing after initialization: %w", errInvalidState)
		}
		secretData, secretExists, err := readSecureFile(SetupSecretPath(configPath), 128)
		if err != nil {
			return nil, err
		}
		if !secretExists {
			secret, err := randomToken()
			if err != nil {
				return nil, err
			}
			if err := createSecureFile(SetupSecretPath(configPath), []byte(secret+"\n")); err != nil {
				return nil, err
			}
			secretData = []byte(secret + "\n")
		}
		secret, err := parseSetupSecret(secretData)
		if err != nil {
			return nil, err
		}
		salt, err := randomSalt()
		if err != nil {
			return nil, err
		}
		pending := authState{Version: stateVersion, Phase: "pending", SetupSalt: encode(salt), SetupHash: encode(hashSecret(secret, salt))}
		data, err = json.Marshal(pending)
		if err != nil {
			return nil, err
		}
		if err := createSecureFile(statePath, data); err != nil {
			return nil, err
		}
	}
	state, err := parseState(data)
	if err != nil {
		return nil, err
	}
	if state.Phase == "pending" {
		secretData, exists, err := readSecureFile(SetupSecretPath(configPath), 128)
		if err != nil || !exists {
			return nil, errInvalidState
		}
		secret, err := parseSetupSecret(secretData)
		if err != nil || !verifySecret(secret, state.SetupSalt, state.SetupHash) {
			return nil, errInvalidState
		}
	} else {
		// Enrollment persists first. A crash before unlink is recovered here.
		if _, exists, err := readSecureFile(SetupSecretPath(configPath), 128); err != nil {
			return nil, err
		} else if exists {
			if err := removeSecureFile(SetupSecretPath(configPath)); err != nil {
				return nil, err
			}
		}
	}
	if state.Version == 1 {
		state.Version = stateVersion
		if state.Phase == "enrolled" {
			state.Users = []userState{{User: User{Username: "admin", Role: RoleAdministrator, Enabled: true}, PasswordSalt: state.PasswordSalt, PasswordHash: state.PasswordHash}}
			state.PasswordSalt, state.PasswordHash = "", ""
		}
		if err := persistState(configPath, state); err != nil {
			return nil, err
		}
	}
	m := &Manager{configPath: configPath, state: state, now: time.Now, sessions: make(map[[32]byte]sessionRecord), sourceAttempts: make(map[string]int), setupSources: make(map[string]int)}
	if _, err := rand.Read(m.csrfKey[:]); err != nil {
		return nil, fmt.Errorf("initialize sessions: %w", err)
	}
	return m, nil
}

func (m *Manager) SetupPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stateCurrentLocked() && m.state.Phase == "pending"
}

func (m *Manager) stateCurrentLocked() bool {
	if m.closed {
		return false
	}
	current, err := loadCurrentState(m.configPath)
	if err == nil && sameState(current, m.state) {
		data, exists, setupErr := readSecureFile(SetupSecretPath(m.configPath), 128)
		if setupErr == nil {
			if current.Phase == "pending" && exists {
				_, setupErr = parseSetupSecret(data)
				if setupErr == nil {
					return true
				}
			} else if current.Phase == "enrolled" && !exists {
				return true
			}
		}
	}
	m.failClosedLocked()
	return false
}

func (m *Manager) failClosedLocked() {
	m.closed = true
	clear(m.sessions)
	m.csrfKey = [32]byte{}
}

func (m *Manager) Enroll(secret, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stateCurrentLocked() || m.state.Phase != "pending" || !strongPassword(password) {
		return errCredentials
	}
	lock, err := lockState(m.configPath)
	if err != nil {
		return err
	}
	defer unlockState(lock)
	current, err := loadCurrentState(m.configPath)
	if err != nil || !sameState(current, m.state) {
		m.failClosedLocked()
		return errInvalidState
	}
	setupData, exists, err := readSecureFile(SetupSecretPath(m.configPath), 128)
	if err != nil || !exists {
		m.failClosedLocked()
		return errCredentials
	}
	if subtle.ConstantTimeCompare(setupData, []byte(secret+"\n")) != 1 {
		return errCredentials
	}
	if !verifySecret(secret, current.SetupSalt, current.SetupHash) {
		return errCredentials
	}
	salt, err := randomSalt()
	if err != nil {
		return err
	}
	next := authState{Version: stateVersion, Phase: "enrolled", Users: []userState{{User: User{Username: "admin", Role: RoleAdministrator, Enabled: true}, PasswordSalt: encode(salt), PasswordHash: encode(hashSecret(password, salt))}}}
	if err := persistState(m.configPath, next); err != nil {
		m.failClosedLocked()
		return err
	}
	m.state = next
	if err := removeSecureFile(SetupSecretPath(m.configPath)); err != nil {
		m.failClosedLocked()
		return err
	}
	return nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	clear(m.sessions)
	clear(m.sourceAttempts)
	clear(m.setupSources)
	m.csrfKey = [32]byte{}
}

func hashSecret(secret string, salt []byte) []byte {
	return argon2.IDKey([]byte(secret), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
}

func verifySecret(secret, saltText, hashText string) bool {
	salt, _ := base64.RawStdEncoding.DecodeString(saltText)
	want, _ := base64.RawStdEncoding.DecodeString(hashText)
	got := hashSecret(secret, salt)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate credential salt: %w", err)
	}
	return salt, nil
}

func encode(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func strongPassword(password string) bool {
	if len(password) < 12 || len(password) > 1024 {
		return false
	}
	canonical := strings.ToLower(strings.TrimSpace(password))
	canonical = strings.NewReplacer("@", "a", "0", "o", "$", "s", "3", "e", "1", "i").Replace(canonical)
	for _, common := range []string{"admin", "password", "welcome", "letmein", "qwerty"} {
		if strings.HasPrefix(canonical, common) {
			return false
		}
	}
	classes := 0
	for _, found := range []bool{strings.IndexAny(password, "abcdefghijklmnopqrstuvwxyz") >= 0, strings.IndexAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") >= 0, strings.IndexAny(password, "0123456789") >= 0, strings.IndexAny(password, "!@#$%^&*()-_=+[]{}:;,.?/|~") >= 0} {
		if found {
			classes++
		}
	}
	return classes >= 3
}

func parseSetupSecret(data []byte) (string, error) {
	secret := strings.TrimSuffix(string(data), "\n")
	b, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(b) != 32 || len(data) != len(secret)+1 {
		return "", errInvalidState
	}
	return secret, nil
}

// encoding/json otherwise accepts duplicate keys, case aliases and null scalars.
func strictStateObject(data []byte, keys ...string) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !slices.Contains(keys, key) {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func parseState(data []byte) (authState, error) {
	if len(data) > maxStateBytes {
		return authState{}, errInvalidState
	}
	fields, ok := strictStateObject(data, "version", "phase", "setup_salt", "setup_hash", "password_salt", "password_hash", "users")
	if !ok {
		return authState{}, errInvalidState
	}
	var state authState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return authState{}, errInvalidState
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return authState{}, errInvalidState
	}
	if state.Version != 1 && state.Version != stateVersion {
		return authState{}, errInvalidState
	}
	if state.Version == 1 && fields["users"] != nil {
		return authState{}, errInvalidState
	}
	if state.Version == stateVersion && (fields["password_salt"] != nil || fields["password_hash"] != nil) {
		return authState{}, errInvalidState
	}
	validVerifier := func(saltText, hashText string) bool {
		salt, err1 := base64.RawStdEncoding.DecodeString(saltText)
		hash, err2 := base64.RawStdEncoding.DecodeString(hashText)
		return err1 == nil && err2 == nil && len(salt) == 16 && len(hash) == argonKeyLen
	}
	switch state.Phase {
	case "pending":
		if !validVerifier(state.SetupSalt, state.SetupHash) || state.PasswordSalt != "" || state.PasswordHash != "" || fields["users"] != nil {
			return authState{}, errInvalidState
		}
	case "enrolled":
		if state.SetupSalt != "" || state.SetupHash != "" {
			return authState{}, errInvalidState
		}
		if state.Version == 1 {
			if !validVerifier(state.PasswordSalt, state.PasswordHash) || len(state.Users) != 0 {
				return authState{}, errInvalidState
			}
			break
		}
		if state.PasswordSalt != "" || state.PasswordHash != "" || len(state.Users) == 0 || len(state.Users) > maxUsers {
			return authState{}, errInvalidState
		}
		var userDocuments []json.RawMessage
		if err := json.Unmarshal(fields["users"], &userDocuments); err != nil {
			return authState{}, errInvalidState
		}
		seen := make(map[string]bool, len(state.Users))
		administrators := 0
		for i, user := range state.Users {
			userFields, ok := strictStateObject(userDocuments[i], "username", "role", "enabled", "password_salt", "password_hash")
			if !ok || len(userFields) != 5 {
				return authState{}, errInvalidState
			}
			username, ok := normalizeUsername(user.Username)
			if !ok || username != user.Username || seen[username] || !validRole(user.Role) || !validVerifier(user.PasswordSalt, user.PasswordHash) {
				return authState{}, errInvalidState
			}
			seen[username] = true
			if user.Enabled && user.Role == RoleAdministrator {
				administrators++
			}
		}
		if administrators == 0 {
			return authState{}, errInvalidState
		}
	default:
		return authState{}, errInvalidState
	}
	return state, nil
}

func loadCurrentState(configPath string) (authState, error) {
	data, exists, err := readSecureFile(StatePath(configPath), maxStateBytes)
	if err != nil || !exists {
		return authState{}, errInvalidState
	}
	return parseState(data)
}

func persistState(configPath string, state authState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return errInvalidState
	}
	return replaceSecureFile(StatePath(configPath), data)
}

func lockState(configPath string) (*os.File, error) {
	path := StatePath(configPath) + ".lock"
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errInvalidState
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err == nil {
		err = validateSecureInfo(info)
	}
	if err != nil || pathErr != nil || !os.SameFile(info, pathInfo) || validateSecureInfo(pathInfo) != nil {
		f.Close()
		return nil, errInvalidState
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock administrator state: %w", err)
	}
	return f, nil
}

func unlockState(f *os.File) {
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

func validateSecureStat(mode os.FileMode, stat *syscall.Stat_t) error {
	if !mode.IsRegular() || mode.Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errInvalidState
	}
	return nil
}

func validateSecureInfo(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errInvalidState
	}
	return validateSecureStat(info.Mode(), stat)
}

// A crash after Link but before unlinking the temp leaves exactly two names
// for the same owner-only inode. Recover only that recognizable temp name.
func recoverInterruptedCreate(path string) error {
	final, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errInvalidState
	}
	stat, ok := final.Sys().(*syscall.Stat_t)
	if !ok {
		return errInvalidState
	}
	if stat.Nlink == 1 {
		return nil
	}
	if !final.Mode().IsRegular() || final.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 2 {
		return errInvalidState
	}
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errInvalidState
	}
	prefix := "." + filepath.Base(path) + ".tmp-"
	var temp string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || len(entry.Name()) == len(prefix) {
			continue
		}
		candidate := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(candidate)
		if err != nil {
			return errInvalidState
		}
		if !os.SameFile(final, info) {
			continue
		}
		if temp != "" || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errInvalidState
		}
		temp = candidate
	}
	if temp == "" {
		return errInvalidState
	}
	current, err1 := os.Lstat(path)
	linked, err2 := os.Lstat(temp)
	if err1 != nil || err2 != nil || !os.SameFile(final, current) || !os.SameFile(current, linked) {
		return errInvalidState
	}
	if err := os.Remove(temp); err != nil {
		return errInvalidState
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	current, err = os.Lstat(path)
	if err != nil || !os.SameFile(final, current) || validateSecureInfo(current) != nil {
		return errInvalidState
	}
	return nil
}

func readSecureFile(path string, limit int64) ([]byte, bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || validateSecureInfo(before) != nil {
		return nil, false, errInvalidState
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, errInvalidState
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, err := f.Stat()
	if err != nil || validateSecureInfo(after) != nil || !os.SameFile(before, after) {
		return nil, false, errInvalidState
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) > int(limit) {
		return nil, false, errInvalidState
	}
	last, err := os.Lstat(path)
	if err != nil || !os.SameFile(after, last) || validateSecureInfo(last) != nil {
		return nil, false, errInvalidState
	}
	return data, true, nil
}

func secureTemp(path string, data []byte) (string, error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		os.Remove(name)
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := f.Sync(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func createSecureFile(path string, data []byte) error {
	tmp, err := secureTemp(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		return errInvalidState
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func replaceSecureFile(path string, data []byte) error {
	old, exists, err := readSecureFile(path, maxStateBytes)
	if err != nil || !exists {
		return errInvalidState
	}
	before, _ := os.Lstat(path)
	tmp, err := secureTemp(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	current, exists, err := readSecureFile(path, maxStateBytes)
	after, statErr := os.Lstat(path)
	if err != nil || !exists || statErr != nil || !os.SameFile(before, after) || !bytes.Equal(old, current) {
		return errInvalidState
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func removeSecureFile(path string) error {
	if _, exists, err := readSecureFile(path, 128); err != nil {
		return err
	} else if !exists {
		return nil
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
