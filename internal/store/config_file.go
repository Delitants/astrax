// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"astrax/internal/model"
)

// Config persistence is infrequent; one lock serializes every accepted path alias.
var configFileMu sync.Mutex

var errConfigLockCanceled = errors.New("config lock acquisition canceled")

type atomicWriteHooks struct {
	lockCancellation      <-chan struct{}
	onLockContended       func()
	afterLock             func()
	beforeRename          func(tempPath, destinationPath string) error
	syncDirectory         func(path string) error
	rollbackSyncDirectory func(path string) error
}

type configSnapshot struct {
	exists  bool
	payload []byte
	hash    [sha256.Size]byte
	mode    os.FileMode
}

type configExpectation struct {
	exists  bool
	payload []byte
	hash    [sha256.Size]byte
}

type pinnedConfigSource struct {
	file     *os.File
	identity os.FileInfo
	snapshot configSnapshot
}

func validateExistingConfigPath(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config path %s is a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config path %s is not a regular file", path)
	}
	return nil
}

func pinConfigSource(path string) (pinnedConfigSource, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return pinnedConfigSource{snapshot: configSnapshot{}}, nil
	}
	if err != nil {
		return pinnedConfigSource{}, err
	}
	if err := validateExistingConfigPath(path, pathInfo); err != nil {
		return pinnedConfigSource{}, err
	}

	file, err := os.Open(path)
	if err != nil {
		return pinnedConfigSource{}, err
	}
	fail := func(cause error) (pinnedConfigSource, error) {
		return pinnedConfigSource{}, errors.Join(cause, file.Close())
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		return fail(errors.New("config source identity changed while opening"))
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		return fail(err)
	}
	postReadInfo, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(fileInfo, postReadInfo) {
		return fail(errors.New("config source identity changed while reading"))
	}
	return pinnedConfigSource{
		file:     file,
		identity: fileInfo,
		snapshot: configSnapshot{
			exists:  true,
			payload: payload,
			hash:    sha256.Sum256(payload),
			mode:    fileInfo.Mode().Perm(),
		},
	}, nil
}

func (source *pinnedConfigSource) close() error {
	if source.file == nil {
		return nil
	}
	err := source.file.Close()
	source.file = nil
	return err
}

func (source *pinnedConfigSource) checkExpected(expected *configExpectation) error {
	if expected == nil {
		return nil
	}
	if source.snapshot.exists != expected.exists ||
		source.snapshot.hash != expected.hash ||
		!bytes.Equal(source.snapshot.payload, expected.payload) {
		return errors.New("config changed after load; refusing atomic replacement")
	}
	return nil
}

func (source *pinnedConfigSource) verify(path string, expected *configExpectation) error {
	if !source.snapshot.exists {
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if expected != nil && expected.exists {
				return errors.New("config changed after load; source no longer exists")
			}
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("config changed during atomic write; destination was created")
	}
	if source.file == nil {
		return errors.New("pinned config source is closed")
	}

	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat config before rename: %w", err)
	}
	if err := validateExistingConfigPath(path, pathInfo); err != nil {
		return err
	}
	fileInfo, err := source.file.Stat()
	if err != nil {
		return fmt.Errorf("stat pinned config before rename: %w", err)
	}
	if !os.SameFile(source.identity, fileInfo) || !os.SameFile(source.identity, pathInfo) {
		return errors.New("config changed during atomic write; source identity no longer matches")
	}
	if _, err := source.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind pinned config before rename: %w", err)
	}
	payload, err := io.ReadAll(source.file)
	if err != nil {
		return fmt.Errorf("read pinned config before rename: %w", err)
	}
	hash := sha256.Sum256(payload)
	if hash != source.snapshot.hash || !bytes.Equal(payload, source.snapshot.payload) {
		return errors.New("config changed during atomic write; source bytes no longer match")
	}
	if expected != nil && (hash != expected.hash || !bytes.Equal(payload, expected.payload)) {
		return errors.New("config changed after load; final source bytes do not match")
	}
	finalPathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("re-stat config before rename: %w", err)
	}
	if err := validateExistingConfigPath(path, finalPathInfo); err != nil {
		return err
	}
	if !os.SameFile(source.identity, finalPathInfo) {
		return errors.New("config changed during atomic write; final source identity no longer matches")
	}
	return nil
}

func readConfigBytes(path string) (payload []byte, retErr error) {
	configFileMu.Lock()
	defer configFileMu.Unlock()

	source, err := pinConfigSource(path)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, source.close())
		}
	}()
	if !source.snapshot.exists {
		return nil, fmt.Errorf("%s: %w", path, os.ErrNotExist)
	}
	if err := source.verify(path, nil); err != nil {
		return nil, err
	}
	payload = append([]byte(nil), source.snapshot.payload...)
	closeErr := source.close()
	closed = true
	if closeErr != nil {
		return nil, closeErr
	}
	return payload, nil
}

func writeConfigAtomic(path string, cfg model.Config) error {
	return writeConfigAtomicConditional(path, cfg, nil, atomicWriteHooks{})
}

func writeConfigAtomicExpected(path string, cfg model.Config, expectedSource []byte) error {
	expected := &configExpectation{
		exists:  true,
		payload: append([]byte(nil), expectedSource...),
		hash:    sha256.Sum256(expectedSource),
	}
	return writeConfigAtomicConditional(path, cfg, expected, atomicWriteHooks{})
}

func writeConfigAtomicWithHooks(path string, cfg model.Config, hooks atomicWriteHooks) error {
	return writeConfigAtomicConditional(path, cfg, nil, hooks)
}

func writeConfigAtomicExpectedWithHooks(path string, cfg model.Config, expectedSource []byte, hooks atomicWriteHooks) error {
	expected := &configExpectation{
		exists:  true,
		payload: append([]byte(nil), expectedSource...),
		hash:    sha256.Sum256(expectedSource),
	}
	return writeConfigAtomicConditional(path, cfg, expected, hooks)
}

func configLockCancellationRequested(cancellation <-chan struct{}) bool {
	if cancellation == nil {
		return false
	}
	select {
	case <-cancellation:
		return true
	default:
		return false
	}
}

func tryConfigFileLock(cancellation <-chan struct{}) (bool, error) {
	if configLockCancellationRequested(cancellation) {
		return false, errConfigLockCanceled
	}
	if !configFileMu.TryLock() {
		return false, nil
	}
	if configLockCancellationRequested(cancellation) {
		configFileMu.Unlock()
		return false, errConfigLockCanceled
	}
	return true, nil
}

func acquireConfigFileLock(hooks atomicWriteHooks) error {
	locked, err := tryConfigFileLock(hooks.lockCancellation)
	if err != nil {
		return err
	}
	if !locked {
		if hooks.onLockContended != nil {
			hooks.onLockContended()
		}
		if hooks.lockCancellation == nil {
			configFileMu.Lock()
		} else {
			// Cancellable acquisition is a test seam; production callers block normally.
			for !locked {
				runtime.Gosched()
				locked, err = tryConfigFileLock(hooks.lockCancellation)
				if err != nil {
					return err
				}
			}
		}
	}
	if hooks.afterLock != nil {
		hooks.afterLock()
	}
	return nil
}

func writeConfigAtomicConditional(path string, cfg model.Config, expected *configExpectation, hooks atomicWriteHooks) error {
	if err := acquireConfigFileLock(hooks); err != nil {
		return err
	}
	defer configFileMu.Unlock()
	return writeConfigAtomicLocked(path, cfg, expected, hooks)
}

func writeConfigAtomicLocked(path string, cfg model.Config, expected *configExpectation, hooks atomicWriteHooks) (retErr error) {
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	source, err := pinConfigSource(path)
	if err != nil {
		return fmt.Errorf("snapshot original config: %w", err)
	}
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			if err := source.close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close original config: %w", err))
			}
		}
	}()
	if err := source.checkExpected(expected); err != nil {
		return err
	}
	snapshot := source.snapshot

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create config temp: %w", err)
	}
	tmpName := tmp.Name()
	tmpClosed := false
	renamed := false
	defer func() {
		if !tmpClosed {
			if err := tmp.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close config temp: %w", err))
			}
		}
		if !renamed {
			if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove config temp: %w", err))
			}
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod config temp: %w", err)
	}
	if _, err := io.Copy(tmp, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("write config temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync config temp: %w", err)
	}
	closeErr := tmp.Close()
	tmpClosed = true
	if closeErr != nil {
		return fmt.Errorf("close config temp: %w", closeErr)
	}
	if hooks.beforeRename != nil {
		if err := hooks.beforeRename(tmpName, path); err != nil {
			return fmt.Errorf("before config rename: %w", err)
		}
	}
	if err := source.verify(path, expected); err != nil {
		return fmt.Errorf("verify config source before rename: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename config temp: %w", err)
	}
	renamed = true

	closeErr = source.close()
	sourceClosed = true
	if closeErr != nil {
		return rollbackConfigReplacement(path, snapshot, fmt.Errorf("close original config after rename: %w", closeErr), hooks)
	}

	syncDir := hooks.syncDirectory
	if syncDir == nil {
		syncDir = syncDirectory
	}
	if err := syncDir(dir); err != nil {
		return rollbackConfigReplacement(path, snapshot, fmt.Errorf("sync config directory: %w", err), hooks)
	}
	return nil
}

func rollbackConfigReplacement(path string, snapshot configSnapshot, cause error, hooks atomicWriteHooks) error {
	rollbackSync := hooks.rollbackSyncDirectory
	if rollbackSync == nil {
		rollbackSync = syncDirectory
	}
	if rollbackErr := restoreConfigSnapshot(path, snapshot, rollbackSync); rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("restore original config; rollback durability is uncertain: %w", rollbackErr))
	}
	return cause
}

func restoreConfigSnapshot(path string, snapshot configSnapshot, syncDir func(string) error) (retErr error) {
	dir := filepath.Dir(path)
	if !snapshot.exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(dir)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".rollback-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	closed := false
	renamed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, tmp.Close())
		}
		if !renamed {
			if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, err)
			}
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(tmp, bytes.NewReader(snapshot.payload)); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	closeErr := tmp.Close()
	closed = true
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	renamed = true
	if err := os.Chmod(path, snapshot.mode); err != nil {
		return err
	}
	restored, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := restored.Sync()
	closeErr = restored.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return err
	}
	return syncDir(dir)
}

func backupConfig(path string, now time.Time) (string, error) {
	configFileMu.Lock()
	defer configFileMu.Unlock()
	return backupConfigLocked(path, now)
}

func backupConfigLocked(path string, now time.Time) (backupPath string, retErr error) {
	source, err := pinConfigSource(path)
	if err != nil {
		return "", fmt.Errorf("open config for backup: %w", err)
	}
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			if err := source.close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close backup source: %w", err))
			}
		}
	}()
	if !source.snapshot.exists {
		return "", fmt.Errorf("open config for backup: %w", os.ErrNotExist)
	}

	dir := filepath.Dir(path)
	stamp := now.UTC().Format("20060102T150405.000000000Z")
	backup, err := os.CreateTemp(dir, filepath.Base(path)+".backup-"+stamp+"-*")
	if err != nil {
		return "", fmt.Errorf("create config backup: %w", err)
	}
	backupPath = backup.Name()
	backupClosed := false
	complete := false
	defer func() {
		if !backupClosed {
			if err := backup.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close config backup: %w", err))
			}
		}
		if !complete {
			removed := false
			if err := os.Remove(backupPath); err == nil {
				removed = true
			} else if !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove incomplete backup: %w", err))
			}
			if removed {
				if err := syncDirectory(dir); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("sync incomplete backup cleanup: %w", err))
				}
			}
			backupPath = ""
		}
	}()

	if err := backup.Chmod(0o600); err != nil {
		return "", fmt.Errorf("chmod config backup: %w", err)
	}
	if _, err := io.Copy(backup, bytes.NewReader(source.snapshot.payload)); err != nil {
		return "", fmt.Errorf("copy config backup: %w", err)
	}
	if err := backup.Sync(); err != nil {
		return "", fmt.Errorf("sync config backup: %w", err)
	}
	closeErr := backup.Close()
	backupClosed = true
	if closeErr != nil {
		return "", fmt.Errorf("close config backup: %w", closeErr)
	}

	if err := source.verify(path, nil); err != nil {
		return "", fmt.Errorf("verify backup source: %w", err)
	}
	closeErr = source.close()
	sourceClosed = true
	if closeErr != nil {
		return "", fmt.Errorf("close backup source: %w", closeErr)
	}

	stored, err := pinConfigSource(backupPath)
	if err != nil {
		return "", fmt.Errorf("open config backup for verification: %w", err)
	}
	storedClosed := false
	defer func() {
		if !storedClosed {
			if err := stored.close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close verified config backup: %w", err))
			}
		}
	}()
	if !stored.snapshot.exists || stored.snapshot.mode != 0o600 {
		return "", fmt.Errorf("config backup mode is %04o, want 0600", stored.snapshot.mode)
	}
	if stored.snapshot.hash != source.snapshot.hash || !bytes.Equal(stored.snapshot.payload, source.snapshot.payload) {
		return "", errors.New("config backup verification failed")
	}
	if err := stored.verify(backupPath, nil); err != nil {
		return "", fmt.Errorf("verify stored config backup: %w", err)
	}
	closeErr = stored.close()
	storedClosed = true
	if closeErr != nil {
		return "", fmt.Errorf("close verified config backup: %w", closeErr)
	}
	if err := syncDirectory(dir); err != nil {
		return "", fmt.Errorf("sync backup directory: %w", err)
	}
	complete = true
	return backupPath, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}
