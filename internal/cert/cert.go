// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFileName = "cert.pem"
	keyFileName  = "key.pem"
)

// Manager handles certificate storage, generation, and retrieval.
type Manager struct {
	mu       sync.RWMutex
	certPath string
	keyPath  string
}

// New creates a certificate manager that stores certs in appDir/certificates/.
func New(appDir string) *Manager {
	dir := filepath.Join(appDir, "certificates")
	return &Manager{
		certPath: filepath.Join(dir, certFileName),
		keyPath:  filepath.Join(dir, keyFileName),
	}
}

// Exists returns true if both certificate and key files are present.
func (m *Manager) Exists() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, certErr := os.Stat(m.certPath)
	_, keyErr := os.Stat(m.keyPath)
	return certErr == nil && keyErr == nil
}

// Paths returns the file paths to the certificate and key.
func (m *Manager) Paths() (cert, key string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certPath, m.keyPath
}

// TLSConfig returns a tls.Config using the stored certificate.
// Returns nil if no certificate exists.
func (m *Manager) TLSConfig() (*tls.Config, error) {
	return m.TLSConfigWithVersion("")
}

// TLSConfigWithVersion returns a tls.Config with the specified minimum TLS version.
// Valid versions: "1.0", "1.1", "1.2", "1.3". Empty defaults to 1.2.
func (m *Manager) TLSConfigWithVersion(minVersion string) (*tls.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, certErr := os.Stat(m.certPath)
	_, keyErr := os.Stat(m.keyPath)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		return nil, nil
	}
	if certErr != nil || keyErr != nil {
		return nil, fmt.Errorf("incomplete certificate/key pair: cert=%v key=%v", certErr, keyErr)
	}
	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   parseTLSVersion(minVersion),
	}
	return cfg, nil
}

func parseTLSVersion(v string) uint16 {
	switch v {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// GenerateSelfSigned creates a new self-signed RSA certificate.
// durationDays controls validity period (0 defaults to 3650 = 10 years).
// commonName controls the certificate CN (empty defaults to "AstraX").
func (m *Manager) GenerateSelfSigned(hosts []string, durationDays int, commonName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(m.certPath), 0755); err != nil {
		return fmt.Errorf("create certificates directory: %w", err)
	}

	if durationDays <= 0 {
		durationDays = 3650
	}
	if commonName == "" {
		commonName = "AstraX"
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AstraX"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().UTC().Add(-5 * time.Minute),
		NotAfter:              time.Now().UTC().AddDate(0, 0, durationDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := parseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	var certPEM, keyPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return err
	}
	return m.savePairLocked(certPEM.Bytes(), keyPEM.Bytes(), os.Rename)
}

// Save validates before touching the stored pair.
func (m *Manager) Save(certPEM, keyPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.savePairLocked(certPEM, keyPEM, os.Rename)
}

// Two renames are not a crash-atomic transaction. Retained backups allow recovery
// from an ordinary replacement error; readers in this process share the lock.
func (m *Manager) savePairLocked(certPEM, keyPEM []byte, rename func(string, string) error) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	dir := filepath.Dir(m.certPath)
	if filepath.Dir(m.keyPath) != dir {
		return errors.New("certificate and key must share a directory")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	type file struct {
		path             string
		data             []byte
		mode             os.FileMode
		staged, backup   string
		existed, changed bool
	}
	files := []file{{path: m.certPath, data: certPEM, mode: 0644}, {path: m.keyPath, data: keyPEM, mode: 0600}}
	retain := false
	defer func() {
		for _, f := range files {
			if f.staged != "" {
				_ = os.Remove(f.staged)
			}
			if !retain && f.backup != "" {
				_ = os.Remove(f.backup)
			}
		}
	}()
	stage := func(data []byte, mode os.FileMode) (string, error) {
		f, err := os.CreateTemp(dir, ".astrax-cert-*")
		if err != nil {
			return "", err
		}
		name := f.Name()
		ok := false
		defer func() {
			_ = f.Close()
			if !ok {
				_ = os.Remove(name)
			}
		}()
		if err = f.Chmod(mode); err != nil {
			return "", err
		}
		if _, err = f.Write(data); err != nil {
			return "", err
		}
		if err = f.Sync(); err != nil {
			return "", err
		}
		if err = f.Close(); err != nil {
			return "", err
		}
		ok = true
		return name, nil
	}
	syncDir := func() error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	for i := range files {
		f := &files[i]
		info, err := os.Lstat(f.path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("certificate target is not a regular file: %s", f.path)
			}
			old, err := os.ReadFile(f.path)
			if err != nil {
				return err
			}
			f.backup, err = stage(old, info.Mode().Perm())
			if err != nil {
				return err
			}
			f.existed = true
		} else if !os.IsNotExist(err) {
			return err
		}
		f.staged, err = stage(f.data, f.mode)
		if err != nil {
			return err
		}
	}
	if err := syncDir(); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []error
		for i := len(files) - 1; i >= 0; i-- {
			f := &files[i]
			if !f.changed {
				continue
			}
			var err error
			if f.existed {
				err = rename(f.backup, f.path)
				if err == nil {
					f.backup = ""
				}
			} else {
				err = os.Remove(f.path)
			}
			if err != nil {
				retain = true
				failures = append(failures, fmt.Errorf("restore %s (backup %s): %w", f.path, f.backup, err))
			}
		}
		if err := syncDir(); err != nil {
			failures = append(failures, err)
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	for i := range files {
		f := &files[i]
		if err := rename(f.staged, f.path); err != nil {
			return rollback(fmt.Errorf("replace %s: %w", f.path, err))
		}
		f.staged = ""
		f.changed = true
	}
	if err := syncDir(); err != nil {
		return rollback(err)
	}
	return nil
}

// Delete removes stored certificates.
func (m *Manager) Delete() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.deletePairLocked(os.Remove, os.Rename, os.Chmod, syncCertificateDirectory)
}

// Private backups allow ordinary failure recovery, not a crash-atomic deletion.
func (m *Manager) deletePairLocked(remove func(string) error, rename func(string, string) error,
	chmod func(string, os.FileMode) error, syncDirectory func(string) error) (result error) {
	dir := filepath.Dir(m.certPath)
	if filepath.Dir(m.keyPath) != dir {
		return errors.New("certificate and key must share a directory")
	}
	type file struct {
		path, backup, restore string
		mode                  os.FileMode
		existed, removed      bool
	}
	files := []file{{path: m.certPath}, {path: m.keyPath}}
	anyExists := false
	for i := range files {
		f := &files[i]
		info, err := os.Lstat(f.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("certificate target is not a regular file: %s", f.path)
		}
		f.mode, f.existed = info.Mode().Perm(), true
		anyExists = true
	}
	if !anyExists {
		return nil
	}
	syncDir := func() error { return syncDirectory(dir) }
	retain := false
	defer func() {
		for _, f := range files {
			if f.restore != "" {
				if err := remove(f.restore); err != nil && !os.IsNotExist(err) {
					result = errors.Join(result, fmt.Errorf("remove recovery staging %s: %w", f.restore, err))
				}
			}
		}
		if retain {
			return
		}
		for _, f := range files {
			if f.backup == "" {
				continue
			}
			if err := remove(f.backup); err != nil && !os.IsNotExist(err) {
				result = errors.Join(result, fmt.Errorf("remove recovery backup %s: %w", f.backup, err))
			}
		}
		if err := syncDir(); err != nil {
			result = errors.Join(result, fmt.Errorf("sync certificate directory: %w", err))
		}
	}()
	stage := func(data []byte, prefix string) (string, error) {
		backup, err := os.CreateTemp(dir, prefix)
		if err != nil {
			return "", err
		}
		err = backup.Chmod(0600)
		if err == nil {
			_, err = backup.Write(data)
		}
		if err == nil {
			err = backup.Sync()
		}
		err = errors.Join(err, backup.Close())
		return backup.Name(), err
	}
	for i := range files {
		f := &files[i]
		if !f.existed {
			continue
		}
		data, err := os.ReadFile(f.path)
		if err != nil {
			return fmt.Errorf("read %s before deletion: %w", f.path, err)
		}
		f.backup, err = stage(data, ".astrax-cert-delete-*")
		if err != nil {
			return fmt.Errorf("prepare deletion backup %s: %w", f.backup, err)
		}
	}
	if err := syncDir(); err != nil {
		return fmt.Errorf("sync deletion backups: %w", err)
	}
	rollback := func(cause error) error {
		failures := []error{cause}
		for i := len(files) - 1; i >= 0; i-- {
			f := &files[i]
			if !f.removed {
				continue
			}
			data, err := os.ReadFile(f.backup)
			if err == nil {
				f.restore, err = stage(data, ".astrax-cert-restore-*")
			}
			if err == nil {
				err = rename(f.restore, f.path)
			}
			if err != nil {
				retain = true
				failures = append(failures, fmt.Errorf("restore %s (backup %s): %w", f.path, f.backup, err))
				continue
			}
			f.restore = ""
			if err := chmod(f.path, f.mode); err != nil {
				retain = true
				failures = append(failures, fmt.Errorf("restore permissions %s: %w", f.path, err))
			}
		}
		if err := syncDir(); err != nil {
			retain = true
			failures = append(failures, fmt.Errorf("sync restored certificates: %w", err))
		}
		return errors.Join(failures...)
	}
	for i := range files {
		f := &files[i]
		if !f.existed {
			continue
		}
		if err := remove(f.path); err != nil && !os.IsNotExist(err) {
			return rollback(fmt.Errorf("delete %s: %w", f.path, err))
		}
		f.removed = true
	}
	if err := syncDir(); err != nil {
		return rollback(fmt.Errorf("sync deleted certificates: %w", err))
	}
	return nil
}

func syncCertificateDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}
