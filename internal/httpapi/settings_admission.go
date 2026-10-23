// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"errors"
	"fmt"

	"astrax/internal/adminauth"
	"astrax/internal/model"
)

// validateManagementSettings mirrors startup preflight for a merged settings
// candidate. It reads the server's existing auth and certificate managers.
func (s *Server) validateManagementSettings(in model.Settings) error {
	if s.certMgr == nil {
		return errors.New("management certificate manager unavailable")
	}
	tlsConfig, err := s.certMgr.TLSConfigWithVersion(in.TLSMinVersion)
	if err != nil {
		return fmt.Errorf("load management TLS certificate: %w", err)
	}
	enrolled, err := s.auth.EnrollmentState()
	if err != nil {
		return fmt.Errorf("verify administrator enrollment: %w", err)
	}
	if in.RedirectHTTPS && !enrolled {
		return errors.New("HTTPS redirect requires administrator enrollment")
	}
	httpsAddr := in.ControlListenHTTPS
	if tlsConfig == nil && !in.RedirectHTTPS && httpsAddr == model.DefaultSettings().ControlListenHTTPS {
		httpsAddr = ""
	}
	admission, err := adminauth.AdmitManagement(in.ControlListen, httpsAddr, enrolled, tlsConfig, false)
	if err != nil {
		return err
	}
	if in.RedirectHTTPS && !admission.StartHTTPS {
		return errors.New("HTTPS redirect requires an admitted HTTPS listener and certificate")
	}
	return nil
}
