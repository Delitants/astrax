// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"astrax/internal/model"
)

// PatchSettings merges only explicitly supplied GUI fields under the same
// runtime/settings gate as full replacement, so concurrent sections cannot
// overwrite each other's acknowledged updates.
func (s *Store) PatchSettings(fields map[string]json.RawMessage) (model.Settings, error) {
	if len(fields) == 0 {
		return model.Settings{}, errors.New("settings patch must contain at least one field")
	}
	return s.setSettings(model.Settings{}, fields)
}

func applySettingsPatch(in model.Settings, fields map[string]json.RawMessage) (model.Settings, error) {
	for name, value := range fields {
		switch name {
		case "http_play_port", "http_play_loopback", "srt_play_port", "playlist_name", "control_listen",
			"control_listen_https", "redirect_https", "tls_min_version", "log_level",
			"epg_enabled", "epg_source_urls", "epg_from_dvb", "epg_dvb_interval_sec",
			"epg_dvb_depth", "epg_dvb_priority", "epg_local_path", "epg_source_retention_hours", "epg_max_source_mib", "epg_source_timeout_sec", "epg_max_programmes":
		default:
			return model.Settings{}, fmt.Errorf("unsupported settings patch field %q", name)
		}
		if strings.TrimSpace(string(value)) == "null" {
			return model.Settings{}, fmt.Errorf("settings patch field %q cannot be null", name)
		}
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return model.Settings{}, err
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return model.Settings{}, fmt.Errorf("invalid settings patch: %w", err)
	}
	for _, name := range []string{"control_listen", "control_listen_https"} {
		if _, supplied := fields[name]; !supplied {
			continue
		}
		address := in.ControlListen
		if name == "control_listen_https" {
			address = in.ControlListenHTTPS
			if address == "" {
				continue
			}
		}
		host, portText, err := net.SplitHostPort(address)
		port, portErr := strconv.Atoi(portText)
		if err != nil || portErr != nil || port < 1 || port > 65535 || strings.ContainsAny(host, " \t\r\n/\\?#") {
			return model.Settings{}, fmt.Errorf("%s must be host:port with a port between 1 and 65535", name)
		}
	}
	if _, supplied := fields["tls_min_version"]; supplied && in.TLSMinVersion != "1.2" && in.TLSMinVersion != "1.3" {
		return model.Settings{}, errors.New("tls_min_version must be 1.2 or 1.3")
	}
	if in.RedirectHTTPS && in.ControlListenHTTPS == "" {
		return model.Settings{}, errors.New("redirect_https requires control_listen_https")
	}
	if _, supplied := fields["srt_play_port"]; supplied && in.SRTPlayPort <= 0 {
		return model.Settings{}, errors.New("srt_play_port must be between 1 and 65535")
	}
	if _, supplied := fields["log_level"]; supplied && in.LogLevel == "" {
		return model.Settings{}, errors.New("log_level must be debug, info, warn or error")
	}
	if _, supplied := fields["epg_dvb_interval_sec"]; supplied && (in.EPGDVBIntervalSec < 60 || in.EPGDVBIntervalSec > 86400) {
		return model.Settings{}, errors.New("epg_dvb_interval_sec must be between 60 and 86400")
	}
	if _, supplied := fields["epg_dvb_depth"]; supplied && in.EPGDVBDepth != "present_following" && in.EPGDVBDepth != "schedule" {
		return model.Settings{}, errors.New("epg_dvb_depth must be present_following or schedule")
	}
	if _, supplied := fields["epg_source_retention_hours"]; supplied && (in.EPGSourceRetentionHours < 1 || in.EPGSourceRetentionHours > 168) {
		return model.Settings{}, errors.New("epg_source_retention_hours must be between 1 and 168")
	}
	if err := validateEPGFetchLimitFields(fields); err != nil {
		return model.Settings{}, err
	}
	return in, nil
}

func logSeverity(level string) (int, bool) {
	switch level {
	case "debug":
		return 0, true
	case "info":
		return 1, true
	case "warn":
		return 2, true
	case "error":
		return 3, true
	default:
		return 1, false
	}
}
