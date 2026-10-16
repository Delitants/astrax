// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"astrax/internal/epg"
	"astrax/internal/model"
	"encoding/json"
	"fmt"
	"time"
)

func normalizeEPGFetchLimits(s *model.Settings) {
	d := model.DefaultSettings()
	if s.EPGMaxSourceMiB == 0 {
		s.EPGMaxSourceMiB = d.EPGMaxSourceMiB
	}
	if s.EPGSourceTimeoutSec == 0 {
		s.EPGSourceTimeoutSec = d.EPGSourceTimeoutSec
	}
	if s.EPGMaxProgrammes == 0 {
		s.EPGMaxProgrammes = d.EPGMaxProgrammes
	}
}

func validateEPGFetchLimits(s model.Settings, legacy bool) error {
	for _, v := range []struct {
		name       string
		value, max int
	}{
		{"epg_max_source_mib", s.EPGMaxSourceMiB, 256},
		{"epg_source_timeout_sec", s.EPGSourceTimeoutSec, 120},
		{"epg_max_programmes", s.EPGMaxProgrammes, 1000000},
	} {
		if legacy && v.value == 0 {
			continue
		}
		if v.value < 1 || v.value > v.max {
			return fmt.Errorf("%s must be between 1 and %d", v.name, v.max)
		}
	}
	return nil
}

// Presence is checked before legacy defaults so explicit null/zero cannot
// silently disable safeguards in a persisted configuration.
func validatePersistedEPGFetchLimits(data []byte) error {
	var raw struct {
		Settings struct {
			Size       json.RawMessage `json:"epg_max_source_mib"`
			Timeout    json.RawMessage `json:"epg_source_timeout_sec"`
			Programmes json.RawMessage `json:"epg_max_programmes"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	return validateEPGFetchLimitFields(map[string]json.RawMessage{
		"epg_max_source_mib": raw.Settings.Size, "epg_source_timeout_sec": raw.Settings.Timeout, "epg_max_programmes": raw.Settings.Programmes,
	})
}

func validateEPGFetchLimitFields(fields map[string]json.RawMessage) error {
	for field, max := range map[string]int{"epg_max_source_mib": 256, "epg_source_timeout_sec": 120, "epg_max_programmes": 1000000} {
		value := fields[field]
		if len(value) == 0 {
			continue
		}
		var number int
		if string(value) == "null" {
			return fmt.Errorf("%s cannot be null", field)
		}
		if err := json.Unmarshal(value, &number); err != nil {
			return fmt.Errorf("invalid %s: %w", field, err)
		}
		if number < 1 || number > max {
			return fmt.Errorf("%s must be between 1 and %d", field, max)
		}
	}
	return nil
}

func runtimeEPGFetchLimits(s model.Settings) epg.FetchLimits {
	return epg.FetchLimits{MaxSourceBytes: int64(s.EPGMaxSourceMiB) * 1024 * 1024, Timeout: time.Duration(s.EPGSourceTimeoutSec) * time.Second, MaxProgrammes: s.EPGMaxProgrammes}
}
