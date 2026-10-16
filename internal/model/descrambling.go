// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

import (
	"encoding/json"
	"errors"
	"slices"
)

// DVBDescramblingConfig carries policy only. SoftcamID remains on Stream.
type DVBDescramblingConfig struct {
	Enabled   bool   `json:"enabled"`
	Algorithm string `json:"algorithm"`
	CAID      string `json:"caid"`
	Provider  string `json:"provider"`
	ECMPID    *int   `json:"ecm_pid,omitempty"`
}

// DVBDescramblingError contains metadata only, never rejected field values.
type DVBDescramblingError struct {
	Field string
	Code  string
}

func (e *DVBDescramblingError) Error() string { return e.Field + ": " + e.Code }

func descramblingJSONField(key string) string {
	if key == "" || len(key) > 64 {
		return "dvb_descrambling"
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "dvb_descrambling"
		}
	}
	return "dvb_descrambling." + key
}

// Keep strict decoding local to this nested policy, including config-file loads.
func (c *DVBDescramblingConfig) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return &DVBDescramblingError{Field: "dvb_descrambling", Code: "invalid_json"}
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		switch key {
		case "enabled", "algorithm", "caid", "provider", "ecm_pid":
		default:
			return &DVBDescramblingError{Field: descramblingJSONField(key), Code: "unknown_field"}
		}
	}
	type policy DVBDescramblingConfig
	var decoded policy
	if err := json.Unmarshal(data, &decoded); err != nil {
		field := "dvb_descrambling"
		var invalid *json.UnmarshalTypeError
		if errors.As(err, &invalid) {
			field = descramblingJSONField(invalid.Field)
		}
		return &DVBDescramblingError{Field: field, Code: "invalid_json"}
	}
	*c = DVBDescramblingConfig(decoded)
	return nil
}

func (c *DVBDescramblingConfig) Clone() *DVBDescramblingConfig {
	if c == nil {
		return nil
	}
	out := *c
	if c.ECMPID != nil {
		pid := *c.ECMPID
		out.ECMPID = &pid
	}
	return &out
}
