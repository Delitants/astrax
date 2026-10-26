// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
)

type monitoringManagementKey struct{}

func restrictedManagement(r *http.Request) bool {
	restricted, _ := r.Context().Value(monitoringManagementKey{}).(bool)
	return restricted
}

// Use an allowlist, not HTTP verbs alone: several GET endpoints contain
// credentials and several POST endpoints can retune shared DVB equipment.
func managementRoleAllows(role, method, resource string) bool {
	if role == "administrator" {
		return true
	}
	if role != "operator" && role != "viewer" {
		return false
	}
	if path.Clean(resource) != resource || strings.ContainsAny(resource, "%\\") || strings.Contains(resource, "//") {
		return false
	}
	if method == http.MethodGet {
		switch resource {
		case "/api/v1/status", "/api/v1/version", "/api/v1/adapters", "/api/v1/streams", "/api/v1/dvb-cards", "/api/v1/dvb-streams", "/api/v1/dvb-groups", "/api/v1/events":
			return true
		}
		for _, prefix := range []string{"/api/v1/dvb-cards/", "/api/v1/dvb-streams/"} {
			if suffix, ok := strings.CutPrefix(resource, prefix); ok && suffix != "" && !strings.Contains(suffix, "/") {
				return true
			}
		}
	}
	if role != "operator" || method != http.MethodPost {
		return false
	}
	if resource == "/api/v1/dvb-streams/bulk" {
		return true
	}
	for _, prefix := range []string{"/api/v1/streams/", "/api/v1/dvb-streams/"} {
		if suffix, ok := strings.CutPrefix(resource, prefix); ok {
			parts := strings.Split(suffix, "/")
			if len(parts) == 2 && parts[0] != "" && (parts[1] == "start" || parts[1] == "stop" || parts[1] == "restart") {
				return true
			}
		}
	}
	return false
}

// Reject duplicate/unknown fields before the ordinary bulk handler can run.
// An operator's request cannot smuggle group or adapter configuration changes.
func operatorBulkControl(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, 2)
	var action string
	var ids []string
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		switch key {
		case "action":
			err = decoder.Decode(&action)
		case "ids":
			err = decoder.Decode(&ids)
		default:
			return false
		}
		if err != nil {
			return false
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false
	}
	if len(ids) < 1 || len(ids) > maxDVBActionItems || !(action == "start" || action == "stop" || action == "restart") {
		return false
	}
	return true
}

func monitoringValue(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var owned any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&owned); err != nil {
		return nil, err
	}
	redactExternalValue(owned)
	return owned, nil
}
