// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestManagementRoleRouteAllowlist(t *testing.T) {
	for _, role := range []string{"viewer", "operator"} {
		for _, path := range []string{"/api/v1/status", "/api/v1/version", "/api/v1/streams", "/api/v1/adapters", "/api/v1/dvb-cards", "/api/v1/dvb-cards/dvb36.0", "/api/v1/dvb-streams", "/api/v1/dvb-streams/channel", "/api/v1/dvb-groups", "/api/v1/events"} {
			if !managementRoleAllows(role, http.MethodGet, path) {
				t.Errorf("%s cannot monitor %s", role, path)
			}
		}
		for _, path := range []string{"/api/v1/settings", "/api/v1/softcams", "/api/v1/adapter-profiles", "/api/v1/users", "/api/v1/logs", "/api/v1/certificates/status", "/api/v1/api/tokens", "/openapi.json", "/api/v1/missing", "/api/v1/dvb-cards/../users", "/api/v1//status", "/api/v1/dvb-streams/a%2Fb"} {
			if managementRoleAllows(role, http.MethodGet, path) {
				t.Errorf("%s granted private or noncanonical %s", role, path)
			}
		}
		for _, path := range []string{"/api/v1/settings", "/api/v1/users", "/api/v1/streams", "/api/v1/streams/channel", "/api/v1/dvb-cards/refresh", "/api/v1/dvb-cards/dvb36.0/restart", "/api/v1/dvb-groups", "/api/v1/dvb-scans", "/api/v1/control/restart"} {
			for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
				if managementRoleAllows(role, method, path) {
					t.Errorf("%s allowed %s %s", role, method, path)
				}
			}
		}
	}
	for _, prefix := range []string{"streams", "dvb-streams"} {
		for _, action := range []string{"start", "stop", "restart"} {
			path := "/api/v1/" + prefix + "/channel/" + action
			if !managementRoleAllows("operator", "POST", path) || managementRoleAllows("viewer", "POST", path) {
				t.Errorf("wrong control permission %s", path)
			}
		}
	}
	if !managementRoleAllows("operator", "POST", "/api/v1/dvb-streams/bulk") {
		t.Fatal("operator bulk control unavailable")
	}
	for _, role := range []string{"", "admin", "Administrator", "unknown"} {
		if managementRoleAllows(role, "GET", "/api/v1/status") {
			t.Errorf("unknown role %q granted access", role)
		}
	}
}

func TestOperatorBulkAllowsOnlyControlFields(t *testing.T) {
	for _, body := range []string{`{"action":"start","ids":["one"]}`, `{"action":"stop","ids":["one","two"]}`, `{"action":"restart","ids":["one"]}`} {
		if !operatorBulkControl([]byte(body)) {
			t.Errorf("valid control rejected: %s", body)
		}
	}
	for _, body := range []string{`{"action":"delete","ids":["one"]}`, `{"action":"assign_adapter","ids":["one"]}`, `{"action":"move_group","ids":["one"]}`, `{"action":"start","ids":["one"],"adapter":{}}`, `{"action":"start","ids":["one"],"group_id":"other"}`, `{"action":"start","ids":[]}`, `{"action":"start","ids":["one"]} {}`, `{"action":"start","action":"stop","ids":["one"]}`} {
		if operatorBulkControl([]byte(body)) {
			t.Errorf("unsafe bulk admitted: %s", body)
		}
	}
}

func TestMonitoringProjectionOwnsAndRedactsSensitiveData(t *testing.T) {
	original := map[string]any{"streams": []any{map[string]any{"id": "s1", "input_url": "srt://user:secret@host", "output_url": "srt://host?passphrase=secret", "runtime": map[string]any{"state": "running", "last_error": "secret diagnostic"}}}, "owner_command": "astra --password secret", "settings": map[string]any{"private_key": "secret"}, "softcams": []any{map[string]any{"password": "secret"}}}
	projected, err := monitoringValue(original)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(projected)
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "input_url") || strings.Contains(string(encoded), "owner_command") {
		t.Fatalf("projection leaks: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"state":"running"`) {
		t.Fatalf("runtime lost: %s", encoded)
	}
	if _, ok := original["owner_command"]; !ok {
		t.Fatal("projection mutated source")
	}
}
