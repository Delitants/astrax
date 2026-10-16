// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
)

type externalResponseWriter struct{ http.ResponseWriter }

func (w externalResponseWriter) writeJSON(status int, data any) {
	blob, err := json.Marshal(data)
	if err != nil {
		writeDVBError(w.ResponseWriter, 500, "internal_error", "Response could not be encoded", "")
		return
	}
	var owned any
	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.UseNumber()
	if err = decoder.Decode(&owned); err != nil {
		writeDVBError(w.ResponseWriter, 500, "internal_error", "Response could not be encoded", "")
		return
	}
	redactExternalValue(owned)
	writeJSON(w.ResponseWriter, status, owned)
}

// Work on a serialized owned copy: redacting an API read must never modify
// the config, subscriber snapshots, or runtime objects shared with management.
func redactExternalValue(value any, path ...string) {
	switch v := value.(type) {
	case []any:
		for _, child := range v {
			redactExternalValue(child, path...)
		}
	case map[string]any:
		// These schemas are opaque identifier-to-count maps, not field objects.
		// Preserve every identifier, but never exempt nonnumeric content.
		if externalCountMap(path) {
			for key, child := range v {
				if _, numeric := child.(json.Number); !numeric {
					delete(v, key)
				}
			}
			return
		}
		for key, child := range v {
			switch key {
			case "input_url", "output_url", "output_template", "owner_command", "control_endpoint", "hash", "password", "des_key", "private_key", "api_tokens", "softcams", "settings", "result":
				delete(v, key)
			case "message", "error", "last_error", "warning", "refresh_error":
				if text, ok := child.(string); ok {
					if text != "" {
						v[key] = "Details withheld; see management UI"
					}
				} else {
					redactExternalValue(child, append(path, key)...)
				}
			default:
				redactExternalValue(child, append(path, key)...)
			}
		}
	}
}

func externalCountMap(path []string) bool {
	return len(path) == 1 && path[0] == "counts" || len(path) == 2 && path[0] == "facets" && slices.Contains([]string{
		"groups", "statuses", "requested_adapters", "actual_adapters", "delivery_systems", "protocols",
	}, path[1])
}
