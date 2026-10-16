// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openAPIPayload []byte

// OpenAPIDocument returns an owned copy of the bundled external API contract.
func OpenAPIDocument() []byte {
	return append([]byte(nil), openAPIPayload...)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeDVBError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", "")
		return
	}
	if _, ok := dvbQuery(w, r, false); !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// This is a static asset, not runtime data. JSON response redaction would
	// corrupt property names and write-only request schemas inside the contract.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPIPayload)
}
