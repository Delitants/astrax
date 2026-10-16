// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"net/http"
	"net/url"

	"astrax/internal/model"
)

type dvbCardInput struct {
	Alias      string                      `json:"alias"`
	Enabled    bool                        `json:"enabled"`
	RFDefaults model.AdapterLNBConfig      `json:"rf_defaults"`
	Advanced   model.AdapterAdvancedConfig `json:"advanced"`
}

func (s *Server) handleDVBCards(w http.ResponseWriter, r *http.Request) {
	parts, ok := dvbRoute(w, r, "/api/v1/dvb-cards")
	if !ok {
		return
	}
	if len(parts) == 0 {
		if !dvbGuard(w, r, http.MethodGet) {
			return
		}
		values, ok := dvbQuery(w, r, true)
		if !ok {
			return
		}
		query, err := parseDVBCardQuery(values)
		if err != nil {
			respondDVBError(w, err)
			return
		}
		if _, external := externalPrincipal(r); external {
			writeJSON(w, 200, s.store.ListPublicDVBCards(query))
		} else {
			writeJSON(w, 200, s.store.ListDVBCards(query))
		}
		return
	}
	if _, ok := dvbQuery(w, r, false); !ok {
		return
	}
	if len(parts) == 1 && parts[0] == "refresh" {
		if !dvbGuard(w, r, http.MethodPost) || !dvbActionBody(w, r) {
			return
		}
		result, err := s.store.RefreshDVBCards(r.Context())
		if err != nil {
			respondDVBError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	if len(parts) == 2 && parts[1] == "restart" || len(parts) == 3 && parts[1] == "operations" {
		s.handleDVBCardOperation(w, r, parts)
		return
	}
	if len(parts) != 1 {
		dvbNotFound(w)
		return
	}
	if !dvbGuard(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	card, err := s.store.DVBCard(parts[0])
	if err != nil || card.ID != parts[0] {
		dvbNotFound(w)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, 200, card)
		return
	}
	var in dvbCardInput
	if !dvbDecode(w, r, &in) {
		return
	}
	updated, err := s.store.UpdateDVBCard(parts[0], model.DVBCardConfig{Alias: in.Alias, Enabled: in.Enabled, RFDefaults: in.RFDefaults, Advanced: in.Advanced})
	if err != nil {
		respondDVBError(w, err)
		return
	}
	writeJSON(w, 200, updated)
}

func (s *Server) handleDVBCardOperation(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 3 {
		if !dvbGuard(w, r, http.MethodGet) {
			return
		}
		op, err := s.dvbOps.Operation(parts[2])
		if err != nil {
			respondDVBError(w, err)
			return
		}
		if op.ID != parts[2] || op.ResourceID != parts[0] || op.Kind != "dvb.card.restart" {
			dvbNotFound(w)
			return
		}
		writeJSON(w, 200, safeDVBOperation(op))
		return
	}
	if !dvbGuard(w, r, http.MethodPost) || !dvbActionBody(w, r) {
		return
	}
	card, err := s.store.DVBCard(parts[0])
	if err != nil || card.ID != parts[0] {
		dvbNotFound(w)
		return
	}
	op, err := s.dvbOps.RestartDVBCard(r.Context(), parts[0])
	if err != nil {
		respondDVBError(w, err)
		return
	}
	location := "/api/v1/dvb-cards/" + url.PathEscape(parts[0]) + "/operations/" + url.PathEscape(op.ID)
	w.Header().Set("Location", location)
	writeJSON(w, http.StatusAccepted, dvbOperationResponse{Operation: safeDVBOperation(op), OperationURL: location})
}
