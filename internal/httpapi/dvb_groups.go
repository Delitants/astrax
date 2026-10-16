// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"net/http"

	"astrax/internal/model"
)

func (s *Server) writeDVBGroups(w http.ResponseWriter) {
	writeJSON(w, 200, struct {
		Groups []model.DVBGroup `json:"groups"`
		Counts map[string]int   `json:"counts"`
	}{s.store.ListDVBGroups(), s.store.DVBGroupCounts()})
}

func (s *Server) handleDVBGroups(w http.ResponseWriter, r *http.Request) {
	parts, ok := dvbRoute(w, r, "/api/v1/dvb-groups")
	if !ok {
		return
	}
	if _, ok := dvbQuery(w, r, false); !ok {
		return
	}
	if len(parts) == 0 {
		if !dvbGuard(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		if r.Method == http.MethodGet {
			s.writeDVBGroups(w)
			return
		}
		var in struct {
			Name string `json:"name"`
		}
		if !dvbDecode(w, r, &in) {
			return
		}
		group, err := s.store.AddDVBGroup(model.DVBGroup{Name: in.Name})
		if err != nil {
			respondDVBError(w, err)
			return
		}
		writeJSON(w, 201, group)
		return
	}
	if len(parts) != 1 {
		dvbNotFound(w)
		return
	}
	if parts[0] == "reorder" {
		if !dvbGuard(w, r, http.MethodPost) {
			return
		}
		var in struct {
			IDs []string `json:"ids"`
		}
		if !dvbDecode(w, r, &in) {
			return
		}
		if len(in.IDs) == 0 || len(in.IDs) > maxDVBActionItems {
			dvbInvalid(w, "ids", "Select between 1 and 1000 groups")
			return
		}
		if err := s.store.ReorderDVBGroups(in.IDs); err != nil {
			respondDVBError(w, err)
			return
		}
		s.writeDVBGroups(w)
		return
	}
	if !dvbGuard(w, r, http.MethodPut, http.MethodDelete) {
		return
	}
	if r.Method == http.MethodDelete {
		if !dvbActionBody(w, r) {
			return
		}
		moved, err := s.store.DeleteDVBGroup(parts[0])
		if err != nil {
			respondDVBError(w, err)
			return
		}
		writeJSON(w, 200, map[string]int{"moved_streams": moved})
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !dvbDecode(w, r, &in) {
		return
	}
	group, err := s.store.UpdateDVBGroup(parts[0], model.DVBGroup{Name: in.Name})
	if err != nil {
		respondDVBError(w, err)
		return
	}
	writeJSON(w, 200, group)
}
