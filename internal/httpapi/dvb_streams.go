// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"astrax/internal/model"
)

type dvbStreamInput struct {
	Name               string                       `json:"name"`
	OutputURL          string                       `json:"output_url"`
	Protocol           string                       `json:"protocol"`
	Enabled            bool                         `json:"enabled"`
	GroupID            string                       `json:"group_id"`
	SoftcamID          string                       `json:"softcam_id"`
	DVB                *model.DVBStreamConfig       `json:"dvb"`
	DVBDescrambling    *model.DVBDescramblingConfig `json:"dvb_descrambling"`
	Scrambled          bool                         `json:"scrambled"`
	CAIDs              []int                        `json:"caids"`
	OnDemand           bool                         `json:"on_demand"`
	OnDemandTimeoutSec int                          `json:"on_demand_timeout_sec"`
	XMLTVChannelID     string                       `json:"xmltv_channel_id"`
}

type dvbStreamDecoder struct {
	input           dvbStreamInput
	policyDecodeErr error
}

// decodeDVBJSON deliberately redacts decoder errors. Preserve only the typed
// policy metadata here, without relaxing its top-level known-field contract.
func (in *dvbStreamDecoder) UnmarshalJSON(data []byte) error {
	var decoded dvbStreamInput
	in.policyDecodeErr = nil
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		var policyErr *model.DVBDescramblingError
		if errors.As(err, &policyErr) {
			in.policyDecodeErr = policyErr
		}
		return err
	}
	in.input = decoded
	return nil
}

func respondDVBStreamError(w http.ResponseWriter, err error) {
	var policyErr *model.DVBDescramblingError
	if errors.As(err, &policyErr) {
		status := http.StatusBadRequest
		message := "Invalid descrambling policy"
		if policyErr.Code == "backend_unavailable" {
			status = http.StatusUnprocessableEntity
			message = "CSA backend is unavailable in this build"
		}
		writeDVBError(w, status, policyErr.Code, message, policyErr.Field)
		return
	}
	respondDVBError(w, err)
}

func (in dvbStreamInput) stream() model.Stream {
	return model.Stream{Name: in.Name, OutputURL: in.OutputURL, Protocol: in.Protocol, Enabled: in.Enabled, GroupID: in.GroupID, SoftcamID: in.SoftcamID, DVB: in.DVB, DVBDescrambling: in.DVBDescrambling.Clone(), Scrambled: in.Scrambled, CAIDs: in.CAIDs, OnDemand: in.OnDemand, OnDemandTimeoutSec: in.OnDemandTimeoutSec, XMLTVChannelID: in.XMLTVChannelID}
}

func readDVBStream(w http.ResponseWriter, r *http.Request) (model.Stream, bool) {
	var decoded dvbStreamDecoder
	if err := r.Context().Err(); err != nil {
		respondDVBStreamError(w, err)
		return model.Stream{}, false
	}
	err := decodeDVBJSON(w, r, &decoded)
	if cancelled := r.Context().Err(); cancelled != nil {
		respondDVBStreamError(w, cancelled)
		return model.Stream{}, false
	}
	if err != nil {
		if decoded.policyDecodeErr != nil {
			err = decoded.policyDecodeErr
		}
		respondDVBStreamError(w, err)
		return model.Stream{}, false
	}
	in := decoded.input
	if strings.TrimSpace(in.Name) == "" {
		dvbInvalid(w, "name", "Name is required")
		return model.Stream{}, false
	}
	if strings.TrimSpace(in.OutputURL) == "" {
		dvbInvalid(w, "output_url", "Output URL is required")
		return model.Stream{}, false
	}
	if !validDVBIdentities(w, [2]string{"group_id", in.GroupID}, [2]string{"softcam_id", in.SoftcamID}) {
		return model.Stream{}, false
	}
	if !validDVBTransport(w, in.DVB, false) {
		return model.Stream{}, false
	}
	return in.stream(), true
}

func (s *Server) handleDVBStreams(w http.ResponseWriter, r *http.Request) {
	parts, ok := dvbRoute(w, r, "/api/v1/dvb-streams")
	if !ok {
		return
	}
	if len(parts) == 0 {
		if !dvbGuard(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		values, ok := dvbQuery(w, r, r.Method == http.MethodGet)
		if !ok {
			return
		}
		if r.Method == http.MethodGet {
			query, err := parseDVBStreamQuery(values)
			if err != nil {
				respondDVBError(w, err)
				return
			}
			if _, external := externalPrincipal(r); external {
				writeJSON(w, 200, s.store.ListPublicDVBStreams(query))
			} else {
				writeJSON(w, 200, s.store.ListDVBStreams(query))
			}
			return
		}
		in, ok := readDVBStream(w, r)
		if !ok {
			return
		}
		created, err := s.store.AddDVBStreamContext(r.Context(), in)
		if err != nil {
			respondDVBStreamError(w, err)
			return
		}
		writeJSON(w, 201, created)
		return
	}
	if len(parts) == 2 && parts[1] == "descrambling" {
		s.handleDVBDescrambling(w, r, parts[0])
		return
	}
	if _, ok := dvbQuery(w, r, false); !ok {
		return
	}
	if len(parts) == 1 && parts[0] == "bulk" {
		s.handleDVBBulk(w, r)
		return
	}
	if len(parts) > 2 || len(parts) == 2 && !slices.Contains([]string{"start", "stop", "restart"}, parts[1]) {
		dvbNotFound(w)
		return
	}
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	if len(parts) == 2 {
		methods = []string{http.MethodPost}
	}
	if !dvbGuard(w, r, methods...) {
		return
	}
	current, err := s.store.DVBStream(parts[0])
	if err != nil {
		respondDVBError(w, err)
		return
	}
	if len(parts) == 2 {
		if !dvbActionBody(w, r) {
			return
		}
		var result model.Stream
		switch parts[1] {
		case "start":
			result, err = s.store.StartStream(parts[0])
		case "stop":
			result, err = s.store.StopStream(parts[0])
		case "restart":
			result, err = s.store.RestartStream(parts[0])
		}
		if err != nil {
			respondDVBStreamError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, current)
	case http.MethodPut:
		in, ok := readDVBStream(w, r)
		if !ok {
			return
		}
		updated, err := s.store.UpdateDVBStreamContext(r.Context(), parts[0], in)
		if err != nil {
			respondDVBStreamError(w, err)
			return
		}
		writeJSON(w, 200, updated)
	case http.MethodDelete:
		if !dvbActionBody(w, r) {
			return
		}
		if err := s.store.DeleteDVBStream(parts[0]); err != nil {
			respondDVBError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleDVBDescrambling(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	if !dvbGuard(w, r, http.MethodGet) {
		return
	}
	read := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := dvbQuery(w, r, false); !ok {
			return
		}
		status, err := s.store.DVBDescramblingStatus(id)
		if err != nil {
			respondDVBError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, status)
	})
	// The external allowlist already authenticated read scope. Management has
	// no global auth middleware, so this endpoint must enforce it locally.
	if _, authenticated := externalPrincipal(r); authenticated {
		read.ServeHTTP(w, r)
		return
	}
	requireBearer(s.store, model.ScopeRead, read).ServeHTTP(w, r)
}

func (s *Server) handleDVBBulk(w http.ResponseWriter, r *http.Request) {
	if !dvbGuard(w, r, http.MethodPost) {
		return
	}
	var in model.BulkDVBStreamRequest
	if !dvbDecode(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > maxDVBActionItems {
		dvbInvalid(w, "ids", "Select between 1 and 1000 streams")
		return
	}
	if !slices.Contains([]string{"start", "stop", "restart", "move_group", "assign_adapter", "delete"}, in.Action) {
		dvbInvalid(w, "action", "Unsupported bulk action")
		return
	}
	if in.Action == "assign_adapter" && (in.Adapter == nil || !slices.Contains([]string{"auto", "fixed"}, in.Adapter.Mode) || in.Adapter.Mode == "fixed" && in.Adapter.DeviceKey == "" && in.Adapter.LastAddress == "") {
		dvbInvalid(w, "adapter", "Select Auto or a fixed DVB card")
		return
	}
	if !validDVBIdentities(w, [2]string{"group_id", in.GroupID}) {
		return
	}
	if in.Adapter != nil && !validDVBIdentities(w, [2]string{"adapter.device_key", in.Adapter.DeviceKey}, [2]string{"adapter.last_address", in.Adapter.LastAddress}) {
		return
	}
	result := model.BulkDVBStreamResult{Results: make([]model.BulkDVBStreamItemResult, len(in.IDs))}
	validIDs := make([]string, 0, len(in.IDs))
	indices := make([]int, 0, len(in.IDs))
	var operationError error
	for i, id := range in.IDs {
		result.Results[i].ID = id
		if strings.TrimSpace(id) != id || id == "" || len(id) > dvbPathPartLimit {
			result.Results[i].Error = "Invalid stream ID"
			continue
		}
		validIDs = append(validIDs, id)
		indices = append(indices, i)
	}
	if len(validIDs) > 0 {
		in.IDs = validIDs
		applied, err := s.store.BulkDVBStreams(in)
		if err != nil && len(applied.Results) == 0 {
			respondDVBError(w, err)
			return
		}
		operationError = err
		for i, item := range applied.Results {
			result.Results[indices[i]] = item
		}
	}
	for _, item := range result.Results {
		if item.OK {
			result.Succeeded++
		} else {
			result.Failed++
		}
	}
	writeDVBBulkResult(w, result, operationError)
}
