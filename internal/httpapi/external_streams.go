// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"astrax/internal/model"
)

type externalStreamInput struct {
	Name               string `json:"name"`
	InputURL           string `json:"input_url"`
	OutputURL          string `json:"output_url"`
	Protocol           string `json:"protocol"`
	SoftcamID          string `json:"softcam_id"`
	Enabled            bool   `json:"enabled"`
	OnDemand           bool   `json:"on_demand"`
	OnDemandTimeoutSec int    `json:"on_demand_timeout_sec"`
	XMLTVChannelID     string `json:"xmltv_channel_id"`
}

func (s *Server) handleExternalStreams(w http.ResponseWriter, r *http.Request) {
	parts, ok := dvbRoute(w, r, "/api/v1/streams")
	if !ok {
		return
	}
	values, ok := dvbQuery(w, r, len(parts) == 0 && r.Method == http.MethodGet)
	if !ok {
		return
	}
	if len(parts) == 0 && r.Method == http.MethodGet {
		query, err := dvbQueryValues(values, "page limit q")
		if err != nil {
			respondDVBError(w, err)
			return
		}
		page, limit, err := dvbPagination(query)
		if err != nil {
			respondDVBError(w, err)
			return
		}
		streams := externalStreams(s.store.ListStreams())
		filtered := make([]model.Stream, 0, len(streams))
		search := strings.ToLower(query["q"])
		for _, stream := range streams {
			if strings.Contains(strings.ToLower(stream.Name), search) || strings.Contains(strings.ToLower(stream.ID), search) {
				filtered = append(filtered, stream)
			}
		}
		total := len(filtered)
		start := min((page-1)*limit, total)
		end := start + min(limit, total-start)
		writeJSON(w, 200, map[string]any{"streams": filtered[start:end], "total": total, "page": page, "limit": limit})
		return
	}
	if len(parts) > 0 {
		found := false
		for _, stream := range externalStreams(s.store.ListStreams()) {
			if stream.ID == parts[0] {
				found = true
				if r.Method == http.MethodGet {
					writeJSON(w, 200, stream)
					return
				}
				break
			}
		}
		if !found {
			writeDVBError(w, 404, "not_found", "Stream not found", "")
			return
		}
	}
	if len(parts) == 2 {
		if !dvbActionBody(w, r) {
			return
		}
		var stream model.Stream
		var err error
		switch parts[1] {
		case "start":
			stream, err = s.store.StartStream(parts[0])
		case "stop":
			stream, err = s.store.StopStream(parts[0])
		case "restart":
			stream, err = s.store.RestartStream(parts[0])
		}
		if err != nil {
			respondDVBError(w, err)
			return
		}
		writeJSON(w, 200, stream)
		return
	}
	if r.Method == http.MethodDelete {
		if !dvbActionBody(w, r) {
			return
		}
		if err := s.store.DeleteStream(parts[0]); err != nil {
			respondDVBError(w, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	var in externalStreamInput
	if !dvbDecode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.InputURL) == "" || strings.TrimSpace(in.OutputURL) == "" {
		writeDVBError(w, 400, "invalid_configuration", "Name, input URL and output URL are required", "")
		return
	}
	parsed, err := url.Parse(in.InputURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "udp") && !strings.EqualFold(parsed.Scheme, "rtp") && !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "srt") && !strings.EqualFold(parsed.Scheme, "rtsp") && !strings.EqualFold(parsed.Scheme, "rtsps") {
		writeDVBError(w, 400, "invalid_configuration", "A supported network input URL is required", "input_url")
		return
	}
	stream := model.Stream{Name: in.Name, InputURL: in.InputURL, OutputURL: in.OutputURL, Protocol: in.Protocol, SoftcamID: in.SoftcamID, Enabled: in.Enabled, OnDemand: in.OnDemand, OnDemandTimeoutSec: in.OnDemandTimeoutSec, XMLTVChannelID: in.XMLTVChannelID}
	status := 200
	if len(parts) == 0 {
		stream, err = s.store.AddStream(stream)
		status = 201
	} else {
		stream, err = s.store.UpdateStream(parts[0], stream)
	}
	if err != nil {
		respondDVBError(w, err)
		return
	}
	writeJSON(w, status, stream)
}

func (s *Server) handleExternalLogs(w http.ResponseWriter, r *http.Request) {
	values, ok := dvbQuery(w, r, true)
	if !ok {
		return
	}
	query, err := dvbQueryValues(values, "limit")
	if err != nil {
		respondDVBError(w, err)
		return
	}
	limit := 200
	if value, present := query["limit"]; present {
		var valid bool
		limit, valid = dvbPositiveInt(value)
		if !valid || limit > 1000 {
			respondDVBError(w, dvbQueryError("limit"))
			return
		}
	}
	writeJSON(w, 200, map[string]any{"logs": s.store.ListLogs(limit), "messages_redacted": true})
}
