// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"astrax/internal/model"
)

type externalRoute struct {
	Method      string
	Pattern     string
	Scope       string
	OperationID string
	Handler     http.HandlerFunc
}

func (s *Server) externalRoutes() []externalRoute {
	routes := []externalRoute{
		{"GET", "/api/v1/version", model.ScopeRead, "getVersion", s.handleVersion},
		{"GET", "/api/v1/status", model.ScopeRead, "getStatus", s.handleStatus},
		{"GET", "/api/v1/logs", model.ScopeRead, "listLogs", s.handleExternalLogs},
		{"GET", "/api/v1/streams", model.ScopeRead, "listStreams", s.handleExternalStreams},
		{"POST", "/api/v1/streams", model.ScopeAdmin, "createStream", s.handleExternalStreams},
		{"GET", "/api/v1/streams/{id}", model.ScopeRead, "getStream", s.handleExternalStreams},
		{"PUT", "/api/v1/streams/{id}", model.ScopeAdmin, "updateStream", s.handleExternalStreams},
		{"DELETE", "/api/v1/streams/{id}", model.ScopeAdmin, "deleteStream", s.handleExternalStreams},
		{"GET", "/api/v1/dvb-cards", model.ScopeRead, "listDVBCards", s.handleDVBCards},
		{"POST", "/api/v1/dvb-cards/refresh", model.ScopeAdmin, "refreshDVBCards", s.handleDVBCards},
		{"GET", "/api/v1/dvb-cards/{id}", model.ScopeRead, "getDVBCard", s.handleDVBCards},
		{"PUT", "/api/v1/dvb-cards/{id}", model.ScopeAdmin, "updateDVBCard", s.handleDVBCards},
		{"POST", "/api/v1/dvb-cards/{id}/restart", model.ScopeStreamsControl, "restartDVBCard", s.handleDVBCards},
		{"GET", "/api/v1/dvb-cards/{id}/operations/{operation}", model.ScopeRead, "getDVBCardOperation", s.handleDVBCards},
		{"GET", "/api/v1/dvb-streams", model.ScopeRead, "listDVBStreams", s.handleDVBStreams},
		{"POST", "/api/v1/dvb-streams", model.ScopeAdmin, "createDVBStream", s.handleDVBStreams},
		{"POST", "/api/v1/dvb-streams/bulk", externalBulkScope, "bulkDVBStreams", s.handleExternalBulk},
		{"GET", "/api/v1/dvb-streams/{id}", model.ScopeRead, "getDVBStream", s.handleDVBStreams},
		{"GET", "/api/v1/dvb-streams/{id}/descrambling", model.ScopeRead, "getDVBDescramblingStatus", s.handleDVBStreams},
		{"PUT", "/api/v1/dvb-streams/{id}", model.ScopeAdmin, "updateDVBStream", s.handleDVBStreams},
		{"DELETE", "/api/v1/dvb-streams/{id}", model.ScopeAdmin, "deleteDVBStream", s.handleDVBStreams},
		{"POST", "/api/v1/dvb-scans", model.ScopeAdmin, "createDVBScan", s.handleDVBScans},
		{"GET", "/api/v1/dvb-scans/{id}", model.ScopeRead, "getDVBScan", s.handleDVBScans},
		{"POST", "/api/v1/dvb-scans/{id}/import", model.ScopeAdmin, "importDVBScan", s.handleDVBScans},
		{"GET", "/api/v1/dvb-groups", model.ScopeRead, "listDVBGroups", s.handleDVBGroups},
		{"POST", "/api/v1/dvb-groups", model.ScopeAdmin, "createDVBGroup", s.handleDVBGroups},
		{"POST", "/api/v1/dvb-groups/reorder", model.ScopeAdmin, "reorderDVBGroups", s.handleDVBGroups},
		{"PUT", "/api/v1/dvb-groups/{id}", model.ScopeAdmin, "updateDVBGroup", s.handleDVBGroups},
		{"DELETE", "/api/v1/dvb-groups/{id}", model.ScopeAdmin, "deleteDVBGroup", s.handleDVBGroups},
		{"GET", "/api/v1/epg", model.ScopeRead, "getEPG", s.handleEPG},
		{"GET", "/openapi.json", model.ScopeRead, "getOpenAPI", s.handleOpenAPI},
	}
	for _, resource := range []struct {
		path, id string
		handler  http.HandlerFunc
	}{{"streams", "Stream", s.handleExternalStreams}, {"dvb-streams", "DVBStream", s.handleDVBStreams}} {
		for _, action := range []string{"start", "stop", "restart"} {
			routes = append(routes, externalRoute{"POST", "/api/v1/" + resource.path + "/{id}/" + action, model.ScopeStreamsControl, action + resource.id, resource.handler})
		}
	}
	return routes
}

// ExternalHandler constructs an allowlisted handler; it never binds a listener.
func (s *Server) ExternalHandler() http.Handler {
	return s.externalHandler(s.store.Settings().ExternalAPI)
}

func (s *Server) externalHandler(settings model.ExternalAPISettings) http.Handler {
	routes := s.externalRoutes()
	return cors(settings, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			if _, err := dvbPathParts(r, ""); err != nil {
				respondDVBError(w, err)
				return
			}
		}
		requested := r.Method
		if r.Method == http.MethodOptions {
			requested = r.Header.Get("Access-Control-Request-Method")
		}
		// Literal segments win over placeholders regardless of the request method.
		// No ServeMux cleaning redirects or implicit HEAD admission at this boundary.
		best := -1
		var candidates []externalRoute
		for _, route := range routes {
			score, ok := externalPathMatch(r.URL.EscapedPath(), route.Pattern)
			if !ok {
				continue
			}
			if score > best {
				best = score
				candidates = nil
			}
			if score == best {
				candidates = append(candidates, route)
			}
		}
		if len(candidates) == 0 {
			writeDVBError(w, 404, "not_found", "Resource not found", "")
			return
		}
		var methods []string
		for _, route := range candidates {
			methods = append(methods, route.Method)
			if route.Method != requested {
				continue
			}
			if r.Method == http.MethodOptions {
				if r.Header.Get("Origin") == "" {
					writeDVBError(w, 403, "invalid_preflight", "Origin is required", "")
					return
				}
				w.Header().Set("Access-Control-Allow-Methods", requested)
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			requireBearer(s.store, route.Scope, route.Handler).ServeHTTP(externalResponseWriter{w}, r)
			return
		}
		slices.Sort(methods)
		w.Header().Set("Allow", strings.Join(methods, ", "))
		writeDVBError(w, 405, "method_not_allowed", "Method not allowed", "")
	}))
}

func externalPathMatch(path, pattern string) (int, bool) {
	actual, want := strings.Split(path, "/"), strings.Split(pattern, "/")
	if len(actual) != len(want) {
		return 0, false
	}
	score := 0
	for i, part := range want {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if actual[i] == "" {
				return 0, false
			}
			continue
		}
		if part != actual[i] {
			return 0, false
		}
		score++
	}
	return score, true
}

func (s *Server) handleExternalBulk(w http.ResponseWriter, r *http.Request) {
	var in model.BulkDVBStreamRequest
	if !dvbDecode(w, r, &in) {
		return
	}
	scope := model.ScopeAdmin
	switch in.Action {
	case "start", "stop", "restart":
		scope = model.ScopeStreamsControl
	case "move_group", "assign_adapter", "delete":
	default:
		dvbInvalid(w, "action", "Unsupported bulk action")
		return
	}
	token, ok := externalPrincipal(r)
	if !ok || !slices.Contains(token.Scopes, scope) {
		externalForbidden(w)
		return
	}
	data, err := json.Marshal(in)
	if err != nil {
		writeDVBError(w, 400, "invalid_json", "Invalid bulk request", "")
		return
	}
	r = r.Clone(r.Context())
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	s.handleDVBStreams(w, r)
}
