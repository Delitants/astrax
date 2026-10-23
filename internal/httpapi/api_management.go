// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"unicode"

	"astrax/internal/model"
	"astrax/internal/store"
)

type apiManagementState struct {
	Settings model.ExternalAPISettings `json:"settings"`
	Status   model.ExternalAPIStatus   `json:"status"`
	Error    *dvbContractError         `json:"error,omitempty"`
}

func (s *Server) apiManagementState() apiManagementState {
	settings := s.store.ExternalAPISettings()
	status := externalStatus(settings, false)
	if s.externalAPI == nil {
		status.LastError = "External API manager is not configured"
	} else {
		status = s.externalAPI.Status()
		if status.LastError != "" {
			status.LastError = "The last listener transition failed"
		}
	}
	return apiManagementState{Settings: settings, Status: status}
}

// These routes belong only to the trusted management listener. Bearer tokens
// authorize external operations, never management settings or token issuance.
func (s *Server) handleAPIManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	parts, ok := dvbRoute(w, r, "/api/v1/api")
	if !ok {
		return
	}
	if _, ok := dvbQuery(w, r, false); !ok {
		return
	}
	if len(parts) == 1 {
		switch parts[0] {
		case "status":
			if dvbGuard(w, r, http.MethodGet) {
				writeJSON(w, 200, s.apiManagementState())
			}
			return
		case "settings":
			s.handleAPISettings(w, r)
			return
		case "tokens":
			s.handleAPITokens(w, r)
			return
		case "openapi.json":
			s.handleOpenAPI(w, r)
			return
		case "try":
			s.handleAPITry(w, r)
			return
		}
	}
	if len(parts) == 3 && parts[0] == "tokens" && parts[2] == "revoke" {
		if !dvbGuard(w, r, http.MethodPost) || !dvbActionBody(w, r) {
			return
		}
		if err := s.store.RevokeAPIToken(parts[1]); err != nil {
			apiTokenError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"id": parts[1], "revoked": true})
		return
	}
	writeDVBError(w, 404, "not_found", "Management API resource not found", "")
}

func (s *Server) apiSettingsError(w http.ResponseWriter, status int, code, message string) {
	state := s.apiManagementState()
	state.Error = &dvbContractError{Code: code, Message: message}
	writeJSON(w, status, state)
}

func (s *Server) handleAPISettings(w http.ResponseWriter, r *http.Request) {
	if !dvbGuard(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, 200, s.apiManagementState())
		return
	}
	var in model.ExternalAPISettings
	if !dvbDecode(w, r, &in) {
		return
	}
	if s.externalAPI == nil {
		s.apiSettingsError(w, 503, "manager_unavailable", "External API manager is not configured")
		return
	}
	if err := in.Validate(); err != nil {
		s.apiSettingsError(w, 400, "invalid_settings", err.Error())
		return
	}
	s.managementConfigMu.Lock()
	defer s.managementConfigMu.Unlock()
	if err := s.store.ValidateExternalAPISettings(in); err != nil {
		if errors.Is(err, store.ErrStoreClosed) {
			s.apiSettingsError(w, 503, "runtime_unavailable", "The runtime is unavailable")
			return
		}
		s.apiSettingsError(w, 400, "settings_rejected", "Check for an active token and a port distinct from management and playback ports")
		return
	}
	if err := s.externalAPI.Apply(r.Context(), in); err != nil {
		var networkError *net.OpError
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			s.apiSettingsError(w, 408, "apply_interrupted", "Listener update was interrupted; inspect current settings and status before retrying")
		case errors.As(err, &networkError):
			s.apiSettingsError(w, 409, "bind_failed", "Cannot bind the requested address or port; previous settings are retained")
		default:
			s.apiSettingsError(w, 500, "apply_failed", "Listener update failed; inspect current settings and status before retrying")
		}
		return
	}
	writeJSON(w, 200, s.apiManagementState())
}

func apiTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAPITokenNameExists):
		writeDVBError(w, 409, "token_name_exists", "A token with this name already exists", "name")
	case errors.Is(err, store.ErrAPITokenNotFound):
		writeDVBError(w, 404, "token_not_found", "Token not found", "id")
	case errors.Is(err, store.ErrStoreClosed):
		writeDVBError(w, 503, "runtime_unavailable", "The runtime is unavailable", "")
	case errors.Is(err, store.ErrAPITokenPersistence):
		writeDVBError(w, 500, "token_persistence_failed", "Token change could not be saved; a revoked token remains blocked in this process until durability is restored", "")
	default:
		writeDVBError(w, 500, "token_operation_failed", "Token operation could not be completed", "")
	}
}

func (s *Server) handleAPITokens(w http.ResponseWriter, r *http.Request) {
	if !dvbGuard(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"tokens": s.store.ListAPITokens()})
		return
	}
	var in model.CreateAPITokenRequest
	if !dvbDecode(w, r, &in) {
		return
	}
	if err := in.Validate(); err != nil {
		writeDVBError(w, 400, "invalid_token", err.Error(), "")
		return
	}
	view, raw, err := s.store.CreateAPIToken(in)
	if err != nil {
		apiTokenError(w, err)
		return
	}
	writeJSON(w, 201, struct {
		Token     model.APITokenView `json:"token"`
		Plaintext string             `json:"plaintext"`
	}{view, raw})
}

type apiTryInput struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Token  string          `json:"token"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// Limit captured output as well as input. The external handler remains the
// sole authentication, authorization, query-validation and redaction boundary.
type apiTryRecorder struct {
	*httptest.ResponseRecorder
	overflow bool
}

func (w *apiTryRecorder) Write(p []byte) (int, error) {
	if len(p) > dvbJSONLimit-w.Body.Len() {
		w.overflow = true
		return 0, io.ErrShortBuffer
	}
	return w.ResponseRecorder.Write(p)
}

func (w *apiTryRecorder) WriteString(p string) (int, error) {
	if len(p) > dvbJSONLimit-w.Body.Len() {
		w.overflow = true
		return 0, io.ErrShortBuffer
	}
	return w.ResponseRecorder.WriteString(p)
}

func (s *Server) handleAPITry(w http.ResponseWriter, r *http.Request) {
	if !dvbGuard(w, r, http.MethodPost) {
		return
	}
	var in apiTryInput
	if !dvbDecode(w, r, &in) {
		return
	}
	u, err := url.Parse(in.Path)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || strings.Contains(in.Path, "#") || !strings.HasPrefix(in.Path, "/api/v1/") {
		writeDVBError(w, 400, "invalid_try_target", "Select a registered relative external API path", "path")
		return
	}
	probe := &http.Request{URL: u}
	if _, err := dvbPathParts(probe, ""); err != nil {
		respondDVBError(w, err)
		return
	}
	best, allowed := -1, false
	for _, route := range s.externalRoutes() {
		score, match := externalPathMatch(u.EscapedPath(), route.Pattern)
		if !match || score < best {
			continue
		}
		if score > best {
			best, allowed = score, false
		}
		if route.Method == in.Method {
			allowed = true
		}
	}
	if !allowed {
		writeDVBError(w, 400, "invalid_try_target", "Select a registered external API method and path", "path")
		return
	}
	if len(in.Token) > 128 || strings.IndexFunc(in.Token, unicode.IsControl) >= 0 {
		writeDVBError(w, 400, "invalid_token", "Invalid token input", "token")
		return
	}
	body := in.Body
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		body = nil
	}
	if len(body) > dvbJSONLimit || in.Method == http.MethodGet && len(body) > 0 {
		writeDVBError(w, 400, "invalid_try_body", "GET requests must not have a body", "body")
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), in.Method, "http://api.internal"+in.Path, bytes.NewReader(body))
	if err != nil {
		writeDVBError(w, 400, "invalid_try_target", "Invalid request target", "path")
		return
	}
	if in.Token != "" {
		request.Header.Set("Authorization", "Bearer "+in.Token)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := &apiTryRecorder{ResponseRecorder: httptest.NewRecorder()}
	// No network client, cookies, management headers, or management mux dispatch.
	s.ExternalHandler().ServeHTTP(recorder, request)
	if recorder.overflow {
		writeDVBError(w, 502, "try_response_too_large", "Response exceeds the Try display limit; use a smaller query", "")
		return
	}
	var responseBody any
	if recorder.Body.Len() > 0 {
		if json.Valid(recorder.Body.Bytes()) {
			// Keep number lexemes intact instead of converting them through float64.
			responseBody = json.RawMessage(recorder.Body.Bytes())
		} else {
			responseBody = recorder.Body.String()
		}
	}
	headers := make(map[string]string)
	for _, name := range []string{"Content-Type", "Location", "WWW-Authenticate", "Allow"} {
		if value := recorder.Header().Get(name); value != "" {
			headers[name] = value
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	// The browser displays this text directly without a lossy parse/stringify pass.
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    any               `json:"body"`
	}{recorder.Code, headers, responseBody}); err != nil {
		log.Printf("write Try response failed: %v", err)
	}
}
