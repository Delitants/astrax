// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"astrax/internal/adminauth"
	"astrax/internal/cert"
	"astrax/internal/model"
	"astrax/internal/softcam"
	"astrax/internal/store"
)

type Server struct {
	store               *store.Store
	dvbOps              dvbOperationService
	certMgr             *cert.Manager
	auth                *adminauth.Manager
	managementTransport adminauth.Admission
	mux                 *http.ServeMux
	webAssets           fs.FS
	externalAPI         *ExternalAPIManager
}

type apiError struct {
	Error string `json:"error"`
}

func New(st *store.Store, webFS fs.FS, certMgr *cert.Manager, auth *adminauth.Manager) (*Server, error) {
	return NewWithManagementTransport(st, webFS, certMgr, auth, adminauth.Admission{})
}

// NewWithManagementTransport binds the management handler to preflight's fixed TLS identities.
func NewWithManagementTransport(st *store.Store, webFS fs.FS, certMgr *cert.Manager, auth *adminauth.Manager, admission adminauth.Admission) (*Server, error) {
	if auth == nil {
		return nil, errors.New("administrator authentication is required")
	}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, fmt.Errorf("load web assets: %w", err)
	}

	s := &Server{
		store:               st,
		dvbOps:              st,
		certMgr:             certMgr,
		auth:                auth,
		managementTransport: admission,
		mux:                 http.NewServeMux(),
	}

	s.registerRoutes(sub)
	s.webAssets = sub
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return &managementHandler{server: s}
}

// ConfigureExternalAPI is called once during process construction, before any
// management requests. The manager remains separate from the management mux.
func (s *Server) ConfigureExternalAPI(reserved ...string) *ExternalAPIManager {
	s.externalAPI = NewExternalAPIManager(s.externalHandler, s.certMgr, s.store, reserved...)
	return s.externalAPI
}

func (s *Server) registerRoutes(webAssets fs.FS) {
	s.mux.HandleFunc("/api/v1/api/", s.handleAPIManagement)
	s.mux.HandleFunc("/openapi.json", s.handleOpenAPI)
	s.mux.HandleFunc("/api/v1/dvb-cards", s.handleDVBCards)
	s.mux.HandleFunc("/api/v1/dvb-cards/", s.handleDVBCards)
	s.mux.HandleFunc("/api/v1/dvb-streams", s.handleDVBStreams)
	s.mux.HandleFunc("/api/v1/dvb-streams/", s.handleDVBStreams)
	s.mux.HandleFunc("/api/v1/dvb-groups", s.handleDVBGroups)
	s.mux.HandleFunc("/api/v1/dvb-groups/", s.handleDVBGroups)
	s.mux.HandleFunc("/api/v1/dvb-scans", s.handleDVBScans)
	s.mux.HandleFunc("/api/v1/dvb-scans/", s.handleDVBScans)
	s.mux.HandleFunc("/api/v1/version", s.handleVersion)
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
	s.mux.HandleFunc("/api/v1/streams", s.handleStreams)
	s.mux.HandleFunc("/api/v1/streams/", s.handleStreamByID)
	s.mux.HandleFunc("/api/v1/softcams", s.handleSoftcams)
	s.mux.HandleFunc("/api/v1/softcams/", s.handleSoftcamByID)
	s.mux.HandleFunc("/api/v1/adapter-profiles", s.handleAdapterProfiles)
	s.mux.HandleFunc("/api/v1/adapter-profiles/", s.handleAdapterProfileByID)
	s.mux.HandleFunc("/api/v1/settings", s.handleSettings)
	s.mux.HandleFunc("/api/v1/adapters", s.handleAdapters)
	s.mux.HandleFunc("/api/v1/logs", s.handleLogs)
	s.mux.HandleFunc("/api/v1/control/restart", s.handleRestart)
	s.mux.HandleFunc("/api/v1/events", s.handleEvents)
	s.mux.HandleFunc("/api/v1/certificates/status", s.handleCertStatus)
	s.mux.HandleFunc("/api/v1/certificates/generate", s.handleCertGenerate)
	s.mux.HandleFunc("/api/v1/certificates/upload", s.handleCertUpload)
	s.mux.HandleFunc("/api/v1/certificates/delete", s.handleCertDelete)
	s.mux.HandleFunc("/api/v1/epg", s.handleEPG)
	s.mux.HandleFunc("/api/v1/epg/status", s.handleEPGHealth)

	fileServer := http.FileServer(http.FS(webAssets))
	s.mux.Handle("/", fileServer)
}

func (s *Server) handleAdapterProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"adapter_profiles": s.store.ListAdapterProfiles()})
		return
	}
	if r.Method == http.MethodPost {
		writeDVBProfileDeprecated(w)
		return
	}
	writeMethodNotAllowed(w)
}

func (s *Server) handleAdapterProfileByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		writeDVBProfileDeprecated(w)
	default:
		writeMethodNotAllowed(w)
	}
}

func writeDVBProfileDeprecated(w http.ResponseWriter) {
	writeDVBError(w, http.StatusGone, "adapter_profiles_deprecated", "Adapter profiles are read-only; use DVB Cards and DVB Streams", "")
}

func (s *Server) handleSoftcams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"softcams": s.store.ListSoftcams()})
	case http.MethodPost:
		var in model.Softcam
		if err := decodeJSON(r, &in); err != nil {
			writeSoftcamError(w, err, http.StatusBadRequest)
			return
		}
		profile, err := s.store.AddSoftcam(in)
		if err != nil {
			writeSoftcamError(w, err, http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, profile)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleSoftcamByID(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.TrimPrefix(r.URL.Path, "/api/v1/softcams/")
	parts := strings.Split(pathValue, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, apiError{Error: "softcam not found"})
		return
	}
	id := parts[0]

	if len(parts) == 2 && parts[1] != "" {
		s.handleSoftcamAction(w, r, id, parts[1])
		return
	}
	if len(parts) > 2 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "softcam not found"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var in model.Softcam
		if err := decodeJSON(r, &in); err != nil {
			writeSoftcamError(w, err, http.StatusBadRequest)
			return
		}
		profile, err := s.store.UpdateSoftcam(id, in)
		if err != nil {
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not found") {
				status = http.StatusNotFound
			}
			writeSoftcamError(w, err, status)
			return
		}
		writeJSON(w, http.StatusOK, profile)
	case http.MethodDelete:
		if err := s.store.DeleteSoftcam(id); err != nil {
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not found") {
				status = http.StatusNotFound
			}
			writeSoftcamError(w, err, status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleSoftcamAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var (
		profile model.Softcam
		err     error
	)
	switch action {
	case "start":
		profile, err = s.store.StartSoftcam(id)
	case "stop":
		profile, err = s.store.StopSoftcam(id)
	case "restart":
		profile, err = s.store.RestartSoftcam(id)
	case "test":
		s.handleSoftcamTest(w, r, id)
		return
	default:
		writeJSON(w, http.StatusNotFound, apiError{Error: "softcam action not found"})
		return
	}

	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeSoftcamError(w, err, status)
		return
	}

	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleSoftcamTest(w http.ResponseWriter, r *http.Request, id string) {
	result, err := s.store.TestSoftcamContext(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, softcam.ErrTestBusy) {
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "1")
		}
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeSoftcamError(w, err, status)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeSoftcamError(w http.ResponseWriter, err error, status int) {
	var committed *store.CommittedRuntimeError
	if errors.As(err, &committed) {
		writeJSON(w, http.StatusInternalServerError, struct {
			Error     string `json:"error"`
			ErrorCode string `json:"error_code"`
			Persisted bool   `json:"persisted"`
		}{Error: committed.Error(), ErrorCode: "runtime_application_failed", Persisted: true})
		return
	}
	writeJSON(w, status, apiError{Error: err.Error()})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	status := s.store.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "AstraX",
		"version": status.Version,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.store.Status())
}

func (s *Server) handleStreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid stream query"})
			return
		}
		external, err := externalStreamScope(query)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		streams := s.store.ListStreams()
		if external {
			streams = externalStreams(streams)
		}
		writeJSON(w, http.StatusOK, map[string]any{"streams": streams})
	case http.MethodPost:
		var in model.Stream
		if err := decodeJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		var stream model.Stream
		var err error
		if in.DVB != nil {
			stream, err = s.store.AddDVBStreamContext(r.Context(), in)
		} else {
			stream, err = s.store.AddStream(in)
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusRequestTimeout
			}
			writeJSON(w, status, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, stream)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleStreamByID(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.TrimPrefix(r.URL.Path, "/api/v1/streams/")
	parts := strings.Split(pathValue, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, apiError{Error: "stream not found"})
		return
	}
	id := parts[0]

	if len(parts) == 2 && parts[1] != "" {
		s.handleStreamAction(w, r, id, parts[1])
		return
	}
	if len(parts) > 2 {
		writeJSON(w, http.StatusNotFound, apiError{Error: "stream not found"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		var in model.Stream
		if err := decodeJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		var stream model.Stream
		var err error
		if in.DVB != nil {
			stream, err = s.store.UpdateDVBStreamContext(r.Context(), id, in)
		} else {
			stream, err = s.store.UpdateStream(id, in)
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusRequestTimeout
			} else if strings.Contains(err.Error(), "not found") {
				status = http.StatusNotFound
			}
			writeJSON(w, status, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stream)
	case http.MethodDelete:
		if err := s.store.DeleteStream(id); err != nil {
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "not found") {
				status = http.StatusNotFound
			}
			writeJSON(w, status, apiError{Error: err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleStreamAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var (
		stream model.Stream
		err    error
	)
	switch action {
	case "start":
		stream, err = s.store.StartStream(id)
	case "stop":
		stream, err = s.store.StopStream(id)
	case "restart":
		stream, err = s.store.RestartStream(id)
	default:
		writeJSON(w, http.StatusNotFound, apiError{Error: "stream action not found"})
		return
	}

	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, apiError{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, stream)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.Settings())
	case http.MethodPut:
		var in model.Settings
		if err := decodeJSON(r, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		settings, err := s.store.SetSettings(in)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, settings)
	case http.MethodPatch:
		var fields map[string]json.RawMessage
		if err := decodeJSON(r, &fields); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		settings, err := s.store.PatchSettings(fields)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, settings)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleAdapters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"adapters": s.store.ListAdapters()})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err == nil && parsed > 0 {
			limit = parsed
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"logs": s.store.ListLogs(limit)})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	s.store.AddLog("warn", "restart requested from web ui")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "restart requested"})
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid json payload: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	if external, ok := w.(externalResponseWriter); ok {
		external.writeJSON(status, data)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("write json response failed: %v", err)
	}
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
}

func writeSSE(w http.ResponseWriter, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleCertStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exists": s.certMgr.Exists()})
}

func (s *Server) handleCertGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var in struct {
		Hosts        []string `json:"hosts"`
		DurationDays int      `json:"duration_days"`
		CommonName   string   `json:"common_name"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	if len(in.Hosts) == 0 {
		in.Hosts = []string{"localhost", "127.0.0.1"}
	}

	if err := s.certMgr.GenerateSelfSigned(in.Hosts, in.DurationDays, in.CommonName); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCertUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var in struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	if in.Cert == "" || in.Key == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "cert and key are required"})
		return
	}

	if err := s.certMgr.Save([]byte(in.Cert), []byte(in.Key)); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCertDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if err := s.certMgr.Delete(); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleEPG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	data, _, ok := s.store.EPGData()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "epg not available"})
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleEPGHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.store.EPGHealth())
}
