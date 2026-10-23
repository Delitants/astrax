// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"astrax/internal/adminauth"
)

const (
	managementCookieName = "astrax_admin"
	managementCSRFHeader = "X-AstraX-CSRF"
	maxAuthBody          = 4096
	maxManagementBody    = 8 << 20
)

type managementHandler struct{ server *Server }

type managementRefererVerifiedKey struct{}

func (h *managementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := h.server
	// Never log untrusted paths, queries, headers, or bodies at this boundary.
	log.Printf("management %s request", r.Method)
	if _, ok := s.managementBrowserOrigin(r); !ok {
		authResponse(w, http.StatusForbidden, apiError{Error: "request not permitted"})
		return
	}
	if r.URL.Path == "/api/v1/auth/session" || r.URL.Path == "/api/v1/auth/setup" || r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/auth/logout" || r.URL.Path == "/api/v1/auth/password" {
		if r.Method == http.MethodHead {
			authResponse(w, http.StatusUnauthorized, apiError{Error: "authentication required"})
			return
		}
		s.serveAuth(w, r)
		return
	}
	if r.Method == http.MethodGet && s.publicAsset(r.URL.Path) {
		if r.URL.Path == "/login" || r.URL.Path == "/setup" || r.URL.Path == "/index.html" {
			clone := r.Clone(r.Context())
			clone.URL.Path = "/"
			s.mux.ServeHTTP(w, clone)
		} else {
			s.mux.ServeHTTP(w, r)
		}
		return
	}
	session, ok := s.requestSession(r)
	if !ok {
		authResponse(w, http.StatusUnauthorized, apiError{Error: "authentication required"})
		return
	}
	if mutatingMethod(r.Method) {
		if !s.sameManagementOrigin(r) || !validManagementCSRF(r, session.CSRFToken) {
			authResponse(w, http.StatusForbidden, apiError{Error: "request not permitted"})
			return
		}
		if len(r.Header.Values("Origin")) == 0 {
			r = r.WithContext(context.WithValue(r.Context(), managementRefererVerifiedKey{}, true))
		}
		if r.ContentLength > maxManagementBody {
			authResponse(w, http.StatusRequestEntityTooLarge, apiError{Error: "request too large"})
			return
		}
		body := r.Body
		if body == nil {
			body = http.NoBody
		}
		limited := http.MaxBytesReader(w, body, maxManagementBody)
		payload, err := io.ReadAll(limited)
		_ = limited.Close()
		if r.Context().Err() != nil {
			authResponse(w, http.StatusRequestTimeout, apiError{Error: "request canceled"})
			return
		}
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				authResponse(w, http.StatusRequestEntityTooLarge, apiError{Error: "request too large"})
			} else {
				authResponse(w, http.StatusBadRequest, apiError{Error: "invalid request"})
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) publicAsset(path string) bool {
	if path == "/" || path == "/login" || path == "/setup" {
		return true
	}
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "/api/") || path == "/openapi.json" || strings.Contains(path, "\\") {
		return false
	}
	name := strings.TrimPrefix(path, "/")
	if strings.Contains(name, "..") || strings.Contains(name, "//") {
		return false
	}
	info, err := fs.Stat(s.webAssets, name)
	return err == nil && info.Mode().IsRegular()
}

func (s *Server) requestSession(r *http.Request) (adminauth.Session, bool) {
	cookie, err := r.Cookie(managementCookieName)
	if err != nil {
		return adminauth.Session{}, false
	}
	return s.auth.VerifySession(cookie.Value)
}

func mutatingMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (s *Server) managementBrowserOrigin(r *http.Request) (string, bool) {
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || addr == nil {
		return "", false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	localHost, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", false
	}
	localIP, err := netip.ParseAddr(localHost)
	if err != nil || localIP.IsUnspecified() || localIP.Is4In6() || localIP.Zone() != "" {
		return "", false
	}
	if scheme == "http" {
		if !localIP.IsLoopback() || (s.managementTransport.HTTPAddr != "" && addr.String() != s.managementTransport.HTTPAddr) {
			return "", false
		}
	} else if !s.managementTransport.StartHTTPS || addr.String() != s.managementTransport.HTTPSAddr {
		return "", false
	}
	host, explicitPort, ok := splitBrowserHost(r.Host)
	if !ok || (explicitPort != "" && explicitPort != port) {
		return "", false
	}
	if explicitPort == "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		return "", false
	}
	canonicalHost := strings.ToLower(host)
	if ip, err := netip.ParseAddr(canonicalHost); err == nil {
		if ip != localIP || ip.Is4In6() || ip.Zone() != "" {
			return "", false
		}
		if scheme == "https" && (r.TLS.ServerName != "" || !s.managementTransport.HTTPSIdentities.AllowsIP(ip)) {
			return "", false
		}
		canonicalHost = ip.String()
	} else if scheme == "http" {
		if canonicalHost != "localhost" {
			return "", false
		}
	} else {
		if !s.managementTransport.HTTPSIdentities.AllowsDNS(canonicalHost) || !strings.EqualFold(r.TLS.ServerName, canonicalHost) {
			return "", false
		}
	}
	authority := canonicalHost
	if strings.Contains(canonicalHost, ":") {
		authority = "[" + canonicalHost + "]"
	}
	if !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		authority = net.JoinHostPort(canonicalHost, port)
	}
	return scheme + "://" + authority, true
}

func splitBrowserHost(authority string) (string, string, bool) {
	if authority == "" || strings.ContainsAny(authority, "/\\@%?# \t\r\n") {
		return "", "", false
	}
	if host, port, err := net.SplitHostPort(authority); err == nil {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host == "" {
			return "", "", false
		}
		return host, port, true
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), "", true
	}
	if strings.Contains(authority, ":") {
		return "", "", false
	}
	return authority, "", true
}

func (s *Server) sameManagementOrigin(r *http.Request) bool {
	want, ok := s.managementBrowserOrigin(r)
	if !ok {
		return false
	}
	if origins := r.Header.Values("Origin"); len(origins) != 0 {
		return len(origins) == 1 && origins[0] == want
	}
	referers := r.Header.Values("Referer")
	if len(referers) != 1 {
		return false
	}
	u, err := url.Parse(referers[0])
	parsedWant, _ := url.Parse(want)
	return err == nil && u.IsAbs() && u.User == nil && u.Scheme == parsedWant.Scheme && u.Host == parsedWant.Host && u.Fragment == ""
}

func validManagementCSRF(r *http.Request, expected string) bool {
	values := r.Header.Values(managementCSRFHeader)
	return len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) == 1
}

func (s *Server) serveAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := r.URL.Path
	if path == "/api/v1/auth/session" && r.Method == http.MethodGet {
		if session, ok := s.requestSession(r); ok {
			authResponse(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": session.CSRFToken})
		} else {
			authResponse(w, http.StatusUnauthorized, map[string]any{"authenticated": false, "setup_pending": s.auth.SetupPending()})
		}
		return
	}
	if r.Method != http.MethodPost || (path != "/api/v1/auth/setup" && path != "/api/v1/auth/login" && path != "/api/v1/auth/logout" && path != "/api/v1/auth/password") {
		authResponse(w, http.StatusNotFound, apiError{Error: "not found"})
		return
	}
	if !s.sameManagementOrigin(r) {
		authResponse(w, http.StatusForbidden, apiError{Error: "request not permitted"})
		return
	}
	var session adminauth.Session
	var ok bool
	if path == "/api/v1/auth/logout" || path == "/api/v1/auth/password" {
		session, ok = s.requestSession(r)
		if !ok {
			authResponse(w, http.StatusUnauthorized, apiError{Error: "authentication required"})
			return
		}
		if !validManagementCSRF(r, session.CSRFToken) {
			authResponse(w, http.StatusForbidden, apiError{Error: "request not permitted"})
			return
		}
	}
	if r.ContentLength > maxAuthBody {
		authResponse(w, http.StatusRequestEntityTooLarge, apiError{Error: "request too large"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	if path == "/api/v1/auth/logout" {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			authResponse(w, http.StatusRequestEntityTooLarge, apiError{Error: "request too large"})
			return
		}
	}
	var in struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Secret      string `json:"secret"`
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if path != "/api/v1/auth/logout" {
		if err := decodeAuthJSON(r, &in); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				authResponse(w, http.StatusRequestEntityTooLarge, apiError{Error: "request too large"})
				return
			}
			authResponse(w, http.StatusBadRequest, apiError{Error: "invalid request"})
			return
		}
	}
	switch path {
	case "/api/v1/auth/setup":
		if !s.auth.AllowSetupAttempt(remoteSource(r)) {
			authResponse(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
			return
		}
		if err := s.auth.Enroll(in.Secret, in.Password); err != nil {
			authResponse(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
			return
		}
		issued, err := s.auth.Login(remoteSource(r), in.Password)
		if err != nil {
			authResponse(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
			return
		}
		s.issueSession(w, r, issued)
	case "/api/v1/auth/login":
		issued, err := s.auth.Login(remoteSource(r), in.Password)
		if err != nil || (in.Username != "" && in.Username != "admin") {
			if err == nil {
				s.auth.Logout(issued.Token)
			}
			authResponse(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
			return
		}
		s.issueSession(w, r, issued)
	case "/api/v1/auth/logout":
		s.auth.Logout(session.Token)
		clearManagementCookie(w, r)
		authResponse(w, http.StatusOK, map[string]bool{"authenticated": false})
	case "/api/v1/auth/password":
		if err := s.auth.ChangePassword(session.Token, in.OldPassword, in.NewPassword); err != nil {
			authResponse(w, http.StatusUnauthorized, apiError{Error: "invalid credentials"})
			return
		}
		clearManagementCookie(w, r)
		authResponse(w, http.StatusOK, map[string]bool{"authenticated": false})
	}
}

func decodeAuthJSON(r *http.Request, out any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("invalid content type")
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func remoteSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	return host
}

func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, session adminauth.Session) {
	http.SetCookie(w, &http.Cookie{Name: managementCookieName, Value: session.Token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	authResponse(w, http.StatusOK, map[string]any{"authenticated": true, "csrf_token": session.CSRFToken})
}

func clearManagementCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: managementCookieName, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func authResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, status, value)
}
