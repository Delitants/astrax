// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"astrax/internal/model"
	"astrax/internal/store"
)

type externalTokenKey struct{}

const externalBulkScope = "action-dependent"

func externalPrincipal(r *http.Request) (model.APITokenView, bool) {
	token, ok := r.Context().Value(externalTokenKey{}).(model.APITokenView)
	return token, ok
}

func requireBearer(st *store.Store, scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
			externalUnauthorized(w)
			return
		}
		required := []string{scope}
		if scope == externalBulkScope {
			required = nil
		}
		token, err := st.AuthenticateAPIToken(strings.TrimPrefix(headers[0], "Bearer "), required...)
		if errors.Is(err, store.ErrInsufficientScope) {
			externalForbidden(w)
			return
		}
		if errors.Is(err, store.ErrStoreClosed) {
			writeDVBError(w, 503, "runtime_unavailable", "The runtime is unavailable", "")
			return
		}
		if err != nil {
			externalUnauthorized(w)
			return
		}
		if scope == externalBulkScope && !slices.Contains(token.Scopes, model.ScopeAdmin) && !slices.Contains(token.Scopes, model.ScopeStreamsControl) {
			externalForbidden(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), externalTokenKey{}, token)))
	})
}

func externalUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="AstraX API"`)
	writeDVBError(w, 401, "unauthorized", "A valid bearer token is required", "")
}

func externalForbidden(w http.ResponseWriter) {
	writeDVBError(w, 403, "forbidden", "The token does not grant this operation", "")
}

func cors(settings model.ExternalAPISettings, next http.Handler) http.Handler {
	// Copy/normalize once: a candidate listener must not share mutable settings.
	normalized, err := settings.Normalized()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Add("Vary", "Origin")
		if err != nil {
			writeDVBError(w, 503, "invalid_configuration", "External API settings are invalid", "")
			return
		}
		origins, present := r.Header["Origin"]
		preflight := r.Method == http.MethodOptions && len(r.Header.Values("Access-Control-Request-Method")) > 0
		if present || preflight {
			allowed := false
			if len(origins) == 1 {
				scheme, host, port, valid := dvbOriginTuple(origins[0])
				if valid {
					for _, origin := range normalized.AllowedOrigins {
						s, h, p, ok := dvbOriginTuple(origin)
						if ok && s == scheme && h == host && p == port {
							allowed = true
							break
						}
					}
				}
			}
			if !allowed {
				writeDVBError(w, 403, "invalid_origin", "Origin is not allowed", "")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origins[0])
			w.Header().Set("Access-Control-Expose-Headers", "Location, WWW-Authenticate")
		}
		if preflight {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if len(r.Header.Values("Access-Control-Request-Method")) != 1 {
				writeDVBError(w, 403, "invalid_preflight", "Invalid preflight request", "")
				return
			}
			for _, line := range r.Header.Values("Access-Control-Request-Headers") {
				for _, header := range strings.Split(line, ",") {
					if !slices.Contains([]string{"authorization", "content-type"}, strings.ToLower(strings.TrimSpace(header))) {
						writeDVBError(w, 403, "invalid_preflight", "Request header is not allowed", "")
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
