// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"astrax/internal/adapters"
	"astrax/internal/model"
)

type staticHTTPDetector struct{}

var _ adapters.Detector = staticHTTPDetector{}

func (staticHTTPDetector) DetectRuntime() []model.Adapter { return []model.Adapter{} }
func (staticHTTPDetector) DetectDVB(context.Context) ([]model.DVBCard, error) {
	return []model.DVBCard{}, nil
}

func externalToken(t *testing.T, s *Server, scopes ...string) string {
	t.Helper()
	_, raw, err := s.store.CreateAPIToken(model.CreateAPITokenRequest{
		Name: fmt.Sprintf("Token %d", len(s.store.ListAPITokens())), Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func externalRequest(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
