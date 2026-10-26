// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"astrax/internal/adminauth"
)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requestSession(r)
	if !ok || session.User.Role != adminauth.RoleAdministrator {
		authResponse(w, http.StatusForbidden, apiError{Error: "administrator access required"})
		return
	}
	if r.URL.RawQuery != "" {
		authResponse(w, 400, apiError{Error: "query parameters are not supported"})
		return
	}
	username := ""
	if r.URL.Path != "/api/v1/users" {
		username = strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
		if username == "" || strings.ContainsAny(username, "/\\%") {
			authResponse(w, 404, apiError{Error: "account not found"})
			return
		}
	}
	if username == "" && r.Method == http.MethodGet {
		users, err := s.auth.Users(session.Token)
		if err != nil {
			userError(w, err)
			return
		}
		authResponse(w, 200, map[string]any{"users": users})
		return
	}
	if r.Method == http.MethodDelete && username != "" {
		if !dvbActionBody(w, r) {
			return
		}
		if err := s.auth.DeleteUser(session.Token, username); err != nil {
			userError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if username == "" && r.Method != http.MethodPost || username != "" && r.Method != http.MethodPut {
		writeMethodNotAllowed(w)
		return
	}
	if r.ContentLength > maxAuthBody {
		authResponse(w, 413, apiError{Error: "request too large"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	if username == "" {
		var in struct {
			Username string         `json:"username"`
			Password string         `json:"password"`
			Role     adminauth.Role `json:"role"`
		}
		if err := decodeAuthJSON(r, &in); err != nil {
			authResponse(w, 400, apiError{Error: "invalid account request"})
			return
		}
		user, err := s.auth.CreateUser(session.Token, in.Username, in.Password, in.Role)
		if err != nil {
			userError(w, err)
			return
		}
		authResponse(w, http.StatusCreated, user)
		return
	}
	var in adminauth.UserUpdate
	if err := decodeAuthJSON(r, &in); err != nil {
		authResponse(w, 400, apiError{Error: "invalid account request"})
		return
	}
	user, err := s.auth.UpdateUser(session.Token, username, in)
	if err != nil {
		userError(w, err)
		return
	}
	authResponse(w, http.StatusOK, user)
}

func userError(w http.ResponseWriter, err error) {
	status, message := 500, "account change could not be saved"
	switch {
	case errors.Is(err, adminauth.ErrForbidden):
		status, message = 403, "administrator access required"
	case errors.Is(err, adminauth.ErrInvalidUser):
		status, message = 400, "invalid account: use a unique username, a valid role and a strong password of at least 12 characters"
	case errors.Is(err, adminauth.ErrUserExists):
		status, message = 409, "username already exists"
	case errors.Is(err, adminauth.ErrUserNotFound):
		status, message = 404, "account not found"
	case errors.Is(err, adminauth.ErrLastAdministrator):
		status, message = 409, "keep at least one enabled Administrator account"
	}
	authResponse(w, status, apiError{Error: message})
}
