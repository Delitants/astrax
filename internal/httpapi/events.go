// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"astrax/internal/model"
)

const eventWriteTimeout = 15 * time.Second

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	external, scopeErr := externalStreamScope(query)
	keys := 1
	if external {
		keys++
	}
	legacy := len(query) == keys && len(query["snapshot"]) == 1 && query.Get("snapshot") == "1"
	if err != nil || scopeErr != nil || len(query) != 0 && !legacy {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "only snapshot=1 with optional scope=external is supported"})
		return
	}
	if _, ok := w.(http.Flusher); !ok {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "streaming is not supported"})
		return
	}
	cookie, err := r.Cookie(managementCookieName)
	if err != nil {
		return
	}
	fullValid := func() bool { return s.auth.SessionValid(cookie.Value) }
	active := func() bool { return s.auth.SessionActive(cookie.Value) }
	if !fullValid() {
		return
	}
	if legacy {
		s.handleSnapshotEvents(w, r, external, active, fullValid)
		return
	}

	id, revision, ch := s.store.SubscribeEventsWithRevision(64)
	if id < 0 {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "event service is closed"})
		return
	}
	defer s.store.UnsubscribeEvents(id)
	setEventHeaders(w)
	if !fullValid() {
		return
	}
	if err := sendEventFrame(w, func() error {
		return writeSSE(w, "ready", struct {
			Revision uint64 `json:"revision"`
		}{revision})
	}); err != nil {
		return
	}

	streamEventChannel(w, r, ch, active, fullValid, func(event model.ResourceEvent) (bool, error) {
		if restrictedManagement(r) {
			projected, err := monitoringValue(event.Payload)
			if err != nil {
				return true, err
			}
			data, err := json.Marshal(projected)
			if err != nil {
				return true, err
			}
			if event.Payload != nil {
				payload, err := model.NewEventWirePayload(data)
				if err != nil {
					return true, err
				}
				event.Payload = payload
			}
		}
		return event.Kind == "resync_required", writeResourceEvent(w, event)
	})
}

func (s *Server) handleSnapshotEvents(w http.ResponseWriter, r *http.Request, external bool, active, fullValid func() bool) {
	id, ch := s.store.Subscribe(32)
	if id < 0 {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "event service is closed"})
		return
	}
	defer s.store.Unsubscribe(id)
	setEventHeaders(w)
	writeSnapshot := func(snapshot model.StateSnapshot) error {
		if external {
			snapshot.Streams = externalStreams(snapshot.Streams)
		}
		if restrictedManagement(r) {
			// Never expose raw logs, softcam profiles or adapter credentials in
			// the legacy monitoring feed, even though it shares a subscriber.
			projected, err := monitoringValue(map[string]any{"at": snapshot.At, "status": snapshot.Status, "streams": snapshot.Streams})
			if err != nil {
				return err
			}
			return writeSSE(w, "snapshot", projected)
		}
		return writeSSE(w, "snapshot", snapshot)
	}
	if !fullValid() {
		return
	}
	if err := sendEventFrame(w, func() error { return writeSnapshot(s.store.Snapshot(120)) }); err != nil {
		return
	}
	streamEventChannel(w, r, ch, active, fullValid, func(snapshot model.StateSnapshot) (bool, error) {
		return false, writeSnapshot(snapshot)
	})
}

func streamEventChannel[T any](w http.ResponseWriter, r *http.Request, ch <-chan T, active, fullValid func() bool, write func(T) (bool, error)) {
	// Bound external durable-state revocation even when no events arrive.
	keepAlive := time.NewTicker(time.Second)
	defer keepAlive.Stop()
	streamEventChannelWithKeepAlive(w, r, ch, active, fullValid, write, keepAlive.C)
}

func streamEventChannelWithKeepAlive[T any](w http.ResponseWriter, r *http.Request, ch <-chan T, active, fullValid func() bool, write func(T) (bool, error), keepAlive <-chan time.Time) {
	for {
		if r.Context().Err() != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			// A ready event must not starve a due durable-state check.
			select {
			case <-keepAlive:
				if !fullValid() {
					return
				}
				if err := sendEventKeepAlive(w); err != nil {
					return
				}
			default:
			}
			if !active() {
				return
			}
			var terminal bool
			if err := sendEventFrame(w, func() (err error) {
				terminal, err = write(event)
				return err
			}); err != nil || terminal {
				return
			}
		case <-keepAlive:
			if !fullValid() {
				return
			}
			if err := sendEventKeepAlive(w); err != nil {
				return
			}
		}
	}
}

func setEventHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
}

func sendEventFrame(w http.ResponseWriter, write func() error) error {
	controller := http.NewResponseController(w)
	// Renew only this streaming response's write deadline; leave the server's
	// normal response timeout intact and bound slow/disconnected clients.
	if err := controller.SetWriteDeadline(time.Now().Add(eventWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	if err := write(); err != nil {
		return err
	}
	return controller.Flush()
}

func sendEventKeepAlive(w http.ResponseWriter) error {
	return sendEventFrame(w, func() error {
		_, err := fmt.Fprint(w, ": keepalive\n\n")
		return err
	})
}

func writeResourceEvent(w http.ResponseWriter, event model.ResourceEvent) error {
	frame, err := model.ResourceEventFrame(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, frame)
	return err
}
