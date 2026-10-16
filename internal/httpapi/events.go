// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
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
	if legacy {
		s.handleSnapshotEvents(w, r, external)
		return
	}

	id, revision, ch := s.store.SubscribeEventsWithRevision(64)
	if id < 0 {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "event service is closed"})
		return
	}
	defer s.store.UnsubscribeEvents(id)
	setEventHeaders(w)
	if err := sendEventFrame(w, func() error {
		return writeSSE(w, "ready", struct {
			Revision uint64 `json:"revision"`
		}{revision})
	}); err != nil {
		return
	}

	streamEventChannel(w, r, ch, func(event model.ResourceEvent) (bool, error) {
		return event.Kind == "resync_required", writeResourceEvent(w, event)
	})
}

func (s *Server) handleSnapshotEvents(w http.ResponseWriter, r *http.Request, external bool) {
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
		return writeSSE(w, "snapshot", snapshot)
	}
	if err := sendEventFrame(w, func() error { return writeSnapshot(s.store.Snapshot(120)) }); err != nil {
		return
	}
	streamEventChannel(w, r, ch, func(snapshot model.StateSnapshot) (bool, error) {
		return false, writeSnapshot(snapshot)
	})
}

func streamEventChannel[T any](w http.ResponseWriter, r *http.Request, ch <-chan T, write func(T) (bool, error)) {
	keepAlive := time.NewTicker(10 * time.Second)
	defer keepAlive.Stop()
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
			var terminal bool
			if err := sendEventFrame(w, func() (err error) {
				terminal, err = write(event)
				return err
			}); err != nil || terminal {
				return
			}
		case <-keepAlive.C:
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
