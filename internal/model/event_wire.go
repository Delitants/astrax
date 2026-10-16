// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MaxEventFrameBytes includes the complete id/event/data SSE framing and final LF.
const MaxEventFrameBytes = 64 * 1024

// EventWirePayload is an immutable, owned JSON document. Subscribers receive this
// value, never the mutable typed snapshots delivered to in-process observers.
type EventWirePayload struct{ document string }

func NewEventWirePayload(data []byte) (EventWirePayload, error) {
	if len(data) > MaxEventFrameBytes || !json.Valid(data) {
		return EventWirePayload{}, errors.New("invalid event payload")
	}
	return EventWirePayload{document: string(data)}, nil
}

// MarshalJSON returns a fresh copy; callers cannot mutate another subscriber.
func (p EventWirePayload) MarshalJSON() ([]byte, error) {
	if p.document == "" {
		return nil, errors.New("empty event payload")
	}
	return []byte(p.document), nil
}

// ResourceEventFrame accepts only frozen bus events. It must not encode arbitrary
// user payloads, even when called directly by a transport outside the bus.
func ResourceEventFrame(event ResourceEvent) (string, error) {
	if event.Kind == "" || len(event.Kind)+len(event.ResourceID) > MaxEventFrameBytes || strings.ContainsAny(event.Kind, "\r\n\x00") {
		return "", errors.New("invalid event kind")
	}
	if _, ok := event.Payload.(EventWirePayload); !ok && !(event.Kind == "resync_required" && event.Payload == nil) {
		return "", errors.New("event payload is not frozen")
	}
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	frame := fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Kind, data)
	if len(frame) > MaxEventFrameBytes {
		return "", errors.New("event frame too large")
	}
	return frame, nil
}
