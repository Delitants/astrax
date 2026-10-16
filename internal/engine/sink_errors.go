// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package engine

import (
	"fmt"
	"log"
	"time"

	"astrax/internal/streamer"
)

func logSinkError(id, operation string, err error) bool {
	if streamer.IsBenignLifecycleError(err) {
		return false
	}
	log.Printf("engine: %s for %s: %v", operation, id, err)
	return true
}

// Retired failures remain diagnostic, but only a still-current worker and sink
// publication may change runtime. Accepted publications keep their running state.
func (e *Engine) reportSinkError(w *worker, operation string, err error, rejected bool) {
	id := ""
	if w != nil {
		id = w.stream.ID
	}
	genuine := logSinkError(id, operation, err)
	if w == nil || (!genuine && !rejected) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing || e.workers[id] != w || w.ctx.Err() != nil || !e.registrationCurrentLocked(w) {
		return
	}
	runtime := e.runtimes[id]
	if rejected {
		runtime.State = "stopped"
		if genuine {
			runtime.State = "error"
		}
		runtime.Since = time.Now().UTC()
		runtime.UptimeSeconds = 0
		runtime.Packets = 0
		runtime.BitrateKbps = 0
	}
	if genuine {
		w.sinkError = err.Error()
		runtime.LastError = w.sinkError
	}
	e.runtimes[id] = runtime
	event := Event{StreamID: id, Generation: w.generation, Runtime: runtime}
	if genuine {
		event.Level = "error"
		event.Message = fmt.Sprintf("%s for %s: %v", operation, w.stream.Name, err)
	}
	e.enqueueEventLocked(event)
}
