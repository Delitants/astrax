// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"errors"
	"math"
	"time"

	"astrax/internal/model"
)

type RuntimeAction string

const (
	ActionStart   RuntimeAction = "start"
	ActionRestart RuntimeAction = "restart"
	ActionStop    RuntimeAction = "stop"
	ActionRemove  RuntimeAction = "remove"
)

// A command is an immutable intent; its applied bit is guarded by manager.mu.
type RuntimeCommand struct {
	manager    *Manager
	profile    model.Softcam
	action     RuntimeAction
	generation uint64
	applied    bool
}

func (c *RuntimeCommand) Generation() uint64 { return c.generation }

func (m *Manager) Prepare(profile model.Softcam, action RuntimeAction) (*RuntimeCommand, error) {
	if profile.ID == "" {
		return nil, errors.New("softcam ID is required")
	}
	switch action {
	case ActionStart, ActionRestart:
		if !profile.Enabled {
			action = ActionStop
		}
	case ActionStop, ActionRemove:
	default:
		return nil, errors.New("invalid softcam runtime action")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return nil, errors.New("softcam manager is closed")
	}
	if action == ActionStart {
		if w := m.workers[profile.ID]; w != nil && w.ctx.Err() == nil && sameConfig(w.profile, profile) {
			if current := m.intents[profile.ID]; current != nil && current.generation == w.generation {
				return current, nil
			}
		}
	}
	if m.nextGeneration == math.MaxUint64 {
		return nil, errors.New("softcam generation exhausted")
	}
	m.nextGeneration++
	c := &RuntimeCommand{manager: m, profile: profile, action: action, generation: m.nextGeneration}
	m.intents[profile.ID] = c
	for w := range m.owned[profile.ID] {
		m.revokeWorkerECMLocked(w)
	}
	return c, nil
}

func (c *RuntimeCommand) Apply() error {
	m := c.manager
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return errors.New("softcam manager is closed")
	}
	if m.intents[c.profile.ID] != c || c.applied {
		m.mu.Unlock()
		return nil
	}
	c.applied = true
	stoppedName := c.profile.Name
	if current := m.workers[c.profile.ID]; current != nil && stoppedName == "" {
		stoppedName = current.profile.Name
	}
	delete(m.workers, c.profile.ID)
	predecessors := make([]*worker, 0, len(m.owned[c.profile.ID]))
	nativePredecessors := make([]*worker, 0, len(m.owned[c.profile.ID]))
	for w := range m.owned[c.profile.ID] {
		m.revokeWorkerECMLocked(w)
		predecessors = append(predecessors, w)
		if w.native {
			nativePredecessors = append(nativePredecessors, w)
		}
	}
	m.mu.Unlock()

	// The ownership registry includes retired workers, not merely the current
	// slot. Concurrent B/C applies must both join native A before either dials.
	for _, w := range predecessors {
		w.cancel()
	}
	for _, w := range nativePredecessors {
		<-w.done
	}

	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return errors.New("softcam manager is closed")
	}
	if m.intents[c.profile.ID] != c {
		m.mu.Unlock()
		return nil
	}
	if c.action == ActionRemove {
		delete(m.runtimes, c.profile.ID)
		delete(m.intents, c.profile.ID)
		m.mu.Unlock()
		return nil
	}
	restartCount := 0
	if previous, ok := m.runtimes[c.profile.ID]; ok {
		restartCount = previous.RestartCount + 1
	}
	if c.action == ActionStop {
		previous, exists := m.runtimes[c.profile.ID]
		if !exists && len(predecessors) == 0 {
			delete(m.intents, c.profile.ID)
			m.mu.Unlock()
			return nil
		}
		restartCount = previous.RestartCount
		rt := model.SoftcamRuntime{State: "stopped", Since: time.Now().UTC(), RestartCount: restartCount}
		m.runtimes[c.profile.ID] = rt
		m.emit(Event{SoftcamID: c.profile.ID, Generation: c.generation, Runtime: rt, Level: "warn", Message: "softcam stopped: " + stoppedName})
		m.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{profile: c.profile, generation: c.generation, ctx: ctx, cancel: cancel, restartCount: restartCount,
		native: m.contextOpener != nil && normalizeSoftcamType(c.profile.Type) == "cccam", done: make(chan struct{})}
	// Add, exposure and closing are serialized under the terminal-admission lock.
	m.workerLifetimes.Add(1)
	if m.owned[c.profile.ID] == nil {
		m.owned[c.profile.ID] = make(map[*worker]struct{})
	}
	m.owned[c.profile.ID][w] = struct{}{}
	m.workers[c.profile.ID] = w
	m.mu.Unlock()

	if err := validateProfile(c.profile); err != nil {
		rt := model.SoftcamRuntime{State: "error", Since: time.Now().UTC(), RestartCount: restartCount, LastError: err.Error()}
		m.publishWorker(w, rt, "error", "softcam profile error: "+c.profile.Name+" ("+err.Error()+")")
		m.finishWorker(w)
		return nil
	}
	go m.runWorker(w)
	return nil
}
