// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

// These projections contain metadata only, never native owners, keys or leases.
type DVBDescramblingBackend struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

type DVBDescramblingIdentity struct {
	InputID         string `json:"input_id"`
	InputGeneration uint64 `json:"input_generation"`
	ONID            uint16 `json:"onid"`
	TSID            uint16 `json:"tsid"`
	ServiceID       uint16 `json:"service_id"`
}

type DVBDescramblingCandidate struct {
	CAID         string   `json:"caid"`
	ECMPID       uint16   `json:"ecm_pid"`
	ProgramLevel bool     `json:"program_level"`
	ESPIDs       []uint16 `json:"es_pids"`
}

type DVBDescramblingMetrics struct {
	Queued       int    `json:"queued"`
	OutputQueued int    `json:"output_queued"`
	Processed    uint64 `json:"processed"`
	Dropped      uint64 `json:"dropped"`
	SampleStale  bool   `json:"sample_stale"`
	SampleAgeMS  int64  `json:"sample_age_ms"`
}

type DVBDescramblingRuntime struct {
	State   string                 `json:"state"`
	Reason  string                 `json:"reason"`
	Metrics DVBDescramblingMetrics `json:"metrics"`
}

func (r *DVBDescramblingRuntime) Clone() *DVBDescramblingRuntime {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}

type DVBDescramblingStatus struct {
	Backend    DVBDescramblingBackend     `json:"backend"`
	Identity   *DVBDescramblingIdentity   `json:"identity"`
	Candidates []DVBDescramblingCandidate `json:"candidates"`
	Policy     *DVBDescramblingConfig     `json:"policy"`
	State      string                     `json:"state"`
	Reason     string                     `json:"reason"`
	Metrics    DVBDescramblingMetrics     `json:"metrics"`
}

func (s DVBDescramblingStatus) Runtime() *DVBDescramblingRuntime {
	return &DVBDescramblingRuntime{State: s.State, Reason: s.Reason, Metrics: s.Metrics}
}
