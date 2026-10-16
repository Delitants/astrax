// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import (
	"astrax/internal/model"
	"errors"
	"strconv"
)

var ErrUnsupportedCALayout = errors.New("unsupported_ca_layout")

type ResolvedRoute struct {
	CAID     uint16
	Provider uint32
	ECMPID   uint16
}

// ResolveRoute resolves exactly one operator-selected policy. Inventory/card
// eligibility remains the broker's responsibility; this never contacts a peer.
func ResolveRoute(s Service, policy model.DVBDescramblingConfig) (ResolvedRoute, error) {
	if !policy.Enabled || policy.Algorithm != "dvb-csa" {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	caid, ok := policyHex(policy.CAID, 4)
	if !ok {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	provider, ok := policyHex(policy.Provider, 6)
	if !ok {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	if s.SID == 0 || !usablePID(s.PMTPID) || (s.PCRPID != 8191 && !usablePID(s.PCRPID)) {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	selected := make(map[uint16]bool)
	if s.PCRPID != 8191 {
		selected[s.PCRPID] = true
	}
	esSet := make(map[uint16]bool)
	if len(s.ElementaryStreams) == 0 || len(s.ElementaryStreams) > maxOutputPIDs {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	for _, es := range s.ElementaryStreams {
		if !usablePID(es.PID) || esSet[es.PID] || !supportedStream(es.StreamType) {
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		esSet[es.PID], selected[es.PID] = true, true
	}
	if len(selected) > maxOutputPIDs {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	// A wire-bounded PMT reserves its header and at least one ES before CA bytes.
	// Bound arbitrary caller-supplied Service values too, before allocating maps.
	if len(s.CADescriptors) == 0 || len(s.CADescriptors) > (maxWireSection-21)/6 {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	routes := make(map[[2]uint16]bool)
	matches := make(map[uint16]bool)
	for _, ca := range s.CADescriptors {
		if !usablePID(ca.ECMPID) || selected[ca.ECMPID] || ca.ECMPID == s.PMTPID || len(ca.PrivateData) > 251 {
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		switch ca.Scope {
		case CAProgram:
			if ca.ESPID != 0 {
				return ResolvedRoute{}, ErrUnsupportedCALayout
			}
		case CAElementary:
			if !esSet[ca.ESPID] {
				return ResolvedRoute{}, ErrUnsupportedCALayout
			}
		default:
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		routes[[2]uint16{ca.CAID, ca.ECMPID}] = true
		if len(routes) > maxCARoutes {
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		if ca.CAID == uint16(caid) {
			matches[ca.ECMPID] = true
		}
	}
	var pid uint16
	if policy.ECMPID != nil {
		if *policy.ECMPID < 32 || *policy.ECMPID >= 8191 || !matches[uint16(*policy.ECMPID)] {
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		pid = uint16(*policy.ECMPID)
	} else {
		if len(matches) != 1 {
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		for p := range matches {
			pid = p
		}
	}
	program := false
	covered := make(map[uint16]bool)
	for _, ca := range s.CADescriptors {
		if ca.Scope == CAProgram {
			if ca.CAID == uint16(caid) && ca.ECMPID == pid {
				program = true
			}
			continue
		}
		// No cross-ES fallback, alternate CAID trial, or contradictory scoped route.
		if ca.CAID != uint16(caid) || ca.ECMPID != pid {
			return ResolvedRoute{}, ErrUnsupportedCALayout
		}
		covered[ca.ESPID] = true
	}
	if !program && len(covered) != len(esSet) {
		return ResolvedRoute{}, ErrUnsupportedCALayout
	}
	return ResolvedRoute{CAID: uint16(caid), Provider: provider, ECMPID: pid}, nil
}

func policyHex(raw string, width int) (uint32, bool) {
	if len(raw) != width {
		return 0, false
	}
	for _, c := range raw {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(raw, 16, 32)
	return uint32(n), err == nil
}
