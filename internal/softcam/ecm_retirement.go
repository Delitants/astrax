// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import "time"

var _ ecmResultFence = (*cccamSession)(nil)
var _ ecmPublicationFence = (*cccamSession)(nil)
var _ ecmSessionFence = (*cccamSession)(nil)

func (s *cccamSession) validateECMSessionLocked(epoch uint64) error {
	// No stateErrorLocked/error wrapping here: publication failures are shared
	// fixed errors, and native ctx is the session's owned cancellation context.
	if s.ctx == nil || s.ctx.Err() != nil || s.closed || s.ecmRetiring || !s.authenticated ||
		s.wire == nil || !s.wire.identityRetained || s.ecmEpoch == 0 {
		return ecmSessionUnavailableError
	}
	if epoch != s.ecmEpoch {
		return ecmStaleError
	}
	return nil
}

func (s *cccamSession) validateECMRouteLocked(route ECMRoute) error {
	if err := s.validateECMSessionLocked(s.ecmEpoch); err != nil {
		return err
	}
	if route.Provider > ecmMaxProvider {
		return ecmNoRouteError
	}
	for _, card := range s.cards {
		if card.CAID != route.CAID {
			continue
		}
		for _, provider := range card.Providers {
			if provider == route.Provider {
				return nil
			}
		}
	}
	return ecmNoRouteError
}

func (s *cccamSession) lockECMResults()   { s.mu.Lock() }
func (s *cccamSession) unlockECMResults() { s.mu.Unlock() }
func (s *cccamSession) validateECMResultLocked(t ecmToken) error {
	if s.ecmRetiring {
		return ecmStaleError
	}
	if err := s.validateECMSessionLocked(t.sessionEpoch); err != nil {
		return err
	}
	if t.cardRevision == 0 || t.operationID == 0 {
		return ecmStaleError
	}
	if len(t.profileID) > ecmMaxIDBytes || len(t.identity.InputID) > ecmMaxIDBytes {
		return ecmInvalidRequestError
	}
	card, ok := s.cards[t.cardID]
	if !ok || s.cardRevisions[t.cardID] != t.cardRevision {
		return ecmStaleError
	}
	if t.route.Provider > ecmMaxProvider || t.route.CAID != card.CAID {
		return ecmNoRouteError
	}
	for _, provider := range card.Providers {
		if provider == t.route.Provider {
			return nil
		}
	}
	return ecmNoRouteError
}
func (b *ecmBroker) expireResultsLocked(nowTime time.Time) {
	for id, owned := range b.results {
		if !b.tokenCurrentLocked(owned.backing.token) || !nowTime.Before(owned.backing.expires) {
			b.dropResultLocked(id)
		}
	}
}
func (b *ecmBroker) revokeBindingResultsLocked(s *ecmServiceBinding) {
	for id, owned := range b.results {
		if owned.backing.token.identity == s.identity && owned.backing.token.serviceEpoch == s.epoch {
			b.dropResultLocked(id)
		}
	}
}
func (b *ecmBroker) revokeResultsLocked() {
	for id := range b.results {
		b.dropResultLocked(id)
	}
}
