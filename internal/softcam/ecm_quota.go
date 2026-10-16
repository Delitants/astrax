// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"sync"
)

// Counters include provisional admission and the active untagged transaction.
// All mutations occur in owner/quota/broker order; result ownership is Task 4.
type ecmQuota struct {
	mu                           sync.Mutex
	brokers, operations, waiters int
	// Published result reservations are owned by this quota under mu.
	results int
}

func newECMQuota() *ecmQuota { return &ecmQuota{} }

var processECMQuota = newECMQuota()

// Shared rejections are immutable. As returns a caller-owned ECMError copy so
// its exported Code field cannot corrupt another admission's error.
type ecmFixedError struct {
	code  string
	cause error
}

func (e ecmFixedError) Error() string    { return ecmErrorText(e.code) }
func (e ecmFixedError) GoString() string { return e.Error() }
func (e ecmFixedError) Unwrap() error    { return e.cause }
func (e ecmFixedError) As(target any) bool {
	owned, ok := target.(**ECMError)
	if !ok {
		return false
	}
	*owned = &ECMError{Code: e.code, cause: e.cause}
	return true
}

// Interface values are allocated once, not on capacity rejection.
var (
	ecmCapacityError       error = ecmFixedError{code: "ecm_capacity"}
	ecmStaleError          error = ecmFixedError{code: "ecm_stale"}
	ecmCancelledError      error = ecmFixedError{code: "ecm_cancelled", cause: context.Canceled}
	ecmTimeoutError        error = ecmFixedError{code: "ecm_timeout", cause: context.DeadlineExceeded}
	ecmInvalidRequestError error = ecmFixedError{code: "ecm_invalid_request"}
	ecmNoRouteError        error = ecmFixedError{code: "ecm_no_route"}
)
