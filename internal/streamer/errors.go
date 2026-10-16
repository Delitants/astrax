// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"context"
	"errors"
)

// IsBenignLifecycleError recognizes only pure supersession/shutdown outcomes.
// A joined error is benign only when every cause is benign; one stale/canceled
// cause must never hide a genuine setup or terminal cleanup failure.
func IsBenignLifecycleError(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if !IsBenignLifecycleError(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if cause := wrapped.Unwrap(); cause != nil {
			return IsBenignLifecycleError(cause)
		}
	}
	return errors.Is(err, ErrStreamTokenMismatch) || errors.Is(err, ErrStreamNotFound) ||
		errors.Is(err, ErrRegistrationSuperseded) || errors.Is(err, ErrStreamerClosed) ||
		errors.Is(err, context.Canceled)
}
