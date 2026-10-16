// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

// DVBInvalidation requests bounded visible-page, count and facet refetches.
// It never carries the contents of an entire collection.
type DVBInvalidation struct {
	Streams bool `json:"streams"`
	Groups  bool `json:"groups"`
	Cards   bool `json:"cards"`
}
