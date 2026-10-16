// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"errors"
	"net/url"

	"astrax/internal/model"
)

func externalStreamScope(query url.Values) (bool, error) {
	values, present := query["scope"]
	if !present {
		return false, nil
	}
	if len(values) != 1 || values[0] != "external" {
		return false, errors.New("scope must be external when specified")
	}
	return true, nil
}

func externalStreams(streams []model.Stream) []model.Stream {
	// A fresh slice keeps shared subscriber snapshots and legacy readers intact.
	result := make([]model.Stream, 0)
	for _, stream := range streams {
		if stream.DVB == nil && stream.AdapterProfileID == "" {
			result = append(result, stream)
		}
	}
	return result
}
