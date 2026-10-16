//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"fmt"

	"astrax/internal/epg"
)

func CollectEIT(session Session, depth string) ([]epg.Programme, error) {
	if session == nil {
		return nil, nil
	}
	return nil, fmt.Errorf("linux dvb EIT collection requires a linux build")
}
