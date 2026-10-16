//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"log"

	"astrax/internal/epg"
)

// CollectEIT opens a demux, reads EIT sections, parses them, and returns programmes.
// If session is non-nil and has lock, it uses the session's demux path.
func CollectEIT(session Session, depth string) ([]epg.Programme, error) {
	var tableIDs []uint8
	switch depth {
	case "schedule":
		for i := uint8(0x50); i <= 0x5F; i++ {
			tableIDs = append(tableIDs, i)
		}
	default:
		tableIDs = []uint8{0x4E}
	}

	if session == nil {
		return nil, nil
	}
	demuxPath := session.DemuxPath()
	var allSections [][]byte
	for _, tid := range tableIDs {
		sections, err := readSectionsRaw(demuxPath, 0x0012, tid, 5000)
		if err != nil {
			log.Printf("eit: read table 0x%02X failed: %v", tid, err)
			continue
		}
		allSections = append(allSections, sections...)
	}
	if len(allSections) == 0 {
		return nil, nil
	}
	return ParseEITSections(allSections), nil
}
