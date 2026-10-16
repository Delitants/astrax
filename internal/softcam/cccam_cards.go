// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import "encoding/binary"

// Only inventory facts survive parsing; serials, SIDs and node IDs do not.
type cccamCard struct {
	ID        uint32
	CAID      uint16
	Providers []uint32
}

func parseCCcamCard(payload []byte, sidForm bool) (cccamCard, error) {
	bad := func() (cccamCard, error) { return cccamCard{}, protocolError("invalid_frame", nil) }
	offset := 21
	if sidForm {
		offset = 23
	}
	if len(payload) < offset+1 || len(payload) > cccamMaxPayload {
		return bad()
	}
	providers := int(payload[20])
	if providers > cccamMaxProviders {
		return bad()
	}
	providerEnd := offset + providers*7
	sidEnd := providerEnd
	if sidForm {
		sidEnd += (int(payload[21]) + int(payload[22])) * 2
	}
	if len(payload) < sidEnd+1 {
		return bad()
	}
	nodes := int(payload[sidEnd])
	if len(payload) != sidEnd+1+nodes*8 {
		return bad()
	}
	card := cccamCard{ID: binary.BigEndian.Uint32(payload[:4]), CAID: binary.BigEndian.Uint16(payload[8:10]), Providers: make([]uint32, providers)}
	for i := range card.Providers {
		p := payload[offset+i*7:]
		card.Providers[i] = uint32(p[0])<<16 | uint32(p[1])<<8 | uint32(p[2])
	}
	return card, nil
}

func parseCCcamRemoval(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, protocolError("invalid_frame", nil)
	}
	return binary.BigEndian.Uint32(payload), nil
}
