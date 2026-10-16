// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import "encoding/binary"

// Ordinary command-1 payload; this function owns no socket or cipher state.
func encodeCCcamECM(route ECMRoute, cardID uint32, serviceID uint16, section []byte) ([]byte, error) {
	if err := validateECMRequest(section, route); err != nil {
		return nil, err
	}
	payload := make([]byte, 13+len(section))
	binary.BigEndian.PutUint16(payload[0:2], route.CAID)
	binary.BigEndian.PutUint32(payload[2:6], route.Provider)
	binary.BigEndian.PutUint32(payload[6:10], cardID)
	binary.BigEndian.PutUint16(payload[10:12], serviceID)
	payload[12] = byte(len(section))
	copy(payload[13:], section)
	return payload, nil
}

// Decode an owned key copy, leaving the encoded input intact for the reader's
// separately verified extra receive-cipher advancement before its next frame.
func decodeCCcamCW(nodeID [8]byte, cardID uint32, payload []byte) (ecmKeys, error) {
	if len(payload) != 16 {
		return ecmKeys{}, ecmError("ecm_invalid_response", nil)
	}
	var keys ecmKeys
	identity := binary.BigEndian.Uint64(nodeID[:])
	for i, encoded := range payload {
		mask := byte(identity>>(4*uint(i))) ^ byte(cardID>>(2*uint(i)))
		if i&1 != 0 {
			mask ^= 0xff
		}
		keys.material[i] = encoded ^ mask
		if keys.material[i] != 0 {
			keys.validMask |= 1 << uint(i/8)
		}
	}
	return keys, nil
}
