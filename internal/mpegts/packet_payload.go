// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

// Payload validates the packet and returns its owned payload storage and original
// scrambling control (0 clear, 2 even, 3 odd). It never clears scrambling flags.
// Adaptation-only packets return nil payload with their original control value.
func (p *Packet) Payload() ([]byte, uint8, error) {
	if p == nil {
		return nil, 0, ErrInvalidPacket
	}
	info, err := inspectPacket(p)
	if err != nil {
		return nil, 0, err
	}
	return info.payload, p[3] >> 6, nil
}
