// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import "bytes"

const (
	maxECMSectionBytes = 255
	maxECMPushSections = 184 / 3
)

// ECMAssembler assembles only one selected ECM PID. Its caller serializes Push
// and Reset. Retention is one partial section and one payload for exact duplicate
// detection; complete sections are copied to the caller, not cached here.
type ECMAssembler struct {
	pid         uint16
	section     [maxECMSectionBytes]byte
	used        int
	total       int
	lastPayload [184]byte
	lastLength  int
	lastCC      byte
	lastPUSI    bool
	lastDisc    bool
	haveCC      bool
}

// NewECMAssembler rejects reserved/system and null PIDs.
func NewECMAssembler(pid uint16) (*ECMAssembler, error) {
	if pid < 32 || pid > 8190 {
		return nil, ErrInvalidPSI
	}
	return &ECMAssembler{pid: pid}, nil
}

// Reset discards partial assembly and duplicate history, preserving the PID.
func (a *ECMAssembler) Reset() {
	if a != nil {
		*a = ECMAssembler{pid: a.pid}
	}
}

// Push returns at most 61 independent sections. Malformed selected-PID packets
// discard all results from this push and reset state. Foreign PIDs, even malformed
// ones, are ignored. Gaps/discontinuities discard partials and await a new PUSI.
func (a *ECMAssembler) Push(packet Packet) ([][]byte, error) {
	if a == nil || a.pid < 32 || a.pid > 8190 {
		return nil, ErrInvalidPSI
	}
	pid := uint16(packet[1]&0x1F)<<8 | uint16(packet[2])
	if pid != a.pid {
		return nil, nil
	}
	info, err := inspectPacket(&packet)
	if err != nil {
		a.Reset()
		return nil, err
	}
	if info.scrambled {
		a.Reset()
		return nil, ErrInvalidPacket
	}
	// Check before discontinuity: replay must not erase a partial started by the
	// original discontinuity packet. A changed discontinuity bit is not a replay.
	if len(info.payload) > 0 && a.haveCC && info.cc == a.lastCC {
		if info.pusi == a.lastPUSI && info.discontinuity == a.lastDisc &&
			len(info.payload) == a.lastLength &&
			bytes.Equal(info.payload, a.lastPayload[:a.lastLength]) {
			return nil, nil
		}
		a.Reset()
		return nil, ErrInvalidPacket
	}
	if info.discontinuity {
		a.Reset()
	}
	if len(info.payload) == 0 {
		// Adaptation-only packets keep the last payload CC, but an unexpected
		// counter still invalidates the partial section.
		if a.haveCC && info.cc != a.lastCC {
			a.used, a.total = 0, 0
		}
		return nil, nil
	}
	if a.haveCC && info.cc != (a.lastCC+1)&15 {
		a.Reset()
	}
	copy(a.lastPayload[:], info.payload)
	a.lastLength, a.lastCC, a.lastPUSI, a.haveCC = len(info.payload), info.cc, info.pusi, true
	a.lastDisc = info.discontinuity
	sections, err := a.pushPayload(info.payload, info.pusi)
	if err != nil {
		a.Reset()
		return nil, err
	}
	return sections, nil
}

func (a *ECMAssembler) pushPayload(data []byte, pusi bool) ([][]byte, error) {
	var out [][]byte
	if !pusi {
		if a.used == 0 {
			return nil, nil
		}
		n, section, err := a.continueECM(data)
		if err != nil {
			return nil, err
		}
		if section != nil {
			if !stuffing(data[n:]) {
				return nil, ErrInvalidPSI
			}
			out = append(out, section)
		}
		return out, nil
	}

	pointer := int(data[0])
	// PUSI promises a section start after the prefix, not an empty suffix.
	if pointer >= len(data)-1 {
		return nil, ErrInvalidPacket
	}
	data = data[1:]
	if a.used > 0 && pointer > 0 {
		n, section, err := a.continueECM(data[:pointer])
		if err != nil {
			return nil, err
		}
		if section != nil {
			if !stuffing(data[n:pointer]) {
				return nil, ErrInvalidPSI
			}
			out = append(out, section)
		}
	}
	// Prefix bytes can only finish the old section. The explicit new boundary
	// abandons any remaining partial, including a one/two-byte header.
	a.used, a.total = 0, 0
	data = data[pointer:]
	for len(data) > 0 {
		if data[0] == 0xFF {
			if !stuffing(data) {
				return nil, ErrInvalidPSI
			}
			break
		}
		n, section, err := a.continueECM(data)
		if err != nil {
			return nil, err
		}
		data = data[n:]
		if section == nil {
			break
		}
		if len(out) >= maxECMPushSections {
			return nil, ErrCapacity
		}
		out = append(out, section)
	}
	return out, nil
}

// continueECM consumes at most one section, including fragmented headers. Only
// the low 12 length bits define the envelope; proprietary ECM has no generic CRC.
func (a *ECMAssembler) continueECM(data []byte) (int, []byte, error) {
	if a.used == 0 && len(data) > 0 && data[0] != 0x80 && data[0] != 0x81 {
		return 0, nil, ErrInvalidPSI
	}
	n := 0
	for a.used < 3 && n < len(data) {
		a.section[a.used] = data[n]
		a.used++
		n++
	}
	if a.used < 3 {
		return n, nil, nil
	}
	if a.total == 0 {
		a.total = 3 + (int(a.section[1]&0x0F) << 8) + int(a.section[2])
		if a.total > maxECMSectionBytes {
			return n, nil, ErrInvalidPSI
		}
	}
	remaining := a.total - a.used
	if remaining > len(data)-n {
		remaining = len(data) - n
	}
	copy(a.section[a.used:a.used+remaining], data[n:n+remaining])
	a.used += remaining
	n += remaining
	if a.used < a.total {
		return n, nil, nil
	}
	section := make([]byte, a.total)
	copy(section, a.section[:a.total])
	a.used, a.total = 0, 0
	return n, section, nil
}
