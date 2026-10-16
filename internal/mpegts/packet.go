// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import "errors"

type Packet [188]byte

var (
	ErrInvalidPacket = errors.New("invalid_packet")
	ErrInvalidPSI    = errors.New("invalid_psi")
	ErrCapacity      = errors.New("psi_capacity")
)

// ParsePacket copies one aligned packet; it never aliases caller storage.
func ParsePacket(raw []byte) (Packet, error) {
	if len(raw) != 188 {
		return Packet{}, ErrInvalidPacket
	}
	var p Packet
	copy(p[:], raw)
	if _, err := inspectPacket(&p); err != nil {
		return Packet{}, err
	}
	return p, nil
}

type packetInfo struct {
	pid           uint16
	cc            byte
	pusi          bool
	discontinuity bool
	scrambled     bool
	payload       []byte
}

func inspectPacket(p *Packet) (packetInfo, error) {
	var out packetInfo
	if p[0] != 0x47 || p[1]&0x80 != 0 || p[3]&0xC0 == 0x40 {
		return out, ErrInvalidPacket
	}
	out.pid = uint16(p[1]&0x1F)<<8 | uint16(p[2])
	out.cc = p[3] & 15
	out.pusi = p[1]&0x40 != 0
	out.scrambled = p[3]&0xC0 != 0
	afc := (p[3] >> 4) & 3
	if afc == 0 {
		return packetInfo{}, ErrInvalidPacket
	}
	pos := 4
	if afc&2 != 0 {
		length := int(p[4])
		end := 5 + length
		if end > 188 || (afc == 2 && end != 188) || (afc == 3 && end >= 188) {
			return packetInfo{}, ErrInvalidPacket
		}
		pos = end
		if length > 0 {
			flags := p[5]
			out.discontinuity = flags&0x80 != 0
			i := 6
			for _, flag := range []byte{0x10, 0x08} {
				if flags&flag == 0 {
					continue
				}
				if i+6 > end || p[i+4]&0x7E != 0x7E || (uint16(p[i+4]&1)<<8|uint16(p[i+5])) >= 300 {
					return packetInfo{}, ErrInvalidPacket
				}
				i += 6
			}
			if flags&4 != 0 {
				if i >= end {
					return packetInfo{}, ErrInvalidPacket
				}
				i++
			}
			if flags&2 != 0 {
				if i >= end {
					return packetInfo{}, ErrInvalidPacket
				}
				n := int(p[i])
				i++
				if i+n > end {
					return packetInfo{}, ErrInvalidPacket
				}
				i += n
			}
			if flags&1 != 0 {
				if i >= end {
					return packetInfo{}, ErrInvalidPacket
				}
				n := int(p[i])
				i++
				if i+n > end {
					return packetInfo{}, ErrInvalidPacket
				}
				xend := i + n
				if n > 0 {
					xflags := p[i]
					i++
					if xflags&0x1F != 0x1F {
						return packetInfo{}, ErrInvalidPacket
					}
					if xflags&0x80 != 0 {
						if i+2 > xend {
							return packetInfo{}, ErrInvalidPacket
						}
						i += 2
					}
					if xflags&0x40 != 0 {
						if i+3 > xend || p[i]&0xC0 != 0xC0 {
							return packetInfo{}, ErrInvalidPacket
						}
						i += 3
					}
					if xflags&0x20 != 0 {
						if i+5 > xend || p[i]&1 == 0 || p[i+2]&1 == 0 || p[i+4]&1 == 0 {
							return packetInfo{}, ErrInvalidPacket
						}
						i += 5
					}
					for ; i < xend; i++ {
						if p[i] != 0xFF {
							return packetInfo{}, ErrInvalidPacket
						}
					}
				}
				i = xend
			}
			for ; i < end; i++ {
				if p[i] != 0xFF {
					return packetInfo{}, ErrInvalidPacket
				}
			}
		}
	}
	if afc&1 != 0 {
		out.payload = p[pos:]
		// These fixed PSI PIDs always use a pointer, unlike a PES PUSI payload.
		if !out.scrambled && out.pusi && (out.pid == 0 || out.pid == 17) &&
			(len(out.payload) == 0 || int(out.payload[0]) >= len(out.payload)-1) {
			return packetInfo{}, ErrInvalidPacket
		}
	} else if out.pusi {
		return packetInfo{}, ErrInvalidPacket
	}
	return out, nil
}
