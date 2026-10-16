// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import "bytes"

const (
	maxWireSection    = 1024
	maxCandidates     = 64
	maxAssemblerBytes = 256 * 1024
	maxServices       = 256
	maxRegisteredPIDs = 256
	maxOutputPIDs     = 64
	maxCARoutes       = 16
)

type Descriptor struct {
	Tag  byte
	Data []byte
}

type CAScope uint8

const (
	CAProgram CAScope = iota + 1
	CAElementary
)

// PrivateData is opaque; it must not be interpreted as a provider or algorithm.
type CADescriptor struct {
	CAID        uint16
	ECMPID      uint16
	Scope       CAScope
	ESPID       uint16
	PrivateData []byte
}

type Subtitle struct {
	Language        string
	Type            byte
	CompositionPage uint16
	AncillaryPage   uint16
}

type ElementaryStream struct {
	PID         uint16
	StreamType  byte
	Descriptors []Descriptor
	Languages   []string
	Subtitles   []Subtitle
}

type Service struct {
	ONID               uint16
	TSID               uint16
	SID                uint16
	PMTPID             uint16
	PCRPID             uint16
	Version            byte
	Name               string
	ProviderName       string
	ProgramDescriptors []Descriptor
	ElementaryStreams  []ElementaryStream
	CADescriptors      []CADescriptor
}

type tableKey struct {
	pid     uint16
	tid     byte
	ext     uint16
	version byte
}

type sectionHeader struct {
	key     tableKey
	current bool
	number  byte
	last    byte
	onid    uint16
}

var psiCRCTable = func() [256]uint32 {
	var table [256]uint32
	for n := range table {
		r := uint32(n) << 24
		for b := 0; b < 8; b++ {
			if r&0x80000000 != 0 {
				r = r<<1 ^ 0x04C11DB7
			} else {
				r <<= 1
			}
		}
		table[n] = r
	}
	return table
}()

func psiCRC(raw []byte) uint32 {
	r := uint32(0xFFFFFFFF)
	for _, b := range raw {
		r = r<<8 ^ psiCRCTable[byte(r>>24)^b]
	}
	return r
}

func word(raw []byte) uint16    { return uint16(raw[0])<<8 | uint16(raw[1]) }
func usablePID(pid uint16) bool { return pid >= 32 && pid < 8191 }

func parseSectionHeader(pid uint16, raw []byte) (sectionHeader, error) {
	var h sectionHeader
	if len(raw) < 12 || len(raw) > maxWireSection ||
		3+int(word(raw[1:3])&0x0FFF) != len(raw) || raw[5]&0xC0 != 0xC0 || psiCRC(raw) != 0 {
		return h, ErrInvalidPSI
	}
	h.key = tableKey{pid: pid, tid: raw[0], ext: word(raw[3:5]), version: (raw[5] >> 1) & 31}
	h.current = raw[5]&1 != 0
	h.number, h.last = raw[6], raw[7]
	if h.number > h.last {
		return h, ErrInvalidPSI
	}
	switch raw[0] {
	case 0:
		if pid != 0 || raw[1]&0xF0 != 0xB0 {
			return h, ErrInvalidPSI
		}
	case 2:
		if raw[1]&0xF0 != 0xB0 || h.key.ext == 0 || h.number != 0 || h.last != 0 || len(raw) < 16 {
			return h, ErrInvalidPSI
		}
	case 0x42:
		if pid != 17 || raw[1]&0xF0 != 0xF0 || len(raw) < 15 || raw[10] != 0xFF {
			return h, ErrInvalidPSI
		}
		h.onid = word(raw[8:10])
	default:
		return h, ErrInvalidPSI
	}
	return h, nil
}

func parsePAT(raw []byte) (map[uint16]uint16, error) {
	body := raw[8 : len(raw)-4]
	if len(body)%4 != 0 {
		return nil, ErrInvalidPSI
	}
	out := make(map[uint16]uint16)
	for len(body) > 0 {
		if body[2]&0xE0 != 0xE0 {
			return nil, ErrInvalidPSI
		}
		sid, pid := word(body[:2]), word(body[2:4])&0x1FFF
		if sid == 0 {
			if pid == 0 || pid == 8191 {
				return nil, ErrInvalidPSI
			}
		} else {
			if !usablePID(pid) {
				return nil, ErrInvalidPSI
			}
			if _, exists := out[sid]; exists {
				return nil, ErrInvalidPSI
			}
			out[sid] = pid
		}
		body = body[4:]
	}
	return out, nil
}

type serviceMetadata struct{ name, provider string }

func parseSDT(raw []byte) (map[uint16]serviceMetadata, error) {
	body := raw[11 : len(raw)-4]
	out := make(map[uint16]serviceMetadata)
	for len(body) > 0 {
		if len(body) < 5 || body[2]&0xFC != 0xFC || body[3]>>5 >= 6 {
			return nil, ErrInvalidPSI
		}
		sid := word(body[:2])
		if sid == 0 {
			return nil, ErrInvalidPSI
		}
		if _, exists := out[sid]; exists {
			return nil, ErrInvalidPSI
		}
		n := int(word(body[3:5]) & 0x0FFF)
		if 5+n > len(body) {
			return nil, ErrInvalidPSI
		}
		loop := body[5 : 5+n]
		var meta serviceMetadata
		seenName := false
		for len(loop) > 0 {
			if len(loop) < 2 || int(loop[1])+2 > len(loop) {
				return nil, ErrInvalidPSI
			}
			d := loop[2 : 2+int(loop[1])]
			if loop[0] == 0x48 {
				if seenName || len(d) < 3 {
					return nil, ErrInvalidPSI
				}
				pn := int(d[1])
				if 2+pn >= len(d) {
					return nil, ErrInvalidPSI
				}
				sn := int(d[2+pn])
				if 3+pn+sn != len(d) {
					return nil, ErrInvalidPSI
				}
				// Retain bounded DVB text bytes; provider name is never a CA provider ID.
				meta.provider, meta.name = string(d[2:2+pn]), string(d[3+pn:])
				seenName = true
			}
			loop = loop[2+int(loop[1]):]
		}
		out[sid] = meta
		body = body[5+n:]
	}
	return out, nil
}

func parseDescriptors(loop []byte, scope CAScope, esPID uint16) ([]Descriptor, []CADescriptor, []string, []Subtitle, error) {
	var descriptors []Descriptor
	var ca []CADescriptor
	var languages []string
	var subtitles []Subtitle
	for len(loop) > 0 {
		if len(loop) < 2 || int(loop[1])+2 > len(loop) {
			return nil, nil, nil, nil, ErrInvalidPSI
		}
		tag, n := loop[0], int(loop[1])
		d := loop[2 : 2+n]
		descriptors = append(descriptors, Descriptor{Tag: tag, Data: bytes.Clone(d)})
		switch tag {
		case 9:
			if n < 4 || d[2]&0xE0 != 0xE0 || !usablePID(word(d[2:4])&0x1FFF) {
				return nil, nil, nil, nil, ErrInvalidPSI
			}
			ca = append(ca, CADescriptor{CAID: word(d[:2]), ECMPID: word(d[2:4]) & 0x1FFF,
				Scope: scope, ESPID: esPID, PrivateData: bytes.Clone(d[4:])})
		case 0x0A:
			if n == 0 || n%4 != 0 {
				return nil, nil, nil, nil, ErrInvalidPSI
			}
			for j := 0; j < n; j += 4 {
				languages = append(languages, string(d[j:j+3]))
			}
		case 0x59:
			if n == 0 || n%8 != 0 {
				return nil, nil, nil, nil, ErrInvalidPSI
			}
			for j := 0; j < n; j += 8 {
				subtitles = append(subtitles, Subtitle{Language: string(d[j : j+3]), Type: d[j+3],
					CompositionPage: word(d[j+4 : j+6]), AncillaryPage: word(d[j+6 : j+8])})
			}
		}
		loop = loop[2+n:]
	}
	return descriptors, ca, languages, subtitles, nil
}

func supportedStream(typ byte) bool {
	switch typ {
	case 1, 2, 3, 4, 6, 0x0F, 0x10, 0x11, 0x1B, 0x24, 0x81, 0x87:
		return true
	default:
		return false
	}
}

func parsePMT(raw []byte, pid uint16) (Service, error) {
	var s Service
	if raw[8]&0xE0 != 0xE0 || raw[10]&0xF0 != 0xF0 {
		return s, ErrInvalidPSI
	}
	s.SID, s.PMTPID, s.PCRPID, s.Version = word(raw[3:5]), pid, word(raw[8:10])&0x1FFF, (raw[5]>>1)&31
	if s.PCRPID != 8191 && !usablePID(s.PCRPID) {
		return Service{}, ErrInvalidPSI
	}
	n := int(word(raw[10:12]) & 0x0FFF)
	end := len(raw) - 4
	if 12+n > end {
		return Service{}, ErrInvalidPSI
	}
	var err error
	s.ProgramDescriptors, s.CADescriptors, _, _, err = parseDescriptors(raw[12:12+n], CAProgram, 0)
	if err != nil {
		return Service{}, err
	}
	pos := 12 + n
	selected := make(map[uint16]bool)
	if s.PCRPID != 8191 {
		selected[s.PCRPID] = true
	}
	esSeen := make(map[uint16]bool)
	for pos < end {
		if pos+5 > end || raw[pos+1]&0xE0 != 0xE0 || raw[pos+3]&0xF0 != 0xF0 || !supportedStream(raw[pos]) {
			return Service{}, ErrInvalidPSI
		}
		es := ElementaryStream{PID: word(raw[pos+1:pos+3]) & 0x1FFF, StreamType: raw[pos]}
		if !usablePID(es.PID) || esSeen[es.PID] {
			return Service{}, ErrInvalidPSI
		}
		esSeen[es.PID], selected[es.PID] = true, true
		if len(selected) > maxOutputPIDs {
			return Service{}, ErrCapacity
		}
		n = int(word(raw[pos+3:pos+5]) & 0x0FFF)
		if pos+5+n > end {
			return Service{}, ErrInvalidPSI
		}
		var ca []CADescriptor
		es.Descriptors, ca, es.Languages, es.Subtitles, err = parseDescriptors(raw[pos+5:pos+5+n], CAElementary, es.PID)
		if err != nil {
			return Service{}, err
		}
		s.CADescriptors = append(s.CADescriptors, ca...)
		s.ElementaryStreams = append(s.ElementaryStreams, es)
		pos += 5 + n
	}
	if len(s.ElementaryStreams) == 0 {
		return Service{}, ErrInvalidPSI
	}
	routes := make(map[[2]uint16]bool)
	for _, ca := range s.CADescriptors {
		if selected[ca.ECMPID] || ca.ECMPID == pid {
			return Service{}, ErrInvalidPSI
		}
		routes[[2]uint16{ca.CAID, ca.ECMPID}] = true
		if len(routes) > maxCARoutes {
			return Service{}, ErrCapacity
		}
	}
	return s, nil
}

func cloneDescriptors(in []Descriptor) []Descriptor {
	if len(in) == 0 {
		return nil
	}
	out := make([]Descriptor, len(in))
	for n, d := range in {
		out[n] = Descriptor{Tag: d.Tag, Data: bytes.Clone(d.Data)}
	}
	return out
}

func cloneService(in Service) Service {
	out := in
	out.ProgramDescriptors = cloneDescriptors(in.ProgramDescriptors)
	out.CADescriptors = make([]CADescriptor, len(in.CADescriptors))
	for n, ca := range in.CADescriptors {
		out.CADescriptors[n] = ca
		out.CADescriptors[n].PrivateData = bytes.Clone(ca.PrivateData)
	}
	out.ElementaryStreams = make([]ElementaryStream, len(in.ElementaryStreams))
	for n, es := range in.ElementaryStreams {
		out.ElementaryStreams[n] = es
		out.ElementaryStreams[n].Descriptors = cloneDescriptors(es.Descriptors)
		out.ElementaryStreams[n].Languages = append([]string(nil), es.Languages...)
		out.ElementaryStreams[n].Subtitles = append([]Subtitle(nil), es.Subtitles...)
	}
	return out
}

// Clone gives a service owner independent descriptor and elementary-stream storage.
func (s Service) Clone() Service { return cloneService(s) }
