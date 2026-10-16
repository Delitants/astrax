// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package mpegts

import (
	"bytes"
	"errors"
	"slices"
	"sort"
	"time"
)

const (
	sptsMaxPackets = 64
	sptsMaxInput   = 256
	sptsMaxSlots   = maxOutputPIDs + 3
)

var (
	ErrSPTSPrepared = errors.New("spts_invalid_prepared")
	ErrSPTSRecovery = errors.New("spts_recovery_adaptation_required")
)

type Selection struct {
	PIDs   []uint16
	PCRPID uint16
}

// SPTS is owned by one actor. Calls, including Publish then Commit, must be
// serialized; the builder never calls clocks, brokers, or publisher callbacks.
type SPTS struct {
	self       *SPTS
	generation *sptsGeneration
	config     sptsConfig
	state      sptsState
	version    byte
}

// Nonzero-sized identity tokens cannot alias while an old proposal holds one.
type sptsGeneration struct{ marker byte }

type sptsCounter struct {
	next byte
	seen bool
}

type sptsState struct {
	counters    [sptsMaxSlots]sptsCounter
	recovery    [sptsMaxSlots]bool
	forceTables bool
	patPMT      time.Time
	sdt         time.Time
	havePATPMT  bool
	haveSDT     bool
}

type sptsTable struct {
	pid     uint16
	section []byte
}

type sptsConfig struct {
	tables        [3]sptsTable
	slots         map[uint16]int
	sourceVersion byte
	identity      [3]uint16
}

type PreparedSPTS struct {
	Packets       []Packet
	Origins       []int
	Consumed      int
	owner         *SPTS
	self          *PreparedSPTS
	generation    *sptsGeneration
	used          bool
	proposal      sptsState
	count         int
	consumed      int
	budget        int
	sealedPackets [sptsMaxPackets]Packet
	sealedOrigins [sptsMaxPackets]int
}

func NewSPTS(service Service, selection Selection) (*SPTS, error) {
	config, err := sptsMakeConfig(service, selection, service.Version)
	if err != nil {
		return nil, err
	}
	b := &SPTS{config: config, version: service.Version,
		generation: &sptsGeneration{}, state: sptsState{forceTables: true}}
	b.self = b
	return b, nil
}

func (b *SPTS) valid() bool { return b != nil && b.self == b && b.generation != nil }

// Prepare scans at most one 256-packet caller-charged prefix. Consumed includes
// filtered input; only the emitted Packets/Origins have the 64-packet ceiling.
// No committed counter, timer, recovery flag, or generation changes here.
func (b *SPTS) Prepare(input []Packet, now time.Time, subscribe bool, maxPackets int) (*PreparedSPTS, error) {
	if !b.valid() {
		return nil, ErrSPTSPrepared
	}
	if maxPackets < 1 || maxPackets > sptsMaxPackets {
		return nil, ErrCapacity
	}
	scan := min(len(input), sptsMaxInput)
	flow := false
	for i := 0; i < scan; i++ {
		pid := uint16(input[i][1]&31)<<8 | uint16(input[i][2])
		if slot, ok := b.config.slots[pid]; ok && slot >= 3 {
			flow = true
			break
		}
	}
	patPMT, sdt := false, false
	if subscribe || flow {
		patPMT = subscribe || b.state.forceTables || !b.state.havePATPMT || now.Sub(b.state.patPMT) >= 100*time.Millisecond
		sdt = subscribe || b.state.forceTables || !b.state.haveSDT || now.Sub(b.state.sdt) >= 500*time.Millisecond
	}
	needed := 0
	if patPMT {
		needed += sptsTablePackets(len(b.config.tables[0].section)) + sptsTablePackets(len(b.config.tables[1].section))
	}
	if sdt {
		needed += sptsTablePackets(len(b.config.tables[2].section))
	}
	if needed > maxPackets {
		return nil, ErrCapacity
	}
	p := &PreparedSPTS{
		owner: b, generation: b.generation, proposal: b.state, budget: maxPackets,
		Packets: make([]Packet, 0, maxPackets), Origins: make([]int, 0, maxPackets),
	}
	p.self = p
	if patPMT {
		p.appendTable(b.config.tables[0], 0)
		p.appendTable(b.config.tables[1], 1)
		if !p.proposal.havePATPMT || now.After(p.proposal.patPMT) {
			p.proposal.patPMT = now
		}
		p.proposal.havePATPMT = true
	}
	if sdt {
		p.appendTable(b.config.tables[2], 2)
		if !p.proposal.haveSDT || now.After(p.proposal.sdt) {
			p.proposal.sdt = now
		}
		p.proposal.haveSDT = true
	}
	if patPMT && sdt {
		p.proposal.forceTables = false
	}
	for i := 0; i < scan; i++ {
		packet := input[i]
		pid := uint16(packet[1]&31)<<8 | uint16(packet[2])
		slot, retained := b.config.slots[pid]
		retained = retained && slot >= 3
		if retained && len(p.Packets) == maxPackets {
			break
		}
		info, err := inspectPacket(&packet)
		if err != nil {
			return nil, err
		}
		if retained {
			if p.proposal.recovery[slot] {
				// Inserting a flag into a full payload would lose PES bytes. The
				// actor must handle this explicit unsupported recovery layout.
				if packet[3]&0x20 == 0 || packet[4] == 0 {
					return nil, ErrSPTSRecovery
				}
				packet[5] |= 0x80
				p.proposal.recovery[slot] = false
			}
			p.proposal.stamp(&packet, slot, len(info.payload) != 0)
			p.Packets = append(p.Packets, packet)
			p.Origins = append(p.Origins, i)
		}
		p.Consumed = i + 1
	}
	p.count, p.consumed = len(p.Packets), p.Consumed
	copy(p.sealedPackets[:], p.Packets)
	copy(p.sealedOrigins[:], p.Origins)
	return p, nil
}

func (state *sptsState) stamp(packet *Packet, slot int, payload bool) {
	counter := &state.counters[slot]
	cc := byte(0)
	if payload {
		cc = counter.next
		counter.next = (cc + 1) & 15
		counter.seen = true
	} else if counter.seen {
		cc = (counter.next + 15) & 15
	}
	packet[3] = packet[3]&0xf0 | cc
}

func sptsTablePackets(length int) int { return (length + 184) / 184 }

func (p *PreparedSPTS) appendTable(table sptsTable, slot int) {
	remaining := table.section
	first := true
	for len(remaining) != 0 {
		var packet Packet
		for i := range packet {
			packet[i] = 0xff
		}
		packet[0], packet[1], packet[2], packet[3] = 0x47, byte(table.pid>>8), byte(table.pid), 0x10
		pos := 4
		if first {
			packet[1] |= 0x40
			packet[4], pos, first = 0, 5, false
		}
		n := copy(packet[pos:], remaining)
		remaining = remaining[n:]
		p.proposal.stamp(&packet, slot, true)
		p.Packets = append(p.Packets, packet)
		p.Origins = append(p.Origins, -1)
	}
}

// Commit is called only after the owner actor's successful queue acceptance.
// The sealed copy prevents public slice/Consumed edits from committing a
// different publication, and self rejects copied or forged proposal objects.
func (b *SPTS) Commit(p *PreparedSPTS) error {
	if !b.valid() || p == nil || p.self != p || p.owner != b || p.used || p.generation != b.generation {
		return ErrSPTSPrepared
	}
	if p.count < 0 || p.count > p.budget || p.budget < 1 || p.budget > sptsMaxPackets ||
		len(p.Packets) != p.count || len(p.Origins) != p.count || cap(p.Packets) > sptsMaxPackets || cap(p.Origins) > sptsMaxPackets ||
		p.Consumed != p.consumed || p.consumed < 0 || p.consumed > sptsMaxInput {
		p.used = true
		return ErrSPTSPrepared
	}
	for i := 0; i < p.count; i++ {
		if p.Packets[i] != p.sealedPackets[i] || p.Origins[i] != p.sealedOrigins[i] {
			p.used = true
			return ErrSPTSPrepared
		}
	}
	b.state = p.proposal
	p.used = true
	b.generation = &sptsGeneration{}
	return nil
}

func (b *SPTS) Discard(p *PreparedSPTS) {
	if b.valid() && p != nil && p.self == p && p.owner == b {
		p.used = true
	}
}

func (b *SPTS) Replace(service Service, selection Selection) error {
	if !b.valid() {
		return ErrSPTSPrepared
	}
	config, err := sptsMakeConfig(service, selection, b.version)
	if err != nil {
		return err
	}
	// Catalog generation is independent of the output wire-version counter.
	// An SDT-name-only refresh is not a new service or PMT generation.
	transition := config.sourceVersion != b.config.sourceVersion || config.identity != b.config.identity ||
		config.tables[1].pid != b.config.tables[1].pid || !bytes.Equal(config.tables[1].section, b.config.tables[1].section)
	identical := len(config.slots) == len(b.config.slots)
	for pid := range config.slots {
		if _, ok := b.config.slots[pid]; !ok {
			identical = false
		}
	}
	for i := range config.tables {
		if config.tables[i].pid != b.config.tables[i].pid || !bytes.Equal(config.tables[i].section, b.config.tables[i].section) {
			identical = false
		}
	}
	if identical && !transition {
		// A catalog handoff still retires outstanding proposals, but does not
		// change effective wire versions, counters, or table deadlines.
		b.generation = &sptsGeneration{}
		return nil
	}
	version := (b.version + 1) & 31
	for i := range config.tables {
		raw := config.tables[i].section
		raw[5] = 0xc1 | version<<1
		sptsSetCRC(raw)
	}
	state := b.state
	state.counters = [sptsMaxSlots]sptsCounter{}
	state.recovery = [sptsMaxSlots]bool{}
	for pid, slot := range config.slots {
		if old, ok := b.config.slots[pid]; ok && (old >= 3) == (slot >= 3) {
			state.counters[slot] = b.state.counters[old]
			state.recovery[slot] = b.state.recovery[old] || (transition && slot >= 3)
		}
	}
	state.forceTables = true
	b.config, b.state, b.version = config, state, version
	b.generation = &sptsGeneration{}
	return nil
}

func (b *SPTS) Discontinuity() {
	if !b.valid() {
		return
	}
	for _, slot := range b.config.slots {
		if slot >= 3 {
			b.state.recovery[slot] = true
		}
	}
	b.state.forceTables = true
	b.generation = &sptsGeneration{}
}

func sptsMakeConfig(service Service, selection Selection, version byte) (sptsConfig, error) {
	var config sptsConfig
	if service.SID == 0 || service.Version > 31 || !usablePID(service.PMTPID) ||
		selection.PCRPID != service.PCRPID || (service.PCRPID != 8191 && !usablePID(service.PCRPID)) ||
		service.PCRPID == service.PMTPID || len(selection.PIDs) == 0 || len(service.ElementaryStreams) == 0 {
		return config, ErrInvalidPSI
	}
	if len(selection.PIDs) > maxOutputPIDs || len(service.ElementaryStreams) > maxOutputPIDs {
		return config, ErrCapacity
	}
	if len(service.ProviderName) > 255 || len(service.Name) > 255 || 3+len(service.ProviderName)+len(service.Name) > 255 {
		return config, ErrCapacity
	}
	selected := make(map[uint16]bool, maxOutputPIDs)
	for _, pid := range selection.PIDs {
		if !usablePID(pid) || pid == service.PMTPID || selected[pid] {
			return config, ErrInvalidPSI
		}
		selected[pid] = true
	}
	program, ca, _, _, wireBytes, err := sptsDescriptors(service.ProgramDescriptors, CAProgram, 0)
	if err != nil {
		return config, err
	}
	inputPMTBytes := 16 + wireBytes
	sourcePIDs := make(map[uint16]bool, maxOutputPIDs)
	if service.PCRPID != 8191 {
		sourcePIDs[service.PCRPID] = true
	}
	esSeen := make(map[uint16]bool, maxOutputPIDs)
	var streams []ElementaryStream
	for _, stream := range service.ElementaryStreams {
		if !usablePID(stream.PID) || stream.PID == service.PMTPID || esSeen[stream.PID] || !supportedStream(stream.StreamType) {
			return config, ErrInvalidPSI
		}
		esSeen[stream.PID], sourcePIDs[stream.PID] = true, true
		if len(sourcePIDs) > maxOutputPIDs {
			return config, ErrCapacity
		}
		descriptors, routes, languages, subtitles, n, err := sptsDescriptors(stream.Descriptors, CAElementary, stream.PID)
		if err != nil {
			return config, err
		}
		inputPMTBytes += 5 + n
		if inputPMTBytes > maxWireSection {
			return config, ErrCapacity
		}
		if !slices.Equal(languages, stream.Languages) || !slices.Equal(subtitles, stream.Subtitles) {
			return config, ErrInvalidPSI
		}
		ca = append(ca, routes...)
		if selected[stream.PID] {
			streams = append(streams, ElementaryStream{PID: stream.PID, StreamType: stream.StreamType, Descriptors: descriptors})
		}
	}
	for pid := range selected {
		if !esSeen[pid] {
			return config, ErrInvalidPSI
		}
	}
	if len(ca) != len(service.CADescriptors) {
		return config, ErrInvalidPSI
	}
	caRoutes := make(map[[2]uint16]bool)
	for i, route := range ca {
		given := service.CADescriptors[i]
		if sourcePIDs[route.ECMPID] || route.ECMPID == service.PMTPID ||
			given.CAID != route.CAID || given.ECMPID != route.ECMPID || given.Scope != route.Scope || given.ESPID != route.ESPID ||
			!bytes.Equal(given.PrivateData, route.PrivateData) {
			return config, ErrInvalidPSI
		}
		caRoutes[[2]uint16{route.CAID, route.ECMPID}] = true
		if len(caRoutes) > maxCARoutes {
			return config, ErrCapacity
		}
	}
	config.slots = make(map[uint16]int, sptsMaxSlots)
	config.slots[0], config.slots[service.PMTPID], config.slots[17] = 0, 1, 2
	if service.PCRPID != 8191 {
		selected[service.PCRPID] = true
	}
	if len(selected) > maxOutputPIDs {
		return config, ErrCapacity
	}
	var pids []uint16
	for pid := range selected {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	for i, pid := range pids {
		config.slots[pid] = i + 3
	}
	patBody := sptsWord(nil, service.SID)
	patBody = sptsWord(patBody, 0xe000|service.PMTPID)
	pat, err := sptsSection(0, service.TSID, version, patBody)
	if err != nil {
		return sptsConfig{}, err
	}
	programBytes := sptsEncodeDescriptors(program)
	pmtBody := sptsWord(nil, 0xe000|service.PCRPID)
	pmtBody = sptsWord(pmtBody, 0xf000|uint16(len(programBytes)))
	pmtBody = append(pmtBody, programBytes...)
	for _, stream := range streams {
		descriptors := sptsEncodeDescriptors(stream.Descriptors)
		pmtBody = append(pmtBody, stream.StreamType)
		pmtBody = sptsWord(pmtBody, 0xe000|stream.PID)
		pmtBody = sptsWord(pmtBody, 0xf000|uint16(len(descriptors)))
		pmtBody = append(pmtBody, descriptors...)
	}
	pmt, err := sptsSection(2, service.SID, version, pmtBody)
	if err != nil {
		return sptsConfig{}, err
	}
	metadata := []byte{1, byte(len(service.ProviderName))}
	metadata = append(metadata, service.ProviderName...)
	metadata = append(metadata, byte(len(service.Name)))
	metadata = append(metadata, service.Name...)
	serviceDescriptor := append([]byte{0x48, byte(len(metadata))}, metadata...)
	sdtBody := sptsWord(nil, service.ONID)
	sdtBody = append(sdtBody, 0xff)
	sdtBody = sptsWord(sdtBody, service.SID)
	sdtBody = append(sdtBody, 0xfc)
	sdtBody = sptsWord(sdtBody, 0x8000|uint16(len(serviceDescriptor)))
	sdtBody = append(sdtBody, serviceDescriptor...)
	sdt, err := sptsSection(0x42, service.TSID, version, sdtBody)
	if err != nil {
		return sptsConfig{}, err
	}
	config.tables = [3]sptsTable{{pid: 0, section: pat}, {pid: service.PMTPID, section: pmt}, {pid: 17, section: sdt}}
	config.sourceVersion = service.Version
	config.identity = [3]uint16{service.ONID, service.TSID, service.SID}
	return config, nil
}

// Validate the complete source layout before dropping CA; normalized language
// and subtitle fields must agree with their preserved wire descriptors.
func sptsDescriptors(descriptors []Descriptor, scope CAScope, pid uint16) ([]Descriptor, []CADescriptor, []string, []Subtitle, int, error) {
	wire := make([]byte, 0)
	for _, descriptor := range descriptors {
		if len(descriptor.Data) > 255 || len(wire)+2+len(descriptor.Data) > maxWireSection-16 {
			return nil, nil, nil, nil, 0, ErrCapacity
		}
		wire = append(wire, descriptor.Tag, byte(len(descriptor.Data)))
		wire = append(wire, descriptor.Data...)
	}
	parsed, ca, languages, subtitles, err := parseDescriptors(wire, scope, pid)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	clean := make([]Descriptor, 0, len(parsed))
	for _, descriptor := range parsed {
		if descriptor.Tag != 9 {
			clean = append(clean, descriptor)
		}
	}
	return clean, ca, languages, subtitles, len(wire), nil
}

func sptsEncodeDescriptors(descriptors []Descriptor) []byte {
	var raw []byte
	for _, descriptor := range descriptors {
		raw = append(raw, descriptor.Tag, byte(len(descriptor.Data)))
		raw = append(raw, descriptor.Data...)
	}
	return raw
}

func sptsWord(raw []byte, value uint16) []byte { return append(raw, byte(value>>8), byte(value)) }

func sptsSection(tableID byte, extension uint16, version byte, payload []byte) ([]byte, error) {
	if version > 31 || 12+len(payload) > maxWireSection {
		return nil, ErrCapacity
	}
	flags := uint16(0xb000)
	if tableID == 0x42 {
		flags = 0xf000
	}
	raw := sptsWord([]byte{tableID}, flags|uint16(9+len(payload)))
	raw = sptsWord(raw, extension)
	raw = append(raw, 0xc1|version<<1, 0, 0)
	raw = append(raw, payload...)
	raw = append(raw, 0, 0, 0, 0)
	sptsSetCRC(raw)
	return raw, nil
}

func sptsSetCRC(raw []byte) {
	n := len(raw) - 4
	crc := psiCRC(raw[:n])
	raw[n], raw[n+1], raw[n+2], raw[n+3] = byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc)
}
