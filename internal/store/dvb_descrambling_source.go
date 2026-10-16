// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
	"astrax/internal/softcam"
)

// The production factory returns only the concrete registry's guarded sources.
// This private seam lets scheduler fixtures exercise ownership without peers.
type descramblingService interface {
	Subscribe(string, mpegts.Selection) (model.PacketSource, error)
	Push(mpegts.Packet, time.Time) error
	Revoke()
	Close() error
}
type descramblingAcquire func(softcam.DescramblingServiceKey, mpegts.Service, model.DVBDescramblingConfig) (descramblingService, error)
type descramblingSinkResources interface{ DescramblingPacketBudget() *packetbudget.Budget }

const descramblingTapBytes = 64 * 1024

type descramblingTap struct {
	sd          *sharedDemux
	key         softcam.DescramblingServiceKey
	service     descramblingService
	stamp       mpegts.CatalogStamp
	route       mpegts.ResolvedRoute
	pmtPID      uint16
	pids        []uint16
	refs        int // guarded by sd.transformMu
	active      atomic.Bool
	reservation *packetbudget.Reservation
}
type dvbDescramblingSource struct {
	base            *streamPacketSource
	output          model.PacketSource
	tap             *descramblingTap
	inputGeneration uint64
	once            sync.Once
	closing         atomic.Bool
	closeErr        error
}

func (s *dvbScheduler) descramblingAdmissionError(st model.Stream) error {
	if !descramblingEnabled(st) {
		return nil
	}
	if !s.descramblingHookup || s.descrambling == nil || s.acquireDescrambling == nil || s.packetBudget == nil {
		return descramblingRuntimeGate(st)
	}
	sink, ok := s.sink.(descramblingSinkResources)
	if !ok || sink.DescramblingPacketBudget() != s.packetBudget {
		return dvbPolicyError("dvb_descrambling", "sink_unavailable")
	}
	switch strings.ToLower(strings.TrimSpace(st.Protocol)) {
	case "mpegts", "http", "udp", "hls":
	default:
		return dvbPolicyError("protocol", "unsupported_descrambling_output")
	}
	return nil
}

func (s *dvbScheduler) revokeStaleDescramblingProfile(profile string) {
	end, err := s.admit()
	if err != nil {
		return
	}
	defer end()
	s.mu.Lock()
	registry := s.descrambling
	s.mu.Unlock()
	if registry != nil {
		registry.RevokeStaleProfile(profile)
	}
}

func (s *dvbScheduler) descramblingSourceRetired(id string) (bool, sinkRegistrationToken) {
	s.mu.Lock()
	a := s.attachments[id]
	if a == nil {
		s.mu.Unlock()
		return true, sinkRegistrationToken{}
	}
	source, ok := a.outputSource.(*dvbDescramblingSource)
	token := a.sinkToken
	s.mu.Unlock()
	if !ok {
		return false, token
	}
	if source.closing.Load() || !source.tap.active.Load() {
		return true, token
	}
	if service, ok := source.tap.service.(interface{ Revoked() bool }); ok {
		return service.Revoked(), token
	}
	return false, token
}
func (s *dvbScheduler) prepareStream(st model.Stream) (model.Stream, error) {
	if err := s.descramblingAdmissionError(st); err != nil {
		return st, err
	}
	return prepareDVBStreamChecked(st, s.descramblingHookup)
}

func (s *dvbScheduler) newDescramblingSource(session *tuningSession, base *streamPacketSource, st model.Stream) (model.PacketSource, error) {
	r := session.runtime
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	var svc mpegts.Service
	var stamp mpegts.CatalogStamp
	for {
		var ok bool
		svc, stamp, ok = r.catalog.Snapshot(uint16(st.DVB.ServiceID), time.Now())
		if ok {
			break
		}
		select {
		case <-s.lifecycle.stopping:
			return nil, ErrDVBSchedulerClosed
		case <-r.ctx.Done():
			return nil, ErrDVBSchedulerSuperseded
		case <-r.demux.done:
			return nil, io.EOF
		case <-deadline.C:
			return nil, dvbPolicyError("dvb_descrambling", "waiting_psi")
		case <-ticker.C:
		}
	}
	route, err := mpegts.ResolveRoute(svc, *st.DVBDescrambling)
	if err != nil {
		return nil, err
	}
	key := softcam.DescramblingServiceKey{InputID: session.id, InputGeneration: r.inputGeneration, ONID: svc.ONID, TSID: svc.TSID, ServiceID: svc.SID, ProfileID: st.SoftcamID}
	service, err := s.acquireDescrambling(key, svc, *st.DVBDescrambling)
	if err != nil {
		return nil, err
	}
	if service == nil {
		return nil, dvbPolicyError("dvb_descrambling", "service_unavailable")
	}
	tap, err := r.demux.joinDescrambling(key, service, svc, stamp, route)
	if err != nil {
		return nil, errors.Join(err, r.demux.retireUnattachedDescrambling(service))
	}
	pids, err := servicePIDs(st)
	if err != nil {
		_ = tap.release()
		return nil, err
	}
	selection := mpegts.Selection{PCRPID: uint16(st.DVB.PCRPID)}
	for _, pid := range pids {
		selection.PIDs = append(selection.PIDs, uint16(pid))
	}
	output, err := service.Subscribe(base.id, selection)
	if err != nil || nilPacketSource(output) {
		if err == nil {
			err = io.EOF
		}
		if !nilPacketSource(output) {
			err = errors.Join(err, output.Close())
		}
		return nil, errors.Join(err, tap.release())
	}
	source := &dvbDescramblingSource{base: base, output: output, tap: tap, inputGeneration: r.inputGeneration}
	if !tap.current() {
		return nil, errors.Join(io.EOF, source.Close())
	}
	return source, nil
}

func (sd *sharedDemux) joinDescrambling(key softcam.DescramblingServiceKey, service descramblingService, svc mpegts.Service, stamp mpegts.CatalogStamp, route mpegts.ResolvedRoute) (*descramblingTap, error) {
	sd.transformMu.Lock()
	defer sd.transformMu.Unlock()
	sd.mu.Lock()
	closed := sd.closed
	sd.mu.Unlock()
	if closed {
		return nil, io.EOF
	}
	if old := sd.transforms[key]; old != nil {
		if old.route != route {
			return nil, dvbPolicyError("dvb_descrambling", "ca_policy_conflict")
		}
		if old.service == service && old.active.Load() && sd.catalog.Current(old.stamp, time.Now()) {
			old.refs++
			return old, nil
		}
		old.active.Store(false)
		old.service.Revoke()
	}
	if sd.transformCount.Load() >= 64 {
		return nil, mpegts.ErrCapacity
	}
	pids := []uint16{route.ECMPID}
	seen := map[uint16]bool{route.ECMPID: true}
	for _, es := range svc.ElementaryStreams {
		if !seen[es.PID] {
			seen[es.PID] = true
			pids = append(pids, es.PID)
		}
	}
	if svc.PCRPID != 8191 && !seen[svc.PCRPID] {
		pids = append(pids, svc.PCRPID)
	}
	hold, err := sd.dependencies.packets.Reserve(descramblingTapBytes)
	if err != nil {
		return nil, err
	}
	sd.mu.Lock()
	err = sd.changeMembersLocked(len(pids))
	sd.mu.Unlock()
	if err != nil {
		hold.Release()
		return nil, err
	}
	t := &descramblingTap{sd: sd, key: key, service: service, stamp: stamp, route: route, pmtPID: svc.PMTPID, pids: pids, refs: 1, reservation: hold}
	t.active.Store(true)
	if sd.transforms == nil {
		sd.transforms = make(map[softcam.DescramblingServiceKey]*descramblingTap)
		sd.transformIndex = make(map[uint16][]*descramblingTap)
		sd.transformPMTs = make(map[uint16]int)
	}
	sd.transforms[key] = t
	sd.transformPMTs[t.pmtPID]++
	for _, pid := range pids {
		sd.transformIndex[pid] = append(sd.transformIndex[pid], t)
	}
	sd.transformCount.Add(1)
	return t, nil
}
func (t *descramblingTap) current() bool {
	if !t.active.Load() {
		return false
	}
	if !t.sd.catalog.Current(t.stamp, time.Now()) {
		t.active.Store(false)
		t.service.Revoke()
		return false
	}
	return t.active.Load()
}
func (t *descramblingTap) release() error {
	sd := t.sd
	sd.transformMu.Lock()
	t.refs--
	last := t.refs == 0
	if last {
		t.active.Store(false)
		t.service.Revoke()
		if sd.transforms[t.key] == t {
			delete(sd.transforms, t.key)
		}
		sd.transformPMTs[t.pmtPID]--
		if sd.transformPMTs[t.pmtPID] == 0 {
			delete(sd.transformPMTs, t.pmtPID)
		}
		for _, pid := range t.pids {
			nodes := sd.transformIndex[pid]
			for i, n := range nodes {
				if n == t {
					nodes = append(nodes[:i], nodes[i+1:]...)
					break
				}
			}
			if len(nodes) == 0 {
				delete(sd.transformIndex, pid)
			} else {
				sd.transformIndex[pid] = nodes
			}
		}
		sd.mu.Lock()
		_ = sd.changeMembersLocked(-len(t.pids))
		sd.mu.Unlock()
		t.reservation.Release()
		sd.transformCount.Add(-1)
	}
	sd.transformMu.Unlock()
	if last {
		return t.service.Close()
	}
	return nil
}

// One indexed tap per service/profile, never one reader per output. Only copied
// packets and nonblocking pipeline ingress run on the shared native reader.
func (sd *sharedDemux) pushDescrambling(pid uint16, raw []byte) {
	if sd.transformCount.Load() == 0 {
		return
	}
	var list [64]*descramblingTap
	count := 0
	sd.transformMu.Lock()
	// PSI may revoke services not interested in that PSI packet's PID.
	if pid == 0 || pid == 17 || sd.transformPMTs[pid] > 0 {
		for _, t := range sd.transforms {
			_ = t.current()
		}
	}
	for _, t := range sd.transformIndex[pid] {
		if count == len(list) {
			break
		}
		list[count] = t
		count++
	}
	sd.transformMu.Unlock()
	if count == 0 {
		return
	}
	packet, err := mpegts.ParsePacket(raw)
	if err != nil {
		return
	}
	at := time.Now()
	for _, t := range list[:count] {
		if t.current() {
			_ = t.service.Push(packet, at)
		}
	}
}
func (sd *sharedDemux) revokeDescrambling() {
	if sd.transformCount.Load() == 0 {
		return
	}
	sd.transformMu.Lock()
	for _, t := range sd.transforms {
		t.active.Store(false)
		t.service.Revoke()
	}
	sd.transformMu.Unlock()
}
func (s *dvbScheduler) profileDescramblingChanged(profile string) {
	end, err := s.admit()
	if err != nil {
		return
	}
	defer end()
	s.mu.Lock()
	var inputs []*sharedDemux
	for _, session := range s.ownedSessions {
		if session.runtime.demux != nil {
			inputs = append(inputs, session.runtime.demux)
		}
	}
	registry := s.descrambling
	s.mu.Unlock()
	for _, sd := range inputs {
		sd.transformMu.Lock()
		for key, t := range sd.transforms {
			if key.ProfileID == profile {
				t.active.Store(false)
				t.service.Revoke()
			}
		}
		sd.transformMu.Unlock()
	}
	if registry != nil {
		registry.ProfileChanged(profile)
	}
}
func (s *dvbDescramblingSource) ReadPacket() ([]byte, error) {
	if s.closing.Load() {
		return nil, io.EOF
	}
	if !s.tap.current() {
		return nil, errors.Join(io.EOF, s.Close())
	}
	p, err := s.output.ReadPacket()
	if s.closing.Load() {
		clear(p)
		return nil, io.EOF
	}
	if !s.tap.current() {
		clear(p)
		return nil, errors.Join(io.EOF, s.Close())
	}
	if errors.Is(err, io.EOF) {
		clear(p)
		return nil, errors.Join(err, s.Close())
	}
	return p, err
}
func (s *dvbDescramblingSource) Close() error {
	s.closing.Store(true)
	s.once.Do(func() { s.closeErr = errors.Join(s.output.Close(), s.base.Close(), s.tap.release()) })
	return s.closeErr
}

func (sd *sharedDemux) retireUnattachedDescrambling(service descramblingService) error {
	sd.transformMu.Lock()
	for _, t := range sd.transforms {
		if t.service == service {
			sd.transformMu.Unlock()
			return nil
		}
	}
	service.Revoke()
	sd.transformMu.Unlock()
	return service.Close()
}
