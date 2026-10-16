// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/streamer"
)

const maxDVBOperations = 256

var (
	ErrDVBOperationNotFound = errors.New("DVB operation not found")
	ErrDVBOperationsFull    = errors.New("all DVB operation records are active")
)

type dvbOperationRecord struct {
	operation model.Operation
	scan      *model.DVBScanResult
	cancel    context.CancelFunc
}
type storeDVBOperations struct {
	mu      sync.Mutex
	records map[string]*dvbOperationRecord
	order   []string
	closing bool
}

func cloneDVBService(in model.Service) model.Service {
	in.AudioLanguages = append([]string(nil), in.AudioLanguages...)
	in.CAIDs = append([]int(nil), in.CAIDs...)
	return in
}
func cloneDVBScan(in model.DVBScanResult) model.DVBScanResult {
	in.Request.DVB = *cloneDVBStreamConfig(&in.Request.DVB)
	in.Signal = cloneDVBSignal(in.Signal)
	in.Services = append([]model.Service(nil), in.Services...)
	for i := range in.Services {
		in.Services[i] = cloneDVBService(in.Services[i])
	}
	if in.CompletedAt != nil {
		at := *in.CompletedAt
		in.CompletedAt = &at
	}
	return in
}
func cloneDVBOperation(in model.Operation) model.Operation {
	in.StreamResults = append([]model.BulkDVBStreamItemResult(nil), in.StreamResults...)
	if in.CompletedAt != nil {
		at := *in.CompletedAt
		in.CompletedAt = &at
	}
	return in
}
func (s *Store) Operation(id string) (model.Operation, error) {
	m := &s.dvbOperations
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.records[id]; r != nil {
		return cloneDVBOperation(r.operation), nil
	}
	return model.Operation{}, ErrDVBOperationNotFound
}
func (s *Store) DVBScan(id string) (model.DVBScanResult, error) {
	m := &s.dvbOperations
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.records[id]; r != nil && r.scan != nil {
		return cloneDVBScan(*r.scan), nil
	}
	return model.DVBScanResult{}, ErrDVBOperationNotFound
}

// Admission is the context boundary: a returned 202 outlives its HTTP request.
// The Store terminal barrier cancels and joins every admitted worker instead.
func (s *Store) newDVBOperation(request context.Context, kind, resource string, scan *model.DVBScanResult) (model.Operation, context.Context, error) {
	if request == nil {
		request = context.Background()
	}
	m := &s.dvbOperations
	var events dvbEventBatch
	m.mu.Lock()
	defer func() { m.mu.Unlock(); events.emit(s) }()
	if err := request.Err(); err != nil {
		return model.Operation{}, nil, err
	}
	if m.closing {
		return model.Operation{}, nil, ErrStoreClosed
	}
	if len(m.order) >= maxDVBOperations {
		evict := -1
		for i, id := range m.order {
			if m.records[id].operation.CompletedAt != nil {
				evict = i
				break
			}
		}
		if evict < 0 {
			return model.Operation{}, nil, ErrDVBOperationsFull
		}
		delete(m.records, m.order[evict])
		m.order = append(m.order[:evict], m.order[evict+1:]...)
	}
	if m.records == nil {
		m.records = make(map[string]*dvbOperationRecord)
	}
	id := newID()
	for m.records[id] != nil {
		id = newID()
	}
	now := s.now().UTC()
	op := model.Operation{ID: id, Kind: kind, ResourceID: resource, Status: "queued", CreatedAt: now, UpdatedAt: now}
	ctx, cancel := context.WithCancel(context.Background())
	record := &dvbOperationRecord{operation: op, cancel: cancel}
	if scan != nil {
		copy := cloneDVBScan(*scan)
		copy.ID = id
		copy.OperationID = id
		copy.Status = "queued"
		copy.StartedAt = now
		record.scan = &copy
		op.Result = id
		record.operation = op
	}
	m.records[id] = record
	m.order = append(m.order, id)
	events.add(s, dvbOperationEventKind(op), op.ID, cloneDVBOperation(op))
	return cloneDVBOperation(op), ctx, nil
}
func dvbOperationEventKind(op model.Operation) string {
	if op.Kind == "dvb.scan" {
		return "dvb.scan.operation.changed"
	}
	return "dvb.card.operation.changed"
}

func (s *Store) changeDVBOperation(id string, mutate func(*dvbOperationRecord)) {
	if event, ok := s.mutateDVBOperation(id, mutate); ok {
		s.emitQueuedEvent(event)
	}
}
func (s *Store) mutateDVBOperation(id string, mutate func(*dvbOperationRecord)) (model.ResourceEvent, bool) {
	m := &s.dvbOperations
	m.mu.Lock()
	r := m.records[id]
	if r == nil {
		m.mu.Unlock()
		return model.ResourceEvent{}, false
	}
	mutate(r)
	r.operation.UpdatedAt = s.now().UTC()
	if r.scan != nil {
		r.scan.Status = r.operation.Status
		r.scan.Error = r.operation.Error
	}
	event, ok := s.queueEvent(dvbOperationEventKind(r.operation), id, cloneDVBOperation(r.operation))
	m.mu.Unlock()
	return event, ok
}
func (s *Store) finishDVBOperation(id string, err error) {
	s.changeDVBOperation(id, s.finishDVBOperationMutation(err))
}
func (s *Store) finishDVBOperationMutation(err error) func(*dvbOperationRecord) {
	return func(r *dvbOperationRecord) {
		succeeded, failed := 0, 0
		for _, item := range r.operation.StreamResults {
			if item.OK {
				succeeded++
			} else {
				failed++
			}
		}
		r.operation.Status = "succeeded"
		if failed > 0 || err != nil {
			r.operation.Status = "failed"
			if succeeded > 0 || r.scan != nil && len(r.scan.Services) > 0 {
				r.operation.Status = "partial"
			}
		}
		if err != nil {
			r.operation.Error = err.Error()
		}
		r.operation.Progress = 100
		at := s.now().UTC()
		r.operation.CompletedAt = &at
		if r.scan != nil {
			r.scan.CompletedAt = &at
		}
		r.cancel()
	}
}
func (s *Store) cancelDVBOperations() {
	m := &s.dvbOperations
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closing = true
	for _, r := range m.records {
		r.cancel()
	}
}
func operationRequestError(ctx context.Context) error {
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

func (s *Store) dvbCardOperationStatus(id string) string {
	m := &s.dvbOperations
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.records {
		if r.operation.ResourceID == id && r.operation.CompletedAt == nil && r.operation.Kind == "dvb.card.restart" {
			return "restarting"
		}
	}
	return ""
}

func (s *Store) checkOperationInventory(lease *dvbCardOperationLease) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, card := range cardSelectionInventory(s.dvbDetected, s.config.DVBCards) {
		if card.ID != lease.card.ID {
			continue
		}
		if card.Status == "busy_external" {
			return ErrCardExternallyBusy
		}
		if !card.Present {
			return ErrDVBCardNotFound
		}
		if cardSelectionFingerprint(card) != cardSelectionFingerprint(lease.desired) {
			return ErrDVBSchedulerSuperseded
		}
		return nil
	}
	return ErrDVBCardNotFound
}

func (s *Store) RestartDVBCard(ctx context.Context, cardID string) (model.Operation, error) {
	if err := operationRequestError(ctx); err != nil {
		return model.Operation{}, err
	}
	end, err := s.admitRuntime()
	if err != nil {
		return model.Operation{}, err
	}
	if s.scheduler == nil {
		end()
		return model.Operation{}, errors.New(dvbStructuredSchedulerUnavailable)
	}
	lease, err := s.scheduler.reserveCardOperation(strings.TrimSpace(cardID), nil)
	if err != nil {
		end()
		return model.Operation{}, err
	}
	if err = s.checkOperationInventory(lease); err != nil {
		s.scheduler.releaseCardOperation(lease)
		end()
		return model.Operation{}, err
	}
	op, work, err := s.newDVBOperation(ctx, "dvb.card.restart", lease.card.ID, nil)
	if err != nil {
		s.scheduler.releaseCardOperation(lease)
		end()
		return model.Operation{}, err
	}
	go func() {
		defer end()
		s.changeDVBOperation(op.ID, func(r *dvbOperationRecord) { r.operation.Status = "running" })
		err := s.runCardRestart(work, op.ID, lease)
		s.scheduler.releaseCardOperation(lease)
		s.finishDVBOperation(op.ID, err)
	}()
	return op, nil
}

// Only a successful, validated inventory observation can authorize relocation
// after losing the target. Detector failure or scheduler invalidation is global.
type dvbOperationTargetMissing struct {
	alternatives map[string]tuningKey
}

func (*dvbOperationTargetMissing) Error() string { return ErrDVBCardNotFound.Error() }
func (*dvbOperationTargetMissing) Unwrap() error { return ErrDVBCardNotFound }

func (s *Store) operationAlternativeSelections(cards []model.DVBCard) map[string]tuningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	allowed := make(map[string]tuningKey)
	for _, card := range cardSelectionInventory(cards, s.config.DVBCards) {
		if card.Present && card.Config.Enabled && card.Status == "available" && card.LastError == "" {
			allowed[card.ID] = cardSelectionFingerprint(card)
		}
	}
	return allowed
}

// Discovery is read-only. Changed identity/selection inputs require a separate
// inventory refresh rather than silently opening a different physical device.
func (s *Store) verifyOperationCard(ctx context.Context, lease *dvbCardOperationLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	inventoryErr := s.checkOperationInventory(lease)
	if inventoryErr != nil && !errors.Is(inventoryErr, ErrDVBCardNotFound) {
		return inventoryErr
	}
	if err := s.scheduler.cardOperationCurrent(lease); err != nil {
		return err
	}
	cards, err := s.adapterDetector.DetectDVB(ctx)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cards, err = validateAndCloneDetectedDVBCards(ctx, cards)
	if err != nil {
		return err
	}
	for _, card := range cards {
		if card.ID != lease.card.ID {
			continue
		}
		if card.Status == "busy_external" {
			return ErrCardExternallyBusy
		}
		physical, present := canonicalPhysicalFrontendKey(card)
		if !present || physical != lease.physical {
			return ErrDVBSchedulerSuperseded
		}
		card.Config = lease.desired.Config
		applyDVBCardStatus(&card, false)
		if cardSelectionFingerprint(card) != cardSelectionFingerprint(lease.desired) {
			return ErrDVBSchedulerSuperseded
		}
		if inventoryErr != nil {
			return inventoryErr
		}
		return s.scheduler.cardOperationCurrent(lease)
	}
	return &dvbOperationTargetMissing{alternatives: s.operationAlternativeSelections(cards)}
}

func (s *Store) runCardRestart(ctx context.Context, id string, lease *dvbCardOperationLease) error {
	ids := lease.ids()
	release := s.lockStructuredIDs(ids)
	defer func() {
		s.scheduler.retireCardRecovery(lease)
		release()
	}()
	if err := s.verifyOperationCard(ctx, lease); err != nil {
		return s.failRestartItems(id, ids, err)
	}
	type recovery struct {
		stream   model.Stream
		previous structuredRuntime
		result   dvbOnDemandResult
		err      error
	}
	rows := make([]recovery, 0, len(ids))
	for _, streamID := range ids {
		s.mu.RLock()
		st, exists := s.currentStructuredLocked(streamID)
		previous := s.structured.owners[streamID]
		s.mu.RUnlock()
		if !exists || !s.scheduler.restartAttachmentCurrent(lease, streamID) {
			rows = append(rows, recovery{stream: model.Stream{ID: streamID}, err: ErrDVBSchedulerSuperseded})
			continue
		}
		row := recovery{stream: st, previous: previous, result: absentOnDemand()}
		if st.OnDemand {
			row.result, row.err = s.scheduler.SuspendOnDemand(streamID)
		} else {
			row.err = s.scheduler.Stop(streamID)
		}
		s.installStructuredResult(streamID, st, true, previous, row.result, false, row.err)
		rows = append(rows, row)
	}
	// Restore fixed services first; Auto placement may reuse an unrelated healthy
	// transport but cannot preempt fixed recovery. No desired config is rewritten.
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].stream.DVB != nil && rows[i].stream.DVB.Adapter.Mode == "fixed" && (rows[j].stream.DVB == nil || rows[j].stream.DVB.Adapter.Mode != "fixed")
	})
	verifyErr := s.verifyOperationCard(ctx, lease)
	if verifyErr == nil {
		verifyErr = s.scheduler.applyCardUnderLease(lease)
	}
	var errs []error
	for i, row := range rows {
		st := row.stream
		err := row.err
		if st.DVB != nil && err == nil {
			err = errors.Join(ctx.Err(), verifyErr)
			var missing *dvbOperationTargetMissing
			if st.DVB.Adapter.Mode == "auto" && errors.As(verifyErr, &missing) {
				err = ctx.Err()
				if err == nil {
					err = s.scheduler.allowCardRelocation(lease, st.ID, missing.alternatives)
				}
			} else if err == nil {
				s.scheduler.allowCardRecovery(lease, st.ID)
			}
			if err == nil {
				if st.OnDemand && row.result.Placeholder != nil {
					row.result, err = s.scheduler.StartOnDemand(st, *row.result.Placeholder)
				} else if !st.OnDemand {
					err = s.scheduler.Start(st)
				} else {
					err = errors.New("restart lost on-demand placeholder")
				}
			}
			s.installStructuredResult(st.ID, st, true, row.previous, row.result, err == nil, err)
		}
		errs = append(errs, err)
		item := model.BulkDVBStreamItemResult{ID: st.ID, OK: err == nil}
		if err != nil {
			item.Error = err.Error()
		}
		s.changeDVBOperation(id, func(r *dvbOperationRecord) {
			r.operation.StreamResults = append(r.operation.StreamResults, item)
			r.operation.Progress = (i + 1) * 100 / max(1, len(rows))
		})
	}
	return errors.Join(append(errs, verifyErr, ctx.Err())...)
}
func (s *Store) failRestartItems(id string, ids []string, err error) error {
	s.changeDVBOperation(id, func(r *dvbOperationRecord) {
		for _, id := range ids {
			r.operation.StreamResults = append(r.operation.StreamResults, model.BulkDVBStreamItemResult{ID: id, Error: err.Error()})
		}
	})
	return err
}

func (s *Store) StartDVBScan(ctx context.Context, in model.DVBScanRequest) (model.Operation, error) {
	if err := operationRequestError(ctx); err != nil {
		return model.Operation{}, err
	}
	end, err := s.admitRuntime()
	if err != nil {
		return model.Operation{}, err
	}
	fail := func(err error) (model.Operation, error) { end(); return model.Operation{}, err }
	if s.scheduler == nil {
		return fail(errors.New(dvbStructuredSchedulerUnavailable))
	}
	in.DVB = *cloneDVBStreamConfig(&in.DVB)
	in.DVB.Normalize()
	// Scans select a transport, not a service. Validate the transport through the
	// same Linux config boundary using a temporary service selector only.
	tune := *cloneDVBStreamConfig(&in.DVB)
	if tune.ServiceID == 0 {
		tune.ServiceID = 1
	}
	if err := dvb.ValidateStreamForLinux(tune); err != nil {
		return fail(err)
	}
	stream := model.Stream{DVB: &tune}
	lease, err := s.scheduler.reserveCardOperation("", &stream)
	if err != nil {
		return fail(err)
	}
	if err = s.checkOperationInventory(lease); err != nil {
		s.scheduler.releaseCardOperation(lease)
		return fail(err)
	}
	scan := model.DVBScanResult{Request: in, CardID: lease.card.ID, Address: lease.card.Address}
	op, work, err := s.newDVBOperation(ctx, "dvb.scan", lease.card.ID, &scan)
	if err != nil {
		s.scheduler.releaseCardOperation(lease)
		return fail(err)
	}
	go func() {
		defer end()
		s.changeDVBOperation(op.ID, func(r *dvbOperationRecord) { r.operation.Status = "running" })
		err := s.runDVBScan(work, op.ID, lease, stream)
		s.finishDVBScan(work, op.ID, lease, err)
	}()
	return op, nil
}

func (s *Store) runDVBScan(ctx context.Context, id string, lease *dvbCardOperationLease, stream model.Stream) (result error) {
	if err := s.verifyOperationCard(ctx, lease); err != nil {
		return err
	}
	tune, err := resolveTune(stream, lease.card)
	if err != nil {
		return err
	}
	frontend, err := s.scheduler.opener.OpenSession(tune.config)
	if !nilDVBSession(frontend) {
		defer func() { e := frontend.Close(); s.recordRuntimeCleanup(e); result = errors.Join(result, e) }()
	}
	if err != nil {
		return err
	}
	if nilDVBSession(frontend) {
		return errors.New("scan opener returned nil session")
	}
	if err := errors.Join(ctx.Err(), s.scheduler.cardOperationCurrent(lease)); err != nil {
		return err
	}
	timeout := lease.card.Config.Advanced.TimeoutSec
	if timeout <= 0 || timeout > 120 {
		timeout = 120
	}
	lockCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	for {
		if err := lockCtx.Err(); err != nil {
			return err
		}
		if err := s.scheduler.cardOperationCurrent(lease); err != nil {
			return err
		}
		signal, err := frontend.Poll()
		if err != nil {
			return err
		}
		if err := s.changeCurrentDVBScan(ctx, id, lease, func(r *dvbOperationRecord) {
			r.scan.Signal = &model.DVBSignal{Locked: signal.Locked, SignalPercent: signal.SignalPercent, SNRPercent: signal.SNRPercent, BER: signal.BER, UncorrectedBlocks: signal.UncorrectedBlocks, StatusBits: signal.StatusBits}
		}); err != nil {
			return err
		}
		if signal.Locked {
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-lockCtx.Done():
			timer.Stop()
			return lockCtx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.scheduler.cardOperationCurrent(lease); err != nil {
		return err
	}
	services, err := frontend.ScanServices()
	if e := errors.Join(ctx.Err(), s.scheduler.cardOperationCurrent(lease)); e != nil {
		return errors.Join(err, e)
	}
	publicationErr := s.changeCurrentDVBScan(ctx, id, lease, func(r *dvbOperationRecord) {
		r.scan.Services = make([]model.Service, 0, len(services))
		for _, v := range services {
			r.scan.Services = append(r.scan.Services, cloneDVBService(model.Service{SID: v.SID, Name: v.Name, VideoPID: v.VideoPID, AudioPID: v.AudioPID, PCR_PID: v.PCR_PID, Type: v.Type, Provider: v.Provider, Scrambled: v.Scrambled, HasEPG: v.HasEPG, AudioLanguages: v.AudioLanguages, CAIDs: v.CAIDs}))
		}
	})
	return errors.Join(err, publicationErr)
}

// Templates use literal {sid}, {name}, {provider}, and one-based {index} placeholders.
// The index follows selected request order, including failed entries. Successful
// item IDs are new stream IDs; failed items use the decimal selected service ID.
func (s *Store) ImportDVBScan(id string, in model.DVBScanImportRequest) (model.BulkDVBStreamResult, error) {
	end, err := s.admitRuntime()
	if err != nil {
		return model.BulkDVBStreamResult{}, err
	}
	defer end()
	scan, err := s.DVBScan(id)
	if err != nil {
		return model.BulkDVBStreamResult{}, err
	}
	if scan.Status != "succeeded" && scan.Status != "partial" {
		return model.BulkDVBStreamResult{}, errors.New("scan is not ready to import")
	}
	if len(in.ServiceIDs) == 0 {
		return model.BulkDVBStreamResult{}, errors.New("service_ids is required")
	}
	if strings.TrimSpace(in.OutputTemplate) == "" {
		return model.BulkDVBStreamResult{}, errors.New("output_template is required")
	}
	services := make(map[int]model.Service)
	for _, v := range scan.Services {
		services[v.SID] = v
	}
	out := model.BulkDVBStreamResult{Results: make([]model.BulkDVBStreamItemResult, 0, len(in.ServiceIDs))}
	for index, sid := range in.ServiceIDs {
		item := model.BulkDVBStreamItemResult{ID: strconv.Itoa(sid)}
		service, ok := services[sid]
		var err error
		if !ok {
			err = fmt.Errorf("service %d not found in scan", sid)
		} else {
			expand := func(value string) string {
				return strings.NewReplacer("{sid}", strconv.Itoa(sid), "{name}", service.Name, "{provider}", service.Provider, "{index}", strconv.Itoa(index+1)).Replace(value)
			}
			name := in.NameTemplate
			if name == "" {
				name = "{name}"
			}
			name = expand(name)
			if strings.TrimSpace(name) == "" {
				name = fmt.Sprintf("Service %d", sid)
			}
			tune := cloneDVBStreamConfig(&scan.Request.DVB)
			tune.Adapter = in.Adapter
			tune.ServiceID = sid
			tune.VideoPID = service.VideoPID
			tune.PCRPID = service.PCR_PID
			tune.AudioPIDs = nil
			if service.AudioPID != 0 {
				tune.AudioPIDs = []int{service.AudioPID}
			}
			metadata := cloneDVBService(service)
			tune.Service = &metadata
			st := model.Stream{Name: name, OutputURL: expand(in.OutputTemplate), Protocol: in.Protocol, Enabled: in.Enabled, GroupID: in.GroupID, SoftcamID: in.SoftcamID, XMLTVChannelID: expand(in.XMLTVChannelIDTemplate), DVB: tune, Scrambled: service.Scrambled, CAIDs: append([]int(nil), service.CAIDs...)}
			if _, err = streamer.ValidateOutputPath(st.OutputURL); err == nil {
				var created model.Stream
				created, err = s.AddDVBStream(st)
				if err == nil {
					item.ID = created.ID
				}
			}
		}
		item.OK = err == nil
		if err != nil {
			item.Error = err.Error()
			out.Failed++
		} else {
			out.Succeeded++
		}
		out.Results = append(out.Results, item)
	}
	return out, nil
}

// Only record mutation is serialized with card desired publication. Backend
// calls and event observers never hold this gate. The final check includes the
// terminal frontend Close, so a blocked close cannot later report stale success.
func (s *Store) changeCurrentDVBScan(ctx context.Context, id string, lease *dvbCardOperationLease, mutate func(*dvbOperationRecord)) error {
	s.cardPublicationMu.Lock()
	err := errors.Join(ctx.Err(), s.scheduler.cardOperationCurrent(lease))
	var event model.ResourceEvent
	var ok bool
	if err == nil {
		event, ok = s.mutateDVBOperation(id, mutate)
	}
	s.cardPublicationMu.Unlock()
	if ok {
		s.emitQueuedEvent(event)
	}
	return err
}
func (s *Store) finishDVBScan(ctx context.Context, id string, lease *dvbCardOperationLease, cause error) {
	s.cardPublicationMu.Lock()
	current := errors.Join(ctx.Err(), s.scheduler.cardOperationCurrent(lease))
	cause = errors.Join(cause, current)
	event, ok := s.mutateDVBOperation(id, func(r *dvbOperationRecord) {
		if current != nil {
			r.scan.Services = nil
			r.scan.Signal = nil
		}
		s.finishDVBOperationMutation(cause)(r)
	})
	s.cardPublicationMu.Unlock()
	s.scheduler.releaseCardOperation(lease)
	if ok {
		s.emitQueuedEvent(event)
	}
}
