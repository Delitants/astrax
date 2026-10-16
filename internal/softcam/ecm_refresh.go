// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"bytes"
	"container/list"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const refreshToken = int64(time.Second)

// Credits are integer nanoseconds of tokens. Exact refill boundaries do not
// depend on floating point, completions, or the wall clock of a control worker.
type ecmRefreshBucket struct {
	credits int64
	last    time.Time
	rate    int64
	burst   int64
}

func newECMRefreshBucket(rate, burst int64) ecmRefreshBucket {
	return ecmRefreshBucket{rate: rate, burst: burst, credits: burst * refreshToken}
}

func (b *ecmRefreshBucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		return
	}
	if !now.After(b.last) {
		return
	}
	elapsed := int64(now.Sub(b.last))
	maximum := b.burst * refreshToken
	// Saturate before multiplication, including after very large clock jumps.
	if elapsed >= (maximum+b.rate-1)/b.rate {
		b.credits = maximum
	} else {
		b.credits = min(maximum, b.credits+elapsed*b.rate)
	}
	b.last = now
}

type ecmRefreshProfile struct {
	count  int
	bucket ecmRefreshBucket
}

// The default owner outlives every registry/coordinator. Removing the final
// service cannot turn spent admission credits into a new constructor burst.
type ecmRefreshLimits struct {
	mu       sync.Mutex
	services int
	profiles map[string]*ecmRefreshProfile
	process  ecmRefreshBucket
	now      time.Time
}

func newECMRefreshLimits() *ecmRefreshLimits {
	return &ecmRefreshLimits{profiles: make(map[string]*ecmRefreshProfile), process: newECMRefreshBucket(512, 32)}
}

var processECMRefreshLimits = newECMRefreshLimits()

type ecmRefreshSection struct {
	data    []byte
	version uint64
	dirty   bool
	retry   bool
	mask    uint8
}

type ecmRefreshService struct {
	mu       sync.Mutex
	client   *ECMClient
	pipeline *DescramblingPipeline
	route    ECMRoute
	id       string
	profile  *ecmRefreshProfile
	position *list.Element
	sections [2]ecmRefreshSection
	owners   [2]int
	bucket   ecmRefreshBucket
	backoff  time.Time
	pending  map[*ecmRefreshJob]struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	removing atomic.Bool
	tasks    sync.WaitGroup
	stop     sync.Once
	done     chan struct{}
}

type ecmRefreshJob struct {
	service  *ecmRefreshService
	slot     int
	version  uint64
	section  []byte
	ctx      context.Context
	cancel   context.CancelFunc
	started  bool
	finished bool
}

// ECMRefreshCoordinator owns bounded ECM input and control tasks, but borrows
// clients and pipelines. It owns no completed result cache, sockets or ticker.
// mu protects membership, FIFO rotation and aggregate admission credits only.
// A service mutex fences Offer against installation; Tick never waits for it.
type ECMRefreshCoordinator struct {
	mu        sync.Mutex
	tickMu    sync.Mutex
	services  map[string]*ecmRefreshService
	limits    *ecmRefreshLimits
	rotation  *list.List
	now       time.Time
	closed    bool
	closeDone chan struct{}
	jobs      chan *ecmRefreshJob
	workers   sync.WaitGroup
	submit    func(context.Context, *ECMClient, []byte, ECMRoute) (*ECMResult, error)
}

func (*ECMRefreshCoordinator) String() string   { return "ECMRefreshCoordinator[redacted]" }
func (*ECMRefreshCoordinator) GoString() string { return "ECMRefreshCoordinator[redacted]" }
func (*ECMRefreshCoordinator) MarshalJSON() ([]byte, error) {
	return []byte(`"ECMRefreshCoordinator[redacted]"`), nil
}

func NewECMRefreshCoordinator(workers int) (*ECMRefreshCoordinator, error) {
	return newECMRefreshCoordinatorWithLimits(workers, processECMRefreshLimits)
}

func newECMRefreshCoordinatorWithLimits(workers int, limits *ecmRefreshLimits) (*ECMRefreshCoordinator, error) {
	if workers <= 0 || limits == nil {
		return nil, ecmInvalidRequestError
	}
	c := &ECMRefreshCoordinator{
		services: make(map[string]*ecmRefreshService),
		limits:   limits, rotation: list.New(),
		jobs: make(chan *ecmRefreshJob, 1024), closeDone: make(chan struct{}),
		submit: func(ctx context.Context, client *ECMClient, section []byte, route ECMRoute) (*ECMResult, error) {
			return client.SubmitECM(ctx, section, route)
		},
	}
	c.workers.Add(min(workers, 8))
	for i := 0; i < min(workers, 8); i++ {
		go c.worker()
	}
	return c, nil
}

func (c *ECMRefreshCoordinator) Add(id, profile string, client *ECMClient, pipeline *DescramblingPipeline) error {
	if id == "" || profile == "" || len(id) > ecmMaxIDBytes || len(profile) > ecmMaxIDBytes || client == nil || pipeline == nil {
		return ecmInvalidRequestError
	}
	if pipeline.client != client || pipeline.closing.Load() {
		return ecmInvalidRequestError
	}
	// The selected route is immutable for this pipeline's entire lifetime.
	ctx, cancel := context.WithCancel(context.Background())
	s := &ecmRefreshService{id: id, client: client, pipeline: pipeline, route: pipeline.route,
		ctx: ctx, cancel: cancel, done: make(chan struct{}), owners: [2]int{-1, -1},
		bucket: newECMRefreshBucket(4, 1), pending: make(map[*ecmRefreshJob]struct{})}
	c.mu.Lock()
	var err error
	switch {
	case c.closed:
		err = ecmStaleError
	case c.services[id] != nil:
		err = ecmInvalidRequestError
	case len(c.services) >= 512:
		err = ecmCapacityError
	default:
		c.limits.mu.Lock()
		c.limits.pruneProfilesLocked(c.limits.now)
		p := c.limits.profiles[profile]
		if c.limits.services >= 512 || (p != nil && p.count >= 64) {
			err = ecmCapacityError
		} else {
			if p == nil {
				p = &ecmRefreshProfile{bucket: newECMRefreshBucket(64, 8)}
				c.limits.profiles[profile] = p
			}
			p.count++
			c.limits.services++
			s.profile = p
			s.position = c.rotation.PushBack(s)
			c.services[id] = s
		}
		c.limits.mu.Unlock()
	}
	c.mu.Unlock()
	if err != nil {
		cancel()
	}
	return err
}

func (c *ECMRefreshCoordinator) Remove(id string) {
	c.mu.Lock()
	s := c.services[id]
	if s != nil {
		s.removing.Store(true)
	}
	c.mu.Unlock()
	if s != nil {
		c.retire(s)
	}
}

// Cancel queued work without waiting for an unrelated blocked worker to consume
// its queue entry. A finished entry is a bounded tombstone, never a live task.
func (c *ECMRefreshCoordinator) retire(s *ecmRefreshService) {
	s.cancel()
	s.stop.Do(func() {
		s.mu.Lock()
		for j := range s.pending {
			if !j.started {
				finishECMRefreshJobLocked(j)
			}
		}
		s.mu.Unlock()
		s.tasks.Wait()
		s.mu.Lock()
		s.sections = [2]ecmRefreshSection{}
		s.client, s.pipeline = nil, nil
		s.mu.Unlock()
		c.mu.Lock()
		if c.services[s.id] == s {
			delete(c.services, s.id)
			c.rotation.Remove(s.position)
			c.limits.mu.Lock()
			s.profile.count--
			c.limits.services--
			c.limits.pruneProfilesLocked(c.limits.now)
			c.limits.mu.Unlock()
		}
		c.mu.Unlock()
		close(s.done)
	})
	<-s.done
}

func (c *ECMRefreshCoordinator) Offer(id string, sections [][]byte) error {
	c.mu.Lock()
	s := c.services[id]
	closed := c.closed
	c.mu.Unlock()
	if closed || s == nil || s.removing.Load() {
		return ecmStaleError
	}
	// Validate the complete batch before changing either current table ID.
	for _, section := range sections {
		if err := validateECMRequest(section, s.route); err != nil {
			return ecmInvalidRequestError
		}
	}
	if !s.mu.TryLock() {
		return ecmCapacityError
	}
	defer s.mu.Unlock()
	if s.removing.Load() || s.ctx.Err() != nil {
		return ecmStaleError
	}
	for _, section := range sections {
		slot := int(section[0] - 0x80)
		current := &s.sections[slot]
		if bytes.Equal(current.data, section) {
			continue
		}
		// Version, not content equality, rejects an A -> B -> A delayed result.
		if current.version == ^uint64(0) {
			return ecmCapacityError
		}
		current.version++
		current.data = append(current.data[:0], section...)
		current.dirty, current.retry, current.mask = true, false, 0
	}
	return nil
}

func (limits *ecmRefreshLimits) pruneProfilesLocked(now time.Time) {
	for name, profile := range limits.profiles {
		if profile.count != 0 {
			continue
		}
		profile.bucket.refill(now)
		if profile.bucket.credits == profile.bucket.burst*refreshToken {
			delete(limits.profiles, name)
		}
	}
}

func (s *ecmRefreshService) candidateLocked(now time.Time, hints ECMRefreshHints) int {
	if len(s.pending) >= 2 || now.Before(s.backoff) {
		return -1
	}
	var busy [2]bool
	for job := range s.pending {
		if job.version == s.sections[job.slot].version || bytes.Equal(job.section, s.sections[job.slot].data) {
			busy[job.slot] = true
		}
	}
	for slot := range s.sections {
		section := &s.sections[slot]
		if len(section.data) != 0 && !busy[slot] && (section.dirty || section.retry) {
			return slot
		}
	}
	for slot := range s.sections {
		section := &s.sections[slot]
		if len(section.data) == 0 || busy[slot] {
			continue
		}
		for parity, info := range hints.Leases {
			bit := uint8(1 << parity)
			if hints.Needed&section.mask&bit == 0 || s.owners[parity] != slot {
				continue
			}
			if info.ReceivedAt.IsZero() || !now.Before(info.ReceivedAt.Add(500*time.Millisecond)) {
				return slot
			}
		}
	}
	return -1
}

// Tick is the only admission clock. It performs at most one admission per
// service per pass and rotates admitted services behind all waiting siblings.
func (c *ECMRefreshCoordinator) Tick(now time.Time) {
	if now.IsZero() {
		return
	}
	c.tickMu.Lock()
	defer c.tickMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if now.Before(c.now) {
		now = c.now
	}
	c.limits.mu.Lock()
	if now.Before(c.limits.now) {
		now = c.limits.now
	}
	c.limits.now = now
	c.limits.pruneProfilesLocked(now)
	c.limits.mu.Unlock()
	c.now = now
	snapshot := make([]*ecmRefreshService, 0, len(c.services))
	for entry := c.rotation.Front(); entry != nil; entry = entry.Next() {
		snapshot = append(snapshot, entry.Value.(*ecmRefreshService))
	}
	c.mu.Unlock()
	for _, s := range snapshot {
		if s.removing.Load() || !s.mu.TryLock() {
			continue
		}
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			continue
		}
		slot := s.candidateLocked(now, s.pipeline.RefreshHints())
		if slot < 0 {
			s.mu.Unlock()
			continue
		}
		s.bucket.refill(now)
		c.mu.Lock()
		c.limits.mu.Lock()
		c.limits.process.refill(now)
		s.profile.bucket.refill(now)
		if c.closed || s.removing.Load() || c.services[s.id] != s ||
			s.bucket.credits < refreshToken || s.profile.bucket.credits < refreshToken || c.limits.process.credits < refreshToken ||
			len(c.jobs) == cap(c.jobs) {
			c.limits.mu.Unlock()
			c.mu.Unlock()
			s.mu.Unlock()
			continue
		}
		section := &s.sections[slot]
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
		job := &ecmRefreshJob{service: s, slot: slot, version: section.version,
			section: append([]byte(nil), section.data...), ctx: ctx, cancel: cancel}
		s.tasks.Add(1)
		s.pending[job] = struct{}{}
		section.dirty, section.retry = false, false
		s.bucket.credits -= refreshToken
		s.profile.bucket.credits -= refreshToken
		c.limits.process.credits -= refreshToken
		c.rotation.MoveToBack(s.position)
		c.jobs <- job
		c.limits.mu.Unlock()
		c.mu.Unlock()
		s.mu.Unlock()
	}
}

func finishECMRefreshJobLocked(job *ecmRefreshJob) {
	if job.finished {
		return
	}
	job.finished = true
	job.cancel()
	clear(job.section)
	job.section = nil
	delete(job.service.pending, job)
	job.service.tasks.Done()
}

func (c *ECMRefreshCoordinator) worker() {
	defer c.workers.Done()
	for job := range c.jobs {
		s := job.service
		s.mu.Lock()
		if job.finished {
			s.mu.Unlock()
			continue
		}
		if s.removing.Load() || job.ctx.Err() != nil || s.sections[job.slot].version != job.version {
			if !s.removing.Load() && s.ctx.Err() == nil && s.sections[job.slot].version == job.version {
				c.mu.Lock()
				s.backoff = c.now.Add(time.Second)
				c.mu.Unlock()
				s.sections[job.slot].retry = true
			}
			finishECMRefreshJobLocked(job)
			s.mu.Unlock()
			continue
		}
		job.started = true
		client := s.client
		s.mu.Unlock()
		result, err := c.submit(job.ctx, client, job.section, s.route)
		s.mu.Lock()
		current := !s.removing.Load() && s.ctx.Err() == nil && s.sections[job.slot].version == job.version
		if !current {
			if result != nil {
				_ = result.Release()
			}
		} else {
			var info ECMLeaseInfo
			if job.ctx.Err() != nil {
				err = ecmStaleError
			} else if err == nil && result != nil {
				info, err = client.LeaseInfo(result)
			} else if err == nil {
				err = ecmStaleError
			}
			if err == nil && (job.ctx.Err() != nil || s.removing.Load()) {
				err = ecmStaleError
			}
			if err == nil {
				// Never occupy the control pool waiting for a media cipher.
				// TryInstallResult consumes the owner even on capacity rejection.
				err = s.pipeline.TryInstallResult(result)
			} else if result != nil {
				_ = result.Release()
			}
			section := &s.sections[job.slot]
			if err != nil {
				// Explicit scheduling time, sampled after any metadata/publication
				// wait. Never retain or format an arbitrary submit error.
				c.mu.Lock()
				s.backoff = c.now.Add(time.Second)
				c.mu.Unlock()
				section.retry = true
			} else {
				section.mask = info.ValidMask
				for parity := range s.owners {
					if info.ValidMask&uint8(1<<parity) != 0 {
						s.owners[parity] = job.slot
					}
				}
			}
		}
		finishECMRefreshJobLocked(job)
		s.mu.Unlock()
	}
}

func (c *ECMRefreshCoordinator) Close() error {
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		<-done
		return nil
	}
	c.closed = true
	services := make([]*ecmRefreshService, 0, len(c.services))
	for _, s := range c.services {
		s.removing.Store(true)
		services = append(services, s)
	}
	close(c.jobs)
	c.mu.Unlock()
	// Cancel all services before joining any one blocked submission.
	for _, s := range services {
		s.cancel()
	}
	for _, s := range services {
		c.retire(s)
	}
	c.workers.Wait()
	close(c.closeDone)
	return nil
}
