// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"

	"astrax/internal/model"
	"astrax/internal/softcam"
)

func (s *Store) TestSoftcam(id string) (*model.SoftcamTestResult, error) {
	return s.TestSoftcamContext(context.Background(), id)
}

func (s *Store) TestSoftcamContext(ctx context.Context, id string) (*model.SoftcamTestResult, error) {
	if err := s.requireActivated(); err != nil {
		return nil, err
	}
	end, err := s.admitRuntime()
	if err != nil {
		return nil, err
	}
	defer end()
	work, detach := s.softcamTestContext(ctx)
	defer detach()
	// RLock is not cancellable; use the cancellable exclusive lock only for the
	// credential snapshot, and release it before invoking the complete runner.
	if err = s.mu.LockContext(work); err != nil {
		return nil, err
	}
	idx := s.findSoftcamIndexLocked(id)
	if idx < 0 {
		s.mu.Unlock()
		return nil, errors.New("softcam not found")
	}
	profile := s.config.Softcams[idx]
	profile.Runtime = model.SoftcamRuntime{}
	s.mu.Unlock()
	tester := s.softcamTester
	if tester == nil {
		tester = softcam.TestConnectionContext
	}
	result, err := tester(work, profile)
	var cleanup interface{ SessionCloseError() error }
	if errors.As(err, &cleanup) {
		s.recordRuntimeCleanup(cleanup.SessionCloseError())
	}
	if work.Err() != nil {
		return nil, errors.Join(work.Err(), err)
	}
	return result, err
}
