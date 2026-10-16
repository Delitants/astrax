// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package packetbudget

import (
	"errors"
	"sync"
)

var ErrCapacity = errors.New("packet budget capacity exceeded")
var ErrInvalid = errors.New("invalid packet reservation")

type Budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	peak  int64
}
type Reservation struct {
	budget *Budget
	bytes  int64
	once   sync.Once
}

func New(limit int64) *Budget { return &Budget{limit: limit} }
func (b *Budget) Reserve(bytes int64) (*Reservation, error) {
	if b == nil || bytes < 0 || b.limit < 0 {
		return nil, ErrInvalid
	}
	b.mu.Lock()
	// Subtraction cannot overflow even for a MaxInt64 request/limit.
	if bytes > b.limit-b.used {
		b.mu.Unlock()
		return nil, ErrCapacity
	}
	b.used += bytes
	if b.used > b.peak {
		b.peak = b.used
	}
	b.mu.Unlock()
	return &Reservation{budget: b, bytes: bytes}, nil
}
func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// PeakUsed reports the highest successful reservation total, not heap or RSS.
func (b *Budget) PeakUsed() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}
func (r *Reservation) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if r.budget == nil {
			return
		}
		r.budget.mu.Lock()
		r.budget.used -= r.bytes
		r.budget.mu.Unlock()
	})
}
