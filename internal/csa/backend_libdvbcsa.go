//go:build linux && dvbcsa && cgo

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package csa

/*
#cgo LDFLAGS: -ldvbcsa
#include "bridge.h"
*/
import "C"

import (
	"runtime"
	"sync"
	"unsafe"
)

const (
	nativeMaxBatch = 128
	tsPayloadSize  = 184
)

type nativeReceipt struct {
	AllocationAttempts uint32
	Allocations        uint32
	Frees              uint32
	LiveAllocations    uint32
	KeyAllocations     uint32
	KeyFrees           uint32
	CWCopyZeroed       bool
	ScratchZeroed      bool
	Count              uint32
	Descriptors        uint32
	NullSentinel       bool
	MaxLength          uint32
	ExactLengths       [nativeMaxBatch]uint32
	RetainedGoPointers uint32
}

type libdvbcsaBackend struct {
	mu          sync.Mutex
	handle      *C.struct_ax_csa_handle
	batch       int
	lastReceipt nativeReceipt
}

var _ Backend = (*libdvbcsaBackend)(nil)

func backendCapability() (bool, string) {
	size := C.ax_csa_batch_size()
	if size == 0 || size > nativeMaxBatch {
		return false, "unsupported_abi"
	}
	return true, ""
}

func newBackend() (Backend, error) {
	r := C.ax_csa_open()
	if err := nativeError(r.status); err != nil {
		return nil, err
	}
	return &libdvbcsaBackend{handle: r.handle, batch: int(r.reported_batch)}, nil
}

// The ceiling is immutable, including after Close; no native pointer is read.
func (b *libdvbcsaBackend) BatchSize() int { return b.batch }

func (b *libdvbcsaBackend) Decrypt(cw [8]byte, payloads [][]byte) error {
	defer func() {
		clear(cw[:])
		runtime.KeepAlive(&cw)
	}()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastReceipt = nativeReceipt{}
	if b.handle == nil {
		return Error{Code: "backend_closed"}
	}
	if len(payloads) > b.batch {
		return Error{Code: "capacity"}
	}
	count := 0
	for i, payload := range payloads {
		if len(payload) > tsPayloadSize {
			return Error{Code: "invalid_payload"}
		}
		if len(payload) == 0 {
			continue
		}
		start := uintptr(unsafe.Pointer(&payload[0]))
		end := start + uintptr(len(payload))
		for _, prior := range payloads[:i] {
			if len(prior) == 0 {
				continue
			}
			other := uintptr(unsafe.Pointer(&prior[0]))
			if start < other+uintptr(len(prior)) && other < end {
				return Error{Code: "invalid_payload"}
			}
		}
		count++
	}
	if count == 0 {
		return nil
	}

	// Go flat storage contains no Go pointers. C borrows it only for this call;
	// the actual cipher descriptors, payload scratch and key live entirely in C.
	var flat [nativeMaxBatch * tsPayloadSize]byte
	var lengths [nativeMaxBatch]C.uint
	defer func() {
		clear(flat[:])
		runtime.KeepAlive(&flat)
	}()
	index := 0
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		copy(flat[index*tsPayloadSize:], payload)
		lengths[index] = C.uint(len(payload))
		index++
	}
	data := (*C.uchar)(unsafe.Pointer(&flat[0]))
	r := C.ax_csa_decrypt(b.handle, (*C.uchar)(unsafe.Pointer(&cw[0])), data,
		&lengths[0], C.uint(count), data)
	b.lastReceipt = receiptFromC(r)
	if err := nativeError(r.status); err != nil {
		return err
	}
	index = 0
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		copy(payload, flat[index*tsPayloadSize:index*tsPayloadSize+len(payload)])
		index++
	}
	return nil
}

func (b *libdvbcsaBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle == nil {
		return nil
	}
	r := C.ax_csa_close(b.handle)
	b.handle = nil
	return nativeError(r.status)
}

func nativeError(status C.enum_ax_csa_status) error {
	switch status {
	case C.AX_CSA_OK:
		return nil
	case C.AX_CSA_UNSUPPORTED_ABI:
		return Error{Code: "unsupported_abi"}
	case C.AX_CSA_ALLOCATION_FAILED:
		return Error{Code: "allocation_failed"}
	case C.AX_CSA_INVALID_PAYLOAD:
		return Error{Code: "invalid_payload"}
	case C.AX_CSA_CAPACITY:
		return Error{Code: "capacity"}
	case C.AX_CSA_CLOSED:
		return Error{Code: "backend_closed"}
	default:
		return Error{Code: "backend_unavailable"}
	}
}

func receiptFromC(r C.struct_ax_csa_result) nativeReceipt {
	out := nativeReceipt{
		AllocationAttempts: uint32(r.allocation_attempts),
		Allocations:        uint32(r.allocations),
		Frees:              uint32(r.frees),
		LiveAllocations:    uint32(r.live_allocations),
		KeyAllocations:     uint32(r.key_allocations),
		KeyFrees:           uint32(r.key_frees),
		CWCopyZeroed:       r.cw_copy_zeroed != 0,
		ScratchZeroed:      r.scratch_zeroed != 0,
		Count:              uint32(r.count),
		Descriptors:        uint32(r.descriptors),
		NullSentinel:       r.null_sentinel != 0,
		MaxLength:          uint32(r.max_length),
		RetainedGoPointers: uint32(r.retained_go_pointers),
	}
	for i := range out.ExactLengths {
		out.ExactLengths[i] = uint32(r.exact_lengths[i])
	}
	return out
}

func nativeProbeABI(reported uint32) (error, nativeReceipt) {
	r := C.ax_csa_probe_abi(C.uint(reported))
	return nativeError(r.status), receiptFromC(r)
}

func nativeProbeAllocation(at uint32) (error, nativeReceipt) {
	r := C.ax_csa_probe_allocation(C.uint(at))
	return nativeError(r.status), receiptFromC(r)
}
