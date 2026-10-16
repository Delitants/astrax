//go:build linux && dvbcsa && cgo

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

// Package csatest provides a scalar libdvbcsa oracle for synthetic backend tests.
// It has no initialization hooks and is not part of the production cipher path.
package csatest

/*
#cgo LDFLAGS: -ldvbcsa
#include <stdlib.h>
#include <dvbcsa/dvbcsa.h>

static void csatest_wipe_free(void *buffer, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)buffer;
    while (length != 0) {
        *p++ = 0;
        --length;
    }
    free(buffer);
}
*/
import "C"

import "errors"

// Encrypt returns a separately owned ciphertext without changing data or cw.
// Empty input is a no-op; all other payloads must be between 1 and 184 bytes.
// Native allocations are freed synchronously before this function returns.
func Encrypt(cw [8]byte, data []byte) ([]byte, error) {
	if len(data) > 184 {
		return nil, errors.New("scalar CSA payload exceeds 184 bytes")
	}
	if len(data) == 0 {
		return nil, nil
	}

	cwBuffer := C.CBytes(cw[:])
	if cwBuffer == nil {
		return nil, errors.New("scalar CSA allocation failed")
	}
	defer C.csatest_wipe_free(cwBuffer, C.size_t(len(cw)))
	dataBuffer := C.CBytes(data)
	if dataBuffer == nil {
		return nil, errors.New("scalar CSA allocation failed")
	}
	defer C.csatest_wipe_free(dataBuffer, C.size_t(len(data)))
	key := C.dvbcsa_key_alloc()
	if key == nil {
		return nil, errors.New("scalar CSA key allocation failed")
	}
	defer C.dvbcsa_key_free(key)

	// Only public opaque-key APIs are used; no guessed key layout or private header.
	C.dvbcsa_key_set((*C.uchar)(cwBuffer), key)
	C.dvbcsa_encrypt(key, (*C.uchar)(dataBuffer), C.uint(len(data)))
	return C.GoBytes(dataBuffer, C.int(len(data))), nil
}
