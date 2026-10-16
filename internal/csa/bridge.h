/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) Delitants */

#ifndef ASTRAX_CSA_BRIDGE_H
#define ASTRAX_CSA_BRIDGE_H

#include <dvbcsa/dvbcsa.h>

#define AX_CSA_MAX_BATCH 128u
#define AX_CSA_PAYLOAD 184u

struct ax_csa_handle;

enum ax_csa_status {
    AX_CSA_OK = 0,
    AX_CSA_UNAVAILABLE,
    AX_CSA_UNSUPPORTED_ABI,
    AX_CSA_ALLOCATION_FAILED,
    AX_CSA_INVALID_PAYLOAD,
    AX_CSA_CAPACITY,
    AX_CSA_CLOSED
};

/* Counts describe this synchronous call, not opaque upstream key erasure. */
struct ax_csa_result {
    enum ax_csa_status status;
    struct ax_csa_handle *handle;
    unsigned int reported_batch;
    unsigned int allocation_attempts;
    unsigned int allocations;
    unsigned int frees;
    unsigned int live_allocations;
    unsigned int key_allocations;
    unsigned int key_frees;
    unsigned int cw_copy_zeroed;
    unsigned int scratch_zeroed;
    unsigned int count;
    unsigned int descriptors;
    unsigned int null_sentinel;
    unsigned int max_length;
    unsigned int exact_lengths[AX_CSA_MAX_BATCH];
    unsigned int retained_go_pointers;
};

unsigned int ax_csa_batch_size(void);
struct ax_csa_result ax_csa_open(void);
struct ax_csa_result ax_csa_close(struct ax_csa_handle *handle);
/* Input/output use fixed 184-byte strides; only lengths[i] bytes are copied.
 * All borrowed pointers expire when this call returns, including on failure. */
struct ax_csa_result ax_csa_decrypt(struct ax_csa_handle *handle,
                                  const unsigned char cw[8],
                                  const unsigned char *input,
                                  const unsigned int *lengths,
                                  unsigned int count, unsigned char *output);
struct ax_csa_result ax_csa_probe_abi(unsigned int reported);
struct ax_csa_result ax_csa_probe_allocation(unsigned int fail_at);

#endif
