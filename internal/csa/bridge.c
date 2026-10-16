//go:build linux && dvbcsa && cgo

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) Delitants */

#include "bridge.h"
#include <stdlib.h>
#include <string.h>

struct ax_csa_handle {
    unsigned int batch;
};

/* Volatile stores wipe only our own buffers. Upstream key layouts stay opaque. */
static unsigned int wipe(void *buffer, size_t length)
{
    volatile unsigned char *p = buffer;
    unsigned int zero = 1;
    size_t i;
    for (i = 0; i < length; ++i)
        p[i] = 0;
    for (i = 0; i < length; ++i)
        zero &= p[i] == 0;
    return zero;
}

static int valid_batch(unsigned int batch)
{
    return batch > 0 && batch <= AX_CSA_MAX_BATCH;
}

unsigned int ax_csa_batch_size(void)
{
    return dvbcsa_bs_batch_size();
}

struct ax_csa_result ax_csa_probe_abi(unsigned int reported)
{
    struct ax_csa_result r = {0};
    r.reported_batch = reported;
    if (!valid_batch(reported))
        r.status = AX_CSA_UNSUPPORTED_ABI;
    return r;
}

struct ax_csa_result ax_csa_open(void)
{
    struct ax_csa_result r = ax_csa_probe_abi(ax_csa_batch_size());
    if (r.status != AX_CSA_OK)
        return r;
    r.allocation_attempts = 1;
    r.handle = calloc(1, sizeof(*r.handle));
    if (r.handle == NULL) {
        r.status = AX_CSA_ALLOCATION_FAILED;
        return r;
    }
    r.handle->batch = r.reported_batch;
    r.allocations = r.live_allocations = 1;
    return r;
}

/* The failure probe goes through these same allocation/cleanup branches.
 * Injection is a per-call argument, never global allocator state. */
static int allocation_allowed(struct ax_csa_result *r, unsigned int fail_at)
{
    ++r->allocation_attempts;
    return fail_at == 0 || r->allocation_attempts != fail_at;
}

static void allocated(struct ax_csa_result *r)
{
    ++r->allocations;
    ++r->live_allocations;
}

static void released(struct ax_csa_result *r)
{
    ++r->frees;
    --r->live_allocations;
}

static struct ax_csa_result decrypt_batch(struct ax_csa_handle *handle,
                                        const unsigned char cw[8],
                                        const unsigned char *input,
                                        const unsigned int *lengths,
                                        unsigned int count, unsigned char *output,
                                        unsigned int fail_at)
{
    struct ax_csa_result r = {0};
    struct dvbcsa_bs_batch_s *descriptors = NULL;
    struct dvbcsa_bs_key_s *key = NULL;
    unsigned char *scratch = NULL, *cw_copy = NULL;
    unsigned int i;

    if (handle == NULL) {
        r.status = AX_CSA_CLOSED;
        return r;
    }
    r.reported_batch = handle->batch;
    if (!valid_batch(handle->batch)) {
        r.status = AX_CSA_UNSUPPORTED_ABI;
        return r;
    }
    if (count > handle->batch) {
        r.status = AX_CSA_CAPACITY;
        return r;
    }
    if (count == 0)
        return r;
    if (cw == NULL || input == NULL || output == NULL || lengths == NULL) {
        r.status = AX_CSA_INVALID_PAYLOAD;
        return r;
    }
    for (i = 0; i < count; ++i) {
        if (lengths[i] == 0 || lengths[i] > AX_CSA_PAYLOAD) {
            r.status = AX_CSA_INVALID_PAYLOAD;
            return r;
        }
        r.exact_lengths[i] = lengths[i];
    }

    r.count = count;
    r.descriptors = count + 1;
    r.max_length = AX_CSA_PAYLOAD;
    /* No owned buffer is left unwiped if its allocation never occurred. */
    r.cw_copy_zeroed = r.scratch_zeroed = 1;
    r.status = AX_CSA_ALLOCATION_FAILED;
    if (allocation_allowed(&r, fail_at))
        descriptors = calloc(count + 1, sizeof(*descriptors));
    if (descriptors == NULL)
        goto cleanup;
    allocated(&r);
    if (allocation_allowed(&r, fail_at))
        scratch = calloc(count, AX_CSA_PAYLOAD);
    if (scratch == NULL)
        goto cleanup;
    allocated(&r);
    if (allocation_allowed(&r, fail_at))
        cw_copy = malloc(8);
    if (cw_copy == NULL)
        goto cleanup;
    allocated(&r);
    memcpy(cw_copy, cw, 8);
    if (allocation_allowed(&r, fail_at))
        key = dvbcsa_bs_key_alloc();
    if (key == NULL)
        goto cleanup;
    allocated(&r);
    r.key_allocations = 1;

    for (i = 0; i < count; ++i) {
        descriptors[i].data = scratch + (size_t)i * AX_CSA_PAYLOAD;
        descriptors[i].len = lengths[i];
        memcpy(descriptors[i].data, input + (size_t)i * AX_CSA_PAYLOAD, lengths[i]);
    }
    r.null_sentinel = descriptors[count].data == NULL;
    dvbcsa_bs_key_set(cw_copy, key);
    dvbcsa_bs_decrypt(key, descriptors, AX_CSA_PAYLOAD);
    for (i = 0; i < count; ++i)
        memcpy(output + (size_t)i * AX_CSA_PAYLOAD, descriptors[i].data, lengths[i]);
    r.status = AX_CSA_OK;

cleanup:
    if (key != NULL) {
        dvbcsa_bs_key_free(key);
        r.key_frees = 1;
        released(&r);
    }
    if (cw_copy != NULL) {
        r.cw_copy_zeroed = wipe(cw_copy, 8);
        free(cw_copy);
        released(&r);
    }
    if (scratch != NULL) {
        r.scratch_zeroed = wipe(scratch, (size_t)count * AX_CSA_PAYLOAD);
        free(scratch);
        released(&r);
    }
    if (descriptors != NULL) {
        wipe(descriptors, (size_t)(count + 1) * sizeof(*descriptors));
        free(descriptors);
        released(&r);
    }
    return r;
}

struct ax_csa_result ax_csa_decrypt(struct ax_csa_handle *handle,
                                  const unsigned char cw[8],
                                  const unsigned char *input,
                                  const unsigned int *lengths,
                                  unsigned int count, unsigned char *output)
{
    return decrypt_batch(handle, cw, input, lengths, count, output, 0);
}

struct ax_csa_result ax_csa_probe_allocation(unsigned int fail_at)
{
    struct ax_csa_handle handle = {ax_csa_batch_size()};
    unsigned char cw[8] = {0}, input[AX_CSA_PAYLOAD] = {0};
    unsigned char output[AX_CSA_PAYLOAD] = {0};
    unsigned int lengths[1] = {AX_CSA_PAYLOAD};
    struct ax_csa_result r;
    if (fail_at == 0 || fail_at > 4) {
        r = (struct ax_csa_result){0};
        r.status = AX_CSA_INVALID_PAYLOAD;
        return r;
    }
    r = decrypt_batch(&handle, cw, input, lengths, 1, output, fail_at);
    wipe(cw, sizeof(cw));
    wipe(input, sizeof(input));
    wipe(output, sizeof(output));
    return r;
}

struct ax_csa_result ax_csa_close(struct ax_csa_handle *handle)
{
    struct ax_csa_result r = {0};
    if (handle != NULL) {
        wipe(handle, sizeof(*handle));
        free(handle);
        r.frees = 1;
    }
    return r;
}
