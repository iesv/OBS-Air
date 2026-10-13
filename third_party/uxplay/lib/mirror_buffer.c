/*
 * Copyright (c) 2019 dsafa22, All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 *================================================================
 * modified by fduncanh 2022
 */

#include "mirror_buffer.h"
#include "raop_rtp.h"
#include <stdint.h>
#include "crypto.h"
#include "compat.h"
#include <math.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

struct mirror_buffer_s {
    logger_t *logger;
    aes_ctx_t *aes_ctx;
    int nextDecryptCount;
    uint8_t og[16];
    /* audio aes key is used in a hash for the video aes key and iv */
    unsigned char aeskey_audio[RAOP_AESKEY_LEN];
};

void
mirror_buffer_init_aes(mirror_buffer_t *mirror_buffer, const uint64_t *streamConnectionID)
{
    unsigned char aeskey_video[64] = {0};
    unsigned char aesiv_video[64] = {0};

    assert(mirror_buffer);
    assert(streamConnectionID);

    /* AES key and IV */
    // Need secondary processing to use

    snprintf((char*) aeskey_video, sizeof(aeskey_video), "AirPlayStreamKey%" PRIu64, *streamConnectionID);
    snprintf((char*) aesiv_video, sizeof(aesiv_video), "AirPlayStreamIV%" PRIu64, *streamConnectionID);

    sha_ctx_t *ctx = sha_init();
    sha_update(ctx, aeskey_video, strlen((char*) aeskey_video));
    sha_update(ctx, mirror_buffer->aeskey_audio, RAOP_AESKEY_LEN);
    sha_final(ctx, aeskey_video, NULL);

    sha_reset(ctx);
    sha_update(ctx, aesiv_video, strlen((char*) aesiv_video));
    sha_update(ctx, mirror_buffer->aeskey_audio, RAOP_AESKEY_LEN);
    sha_final(ctx, aesiv_video, NULL);
    sha_destroy(ctx);

    /* A new stream starts with a fresh keystream. */
    mirror_buffer->nextDecryptCount = 0;
    memset(mirror_buffer->og, 0, sizeof(mirror_buffer->og));
    if (mirror_buffer->aes_ctx) {
        aes_ctr_destroy(mirror_buffer->aes_ctx);
        mirror_buffer->aes_ctx = NULL;
    }

    // Need to be initialized externally
    mirror_buffer->aes_ctx = aes_ctr_init(aeskey_video, aesiv_video);
}

mirror_buffer_t *
mirror_buffer_init(logger_t *logger, const unsigned char *aeskey)
{
    assert(aeskey);
    mirror_buffer_t *mirror_buffer = (mirror_buffer_t *) calloc(1, sizeof(mirror_buffer_t));
    if (!mirror_buffer) {
        return NULL;
    }
    memcpy(mirror_buffer->aeskey_audio, aeskey, RAOP_AESKEY_LEN);
    mirror_buffer->logger = logger;
    mirror_buffer->nextDecryptCount = 0;
    return mirror_buffer;
}

void mirror_buffer_decrypt(mirror_buffer_t *mirror_buffer, unsigned char* input, unsigned char* output, int inputLen) {
    if (!mirror_buffer || !input || !output || inputLen <= 0) {
        return;
    }

    /* Invalid output is rejected by the caller's NAL validation. */
    if (!mirror_buffer->aes_ctx) {
        memset(output, 0, (size_t) inputLen);
        return;
    }

    int residual = mirror_buffer->nextDecryptCount;
    if (residual < 0 || residual > 16) {
        residual = 0;
        mirror_buffer->nextDecryptCount = 0;
        memset(mirror_buffer->og, 0, sizeof(mirror_buffer->og));
    }

    /* Short packets may consume only part of the pending keystream. */
    int carry = (inputLen < residual) ? inputLen : residual;
    for (int i = 0; i < carry; i++) {
        output[i] = input[i] ^ mirror_buffer->og[(16 - residual) + i];
    }
    if (carry < residual) {
        mirror_buffer->nextDecryptCount = residual - carry;
        return;
    }

    int remaining = inputLen - carry;
    int encryptlen = (remaining / 16) * 16;
    if (encryptlen > 0) {
        /* Advance to the next fresh counter block after consuming any
         * residual keystream bytes from the preceding packet. */
        aes_ctr_start_fresh_block(mirror_buffer->aes_ctx);
        aes_ctr_decrypt(mirror_buffer->aes_ctx, input + carry,
                        input + carry, encryptlen);
        memcpy(output + carry, input + carry, (size_t) encryptlen);
    }

    int restlen = remaining - encryptlen;
    mirror_buffer->nextDecryptCount = 0;
    if (restlen > 0) {
        int reststart = carry + encryptlen;
        memset(mirror_buffer->og, 0, sizeof(mirror_buffer->og));
        memcpy(mirror_buffer->og, input + reststart, (size_t) restlen);
        aes_ctr_decrypt(mirror_buffer->aes_ctx, mirror_buffer->og, mirror_buffer->og, 16);
        for (int j = 0; j < restlen; j++) {
            output[reststart + j] = mirror_buffer->og[j];
        }
        mirror_buffer->nextDecryptCount = 16 - restlen;
    }
}

void
mirror_buffer_destroy(mirror_buffer_t *mirror_buffer)
{
    if (mirror_buffer) {
        aes_ctr_destroy(mirror_buffer->aes_ctx);
        free(mirror_buffer);
    }
}
