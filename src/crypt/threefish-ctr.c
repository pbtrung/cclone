/***************************************************************************
 * Copyright (C) 2017 Trung Pham <me@trungbpham.com>                       *
 * All rights reserved.                                                    *
 *                                                                         *
 * Redistribution and use in source and binary forms, with or without      *
 * modification, are permitted provided that the following conditions      *
 * are met:                                                                *
 *                                                                         *
 *    * Redistributions of source code must retain the above copyright     *
 *    notice, this list of conditions and the following disclaimer.        *
 *                                                                         *
 *    * Redistributions in binary form must reproduce the above copyright  *
 *    notice, this list of conditions and the following disclaimer in the  *
 *    documentation and/or other materials provided with the distribution. *
 *                                                                         *
 *    * Neither the name of cclone nor the names of its contributors may   *
 *    may be used to endorse or promote products derived from this         *
 *    software without specific prior written permission.                  *
 *                                                                         *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR   *
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT    *
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,  *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        *
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   *
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   *
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   *
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    *
 ***************************************************************************/

#include <assert.h>

#include "crypt/threefish-ctr.h"

void t3c_encrypt(ThreefishKey_t *t3f_x, hc256_ctx_t *hc_x, unsigned char *input,
                 size_t in_len, unsigned char *output) {
    assert(t3f_x != NULL);
    assert(hc_x != NULL);
    assert(input != NULL);
    assert(output != NULL);
    assert(in_len <= T3C_MAX_BLOCK_LEN);

    unsigned char tmp[THREEFISH_BLOCK_LEN];
    unsigned char ctr[THREEFISH_BLOCK_LEN];

    uint32_t i = 0;
    for (; in_len >= THREEFISH_BLOCK_LEN; ++i, in_len -= THREEFISH_BLOCK_LEN) {
        hc256_gen_bytes(hc_x, ctr, THREEFISH_BLOCK_LEN);
        t3f_encrypt(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < THREEFISH_BLOCK_LEN; ++j) {
            output[i * THREEFISH_BLOCK_LEN + j] =
                tmp[j] ^ input[i * THREEFISH_BLOCK_LEN + j];
        }
    }
    if (in_len > 0) {
        hc256_gen_bytes(hc_x, ctr, THREEFISH_BLOCK_LEN);
        t3f_encrypt(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < in_len; ++j) {
            output[i * THREEFISH_BLOCK_LEN + j] =
                tmp[j] ^ input[i * THREEFISH_BLOCK_LEN + j];
        }
    }
}

void t3c_decrypt(ThreefishKey_t *t3f_x, hc256_ctx_t *hc_x, unsigned char *input,
                 size_t in_len, unsigned char *output) {
    assert(t3f_x != NULL);
    assert(hc_x != NULL);
    assert(input != NULL);
    assert(output != NULL);
    assert(in_len <= T3C_MAX_BLOCK_LEN);
    t3c_encrypt(t3f_x, hc_x, input, in_len, output);
}