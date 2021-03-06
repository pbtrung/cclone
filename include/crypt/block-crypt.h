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

#ifndef __BLOCK_CRYPT_H__
#define __BLOCK_CRYPT_H__

#include "crypt/key.h"

struct bc_ctx_t {
    ThreefishKey_t t3f_x;
    SkeinCtx_t skein_x;
    cryptmt_ctx_t cryptmt_x;
    hc256_ctx_t hc_x;
};
typedef struct bc_ctx_t bc_ctx_t;

int bc_prepare(bc_ctx_t *bc_x, key_ctx_t *key_x);
void bc_reset_t3f_mt(bc_ctx_t *bc_x, key_ctx_t *key_x, unsigned char *t3f_tweak,
                     unsigned char *cryptmt_iv);
int bc_encrypt(bc_ctx_t *bc_x, unsigned char *input, size_t in_len,
               unsigned char *output);
int bc_decrypt(bc_ctx_t *bc_x, unsigned char *input, size_t in_len,
               unsigned char *output);

#endif //__BLOCK_CRYPT_H__
