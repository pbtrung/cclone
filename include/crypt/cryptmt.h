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

#ifndef __CRYPTMT_H__
#define __CRYPTMT_H__

#include "crypt/cryptmt/ecrypt-sync.h"

#define CRYPTMT_KEY_LEN 256U
#define CRYPTMT_IV_LEN 256U

void cmt_init();
void cmt_keysetup(cryptmt_ctx_t *cryptmt_x, const u8 *cryptmt_key);
void cmt_ivsetup(cryptmt_ctx_t *cryptmt_x, const u8 *cryptmt_iv);

void cmt_encrypt(cryptmt_ctx_t *cryptmt_x, const u8 *input, u8 *output,
                 u32 in_len);
void cmt_decrypt(cryptmt_ctx_t *cryptmt_x, const u8 *input, u8 *output,
                 u32 in_len);

#endif //__CRYPTMT_H__