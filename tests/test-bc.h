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

#include "crypt/block-crypt.h"
#include "log.h"
#include "macro.h"
#include "rc.h"
#include "utils/cleanup.h"

static void test_bc();

static void test_bc() {
    int rc = CCLONE_SUCCESS;

    _cleanup_free_ key_ctx_t *key_x = malloc(sizeof(key_ctx_t));
    _cleanup_free_ bc_ctx_t *bc_x = malloc(sizeof(bc_ctx_t));

    size_t test_len = 1024;
    _cleanup_free_ unsigned char *input =
        calloc(test_len, sizeof(unsigned char));
    _cleanup_free_ unsigned char *output =
        calloc(test_len + SKEIN_MAC_LEN, sizeof(unsigned char));
    _cleanup_free_ unsigned char *dec_output =
        calloc(test_len, sizeof(unsigned char));

    _cleanup_free_ unsigned char *pwd =
        calloc(CCLONE_PWD_LEN, sizeof(unsigned char));
    _cleanup_free_ unsigned char *salt =
        calloc(CCLONE_SALT_LEN, sizeof(unsigned char));

    key_derive(key_x, pwd, salt, 3, 1 << 6, 2);
    bc_prepare(bc_x, key_x);
    rc = bc_encrypt(bc_x, input, test_len, output);
    sput_fail_if(rc != CCLONE_SUCCESS, "bc_encrypt");

    bc_prepare(bc_x, key_x);
    rc = bc_decrypt(bc_x, output, test_len + SKEIN_MAC_LEN, dec_output);
    sput_fail_if(rc != CCLONE_SUCCESS, "bc_decrypt");

    rc = memcmp(input, dec_output, test_len);
    sput_fail_if(rc != CCLONE_SUCCESS, "Compare input and decrypted");
}