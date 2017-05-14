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

#include "crypt/block-crypt.h"
#include "crypt/threefish-ctr.h"
#include "log.h"
#include "macro.h"
#include "rc.h"
#include "utils/cleanup.h"

int bc_prepare(bc_ctx_t *bc_x, key_ctx_t *key_x) {
    assert(bc_x != NULL);
    assert(key_x != NULL);

    int rc = CCLONE_SUCCESS;

    hc256_set_kiv(&bc_x->hc_x, key_x->hc256_kiv);
    unsigned char t3f_tweak[THREEFISH_TWEAK_LEN];
    hc256_gen_bytes(&bc_x->hc_x, t3f_tweak, THREEFISH_TWEAK_LEN);
    unsigned char cryptmt_iv[CRYPTMT_IV_LEN];
    hc256_gen_bytes(&bc_x->hc_x, cryptmt_iv, CRYPTMT_IV_LEN);

    rc = skm_set_key(&bc_x->skein_x, key_x->skein_mac_key);
    check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);
    t3f_set_key(&bc_x->t3f_x, (uint64_t *)key_x->t3f_key,
                (uint64_t *)t3f_tweak);
    cmt_init();
    cmt_keysetup(&bc_x->cryptmt_x, key_x->cryptmt_key);
    cmt_ivsetup(&bc_x->cryptmt_x, cryptmt_iv);

    return rc;
}

void bc_reset_t3f_mt(bc_ctx_t *bc_x, key_ctx_t *key_x, unsigned char *t3f_tweak,
                     unsigned char *cryptmt_iv) {
    assert(bc_x != NULL);
    assert(key_x != NULL);
    assert(t3f_tweak != NULL);
    assert(cryptmt_iv != NULL);

    t3f_set_key(&bc_x->t3f_x, (uint64_t *)key_x->t3f_key,
                (uint64_t *)t3f_tweak);
    cmt_ivsetup(&bc_x->cryptmt_x, cryptmt_iv);
}

int bc_encrypt(bc_ctx_t *bc_x, unsigned char *input, size_t in_len,
               unsigned char *output) {
    assert(bc_x != NULL);
    assert(input != NULL);
    assert(output != NULL);
    assert(in_len <= T3C_MAX_BLOCK_LEN);

    int rc = CCLONE_SUCCESS;

    _cleanup_free_ unsigned char *t3f_out = malloc(in_len);
    check_if_log(t3f_out == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    t3c_encrypt(&bc_x->t3f_x, &bc_x->hc_x, input, in_len, t3f_out);
    _cleanup_free_ unsigned char *cryptmt_out = malloc(in_len);
    check_if_log(cryptmt_out == NULL,
                 log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    cmt_encrypt(&bc_x->cryptmt_x, t3f_out, cryptmt_out, in_len);
    _cleanup_free_ unsigned char *skein_mac = malloc(SKEIN_MAC_LEN);
    check_if_log(skein_mac == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    rc = skm_hash(&bc_x->skein_x, cryptmt_out, in_len, skein_mac);
    check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);

    memcpy(output, skein_mac, SKEIN_MAC_LEN);
    memcpy(&output[SKEIN_MAC_LEN], cryptmt_out, in_len);

    return rc;
}

int bc_decrypt(bc_ctx_t *bc_x, unsigned char *input, size_t in_len,
               unsigned char *output) {
    assert(bc_x != NULL);
    assert(input != NULL);
    assert(output != NULL);
    assert(in_len <= T3C_MAX_BLOCK_LEN + SKEIN_MAC_LEN);
    assert(in_len > SKEIN_MAC_LEN);

    int rc = CCLONE_SUCCESS;
    uint32_t output_len = in_len - SKEIN_MAC_LEN;

    _cleanup_free_ unsigned char *skein_mac = malloc(SKEIN_MAC_LEN);
    check_if_log(skein_mac == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    rc = skm_hash(&bc_x->skein_x, &input[SKEIN_MAC_LEN], output_len, skein_mac);
    check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);
    rc = memcmp(input, skein_mac, SKEIN_MAC_LEN);
    check_if_log(rc != CCLONE_SUCCESS,
                 log_error("%s", rc_msg(CCLONE_INVALID_SKEIN_MAC_ERR)),
                 return CCLONE_INVALID_SKEIN_MAC_ERR);

    _cleanup_free_ unsigned char *cryptmt_out = malloc(output_len);
    check_if_log(cryptmt_out == NULL,
                 log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    cmt_decrypt(&bc_x->cryptmt_x, &input[SKEIN_MAC_LEN], cryptmt_out,
                output_len);
    t3c_decrypt(&bc_x->t3f_x, &bc_x->hc_x, cryptmt_out, output_len, output);

    return rc;
}