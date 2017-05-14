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

#include "argon2/argon2.h"
#include "crypt/key.h"
#include "log.h"
#include "macro.h"
#include "rc.h"

int key_derive(key_ctx_t *key_x, const unsigned char *pwd,
               const unsigned char *salt, uint32_t t, uint32_t m, uint32_t p) {
    assert(pwd != NULL);
    assert(salt != NULL);
    // assert(t >= 6 && m >= (1 << 15) && p >= 1);
    assert(key_x != NULL);

    int rc = CCLONE_SUCCESS;
    unsigned char hash[CCLONE_HASH_LEN];

    // n-pass computation t = 8
    // 128 mebibytes memory usage m = (1 << 17)
    // number of threads and lanes p = 2
    rc = argon2i_hash_raw(t, m, p, pwd, CCLONE_PWD_LEN, salt, CCLONE_SALT_LEN,
                          hash, CCLONE_HASH_LEN);
    check_if_log(rc != CCLONE_SUCCESS,
                 log_error("%s", rc_msg(CCLONE_ARGON2_ERR)),
                 return CCLONE_ARGON2_ERR);

    memcpy(key_x->salt, salt, CCLONE_SALT_LEN);
    memcpy(key_x->t3f_key, hash, THREEFISH_KEY_LEN);
    memcpy(key_x->hc256_kiv, &hash[THREEFISH_KEY_LEN], HC256_KIV_LEN);
    memcpy(key_x->cryptmt_key, &hash[THREEFISH_KEY_LEN + HC256_KIV_LEN],
           CRYPTMT_KEY_LEN);
    memcpy(key_x->skein_mac_key,
           &hash[THREEFISH_KEY_LEN + HC256_KIV_LEN + SKEIN_MAC_KEY_LEN],
           SKEIN_MAC_KEY_LEN);

    return rc;
}