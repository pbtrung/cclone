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

#include "crypt/skein-mac.h"
#include "log.h"
#include "macro.h"
#include "rc.h"

int skm_set_key(SkeinCtx_t *skein_x, const unsigned char *skein_mac_key) {
    assert(skein_x != NULL);
    assert(skein_mac_key != NULL);

    int rc = CCLONE_SUCCESS;
    rc = skeinCtxPrepare(skein_x, Skein1024);
    check_if_log(rc != CCLONE_SUCCESS,
                 log_error("%s", rc_msg(CCLONE_SKEIN_ERR)),
                 return CCLONE_SKEIN_ERR);
    rc = skeinMacInit(skein_x, skein_mac_key, SKEIN_MAC_KEY_LEN, Skein1024);
    check_if_log(rc != CCLONE_SUCCESS,
                 log_error("%s", rc_msg(CCLONE_SKEIN_ERR)),
                 return CCLONE_SKEIN_ERR);
    return rc;
}

void skm_reset(SkeinCtx_t *skein_x) {
    assert(skein_x != NULL);
    skeinReset(skein_x);
}

int skm_hash(SkeinCtx_t *skein_x, const unsigned char *input, size_t in_len,
             unsigned char *output) {
    assert(skein_x != NULL);
    assert(input != NULL);
    assert(output != NULL);

    int rc = CCLONE_SUCCESS;
    rc = skeinUpdate(skein_x, input, in_len);
    check_if_log(rc != CCLONE_SUCCESS,
                 log_error("%s", rc_msg(CCLONE_SKEIN_ERR)),
                 return CCLONE_SKEIN_ERR);
    rc = skeinFinal(skein_x, output);
    check_if_log(rc != CCLONE_SUCCESS,
                 log_error("%s", rc_msg(CCLONE_SKEIN_ERR)),
                 return CCLONE_SKEIN_ERR);
    return rc;
}