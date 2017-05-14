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
#include <stdio.h>

#include "crypt/file-crypt.h"
#include "crypt/threefish-ctr.h"
#include "log.h"
#include "macro.h"
#include "rc.h"
#include "utils/cleanup.h"
#include "utils/convert.h"
#include "utils/zbase32.h"

int fc_encrypt_header(bc_ctx_t *bc_x, file_header_t *header, char *filename,
                      size_t filename_len) {
    assert(bc_x != NULL);
    assert(filename != NULL);
    assert(header != NULL);

    int rc = CCLONE_SUCCESS;
    rc = bc_encrypt(bc_x, (unsigned char *)filename, filename_len,
                    header->enc_filename);
    check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);
    rc = zbase32_encode(header->zbase32_enc_filename, header->enc_filename,
                        ZBASE32_FILENAME_ENCODE_LEN * 8);
    check_if_log(rc <= CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);
    header->zbase32_enc_filename[ZBASE32_FILENAME_LEN] = '\0';
    cvt_u32_le_from_ul(header->enc_filename_len,
                       (unsigned long)(filename_len + SKEIN_MAC_LEN));
    return rc;
}

int fc_decrypt_header(bc_ctx_t *bc_x, file_header_t *header, char *filename) {
    assert(bc_x != NULL);
    assert(filename != NULL);
    assert(header != NULL);

    int rc = CCLONE_SUCCESS;
    uint32_t enc_filename_len = cvt_ul_from_u32_le(header->enc_filename_len);
    rc = bc_decrypt(bc_x, header->enc_filename, enc_filename_len,
                    (unsigned char *)filename);
    check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);
    return rc;
}

int fc_write_header(file_header_t *header, key_ctx_t *key_x, FILE *out_file) {
    int rc = CCLONE_SUCCESS;

    uint32_t write_len = CCLONE_SALT_LEN;
    write_len = fwrite(key_x->salt, 1, write_len, out_file);
    check_if_log(write_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                 return CCLONE_FILEIO_ERR);
    write_len = 4;
    write_len = fwrite(header->enc_filename_len, 1, write_len, out_file);
    check_if_log(write_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                 return CCLONE_FILEIO_ERR);
    write_len = cvt_ul_from_u32_le(header->enc_filename_len);
    write_len = fwrite(header->enc_filename, 1, write_len, out_file);
    check_if_log(write_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                 return CCLONE_FILEIO_ERR);

    return rc;
}

int fc_encrypt(bc_ctx_t *bc_x, file_header_t *header, key_ctx_t *key_x,
               FILE *in_file, FILE *out_file) {
    assert(bc_x != NULL);
    assert(in_file != NULL);
    assert(out_file != NULL);
    assert(header != NULL);

    int rc = CCLONE_SUCCESS;

    uint32_t read_len = T3C_MAX_BLOCK_LEN;
    uint32_t write_len = T3C_MAX_BLOCK_LEN + SKEIN_MAC_LEN;
    _cleanup_free_ unsigned char *in_buf = malloc(read_len);
    check_if_log(in_buf == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    _cleanup_free_ unsigned char *out_buf = malloc(write_len);
    check_if_log(out_buf == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    _cleanup_free_ unsigned char *t3f_tweak = malloc(THREEFISH_TWEAK_LEN);
    check_if_log(t3f_tweak == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    _cleanup_free_ unsigned char *cryptmt_iv = malloc(CRYPTMT_IV_LEN);
    check_if_log(cryptmt_iv == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);

    rc = fc_write_header(header, key_x, out_file);
    check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)), return rc);

    while (read_len == T3C_MAX_BLOCK_LEN) {
        read_len = fread(in_buf, 1, read_len, in_file);
        check_if_log(read_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                     return CCLONE_FILEIO_ERR);

        hc256_gen_bytes(&bc_x->hc_x, t3f_tweak, THREEFISH_TWEAK_LEN);
        hc256_gen_bytes(&bc_x->hc_x, cryptmt_iv, CRYPTMT_IV_LEN);
        bc_reset_t3f_mt(bc_x, key_x, t3f_tweak, cryptmt_iv);
        rc = bc_encrypt(bc_x, in_buf, read_len, out_buf);
        check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)),
                     return rc);
        write_len = read_len + SKEIN_MAC_LEN;
        write_len = fwrite(out_buf, 1, write_len, out_file);
        check_if_log(write_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                     return CCLONE_FILEIO_ERR);
    }

    return rc;
}

int fc_read_header(file_header_t *header, key_ctx_t *key_x, FILE *in_file) {
    int rc = CCLONE_SUCCESS;

    uint32_t read_len = CCLONE_SALT_LEN;
    read_len = fread(key_x->salt, 1, read_len, in_file);
    check_if_log(read_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                 return CCLONE_FILEIO_ERR);
    read_len = 4;
    read_len = fread(header->enc_filename_len, 1, read_len, in_file);
    check_if_log(read_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                 return CCLONE_FILEIO_ERR);
    read_len = cvt_ul_from_u32_le(header->enc_filename_len);
    read_len = fread(header->enc_filename, 1, read_len, in_file);
    check_if_log(read_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                 return CCLONE_FILEIO_ERR);

    return rc;
}

int fc_decrypt(bc_ctx_t *bc_x, file_header_t *header, key_ctx_t *key_x,
               FILE *in_file, FILE *out_file) {
    assert(bc_x != NULL);
    assert(header != NULL);
    assert(key_x != NULL);
    assert(in_file != NULL);
    assert(out_file != NULL);

    int rc = CCLONE_SUCCESS;

    uint32_t read_len = T3C_MAX_BLOCK_LEN + SKEIN_MAC_LEN;
    uint32_t write_len = T3C_MAX_BLOCK_LEN;
    _cleanup_free_ unsigned char *in_buf = malloc(read_len);
    check_if_log(in_buf == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    _cleanup_free_ unsigned char *out_buf = malloc(write_len);
    check_if_log(out_buf == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    _cleanup_free_ unsigned char *t3f_tweak = malloc(THREEFISH_TWEAK_LEN);
    check_if_log(t3f_tweak == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);
    _cleanup_free_ unsigned char *cryptmt_iv = malloc(CRYPTMT_IV_LEN);
    check_if_log(cryptmt_iv == NULL, log_error("%s", rc_msg(CCLONE_MALLOC_ERR)),
                 return CCLONE_MALLOC_ERR);

    while (read_len == T3C_MAX_BLOCK_LEN + SKEIN_MAC_LEN) {
        read_len = fread(in_buf, 1, read_len, in_file);
        check_if_log(read_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                     return CCLONE_FILEIO_ERR);

        hc256_gen_bytes(&bc_x->hc_x, t3f_tweak, THREEFISH_TWEAK_LEN);
        hc256_gen_bytes(&bc_x->hc_x, cryptmt_iv, CRYPTMT_IV_LEN);
        bc_reset_t3f_mt(bc_x, key_x, t3f_tweak, cryptmt_iv);
        rc = bc_decrypt(bc_x, in_buf, read_len, out_buf);
        check_if_log(rc != CCLONE_SUCCESS, log_error("%s", rc_msg(rc)),
                     return rc);
        write_len = read_len - SKEIN_MAC_LEN;
        write_len = fwrite(out_buf, 1, write_len, out_file);
        check_if_log(write_len <= 0, log_error("%s", rc_msg(CCLONE_FILEIO_ERR)),
                     return CCLONE_FILEIO_ERR);
    }

    return rc;
}