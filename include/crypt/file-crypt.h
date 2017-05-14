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

#ifndef __FILE_CRYPT_H__
#define __FILE_CRYPT_H__

#include "crypt/block-crypt.h"

#define ZBASE32_FILENAME_LEN 64U
#define ZBASE32_FILENAME_ENCODE_LEN 40U

struct file_header_t {
    unsigned char enc_filename_len[4];
    unsigned char enc_filename[128 + 256];
    unsigned char zbase32_enc_filename[ZBASE32_FILENAME_LEN + 1];
};
typedef struct file_header_t file_header_t;

int fc_encrypt_header(bc_ctx_t *bc_x, file_header_t *header, char *filename,
                      size_t filename_len);
int fc_decrypt_header(bc_ctx_t *bc_x, file_header_t *header, char *filename);

int fc_write_header(file_header_t *header, key_ctx_t *key_x, FILE *out_file);

int fc_encrypt(bc_ctx_t *bc_x, file_header_t *header, key_ctx_t *key_x,
               FILE *in_file, FILE *out_file);
int fc_read_header(file_header_t *header, key_ctx_t *key_x, FILE *in_file);
int fc_decrypt(bc_ctx_t *bc_x, file_header_t *header, key_ctx_t *key_x,
               FILE *in_file, FILE *out_file);

#endif //__FILE_CRYPT_H__
