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

#include <string.h>

#include "crypt/file-crypt.h"
#include "log.h"
#include "macro.h"
#include "rc.h"
#include "utils/cleanup.h"
#include "utils/convert.h"
#include "utils/file.h"
//#include "utils/tinydir.h"

static void test_fc();
static void test_fc_encrypt();
static void test_fc_decrypt();
// static void test_fc_dir();

static void test_fc() {
    test_fc_encrypt();
    test_fc_decrypt();
    // test_fc_dir();
}

// void test_fc_dir_all(char *dirname, bc_ctx_t *bc_x, key_ctx_t *key_x) {
//     int rc = CCLONE_SUCCESS;
//     tinydir_dir dir;
//     if (tinydir_open(&dir, dirname) == -1) {
//         perror("Error opening file");
//     }
//     while (dir.has_next) {
//         tinydir_file file;
//         if (tinydir_readfile(&dir, &file) == -1) {
//             perror("Error getting file");
//         }

//         if (!file.is_dir) {
//             _cleanup_free_ file_header_t *header =
//                 malloc(sizeof(file_header_t));
//             rc = fc_encrypt_header(bc_x, header, file.name,
//             strlen(file.name));

//             _cleanup_fclose_ FILE *in_file = cclone_fopen((const char
//             *)file.path, "rb");
//             _cleanup_fclose_ FILE *out_file =
//                 cclone_fopen((const char *)header->zbase32_enc_filename,
//                 "wb");

//             rc = fc_encrypt(bc_x, header, key_x, in_file, out_file);
//         } else if (strcmp(file.name, ".") != 0 &&
//                    strcmp(file.name, "..") != 0) {
//             test_fc_dir_all(file.path, bc_x, key_x);
//         }

//         if (tinydir_next(&dir) == -1) {
//             perror("Error getting next file");
//         }
//     }

//     sput_fail_if(rc != CCLONE_SUCCESS, "test_fc_dir_all");
//     tinydir_close(&dir);
// }

// static void test_fc_dir() {
//     _cleanup_free_ key_ctx_t *key_x = malloc(sizeof(key_ctx_t));
//     _cleanup_free_ bc_ctx_t *bc_x = malloc(sizeof(bc_ctx_t));

//     _cleanup_free_ unsigned char *pwd =
//         calloc(CCLONE_PWD_LEN, sizeof(unsigned char));
//     _cleanup_free_ unsigned char *salt =
//         calloc(CCLONE_SALT_LEN, sizeof(unsigned char));

//     key_derive(key_x, pwd, salt, 3, 1 << 6, 2);
//     bc_prepare(bc_x, key_x);

//     test_fc_dir_all("./test", bc_x, key_x);
// }

static void test_fc_encrypt() {
    int rc = CCLONE_SUCCESS;

    _cleanup_free_ key_ctx_t *key_x = malloc(sizeof(key_ctx_t));
    _cleanup_free_ bc_ctx_t *bc_x = malloc(sizeof(bc_ctx_t));

    _cleanup_free_ unsigned char *pwd =
        calloc(CCLONE_PWD_LEN, sizeof(unsigned char));
    _cleanup_free_ unsigned char *salt =
        calloc(CCLONE_SALT_LEN, sizeof(unsigned char));

    key_derive(key_x, pwd, salt, 3, 1 << 6, 2);
    bc_prepare(bc_x, key_x);

#ifdef _WIN32
    char *filename = "test-cclone.exe";
#else
    char *filename = "test-cclone";
#endif

    _cleanup_fclose_ FILE *in_file = cclone_fopen(filename, "rb");
    _cleanup_fclose_ FILE *out_file = cclone_fopen("test-cclone.enc", "wb");

    _cleanup_free_ file_header_t *header = malloc(sizeof(file_header_t));
    rc = fc_encrypt_header(bc_x, header, filename, strlen(filename));
    sput_fail_if(rc <= CCLONE_SUCCESS, "fc_encrypt_header");

    rc = fc_encrypt(bc_x, header, key_x, in_file, out_file);
    sput_fail_if(rc != CCLONE_SUCCESS, "fc_encrypt");
}

static void test_fc_decrypt() {
    int rc = CCLONE_SUCCESS;

    _cleanup_free_ key_ctx_t *key_x = malloc(sizeof(key_ctx_t));
    _cleanup_free_ bc_ctx_t *bc_x = malloc(sizeof(bc_ctx_t));
    _cleanup_free_ file_header_t *header = malloc(sizeof(file_header_t));

    _cleanup_free_ unsigned char *pwd =
        calloc(CCLONE_PWD_LEN, sizeof(unsigned char));

    char *filename = "test-cclone.enc";
    _cleanup_fclose_ FILE *in_file = cclone_fopen(filename, "rb");
    rc = fc_read_header(header, key_x, in_file);
    sput_fail_if(rc != CCLONE_SUCCESS, "fc_read_header");

    key_derive(key_x, pwd, key_x->salt, 3, 1 << 6, 2);
    bc_prepare(bc_x, key_x);

#ifdef _WIN32
    char *orig_filename = "test-cclone.exe";
#else
    char *orig_filename = "test-cclone";
#endif

    uint32_t enc_filename_len =
        cvt_ul_from_u32_le(header->enc_filename_len) - SKEIN_MAC_LEN;
    _cleanup_free_ char *dec_filename =
        calloc(enc_filename_len, sizeof(unsigned char));
    fc_decrypt_header(bc_x, header, dec_filename);
    rc = memcmp(dec_filename, orig_filename, enc_filename_len);
    sput_fail_if(rc != CCLONE_SUCCESS,
                 "fc_decrypt_header: Compare input and decrypted");

    _cleanup_fclose_ FILE *out_file = cclone_fopen("test-cclone.enc.dec", "wb");

    rc = fc_decrypt(bc_x, header, key_x, in_file, out_file);
    sput_fail_if(rc != CCLONE_SUCCESS, "fc_decrypt");
}