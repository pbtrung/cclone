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

#include "curl/curl.h"

static void test_curl();

static size_t wrfu(void *ptr, size_t size, size_t nmemb, void *stream) {
    (void)stream;
    (void)ptr;
    return size * nmemb;
}

static void test_curl() {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.trungbpham.com/");

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wrfu);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

        res = curl_easy_perform(curl);

        if (!res) {
            union {
                struct curl_slist *to_info;
                struct curl_certinfo *to_certinfo;
            } ptr;

            ptr.to_info = NULL;

            res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ptr.to_info);
            sput_fail_unless(!res && ptr.to_info, "test_curl");
            // curl_slist_free_all(ptr.to_info);

            // if (!res && ptr.to_info) {
            //     int i;

            //     printf("%d certs!\n", ptr.to_certinfo->num_of_certs);

            //     for (i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
            //         struct curl_slist *slist;

            //         for (slist = ptr.to_certinfo->certinfo[i]; slist;
            //              slist = slist->next)
            //             printf("%s\n", slist->data);
            //     }
            // }
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}