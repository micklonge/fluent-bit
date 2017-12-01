/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <msgpack.h>

#include "logformat_meta.h"
#include "logformat_conf.h"

static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    struct flb_logformat_pod_info *meta = data;

    if (meta->podname == NULL && strcmp((char *) name, "pod_name") == 0) {
        meta->podname = flb_strndup((char *) value, vlen);
        meta->podname_len = vlen;
    } else if (meta->namespace == NULL &&
             strcmp((char *) name, "namespace_name") == 0) {
        meta->namespace = flb_strndup((char *) value, vlen);
        meta->namespace_len = vlen;
    } else if (meta->dockerid == NULL &&
    		strcmp((char *) name, "docker_id") == 0) {
    	meta->dockerid = flb_strndup((char *) value, vlen);
    	meta->dockerid_len = vlen;
    }
}

static inline int tag_to_meta(struct flb_logformat *ctx, char *tag, int tag_len,
                              struct flb_logformat_pod_info *meta)
{
    ssize_t n;
    struct flb_regex_search result;

    meta->podname = NULL;
    meta->namespace = NULL;
    meta->dockerid = NULL;

    n = flb_regex_do(ctx->regex_tag, (unsigned char *) tag, tag_len, &result);
    if (n <= 0) {
        return -1;
    }

    /* Parse the regex results */
    flb_regex_parse(ctx->regex_tag, &result, cb_results, meta);

    return 0;
}

/* Initialize local context */
int flb_logformat_meta_init(struct flb_logformat *ctx, struct flb_config *config)
{
    return 0;
}

int flb_logformat_meta_get(struct flb_logformat *ctx,
                      char *tag, int tag_len,
                      struct flb_logformat_pod_info *logformat_pod_info)
{
    int ret;

    if (logformat_pod_info == NULL) {
    	return -1;
    }

    /* Get meta from the tag (cache key is the important one) */
    ret = tag_to_meta(ctx, tag, tag_len, logformat_pod_info);
    if (ret != 0) {
        return -1;
    }

    return 0;
}
