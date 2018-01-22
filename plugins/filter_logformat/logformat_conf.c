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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#ifndef FLB_HAVE_TLS
#error "Fluent Bit was built without TLS support"
#endif

#include "logformat_log.h"
#include "logformat_regex.h"
#include "logformat_meta.h"
#include "logformat_conf.h"

struct flb_logformat_pod_info *flb_logformat_pod_info_create() {
	struct flb_logformat_pod_info *logformat_pod_info = NULL;

	logformat_pod_info = flb_calloc(1, sizeof(struct flb_logformat_pod_info));
	if (!logformat_pod_info) {
		flb_errno();
		return NULL;
	}

	return logformat_pod_info;
}

void flb_logformat_pod_info_destroy(struct flb_logformat_pod_info *logformat_pod_info) {
	if (logformat_pod_info == NULL) {
		return;
	}

	if (logformat_pod_info->namespace) {
		flb_free(logformat_pod_info->namespace);
		logformat_pod_info->namespace = NULL;
	}

	if (logformat_pod_info->podname) {
		flb_free(logformat_pod_info->podname);
		logformat_pod_info->podname = NULL;
	}

	if (logformat_pod_info->dockerid) {
		flb_free(logformat_pod_info->dockerid);
		logformat_pod_info->dockerid = NULL;
	}

	if (logformat_pod_info->token) {
		flb_free(logformat_pod_info->token);
		logformat_pod_info->token = NULL;
	}

	if (logformat_pod_info->regex) {
		flb_regex_destroy(logformat_pod_info->regex);
		logformat_pod_info->regex = NULL;
	}

	if (logformat_pod_info->logformat_log_format) {
		flb_logformat_log_format_desctroy(logformat_pod_info->logformat_log_format);
		logformat_pod_info->logformat_log_format = NULL;
	}

	flb_free(logformat_pod_info);
}

int flb_logformat_tag_cmp(struct flb_logformat_tag *tag1, struct flb_logformat_tag *tag2) {
	if (tag1 == NULL || tag2 == NULL) {
		return 0;
	}

	return tag1->lastUpdateTime - tag2->lastUpdateTime;
}

void flb_logformat_tag_destroy(struct flb_logformat_tag* logformat_tag) {
	if (logformat_tag == NULL) {
		return;
	}

	if (logformat_tag->tag != NULL) {
		flb_free(logformat_tag->tag);
	}

	flb_free(logformat_tag);
}

struct flb_logformat_tag* flb_logformat_tag_create(char *tag) {
	struct flb_logformat_tag *logformat_tag = NULL;

	logformat_tag = flb_calloc(1, sizeof(struct flb_logformat_tag));
	if (logformat_tag == NULL) {
		flb_errno();
		return NULL;
	}

	logformat_tag->tag = flb_strdup(tag);
	if (logformat_tag->tag == NULL) {
		flb_logformat_tag_destroy(logformat_tag);
		return NULL;
	}
	logformat_tag->lastUpdateTime = getCurrentSeconds();

	return logformat_tag;
}

struct flb_logformat *flb_logformat_conf_create(struct flb_filter_instance *ins,
                                      struct flb_config *config)
{
	char *tmp;

    struct flb_logformat *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_logformat));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->config = config;

    tmp = flb_filter_get_property("Type", ins);
    if (tmp) {
    	if (strcmp(tmp, FLB_LOGFORMAT_LOG_TYPE_POD) == 0) {
    		/* Initialize regex context */
    		ctx->regex_tag = flb_logformat_regex_init_tag();
			if (ctx->regex_tag == NULL) {
				flb_logformat_conf_destroy(ctx);
				return NULL;
			}

			ctx->hashTable = flb_hash_create(FLB_HASH_EVICT_NONE, FLB_LOGFORMAT_HASH_SIZE, -1, (void (*)(void *))flb_logformat_pod_info_destroy);
			if (ctx->hashTable == NULL) {
				flb_logformat_conf_destroy(ctx);
				return NULL;
			}

			ctx->heap = flb_heap_create(FLB_LOGFORMAT_HEAP_SIZE, (int (*)(void *, void *))flb_logformat_tag_cmp, (void (*)(void *))flb_logformat_tag_destroy);
			if (ctx->heap == NULL) {
				flb_logformat_conf_destroy(ctx);
				return NULL;
			}

			tmp = flb_filter_get_property("DockerConfig", ins);
			if (tmp) {
				ctx->dockerconfig = flb_strdup(tmp);
				if (ctx->dockerconfig == NULL) {
					flb_logformat_conf_destroy(ctx);
					return NULL;
				}
				flb_info("DockerConfig: %s", tmp);
				ctx->dockerconfig_len = strlen(tmp);
			} else {
				ctx->dockerconfig = NULL;
			}
    	} else if (strcmp(tmp, FLB_LOGFORMAT_LOG_TYPE_SYSTEM) == 0) {
    		ctx->logformat_pod_info = flb_logformat_pod_info_create();
			if (!ctx->logformat_pod_info) {
				flb_logformat_conf_destroy(ctx);
				return NULL;
			}

			tmp = flb_filter_get_property("Regex", ins);
			if (tmp) {
				ctx->logformat_pod_info->regex = flb_logformat_regex_init_userdefined(tmp);
				if (ctx->logformat_pod_info->regex == NULL) {
					flb_logformat_conf_destroy(ctx);
					return NULL;
				}
				flb_info("Regex: %s", tmp);
			} else {
				ctx->logformat_pod_info->regex = NULL;
			}

			tmp = flb_filter_get_property("Format", ins);
			if (tmp) {
				ctx->logformat_pod_info->logformat_log_format = flb_logformat_log_format_create(tmp);
				if (ctx->logformat_pod_info->logformat_log_format == NULL) {
					flb_logformat_conf_destroy(ctx);
					return NULL;
				}
				flb_info("Format: %s", tmp);
			} else {
				ctx->logformat_pod_info->logformat_log_format = NULL;
			}

			tmp = flb_filter_get_property("Token", ins);
			if (tmp) {
				ctx->logformat_pod_info->token = flb_strdup(tmp);
				if (ctx->logformat_pod_info->token == NULL) {
					flb_logformat_conf_destroy(ctx);
					return NULL;
				}
				ctx->logformat_pod_info->token_len = strlen(tmp);
				flb_info("gatewaytoken: %s", tmp);
			} else {
				ctx->logformat_pod_info->token = NULL;
			}
    	} else {
    		flb_logformat_conf_destroy(ctx);
    		flb_error("[filter_logformat], Type is not expected, it is %s", tmp);
			return NULL;
    	}
	} else {
		flb_logformat_conf_destroy(ctx);
		flb_error("[filter_logformat], Type is expected");
		return NULL;
	}

    return ctx;
}

void flb_logformat_conf_destroy(struct flb_logformat *ctx)
{
	if (ctx->logformat_pod_info != NULL) {
		flb_logformat_pod_info_destroy(ctx->logformat_pod_info);
	}

    if (ctx->regex_tag) {
        flb_regex_destroy(ctx->regex_tag);
    }

    if (ctx->hashTable != NULL) {
    	flb_hash_destroy(ctx->hashTable);
    }

    if (ctx->heap != NULL) {
    	flb_heap_destroy(ctx->heap);
    }

    if (ctx->dockerconfig) {
		flb_free(ctx->dockerconfig);
		ctx->dockerconfig = NULL;
	}

    flb_free(ctx);
}

struct flb_logformat_hash_item* flb_logformat_hash_item_create() {
	struct flb_logformat_hash_item *hash_item = NULL;

	hash_item = flb_calloc(1, sizeof(struct flb_logformat_hash_item));
	if (hash_item == NULL) {
		flb_errno();
		return NULL;
	}

	hash_item->heap_item = NULL;
	hash_item->logformat_pod_info = NULL;

	return hash_item;
}

void flb_logformat_hash_item_destroy(struct flb_logformat *ctx, struct flb_logformat_hash_item *hash_item) {
	if (hash_item == NULL) {
		return;
	}

	flb_logformat_pod_info_destroy(hash_item->logformat_pod_info);
	flb_heap_item_destroy(ctx->heap, hash_item->heap_item);

	flb_free(hash_item);
}
