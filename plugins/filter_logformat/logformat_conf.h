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

#ifndef FLB_FILTER_LOGFORMAT_CONF_H
#define FLB_FILTER_LOGFORMAT_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_heap.h>
#include <fluent-bit/flb_hash.h>

#include "logformat_log.h"

#define FLB_LOGFORMAT_LOG_TYPE_POD     "k8s-pod"
#define FLB_LOGFORMAT_LOG_TYPE_SYSTEM  "k8s-system"

#define FLB_LOGFORMAT_HASH_SIZE  2048  /* 2KB */
#define FLB_LOGFORMAT_HEAP_SIZE  2000  /* 2KB */

/*
 * When merging nested JSON strings from Docker logs, we need a temporal
 * buffer to perform the convertion. To optimize the process, we pre-allocate
 * a buffer for that purpose. The FLB_MERGE_BUF_SIZE defines the buffer size.
 *
 * Note: this is only the initial buffer size, it can grow depending on needs
 * for every incoming json-string.
 */
#define FLB_MERGE_BUF_SIZE  2048  /* 2KB */

struct logformat_meta;

struct flb_logformat_tag {
	uint64_t lastUpdateTime;
	char *tag;
};

struct flb_logformat_pod_info {
	int namespace_len;
	char *namespace;

	int podname_len;
	char *podname;

	int dockerid_len;
	char *dockerid;

	char token_len;
	char *token;

    struct flb_regex *regex;
    struct flb_logformat_log_format *logformat_log_format;
};

struct flb_logformat_hash_item {
	//struct flb_logformat_tag *logformat_tag;
	struct flb_heap_item *heap_item;
	struct flb_logformat_pod_info *logformat_pod_info;
};

/* Filter context */
struct flb_logformat {
    struct flb_config *config;

    // system
    struct flb_logformat_pod_info *logformat_pod_info;

    // pod
    struct flb_regex *regex_tag;
    struct flb_hash *hashTable;         // key:flb_logformat_pod_info
    struct flb_heap *heap;

    int dockerconfig_len;
	char *dockerconfig;
};

struct flb_logformat_pod_info *flb_logformat_pod_info_create();
void flb_logformat_pod_info_destroy(struct flb_logformat_pod_info *logformat_pod_info);

int flb_logformat_tag_cmp(struct flb_logformat_tag *tag1, struct flb_logformat_tag *tag2);
void flb_logformat_tag_destroy(struct flb_logformat_tag* logformat_tag);
struct flb_logformat_tag* flb_logformat_tag_create(char *tag);

struct flb_logformat_hash_item* flb_logformat_hash_item_create();
void flb_logformat_hash_item_destroy(struct flb_logformat *ctx, struct flb_logformat_hash_item *hash_item);

struct flb_logformat *flb_logformat_conf_create(struct flb_filter_instance *i,
                                      struct flb_config *config);
void flb_logformat_conf_destroy(struct flb_logformat *ctx);

#endif
