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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_heap.h>
#include <fluent-bit/flb_pack.h>

#include <monkey/mk_core.h>

#include <stdio.h>
#include <msgpack.h>
#include "logformat_conf.h"
#include "logformat_meta.h"
#include "logformat_regex.h"

static int cb_logformat_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    struct flb_logformat *ctx;
    (void) data;

    /* Create configuration context */
    ctx = flb_logformat_conf_create(f_ins, config);
    if (!ctx) {
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    flb_logformat_meta_init(ctx, config);

    return 0;
}

static int pack_map_content(msgpack_packer *pck, msgpack_sbuffer *sbuf,
                            msgpack_object source_map,
							struct flb_logformat_pod_info *logformat_pod_info, char* token, int token_len,
							struct flb_regex *regex, struct flb_logformat_log_format *logformat_log_format)
{
    int i;
    int len;
    int map_size;
    int new_map_size = 0;
    char log[102400];
    msgpack_object k;
    msgpack_object v;

    struct mk_list *head = NULL;
    struct flb_logformat_log_result_item *entry = NULL;

    struct flb_logformat_log_match_result* match_result = NULL;
    struct flb_logformat_log_result* logformat_log_result = NULL;

    /* Original map size */
    map_size = source_map.via.map.size;

    /* Determinate the size of the new map */
    new_map_size = map_size;

    /* logformat metadata */
    if (logformat_pod_info != NULL) {
    	if (logformat_pod_info->namespace != NULL) {
    		new_map_size++;
    	}

    	if (logformat_pod_info->podname != NULL) {
    		new_map_size++;
    	}
    }

    if (token != NULL) {
    	new_map_size++;
    }

    log[0] = '\0';
    for (i = 0; i < map_size; i++) {
		k = source_map.via.map.ptr[i].key;
		if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "stream", 6) == 0) {
			new_map_size--;
		} else if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "time", 4) == 0) {
			new_map_size--;
		} else if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "log", 3) == 0 && regex != NULL && logformat_log_format != NULL) {
			memcpy(log, source_map.via.map.ptr[i].val.via.str.ptr, source_map.via.map.ptr[i].val.via.str.size);
			log[source_map.via.map.ptr[i].val.via.str.size - 1] = '\0';
		}
	}

    if (strlen(log) > 0) {
    	match_result = flb_logformat_log_match_result_create(log, regex);

    	if (match_result != NULL) {
    		logformat_log_result = flb_logformat_log_result_create(match_result, logformat_log_format);
    		if (logformat_log_result != NULL) {
    			new_map_size = new_map_size + logformat_log_result->count - 1;
    		}

    		flb_logformat_log_match_result_desctroy(match_result);
    		match_result = NULL;
    	}
    }

    msgpack_pack_map(pck, new_map_size);

    /* Original map */
    for (i = 0; i < map_size; i++) {
        k = source_map.via.map.ptr[i].key;
        v = source_map.via.map.ptr[i].val;
        if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "stream", 6) == 0) {
        	continue;
        } else if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "time", 4) == 0) {
        	continue;
        } else if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "log", 3) == 0) {
        	if (logformat_log_result != NULL) {
        		/* Iterate entries */
				mk_list_foreach(head, &logformat_log_result->chains) {
					entry = mk_list_entry(head, struct flb_logformat_log_result_item, _head);
					if (entry->name != NULL && entry->val != NULL) {
						msgpack_pack_str(pck, entry->name_len);
						msgpack_pack_str_body(pck, entry->name, entry->name_len);

						msgpack_pack_str(pck, entry->val_len);
						msgpack_pack_str_body(pck, entry->val, entry->val_len);
					}

					entry = NULL;
				}

        		flb_logformat_log_result_desctroy(logformat_log_result);
        		continue;
        	}
        }
        msgpack_pack_object(pck, k);
        msgpack_pack_object(pck, v);
    }

    /* logformat */
    if (logformat_pod_info != NULL) {
    	if (logformat_pod_info->namespace != NULL) {
    		len = strlen("nameSpace");
    		msgpack_pack_str(pck, len);
    		msgpack_pack_str_body(pck, "nameSpace", len);
    		msgpack_pack_str(pck, logformat_pod_info->namespace_len);
    		msgpack_pack_str_body(pck, logformat_pod_info->namespace, logformat_pod_info->namespace_len);
    	}

    	if (logformat_pod_info->podname != NULL) {
    		len = strlen("podName");
    		msgpack_pack_str(pck, len);
    		msgpack_pack_str_body(pck, "podName", len);
    		msgpack_pack_str(pck, logformat_pod_info->podname_len);
    		msgpack_pack_str_body(pck, logformat_pod_info->podname, logformat_pod_info->podname_len);
    	}
    }

    if (token != NULL) {
    	len = strlen("token");
    	msgpack_pack_str(pck, len);
		msgpack_pack_str_body(pck, "token", len);
		msgpack_pack_str(pck, token_len);
		msgpack_pack_str_body(pck, token, token_len);
    }

    return 0;
}

static int cb_logformat_filter_system(void *data, size_t bytes,
        char *tag, int tag_len,
        void **out_buf, size_t *out_bytes,
        struct flb_filter_instance *f_ins,
        void *filter_context,
        struct flb_config *config) {
	int ret;
	size_t off = 0;
	msgpack_unpacked result;
	msgpack_object time;
	msgpack_object map;
	msgpack_object root;
	msgpack_sbuffer tmp_sbuf;
	msgpack_packer tmp_pck;
	struct flb_logformat *ctx = filter_context;
	(void) f_ins;
	(void) config;

	/* Create temporal msgpack buffer */
	msgpack_sbuffer_init(&tmp_sbuf);
	msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

	/* Iterate each item array and append meta */
	msgpack_unpacked_init(&result);
	while (msgpack_unpack_next(&result, data, bytes, &off)) {
		root = result.data;
		if (root.type != MSGPACK_OBJECT_ARRAY) {
			continue;
		}

		/* get time and map */
		time = root.via.array.ptr[0];
		map  = root.via.array.ptr[1];

		/* Compose the new array */
		msgpack_pack_array(&tmp_pck, 2);
		msgpack_pack_object(&tmp_pck, time);

		ret = pack_map_content(&tmp_pck, &tmp_sbuf,
							   map, NULL, ctx->logformat_pod_info->token, ctx->logformat_pod_info->token_len,
							   ctx->logformat_pod_info->regex, ctx->logformat_pod_info->logformat_log_format);
		if (ret != 0) {
			msgpack_sbuffer_destroy(&tmp_sbuf);
			msgpack_unpacked_destroy(&result);
			return FLB_FILTER_NOTOUCH;
		}
	}
	msgpack_unpacked_destroy(&result);

	/* link new buffers */
	*out_buf   = tmp_sbuf.data;
	*out_bytes = tmp_sbuf.size;

	return FLB_FILTER_MODIFIED;
}

static int unescape_string(char *buf, int buf_len) {
    int i = 0;
    int j = 0;
    char *p;

    p = buf;

    while (i < buf_len) {
        if (buf[i] == '\\') {
            if (i < buf_len - 5) {
                if (buf[i + 1] == 'u' && buf[i + 2] == '0' && buf[i + 3] == '0' && buf[i + 4] == '3') {
                	if (buf[i + 5] == 'c') {
                		p[j++] = '<';
                		i += 6;
                		continue;
                	}

                	if (buf[i + 5] == 'e') {
                		p[j++] = '>';
                		i += 6;
                		continue;
                	}
                }
            }

            if (i < buf_len - 1) {
            	if (buf[i + 1] == '\\') {
            		i = i + 1;
            	}
            }
        }
        p[j++] = buf[i++];
    }
    p[j] = '\0';
    return j;
}


static struct flb_logformat_pod_info * build_tag_index(char *tag, int tag_len, void *filter_context) {
	struct flb_logformat *ctx = filter_context;

	char configPath[10240];

	size_t hash_item_size = 0;
	struct flb_logformat_tag *logformat_tag = NULL;
	struct flb_logformat_hash_item *hash_item = NULL;

	struct flb_heap_item *heap_item = NULL;

	int ret;

	char buf[10240];  /*缓冲区*/
	char *buf_ptr = NULL;
	char *buf_end = NULL;

	int configBufSize = 10240;
	char *pConfigBuf = NULL;

	FILE *fp = NULL;  /*文件指针*/

	flb_hash_get(ctx->hashTable, tag, strlen(tag), (char **)&hash_item, &hash_item_size);
	if (hash_item != 0) {   // change time index
		if (hash_item->heap_item != NULL) {
			logformat_tag = hash_item->heap_item->value;
			logformat_tag->lastUpdateTime = getCurrentSeconds();
			flb_heap_update(ctx->heap, hash_item->heap_item);
		}
	} else {
		hash_item = flb_logformat_hash_item_create();
		if (hash_item == NULL) {
			return NULL;
		}

		hash_item->logformat_pod_info = flb_logformat_pod_info_create();
		if (hash_item->logformat_pod_info == NULL) {
			flb_logformat_hash_item_destroy(ctx, hash_item);
			return NULL;
		}

		logformat_tag = flb_logformat_tag_create(tag);
		if (logformat_tag == NULL) {
			flb_logformat_hash_item_destroy(ctx, hash_item);
			return NULL;
		}

		heap_item = flb_heap_add(ctx->heap, logformat_tag);
		if (heap_item == NULL) {
			flb_logformat_hash_item_destroy(ctx, hash_item);
			return NULL;
		}
		hash_item->heap_item = heap_item;

		flb_logformat_meta_get(ctx, tag, tag_len, hash_item->logformat_pod_info);
		sprintf(configPath, "/data/docker/containers/%s/config.v2.json", hash_item->logformat_pod_info->dockerid);

		if((fp = fopen(configPath, "r")) == NULL) {
			flb_error("%s fail to open", configPath);
			flb_logformat_hash_item_destroy(ctx, hash_item);
			return NULL;
		}

		while(fgets(buf, 10240, fp) != NULL) {
			if (pConfigBuf == NULL) {
				pConfigBuf = flb_calloc(1, configBufSize);
				*pConfigBuf = '\0';
			} else {
				if (configBufSize < strlen(pConfigBuf) + strlen(buf)) {
					configBufSize = strlen(pConfigBuf) + strlen(buf) + 10240;
					pConfigBuf = flb_realloc(pConfigBuf, configBufSize);
				}
			}

			strcat(pConfigBuf, buf);
		}

		if (fp != NULL) {
			fclose(fp);
		}

		unescape_string(pConfigBuf, strlen(pConfigBuf));

		//flb_info("config json:%s", pConfigBuf);
		//flb_info("config size:%d\n", strlen(pConfigBuf));

		if ((buf_ptr = strstr(pConfigBuf, "LOGPATTERN=")) != NULL) {
			buf_ptr = buf_ptr + strlen("LOGPATTERN=");
			buf_end = buf_ptr;
			while (*buf_end != '\"') {
				++buf_end;
			}
			*buf_end = '\0';

			flb_info("tag: %s", tag);
			flb_info("pattern: %s", buf_ptr);

			hash_item->logformat_pod_info->regex = flb_logformat_regex_init_userdefined(buf_ptr);
			*buf_end = '\"';
		} else {
			hash_item->logformat_pod_info->regex = NULL;
		}

		if ((buf_ptr = strstr(pConfigBuf, "LOGASSEMBLE=")) != NULL) {
			buf_ptr = buf_ptr + strlen("LOGASSEMBLE=");
			buf_end = buf_ptr;
			while (*buf_end != '\"') {
				++buf_end;
			}
			*buf_end = '\0';

			flb_info("format: %s", buf_ptr);

			hash_item->logformat_pod_info->logformat_log_format = flb_logformat_log_format_create(buf_ptr);
			*buf_end = '\"';
		} else {
			hash_item->logformat_pod_info->logformat_log_format = NULL;
		}

		if ((buf_ptr = strstr(pConfigBuf, "GATEWAYTOKEN=")) != NULL) {
			buf_ptr = buf_ptr + strlen("GATEWAYTOKEN=");
			buf_end = buf_ptr;
			while (*buf_end != '\"') {
				++buf_end;
			}
			*buf_end = '\0';

			flb_info("gatewaytoken: %s", buf_ptr);

			hash_item->logformat_pod_info->token = flb_strdup(buf_ptr);
			hash_item->logformat_pod_info->token_len = strlen(buf_ptr);
		} else {
			hash_item->logformat_pod_info->token = NULL;
		}

		flb_free(pConfigBuf);

		ret = flb_hash_add(ctx->hashTable, logformat_tag->tag, strlen(logformat_tag->tag),
						(char *)hash_item, sizeof(struct flb_logformat_hash_item));
		if (ret == -1) {
			// delete hash_item->heap_item, but not do
			flb_logformat_hash_item_destroy(ctx, hash_item);
			return NULL;
		}
	}

	return hash_item->logformat_pod_info;
}

static void delete_tag_index(void *filter_context) {
	struct flb_logformat *ctx = filter_context;

	struct flb_logformat_tag *logformat_tag = NULL;
	struct flb_heap_item *heap_item = NULL;

	size_t hash_item_size = 0;
	struct flb_logformat_hash_item *hash_item = NULL;

	uint64_t currentDaySeconds;

	if (ctx->heap == NULL) {
		return;
	}

	currentDaySeconds = getCurrentSeconds() - getOneDaySeconds();

	heap_item = flb_heap_get(ctx->heap);
	while (heap_item != NULL && heap_item->value != NULL) {
		logformat_tag = heap_item->value;

		if (logformat_tag->lastUpdateTime >= currentDaySeconds) {
			break;
		}

		// logformat_tag will be release in flb_heap_delete, so must be NULL
		flb_hash_get(ctx->hashTable, logformat_tag->tag, strlen(logformat_tag->tag), (char **)&hash_item, &hash_item_size);
		hash_item->heap_item = NULL;

		flb_hash_del(ctx->hashTable, logformat_tag->tag);
		flb_heap_delete(ctx->heap);

		heap_item = flb_heap_get(ctx->heap);
	}
}

static int cb_logformat_filter_pod(void *data, size_t bytes,
        char *tag, int tag_len,
        void **out_buf, size_t *out_bytes,
        struct flb_filter_instance *f_ins,
        void *filter_context,
        struct flb_config *config) {
	int ret;
	size_t off = 0;
	msgpack_unpacked result;
	msgpack_object time;
	msgpack_object map;
	msgpack_object root;
	msgpack_sbuffer tmp_sbuf;
	msgpack_packer tmp_pck;

	struct flb_logformat_pod_info *logformat_pod_info = NULL;

	logformat_pod_info = build_tag_index(tag, tag_len, filter_context);
	if (logformat_pod_info == NULL) {
		return FLB_FILTER_NOTOUCH;
	}

	msgpack_sbuffer_init(&tmp_sbuf);
	msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

	msgpack_unpacked_init(&result);
	while (msgpack_unpack_next(&result, data, bytes, &off)) {
		root = result.data;
		if (root.type != MSGPACK_OBJECT_ARRAY) {
			continue;
		}

		time = root.via.array.ptr[0];
		map  = root.via.array.ptr[1];

		msgpack_pack_array(&tmp_pck, 2);
		msgpack_pack_object(&tmp_pck, time);

		ret = pack_map_content(&tmp_pck, &tmp_sbuf,
							   map, logformat_pod_info, logformat_pod_info->token, logformat_pod_info->token_len,
							   logformat_pod_info->regex, logformat_pod_info->logformat_log_format);
		if (ret != 0) {
			msgpack_sbuffer_destroy(&tmp_sbuf);
			msgpack_unpacked_destroy(&result);
			return FLB_FILTER_NOTOUCH;
		}
	}
	msgpack_unpacked_destroy(&result);

	*out_buf   = tmp_sbuf.data;
	*out_bytes = tmp_sbuf.size;

	// delete timeouts tag, the time is one day
	delete_tag_index(filter_context);

	return FLB_FILTER_MODIFIED;
}

static int cb_logformat_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    struct flb_logformat *ctx = filter_context;

    if (ctx->logformat_pod_info != NULL) {   // system
    	return cb_logformat_filter_system(data, bytes, tag, tag_len, out_buf, out_bytes, f_ins, filter_context, config);
    } else {							// pod
    	return cb_logformat_filter_pod(data, bytes, tag, tag_len, out_buf, out_bytes, f_ins, filter_context, config);
    }
}

static int cb_logformat_exit(void *data, struct flb_config *config)
{
    struct flb_logformat *ctx;

    ctx = data;
    flb_logformat_conf_destroy(ctx);

    return 0;
}

struct flb_filter_plugin filter_logformat_plugin = {
    .name         = "logformat",
    .description  = "Filter to append logformat metadata",
    .cb_init      = cb_logformat_init,
    .cb_filter    = cb_logformat_filter,
    .cb_exit      = cb_logformat_exit,
    .flags        = 0
};
