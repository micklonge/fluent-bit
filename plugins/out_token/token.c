#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>

#include "token.h"
#include "token_conf.h"

static inline void token_pack_map_content(msgpack_packer *tmp_pck, msgpack_object map, char **source, int *source_len, char **token, int *token_len)
{
    int i;
    char *ptr_key = NULL;
    char buf_key[256];
    msgpack_object *k;
    msgpack_object *v;

    for (i = 0; i < map.via.map.size; i++) {
        k = &map.via.map.ptr[i].key;
        v = &map.via.map.ptr[i].val;
        ptr_key = NULL;

        /* Store key */
        char *key_ptr = NULL;
        size_t key_size = 0;

        if (k->type == MSGPACK_OBJECT_BIN) {
            key_ptr  = (char *) k->via.bin.ptr;
            key_size = k->via.bin.size;
        }
        else if (k->type == MSGPACK_OBJECT_STR) {
            key_ptr  = (char *) k->via.str.ptr;
            key_size = k->via.str.size;
        }

        if (key_size < (sizeof(buf_key) - 1)) {
            memcpy(buf_key, key_ptr, key_size);
            buf_key[key_size] = '\0';
            ptr_key = buf_key;
        }
        else {
            /* Long map keys have a performance penalty */
            ptr_key = flb_malloc(key_size + 1);
            memcpy(ptr_key, key_ptr, key_size);
            ptr_key[key_size] = '\0';
        }

        /*
         * Sanitize key name, Elastic Search 2.x don't allow dots
         * in field names:
         *
         *   https://goo.gl/R5NMTr
         */
        char *p   = ptr_key;
        char *end = ptr_key + key_size;
        while (p != end) {
            if (*p == '.') *p = '_';
            p++;
        }

        /* Append the key */
        msgpack_pack_str(tmp_pck, key_size);
        msgpack_pack_str_body(tmp_pck, ptr_key, key_size);

        /* Release temporal key if was allocated */
        if (ptr_key && ptr_key != buf_key) {
            flb_free(ptr_key);
        }
        ptr_key = NULL;

        /*
         * The value can be any data type, if it's a map we need to
         * sanitize to avoid dots.
         */
        if (v->type == MSGPACK_OBJECT_MAP) {
            msgpack_pack_map(tmp_pck, v->via.map.size);
            token_pack_map_content(tmp_pck, *v, source, source_len, token, token_len);
        }
        else {
        	if (strncmp(key_ptr, "customSource", key_size) == 0) {
        		if (v->type == MSGPACK_OBJECT_STR) {
        			*source = (char *)v->via.str.ptr;
        			*source_len = v->via.str.size;
        		}
        	}

        	if (strncmp(key_ptr, "token", key_size) == 0) {
				if (v->type == MSGPACK_OBJECT_STR) {
					*token = (char *)v->via.str.ptr;
					*token_len = v->via.str.size;
				}
			}

        	msgpack_pack_object(tmp_pck, *v);
        }
    }

}

int cb_token_init(struct flb_output_instance *ins, struct flb_config *config,
		void *data) {
	struct flb_token *ctx;

	ctx = flb_token_conf_create(ins, config);
	if (!ctx) {
		flb_error("[out_token] cannot initialize plugin");
		return -1;
	}

	flb_info("[out_token] host=%s port=%d source=%s", ctx->host, ctx->port, ctx->source);
	if (ctx->clusterName != NULL) {
		flb_info("[out_token] clusterName=%s", ctx->clusterName);
	}
	if (ctx->nodeName != NULL) {
		flb_info("[out_token] nodeName=%s", ctx->nodeName);
	}
	if (ctx->appName != NULL) {
		flb_info("[out_token] appName=%s", ctx->appName);
	}

	flb_output_set_context(ins, ctx);

	return 0;
}

void cb_token_flush(void *data, size_t bytes, char *tag, int tag_len,
		struct flb_input_instance *i_ins, void *out_context,
		struct flb_config *config) {
	struct flb_token *ctx = out_context;

	int ret;
	int map_size;
	int key_len;
	size_t off = 0;
	msgpack_unpacked result;
	msgpack_object root;
	msgpack_object map;
	msgpack_object otime;
	msgpack_sbuffer tmp_sbuf;
	msgpack_packer tmp_pck;

	char *json_buf;
	size_t json_size;

	char *source = NULL;
	int source_len;
	char *token = NULL;
	int token_len;

	char *defaultToken = "0634126496E2DF493C2820A1DA187C57";
	char tmpToken[1000];
	char tmpSource[1000];

	//flb_info("cb_token_flush");

	/* Iterate the original buffer and perform adjustments */
	msgpack_unpacked_init(&result);

	/* Perform some format validation */
	ret = msgpack_unpack_next(&result, data, bytes, &off);
	if (!ret) {
		msgpack_unpacked_destroy(&result);
		return FLB_OUTPUT_RETURN(FLB_ERROR);
	}

	/* We 'should' get an array */
	if (result.data.type != MSGPACK_OBJECT_ARRAY) {
		/*
		 * If we got a different format, we assume the caller knows what he is
		 * doing, we just duplicate the content in a new buffer and cleanup.
		 */
		msgpack_unpacked_destroy(&result);
		return FLB_OUTPUT_RETURN(FLB_ERROR);
	}

	root = result.data;
	if (root.via.array.size == 0) {
		return FLB_OUTPUT_RETURN(FLB_ERROR);
	}

	msgpack_unpacked_destroy(&result);

	/* deal with data */
	msgpack_unpacked_init(&result);

	// 通过off实现item的下一次迭代
	off = 0;
	while (msgpack_unpack_next(&result, data, bytes, &off)) {
		source = NULL;
		source_len = 0;
		token = NULL;
		token_len = 0;

		if (result.data.type != MSGPACK_OBJECT_ARRAY) {
			continue;
		}

		/* Each array must have two entries: time and record */
		root = result.data;
		if (root.via.array.size != 2) {
			continue;
		}

		otime = root.via.array.ptr[0];
		map   = root.via.array.ptr[1];
		map_size = map.via.map.size;

		/* Create temporal msgpack buffer */
		msgpack_sbuffer_init(&tmp_sbuf);
		msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

		if (ctx->clusterName != NULL) {
			map_size++;
		}

		if (ctx->nodeName != NULL) {
			map_size++;
		}

		if (ctx->appName != NULL) {
			map_size++;
		}

		/* Set the new map size */
		msgpack_pack_map(&tmp_pck, map_size + 1);

		key_len = strlen("createTime");
		msgpack_pack_str(&tmp_pck, key_len);
		msgpack_pack_str_body(&tmp_pck, "createTime", key_len);
		msgpack_pack_uint64(&tmp_pck, otime.via.u64);

		if (ctx->clusterName != NULL) {
			key_len = strlen("clusterName");
			msgpack_pack_str(&tmp_pck, key_len);
			msgpack_pack_str_body(&tmp_pck, "clusterName", key_len);
			msgpack_pack_str(&tmp_pck, ctx->clusterName_len);
			msgpack_pack_str_body(&tmp_pck, ctx->clusterName, ctx->clusterName_len);
		}

		if (ctx->nodeName != NULL) {
			key_len = strlen("nodeName");
			msgpack_pack_str(&tmp_pck, key_len);
			msgpack_pack_str_body(&tmp_pck, "nodeName", key_len);
			msgpack_pack_str(&tmp_pck, ctx->nodeName_len);
			msgpack_pack_str_body(&tmp_pck, ctx->nodeName, ctx->nodeName_len);
		}

		if (ctx->appName != NULL) {
			key_len = strlen("appName");
			msgpack_pack_str(&tmp_pck, key_len);
			msgpack_pack_str_body(&tmp_pck, "appName", key_len);
			msgpack_pack_str(&tmp_pck, ctx->appName_len);
			msgpack_pack_str_body(&tmp_pck, ctx->appName, ctx->appName_len);
		}

		//flb_info("before token_pack_map_content");
		token_pack_map_content(&tmp_pck, map, &source, &source_len, &token, &token_len);
		//flb_info("after token_pack_map_content");

		/* Convert msgpack to JSON */
		ret = flb_msgpack_raw_to_json_str(tmp_sbuf.data, tmp_sbuf.size,
										  &json_buf, &json_size);
		msgpack_sbuffer_destroy(&tmp_sbuf);
		if (ret != 0) {
			msgpack_unpacked_destroy(&result);
			source = NULL;
			return FLB_OUTPUT_RETURN(FLB_ERROR);
		}

		//flb_info("json = %s", json_buf);

		if (source == NULL) {
			source = ctx->source;
		} else {
			memcpy(tmpSource, source, source_len);
			source = tmpSource;
			source[source_len] = '\0';
		}

		if (token == NULL) {
			strcpy(tmpToken, defaultToken);
			token = tmpToken;
		} else {
			memcpy(tmpToken, token, token_len);
			token = tmpToken;
			token[token_len] = '\0';
		}

		//flb_info("source = %s, token = %s", source, token);

		put(token, source, json_buf);

		flb_free(json_buf);
		json_buf = NULL;

		//flb_info("flush end while");
	}

	msgpack_unpacked_destroy(&result);

	//flb_info("flush end");

	FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_token_exit(void *data, struct flb_config *config) {
	struct flb_token *ctx = data;

	flb_token_conf_destroy(ctx);

	return 0;
}

struct flb_output_plugin out_token_plugin = {
		.name = "token",
		.description = "out token",
		.cb_init = cb_token_init,
		.cb_flush = cb_token_flush,
		.cb_exit = cb_token_exit,
		.flags = 0,
};
