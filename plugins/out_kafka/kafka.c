#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>

#include "kafka.h"
#include "kafka_conf.h"

/**
 * Kafka logger callback (optional)
 */
static void logger(const rd_kafka_t *rk, int level, const char *fac,
		const char *buf) {
	flb_info("RDKAFKA-%i-%s: %s: %s\n", level, fac, rk ? rd_kafka_name(rk) : NULL, buf);
}

struct flb_kafka_rtk* flb_kafka_rtk_create() {
	struct flb_kafka_rtk *kafka_rtk = NULL;

	kafka_rtk = flb_calloc(1, sizeof(struct flb_kafka_rtk));
	if (kafka_rtk == NULL) {
		flb_errno();
		return NULL;
	}

	return kafka_rtk;
}

void flb_kafka_rtk_destroy(struct flb_kafka_rtk *kafka_rtk) {
	if (kafka_rtk == NULL) {
		return;
	}

	if (kafka_rtk->rkt != NULL) {
		rd_kafka_topic_destroy(kafka_rtk->rkt);
	}

	flb_free(kafka_rtk);
}

static inline char* kafka_pack_map_content(msgpack_packer *tmp_pck, msgpack_object map)
{
    int i;
    char *ptr_key = NULL;
    char buf_key[256];
    msgpack_object *k;
    msgpack_object *v;

    char *topic = NULL;

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
            kafka_pack_map_content(tmp_pck, *v);
        }
        else {
        	if (strcmp(key_ptr, "customTopic") == 0) {
        		if (v->type == MSGPACK_OBJECT_STR) {
        			topic = (char *)v->via.str.ptr;
        		}
        	}

        	msgpack_pack_object(tmp_pck, *v);
        }
    }

    return topic;
}

int cb_kafka_init(struct flb_output_instance *ins, struct flb_config *config,
		void *data) {
	struct flb_kafka *ctx;

	char errstr[5120];
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;

	ctx = flb_kafka_conf_create(ins, config);
	if (!ctx) {
		flb_error("[out_kafka] cannot initialize plugin");
		return -1;
	}

	flb_info("[out_kafka] kafkaUrl=%s topic=%s", ctx->kafkaUrl, ctx->topic);
	if (ctx->clusterName != NULL) {
		flb_info("[out_kafka] clusterName=%s", ctx->clusterName);
	}
	if (ctx->nodeName != NULL) {
		flb_info("[out_kafka] nodeName=%s", ctx->nodeName);
	}
	if (ctx->appName != NULL) {
		flb_info("[out_kafka] appName=%s", ctx->appName);
	}

	/* Kafka configuration */
	conf = rd_kafka_conf_new();

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();

	/* Set logger */
	rd_kafka_conf_set_log_cb(conf, logger);
	rd_kafka_conf_set(conf, "bootstrap.servers", ctx->kafkaUrl, errstr, sizeof(errstr));

	/* Create Kafka handle */
	if (!(ctx->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr)))) {
		rd_kafka_conf_destroy(conf);
		flb_error("Failed to create new producer: %s\n", errstr);
		return -1;
	}

	ctx->rkt = rd_kafka_topic_new(ctx->rk, ctx->topic, topic_conf);
	topic_conf = NULL;

	flb_output_set_context(ins, ctx);

	return 0;
}

static void handler_error(rd_kafka_resp_err_t errorno) {
	if (errorno == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
		sleep(1);
	}
}

void cb_kafka_flush(void *data, size_t bytes, char *tag, int tag_len,
		struct flb_input_instance *i_ins, void *out_context,
		struct flb_config *config) {
	struct flb_kafka *ctx = out_context;

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

	rd_kafka_topic_conf_t *topic_conf = NULL;
	char *topic = NULL;

	struct flb_kafka_rtk *kafka_rkt = NULL;
	size_t rtkSize;

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

		topic = kafka_pack_map_content(&tmp_pck, map);

		/* Convert msgpack to JSON */
		ret = flb_msgpack_raw_to_json_str(tmp_sbuf.data, tmp_sbuf.size,
										  &json_buf, &json_size);
		msgpack_sbuffer_destroy(&tmp_sbuf);
		if (ret != 0) {
			msgpack_unpacked_destroy(&result);
			topic = NULL;
			return FLB_OUTPUT_RETURN(FLB_ERROR);
		}

		/* Send/Produce message. */
		if (rd_kafka_produce(ctx->rkt, -1, RD_KAFKA_MSG_F_COPY, json_buf, strlen(json_buf), NULL, 0, NULL) == -1) {
			flb_error("Failed to produce to topic %s partition %i: %s", rd_kafka_topic_name(ctx->rkt),
					-1, rd_kafka_err2str(rd_kafka_last_error()));
			rd_kafka_poll(ctx->rk, 0);
			topic = NULL;

			handler_error(rd_kafka_last_error());
			continue;
		}

		if (topic != NULL) {
			if (ctx->rkt_topic_map == NULL) {
				ctx->rkt_topic_map = flb_hash_create(FLB_HASH_EVICT_NONE, 10, -1, (void (*)(void *))flb_kafka_rtk_destroy);
				if (ctx->rkt_topic_map == NULL) {
					topic = NULL;
					continue;
				}
			}

			flb_hash_get(ctx->rkt_topic_map, topic, strlen(topic), (char **)&kafka_rkt, &rtkSize);
			if (kafka_rkt == NULL) {
				kafka_rkt = flb_kafka_rtk_create();
				if (kafka_rkt == NULL) {
					topic = NULL;
					continue;
				}
				topic_conf = rd_kafka_topic_conf_new();
				kafka_rkt->rkt = rd_kafka_topic_new(ctx->rk, topic, topic_conf);
				ret = flb_hash_add(ctx->rkt_topic_map, topic, strlen(topic), (char *)kafka_rkt, sizeof(struct flb_kafka_rtk));
				if (ret < -1) {
					topic = NULL;
					continue;
				}
			}

			if (rd_kafka_produce(kafka_rkt->rkt, -1, RD_KAFKA_MSG_F_COPY, json_buf, strlen(json_buf), NULL, 0, NULL) == -1) {
				flb_error("Failed to produce to topic %s partition %i: %s", rd_kafka_topic_name(kafka_rkt->rkt),
						-1, rd_kafka_err2str(rd_kafka_last_error()));
				rd_kafka_poll(ctx->rk, 0);
				topic = NULL;

				handler_error(rd_kafka_last_error());
				continue;
			}

			topic = NULL;
		}

		rd_kafka_poll(ctx->rk, 0);

		//flb_info("json = %s", json_buf);

		flb_free(json_buf);
		json_buf = NULL;
	}

	msgpack_unpacked_destroy(&result);

	FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_kafka_exit(void *data, struct flb_config *config) {
	struct flb_kafka *ctx = data;

	/* Destroy topic */
	rd_kafka_topic_destroy(ctx->rkt);

	if (ctx->rkt_topic_map != NULL) {
		flb_hash_destroy(ctx->rkt_topic_map);
	}

	/* Destroy the handle */
	rd_kafka_destroy(ctx->rk);

	flb_kafka_conf_destroy(ctx);

	return 0;
}

struct flb_output_plugin out_kafka_plugin = {
		.name = "kafka",
		.description = "out kafka",
		.cb_init = cb_kafka_init,
		.cb_flush = cb_kafka_flush,
		.cb_exit = cb_kafka_exit,
		.flags = 0,
};
