#include <stdio.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_heap.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#include <msgpack.h>

#include "suppress_conf.h"

static int cb_suppress_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
	struct flb_suppress *ctx = NULL;

	/* Create configuration context */
	ctx = flb_suppress_conf_create(f_ins, config);
	if (!ctx) {
		return -1;
	}

	flb_filter_set_context(f_ins, ctx);

	return 0;
}

static int build_log_index(char *data, int len, void *filter_context) {
	struct flb_suppress *ctx = NULL;

	int *count = NULL;
	size_t countSize = 0;

	struct flb_heap_item* heap_item = NULL;

	struct flb_suppress_log *suppress_log = NULL;

	ctx = filter_context;

	flb_hash_get(ctx->hashTable, data, len, (char **)&count, &countSize);
	if (count == NULL) {
		count = flb_calloc(1, sizeof(int));
		*count = 1;

		flb_hash_add(ctx->hashTable, data, strlen(data), (char *)count, sizeof(int));

		flb_free(count);

		suppress_log = flb_suppress_log_create();
		if (suppress_log == NULL) {
			flb_hash_del(ctx->hashTable, data);
			return -1;
		}
		suppress_log->lastUpdateTime = getCurrentSeconds();
		suppress_log->log = flb_strdup(data);
		heap_item = flb_heap_add(ctx->heap, (void *)suppress_log);
		if (heap_item == NULL) {
			flb_hash_del(ctx->hashTable, data);
			return 0;
		}
		return 0;
	} else if (*count < ctx->number_of_log) {
		*count = *count + 1;
		return 0;
	} else {
		return -1;
	}
}

static void delete_log_index(void *filter_context) {
	struct flb_suppress *ctx = filter_context;

	struct flb_suppress_log *suppress_log = NULL;

	uint64_t currentDaySeconds;

	if (ctx->heap == NULL) {
		return;
	}

	currentDaySeconds = getCurrentSeconds() - ctx->seconds;
	suppress_log = flb_heap_get(ctx->heap);
	while (suppress_log != NULL && suppress_log->lastUpdateTime < currentDaySeconds) {
		flb_hash_del(ctx->hashTable, suppress_log->log);
		flb_heap_delete(ctx->heap);

		suppress_log = flb_heap_get(ctx->heap);
	}
}

static char* get_log(msgpack_object source_map) {
	int i;
	int map_size;

	char *log = NULL;

	msgpack_object k;

	map_size = source_map.via.map.size;
	for (i = 0; i < map_size; i++) {
		k = source_map.via.map.ptr[i].key;
		if (k.type == MSGPACK_OBJECT_STR && strncmp(k.via.str.ptr, "log", 3) == 0) {
			log = (char *)source_map.via.map.ptr[i].val.via.str.ptr;
			break;
		}
	}

	return log;
}

static int cb_suppress_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **out_buf, size_t *out_bytes,
                            struct flb_filter_instance *f_ins,
                            void *filter_context,
                            struct flb_config *config)
{
	int currentSeconds = 0;

	size_t off = 0;
	msgpack_unpacked result;
	msgpack_object time;
	msgpack_object map;
	msgpack_object root;
	msgpack_sbuffer tmp_sbuf;
	msgpack_packer tmp_pck;

	struct flb_suppress *ctx = filter_context;

	char *log = NULL;

	msgpack_sbuffer_init(&tmp_sbuf);
	msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

	delete_log_index(filter_context);

	currentSeconds = getCurrentSeconds();
	if (currentSeconds > ctx->lastTimeSeconds) {
		ctx->lastTimeSeconds = currentSeconds;
		ctx->logNum = 0;
	}

	msgpack_unpacked_init(&result);
	while (msgpack_unpack_next(&result, data, bytes, &off)) {
		root = result.data;
		if (root.type != MSGPACK_OBJECT_ARRAY) {
			continue;
		}

		time = root.via.array.ptr[0];
		map  = root.via.array.ptr[1];

		log = get_log(map);
		if (log == NULL) {
			continue;
		}

		if (build_log_index(log, strlen(log), filter_context) < 0) {
			continue;
		}

		if (ctx->logNum >= ctx->logLimit) {
			break;
		}

		msgpack_pack_array(&tmp_pck, 2);
		msgpack_pack_object(&tmp_pck, time);
		msgpack_pack_object(&tmp_pck, map);
		++ctx->logNum;
	}
	msgpack_unpacked_destroy(&result);

	*out_buf   = tmp_sbuf.data;
	*out_bytes = tmp_sbuf.size;

	return FLB_FILTER_MODIFIED;
}

static int cb_suppress_exit(void *data, struct flb_config *config)
{
	struct flb_suppress *ctx = NULL;

	ctx = data;
	flb_suppress_conf_destroy(ctx);

	return 0;
}

struct flb_filter_plugin filter_suppress_plugin = {
    .name         = "suppress",
    .description  = "Filter events to SUPPRESS",
    .cb_init      = cb_suppress_init,
    .cb_filter    = cb_suppress_filter,
    .cb_exit      = cb_suppress_exit,
    .flags        = 0
};

