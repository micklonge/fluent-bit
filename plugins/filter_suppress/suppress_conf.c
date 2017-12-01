#include <stdlib.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_heap.h>

#include "suppress_conf.h"

int flb_suppress_log_cmp(struct flb_suppress_log *log1, struct flb_suppress_log *log2) {
	if (log1 == NULL || log2 == NULL) {
		return 0;
	}

	return log1->lastUpdateTime - log2->lastUpdateTime;
}

void flb_suppress_log_destroy(struct flb_suppress_log* suppress_log) {
	if (suppress_log == NULL) {
		return;
	}

	if (suppress_log->log != NULL) {
		flb_free(suppress_log->log);
		suppress_log->log = NULL;
	}

	flb_free(suppress_log);
}

struct flb_suppress_log* flb_suppress_log_create() {
	struct flb_suppress_log *suppress_log = NULL;

	suppress_log = flb_calloc(1, sizeof(struct flb_suppress_log));
	if (suppress_log == NULL) {
		flb_errno();
		return NULL;
	}

	return suppress_log;
}

struct flb_suppress *flb_suppress_conf_create(struct flb_filter_instance *ins,
                                      struct flb_config *config) {
	char *tmp;

	struct flb_suppress *ctx = NULL;

	ctx = (struct flb_suppress *)flb_calloc(1, sizeof(struct flb_suppress));
	if (ctx == NULL) {
		flb_errno();
		return NULL;
	}

	ctx->hashTable = flb_hash_create(FLB_HASH_EVICT_NONE, FLB_SUPPRESS_HASH_SIZE, -1, NULL);
	if (ctx->hashTable == NULL) {
		flb_suppress_conf_destroy(ctx);
		return NULL;
	}

	ctx->heap = flb_heap_create(FLB_SUPPRESS_HEAP_SIZE, (int (*)(void *, void *))flb_suppress_log_cmp, (void (*)(void *))flb_suppress_log_destroy);
	if (ctx->heap == NULL) {
		flb_suppress_conf_destroy(ctx);
		return NULL;
	}

	tmp = flb_filter_get_property("Period", ins);
	if (tmp == NULL) {
		tmp = "30s";
	}
	if (tmp[strlen(tmp) - 1] == 's') {
		tmp[strlen(tmp) - 1] = '\0';
		ctx->seconds = atoi(tmp);
	} else if (tmp[strlen(tmp) - 1] == 'm') {
		tmp[strlen(tmp) - 1] = '\0';
		ctx->seconds = atoi(tmp) * 60;
	} else {
		flb_error("the config Period is not expected, %s", tmp);
		flb_suppress_conf_destroy(ctx);
		return NULL;
	}

	tmp = flb_filter_get_property("Number", ins);
	if (tmp == NULL) {
		tmp = "10";
	}
	ctx->number_of_log = atoi(tmp);

	tmp = flb_filter_get_property("LogLimit", ins);
	if (tmp == NULL) {
		tmp = "1000000000";
	}
	ctx->logLimit = atoi(tmp);

	ctx->lastTimeSeconds = 0;
	ctx->logNum = 0;

	return ctx;
}

void flb_suppress_conf_destroy(struct flb_suppress *suppress) {
	if (suppress == NULL) {
		return;
	}

	if (suppress->hashTable != NULL) {
		flb_hash_destroy(suppress->hashTable);
	}

	if (suppress->heap != NULL) {
		flb_heap_destroy(suppress->heap);
	}

	flb_free(suppress);
}

