#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>

#include "kafka.h"
#include "kafka_conf.h"

struct flb_kafka *flb_kafka_conf_create(struct flb_output_instance *ins,
		struct flb_config *config) {

	char *tmp;
	struct flb_kafka *ctx;

	/* Allocate context */
	ctx = flb_calloc(1, sizeof(struct flb_kafka));
	if (!ctx) {
		flb_errno();
		return NULL;
	}

	tmp = flb_output_get_property("KafkaUrl", ins);
	if (tmp) {
		ctx->kafkaUrl = flb_strdup(tmp);
		ctx->kafkaUrl_len = strlen(tmp);
	} else {
		ctx->kafkaUrl = flb_strdup(FLB_KAFKA_DEFAULT_URL);
		ctx->kafkaUrl_len = sizeof(FLB_KAFKA_DEFAULT_URL) - 1;
	}

	tmp = flb_output_get_property("Topic", ins);
	if (tmp) {
		ctx->topic = flb_strdup(tmp);
		ctx->topic_len = strlen(tmp);
	} else {
		ctx->topic = flb_strdup(FLB_KAFKA_DEFAULT_TOPIC);
		ctx->topic_len = sizeof(FLB_KAFKA_DEFAULT_TOPIC) - 1;
	}

	tmp = flb_output_get_property("ClusterName", ins);
	if (tmp) {
		ctx->clusterName = flb_strdup(tmp);
		ctx->clusterName_len = strlen(tmp);
	} else {
		ctx->clusterName = NULL;
		ctx->clusterName_len = 0;
	}

	tmp = flb_output_get_property("NodeName", ins);
	if (tmp) {
		ctx->nodeName = flb_strdup(tmp);
		ctx->nodeName_len = strlen(tmp);
	} else {
		ctx->nodeName = NULL;
		ctx->nodeName_len = 0;
	}

	tmp = flb_output_get_property("AppName", ins);
	if (tmp) {
		ctx->appName = flb_strdup(tmp);
		ctx->appName_len = strlen(tmp);
	} else {
		ctx->appName = NULL;
		ctx->appName_len = 0;
	}

	return ctx;
}

int flb_kafka_conf_destroy(struct flb_kafka *ctx) {
	if (ctx->kafkaUrl != NULL) {
		flb_free(ctx->kafkaUrl);
		ctx->kafkaUrl = NULL;
	}

	if (ctx->topic != NULL) {
		flb_free(ctx->topic);
		ctx->topic = NULL;
	}

	if (ctx->appName != NULL) {
		flb_free(ctx->appName);
		ctx->appName = NULL;
	}

	if (ctx->clusterName != NULL) {
		flb_free(ctx->clusterName);
		ctx->clusterName = NULL;
	}

	if (ctx->nodeName != NULL) {
		flb_free(ctx->nodeName);
		ctx->nodeName = NULL;
	}

	flb_free(ctx);

	return 0;
}
