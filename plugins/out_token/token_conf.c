#include "token_conf.h"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>

#include "token.h"

struct flb_token *flb_token_conf_create(struct flb_output_instance *ins,
		struct flb_config *config) {

	char *tmp;
	struct flb_token *ctx;

	/* Allocate context */
	ctx = flb_calloc(1, sizeof(struct flb_token));
	if (!ctx) {
		flb_errno();
		return NULL;
	}

	if (ins->host.name != NULL) {
		ctx->host = flb_strdup(ins->host.name);
		ctx->host_len = strlen(ins->host.name);
	} else {
		ctx->host = NULL;
		ctx->host_len = 0;
	}

	//flb_info("%s", ctx->host);

	if (ins->host.port != 0) {
		ctx->port = ins->host.port;
	} else {
		ctx->port = 80;
	}

	tmp = flb_output_get_property("Source", ins);
	if (tmp) {
		ctx->source = flb_strdup(tmp);
		ctx->source_len = strlen(tmp);
	} else {
		ctx->source = NULL;
		ctx->source_len = 0;
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

	initClient(ctx->host, ctx->port, 16);

	return ctx;
}

int flb_token_conf_destroy(struct flb_token *ctx) {
	if (ctx->host != NULL) {
		flb_free(ctx->host);
		ctx->host = NULL;
	}

	if (ctx->source != NULL) {
		flb_free(ctx->source);
		ctx->source = NULL;
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
