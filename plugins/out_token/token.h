#ifndef FLB_OUT_TOKEN_H
#define FLB_OUT_TOKEN_H

#define FLB_TOKEN_CONTENT_TYPE   "Content-Type"
#define FLB_TOKEN_MIME_MSGPACK   "application/msgpack"
#define FLB_TOKEN_MIME_JSON      "application/json"

#include "EnnMonitorSecurityGatewayClient.h"

struct flb_token {
	int host_len;
	char *host;

	int port;

	int source_len;
	char *source;

	int clusterName_len;
	char *clusterName;

	int nodeName_len;
	char *nodeName;

	int appName_len;
	char *appName;
};

#endif
