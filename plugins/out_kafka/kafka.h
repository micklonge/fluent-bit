#ifndef FLB_OUT_KAFKA_H
#define FLB_OUT_KAFKA_H

#include <fluent-bit/flb_hash.h>

#define FLB_KAFKA_DEFAULT_URL       "127.0.0.1"
#define FLB_KAFKA_DEFAULT_TOPIC     "fluentbit"

#include "rdkafka.h"  /* for Kafka driver */

struct flb_kafka_rtk {
	rd_kafka_topic_t *rkt;
};

struct flb_kafka {
	int kafkaUrl_len;
	char *kafkaUrl;

	int topic_len;
	char *topic;

	int clusterName_len;
	char *clusterName;

	int nodeName_len;
	char *nodeName;

	int appName_len;
	char *appName;

	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	struct flb_hash *rkt_topic_map;         // key:flb_kube_pod_info
};

#endif
