#ifndef FLB_OUT_KAFKA_CONF_H
#define FLB_OUT_KAFKA_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>

#include "kafka.h"

struct flb_kafka *flb_kafka_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config);
int flb_kafka_conf_destroy(struct flb_kafka *ctx);

#endif
