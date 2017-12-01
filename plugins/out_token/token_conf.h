#ifndef FLB_OUT_TOKEN_CONF_H
#define FLB_OUT_TOKEN_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>

#include "token.h"

struct flb_token *flb_token_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config);
int flb_token_conf_destroy(struct flb_token *ctx);

#endif
