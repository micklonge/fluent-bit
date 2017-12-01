#ifndef FLB_LOGFORMAT_LOG_H
#define FLB_LOGFORMAT_LOG_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_regex.h>

enum FieldDataTypeEnum {
	None = 1, Value = 2, Variable = 3, FunctionName = 4
};

struct flb_logformat_log_data_item {
	enum FieldDataTypeEnum fieldDataTypeEnum;

	char *value;
	struct flb_hash *hash;

	struct mk_list _head;
};

struct flb_logformat_log_data {
	char *key;
	struct mk_list logformat_log_data_head;
	struct mk_list _head;
};

struct flb_logformat_log_format {
	struct mk_list logformat_log_data_head;
};

struct flb_logformat_log_match_result {
	struct flb_hash *hash;
};

struct flb_logformat_log_result_item {
	char *name;
	size_t name_len;
	char *val;
	size_t val_len;

	struct mk_list _head;
};

struct flb_logformat_log_result {
    int count;
    struct mk_list chains;
};

struct flb_logformat_log_data_item* flb_logformat_log_data_item_create();
void flb_logformat_log_data_item_destroy(struct flb_logformat_log_data_item *logformat_log_data_item);

struct flb_logformat_log_data* flb_logformat_log_data_create();
void flb_logformat_log_data_destroy(struct flb_logformat_log_data *logformat_log_data);

struct flb_logformat_log_format* flb_logformat_log_format_create(char *format);
void flb_logformat_log_format_desctroy(struct flb_logformat_log_format* logformat_log);
void flb_logformat_log_format_print(struct flb_logformat_log_format* logformat_log);

struct flb_logformat_log_match_result* flb_logformat_log_match_result_create(const char *log, struct flb_regex *regex);
void flb_logformat_log_match_result_desctroy(struct flb_logformat_log_match_result* match_result);

struct flb_logformat_log_result* flb_logformat_log_result_create(struct flb_logformat_log_match_result* match_result, struct flb_logformat_log_format *logformat_log_format);
void flb_logformat_log_result_desctroy(struct flb_logformat_log_result *log_result);
void flb_logformat_log_result_print(struct flb_logformat_log_result *log_result);

#endif
