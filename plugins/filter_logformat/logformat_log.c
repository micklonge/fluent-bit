#include <stdlib.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_regex.h>

#include "logformat_log.h"

struct flb_logformat_log_data_item* flb_logformat_log_data_item_create() {
	struct flb_logformat_log_data_item * logformat_log_data_item = NULL;

	logformat_log_data_item = flb_calloc(1, sizeof(struct flb_logformat_log_data_item));
	if (logformat_log_data_item == NULL) {
		flb_errno();
		return NULL;
	}

	logformat_log_data_item->fieldDataTypeEnum = None;

	return logformat_log_data_item;
}

void flb_logformat_log_data_item_destroy(struct flb_logformat_log_data_item *logformat_log_data_item) {
	if (logformat_log_data_item == NULL) {
		return;
	}

	if (logformat_log_data_item->value != NULL) {
		flb_free(logformat_log_data_item->value);
	}

	if (logformat_log_data_item->hash != NULL) {
		flb_hash_destroy(logformat_log_data_item->hash);
	}

	flb_free(logformat_log_data_item);
}

struct flb_logformat_log_data* flb_logformat_log_data_create() {
	struct flb_logformat_log_data *logformat_log_data;

	logformat_log_data = flb_calloc(1, sizeof(struct flb_logformat_log_data));
	if (logformat_log_data == NULL) {
		flb_errno();
		return NULL;
	}

	return logformat_log_data;
}

void flb_logformat_log_data_destroy(struct flb_logformat_log_data *logformat_log_data) {
	struct mk_list *head = NULL;
	struct mk_list *tmp = NULL;

	struct flb_logformat_log_data_item *logformat_log_data_item = NULL;

	if (logformat_log_data == NULL) {
		return;
	}

	if (logformat_log_data->key != NULL) {
		flb_free(logformat_log_data->key);
	}

	mk_list_foreach_safe(head, tmp, &logformat_log_data->logformat_log_data_head) {
		logformat_log_data_item = mk_list_entry(head, struct flb_logformat_log_data_item, _head);
		mk_list_del(&logformat_log_data_item->_head);
		flb_logformat_log_data_item_destroy(logformat_log_data_item);
	}

	flb_free(logformat_log_data);
}

static void strccat(char *ptr, char ch) {
	int len = strlen(ptr);
	ptr[len] = ch;
	ptr[len + 1] = '\0';
}

/*
 %logLevel[I:INFO/W:WARN/E:ERROR/F:FATAL]%,%position%,%log%,<dateTime>$year$-%month%-%day% %time%

 logFormat = logItem,logItem,logItem
 logItem = logKey?logValue
 logKey = <\w+>
 logValue = [^$%]*logField[[^$%]|logField]*
 logField = logFunction | logVariable
 logFunction = $variable$
 logVariable = %variable\[logReplace[/logReplace]*\]%
 logReplace = \w+ : \w+
 variable = \w+
 */

struct flb_logformat_log_format* flb_logformat_log_format_create(char *format) {
	int status = 0;
	char *ptr = NULL;

	char key[1024];
	char data[1024];

	char fkey[1024];
	char fvalue[1024];

	struct flb_logformat_log_data_item *logformat_log_data_item = NULL;
	struct flb_logformat_log_data *logformat_log_data = NULL;
	struct flb_logformat_log_format* logformat_log_format = NULL;

	logformat_log_format = flb_calloc(1, sizeof(struct flb_logformat_log_format));
	if (!logformat_log_format) {
		flb_errno();
		return NULL;
	}
	mk_list_init(&logformat_log_format->logformat_log_data_head);

	key[0] = '\0';
	data[0] = '\0';
	ptr = format;
	while (1) {
		switch (status) {
		case 0:
			switch (*ptr) {
			case '<':
				status = 1;
				break;
			case '%':
				status = 3;
				break;
			case '$':
				status = 6;
				break;
			default:
				strccat(data, *ptr);
				status = 2;
				break;
			}
			break;
		case 1:
			switch (*ptr) {
			case '>':
				status = 2;
				break;
			default:
				strccat(key, *ptr);
				break;
			}
			break;
		case 2:
			switch (*ptr) {
			case '%':
			case '$':
			case ',':
			case '\0':
				if (strlen(data) != 0) {
					if (logformat_log_data_item == NULL) {
						logformat_log_data_item = flb_calloc(1, sizeof(struct flb_logformat_log_data_item));
						if (logformat_log_data_item == NULL) {
							flb_logformat_log_data_destroy(logformat_log_data);
							flb_logformat_log_format_desctroy(logformat_log_format);
							return NULL;
						}
					}

					logformat_log_data_item->fieldDataTypeEnum = Value;
					logformat_log_data_item->value = flb_strdup(data);
					if (logformat_log_data == NULL) {
						logformat_log_data = flb_calloc(1, sizeof(struct flb_logformat_log_data));
						if (logformat_log_data == NULL) {
							flb_logformat_log_format_desctroy(logformat_log_format);
							return NULL;
						}
						mk_list_init(&logformat_log_data->logformat_log_data_head);
					}

					mk_list_add(&logformat_log_data_item->_head, &logformat_log_data->logformat_log_data_head);
					logformat_log_data_item = NULL;
					data[0] = '\0';
				}

				if (*ptr == '%') {
					status = 3;
					break;
				} else if (*ptr == '$') {
					status = 6;
					break;
				}

				// , '\0
				if (logformat_log_data != NULL) {
					logformat_log_data->key = flb_strdup(key);

					mk_list_add(&logformat_log_data->_head, &logformat_log_format->logformat_log_data_head);
					logformat_log_data_item = NULL;
					logformat_log_data = NULL;
					data[0] = '\0';
					key[0] = '\0';
				}

				if (*ptr == ',') {
					status = 0;
					break;
				}

				return logformat_log_format;
			default:
				strccat(data, *ptr);
				break;
			}
			break;
		case 3:
			switch (*ptr) {
			case '%':
				if (strlen(key) == 0) {
					strcpy(key, data);
				}

				if (logformat_log_data_item == NULL) {
					logformat_log_data_item = flb_calloc(1, sizeof(struct flb_logformat_log_data_item));
					if (logformat_log_data_item == NULL) {
						flb_logformat_log_data_destroy(logformat_log_data);
						flb_logformat_log_format_desctroy(logformat_log_format);
						return NULL;
					}
				}

				logformat_log_data_item->fieldDataTypeEnum = Variable;
				logformat_log_data_item->value = flb_strdup(data);
				if (logformat_log_data == NULL) {
					logformat_log_data = flb_calloc(1, sizeof(struct flb_logformat_log_data));
					if (logformat_log_data == NULL) {
						flb_logformat_log_format_desctroy(logformat_log_format);
						return NULL;
					}
					mk_list_init(&logformat_log_data->logformat_log_data_head);
				}

				mk_list_add(&logformat_log_data_item->_head, &logformat_log_data->logformat_log_data_head);
				logformat_log_data_item = NULL;
				data[0] = '\0';
				status = 2;
				break;
			case '[':
				status = 4;
				fkey[0] = '\0';
				fvalue[0] = '\0';
				break;
			default:
				strccat(data, *ptr);
				break;
			}
			break;
		case 4:
			switch(*ptr) {
			case ':':
				status = 5;
				break;
			default:
				strccat(fkey, *ptr);
				break;
			}
			break;
		case 5:
			switch (*ptr) {
			case '/':
			case ']':
				if (logformat_log_data_item == NULL) {
					logformat_log_data_item = flb_calloc(1, sizeof(struct flb_logformat_log_data_item));
					if (logformat_log_data_item == NULL) {
						flb_logformat_log_data_destroy(logformat_log_data);
						flb_logformat_log_format_desctroy(logformat_log_format);
						return NULL;
					}
				}

				if (logformat_log_data_item->hash == NULL) {
					logformat_log_data_item->hash = flb_hash_create(FLB_HASH_EVICT_NONE, 10, -1, NULL);
					if (logformat_log_data_item->hash == NULL) {
						flb_logformat_log_data_item_destroy(logformat_log_data_item);
						flb_logformat_log_data_destroy(logformat_log_data);
						flb_logformat_log_format_desctroy(logformat_log_format);
						return NULL;
					}
				}

				flb_hash_add(logformat_log_data_item->hash, fkey, strlen(fkey), fvalue, strlen(fvalue));

				fkey[0] = '\0';
				fvalue[0] = '\0';
				if (*ptr == '/') {
					status = 4;
				} else {
					status = 3;
				}
				break;
			default:
				strccat(fvalue, *ptr);
			}
			break;
		case 6:
			switch (*ptr) {
			case '$':
				if (strlen(key) == 0) {
					strcpy(key, data);
				}

				if (logformat_log_data_item == NULL) {
					logformat_log_data_item = flb_calloc(1, sizeof(struct flb_logformat_log_data_item));
					if (logformat_log_data_item == NULL) {
						flb_logformat_log_data_destroy(logformat_log_data);
						flb_logformat_log_format_desctroy(logformat_log_format);
						return NULL;
					}
				}

				logformat_log_data_item->fieldDataTypeEnum = FunctionName;
				logformat_log_data_item->value = flb_strdup(data);

				status = 2;

				if (logformat_log_data == NULL) {
					logformat_log_data = flb_calloc(1, sizeof(struct flb_logformat_log_data));
					if (logformat_log_data == NULL) {
						flb_logformat_log_format_desctroy(logformat_log_format);
						return NULL;
					}
					mk_list_init(&logformat_log_data->logformat_log_data_head);
				}
				mk_list_add(&logformat_log_data_item->_head, &logformat_log_data->logformat_log_data_head);

				logformat_log_data_item = NULL;
				data[0] = '\0';
				break;
			default:
				strccat(data, *ptr);
				break;
			}
			break;
		}
		++ptr;
	}

	return logformat_log_format;
}

void flb_logformat_log_format_desctroy(struct flb_logformat_log_format* logformat_log_format) {
	if (logformat_log_format == NULL) {
		return;
	}

	flb_free(logformat_log_format);
}

void flb_logformat_log_format_print(struct flb_logformat_log_format* logformat_log_format) {
	struct mk_list *logformat_log_data_head = NULL;
	struct mk_list *logformat_log_data_item_head = NULL;

	struct flb_logformat_log_data *logformat_log_data = NULL;
	struct flb_logformat_log_data_item *logformat_log_data_item = NULL;


	mk_list_foreach(logformat_log_data_head, &logformat_log_format->logformat_log_data_head) {
		logformat_log_data = mk_list_entry(logformat_log_data_head, struct flb_logformat_log_data, _head);

		printf("key:%s\n", logformat_log_data->key);
		mk_list_foreach(logformat_log_data_item_head, &logformat_log_data->logformat_log_data_head) {
			logformat_log_data_item = mk_list_entry(logformat_log_data_item_head, struct flb_logformat_log_data_item, _head);
			switch (logformat_log_data_item->fieldDataTypeEnum) {
			case None:
				printf("Exception\n");
				return;
				break;
			case Value:
				if (logformat_log_data_item->value == NULL) {
					continue;
				}

				printf("Value:    %s\n", logformat_log_data_item->value);
				break;
			case Variable:
				if (logformat_log_data_item->value == NULL) {
					continue;
				}

				printf("Variable:    %s\n", logformat_log_data_item->value);
				if (logformat_log_data_item->hash != NULL) {
					flb_hash_print(logformat_log_data_item->hash, NULL);
				}
				break;
			case FunctionName:
				if (logformat_log_data_item->value == NULL) {
					continue;
				}

				printf("FunctionName:    %s\n", logformat_log_data_item->value);
				break;
			}
		}

		printf("\n");
	}
}

static void cb_log_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
	struct flb_hash *hash = data;

	if (hash == NULL) {
		return;
	}

	flb_hash_add(hash, (char *)name, strlen((char *)name), (char *)value, vlen);
}

struct flb_logformat_log_match_result* flb_logformat_log_match_result_create(const char *log, struct flb_regex *regex) {
	ssize_t n;
	struct flb_regex_search result;

	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;

	n = flb_regex_do(regex, (unsigned char *) log, strlen(log), &result);
	if (n <= 0) {
		return NULL;
	}

	logformat_log_match_result = flb_calloc(1, sizeof(struct flb_logformat_log_match_result));
	if (logformat_log_match_result == NULL) {
		flb_errno();
		return NULL;
	}

	logformat_log_match_result->hash = flb_hash_create(FLB_HASH_EVICT_NONE, 10, -1, NULL);
	if (logformat_log_match_result->hash == NULL) {
		flb_logformat_log_match_result_desctroy(logformat_log_match_result);
		return NULL;
	}

	/* Parse the regex results */
	flb_regex_parse(regex, &result, cb_log_results, logformat_log_match_result->hash);

	return logformat_log_match_result;
}

void flb_logformat_log_match_result_desctroy(struct flb_logformat_log_match_result* logformat_log_match_result) {
	if (logformat_log_match_result == NULL) {
		return;
	}

	if (logformat_log_match_result->hash != NULL) {
		flb_hash_destroy(logformat_log_match_result->hash);
	}

	flb_free(logformat_log_match_result);
}

struct flb_logformat_log_result* flb_logformat_log_result_create(struct flb_logformat_log_match_result* match_result, struct flb_logformat_log_format *logformat_log_format) {
	char logData[102400];

	char *buf = NULL;
	size_t bufSize;
	char *bufReplace = NULL;
	size_t bufReplaceSize;

	char year[64];

	struct mk_list *logformat_log_data_head = NULL;
	struct mk_list *logformat_log_data_item_head = NULL;

	struct flb_logformat_log_data *logformat_log_data = NULL;
	struct flb_logformat_log_data_item *logformat_log_data_item = NULL;

	struct flb_logformat_log_result_item *logformat_log_result_item = NULL;
	struct flb_logformat_log_result *logformat_log_result = NULL;

	logformat_log_result = flb_calloc(1, sizeof(struct flb_logformat_log_result));
	if (logformat_log_result == NULL) {
		flb_errno();
		return NULL;
	}
	mk_list_init(&logformat_log_result->chains);
	logformat_log_result->count = 0;

	mk_list_foreach(logformat_log_data_head, &logformat_log_format->logformat_log_data_head) {
		logformat_log_data = mk_list_entry(logformat_log_data_head, struct flb_logformat_log_data, _head);

		logData[0] = '\0';

		mk_list_foreach(logformat_log_data_item_head, &logformat_log_data->logformat_log_data_head) {
			logformat_log_data_item = mk_list_entry(logformat_log_data_item_head, struct flb_logformat_log_data_item, _head);
			switch (logformat_log_data_item->fieldDataTypeEnum) {
			case None:
				return NULL;
				break;
			case Value:
				if (logformat_log_data_item->value == NULL) {
					continue;
				}

				strcat(logData, logformat_log_data_item->value);
				break;
			case Variable:
				if (logformat_log_data_item->value == NULL) {
					continue;
				}

				buf = NULL;
				if (match_result->hash != NULL) {
					flb_hash_get(match_result->hash, logformat_log_data_item->value, strlen(logformat_log_data_item->value), &buf, &bufSize);
					if (buf != NULL) {
						if (logformat_log_data_item->hash == NULL) {
							strcat(logData, buf);
						} else {
							bufReplace = NULL;
							flb_hash_get(logformat_log_data_item->hash, buf, strlen(buf), &bufReplace, &bufReplaceSize);
							if (bufReplace != NULL) {
								strcat(logData, bufReplace);
							} else {
								strcat(logData, buf);
							}
						}
					}
				}

				break;
			case FunctionName:
				if (logformat_log_data_item->value == NULL) {
					continue;
				}

				if (strcmp(logformat_log_data_item->value, "year") == 0) {
					itoa(getCurrentYear(), year);
					strcat(logData, year);
				}
				break;
			}
		}

		if (strlen(logData) == 0) {
			continue;
		}

		logformat_log_result_item = flb_calloc(1, sizeof(struct flb_logformat_log_result_item));
		logformat_log_result_item->name = flb_strdup(logformat_log_data->key);
		logformat_log_result_item->name_len = strlen(logformat_log_result_item->name);
		logformat_log_result_item->val = flb_strdup(logData);
		logformat_log_result_item->val_len = strlen(logformat_log_result_item->val);
		mk_list_add(&logformat_log_result_item->_head, &logformat_log_result->chains);

		++logformat_log_result->count;
	}

	return logformat_log_result;
}

void flb_logformat_log_result_desctroy(struct flb_logformat_log_result *logformat_log_result) {
	struct mk_list *head = NULL;
	struct mk_list *tmp = NULL;
	struct flb_logformat_log_result_item *logformat_log_result_item = NULL;

	mk_list_foreach_safe(head, tmp, &logformat_log_result->chains) {
		logformat_log_result_item = mk_list_entry(head, struct flb_logformat_log_result_item, _head);
		mk_list_del(&logformat_log_result_item->_head);
		if (logformat_log_result_item->name != NULL) {
			flb_free(logformat_log_result_item->name);
		}
		if (logformat_log_result_item->val != NULL) {
			flb_free(logformat_log_result_item->val);
		}
		flb_free(logformat_log_result_item);
	}
	flb_free(logformat_log_result);
}

void flb_logformat_log_result_print(struct flb_logformat_log_result *logformat_log_result) {
	struct mk_list *head = NULL;
	struct mk_list *tmp = NULL;
	struct flb_logformat_log_result_item *logformat_log_result_item = NULL;

	mk_list_foreach_safe(head, tmp, &logformat_log_result->chains) {
		logformat_log_result_item = mk_list_entry(head, struct flb_logformat_log_result_item, _head);
		if (logformat_log_result_item->name != NULL) {
			printf("%s --- ", logformat_log_result_item->name);
		}
		if (logformat_log_result_item->val != NULL) {
			printf("%s", logformat_log_result_item->val);
		}
		printf("\n");
	}
}
