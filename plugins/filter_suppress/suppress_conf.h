#ifndef FLB_FILTER_SUPPRESS_CONF_H
#define FLB_FILTER_SUPPRESS_CONF_H

#define FLB_SUPPRESS_HASH_SIZE  1048576
#define FLB_SUPPRESS_HEAP_SIZE  1048576

struct flb_suppress_log {
	uint64_t lastUpdateTime;
	char *log;
};

struct flb_suppress {
	int seconds;
	int number_of_log;  				// suppress

	int	lastTimeSeconds;
	int logLimit;
	int logNum;							// limit

	struct flb_hash *hashTable;         // key:flb_kube_pod_info
	struct flb_heap *heap;
};

struct flb_suppress_log* flb_suppress_log_create();
void flb_suppress_log_destroy(struct flb_suppress_log* suppress_log);

struct flb_suppress *flb_suppress_conf_create(struct flb_filter_instance *ins,
                                      struct flb_config *config);
void flb_suppress_conf_destroy(struct flb_suppress *suppress);

#endif
