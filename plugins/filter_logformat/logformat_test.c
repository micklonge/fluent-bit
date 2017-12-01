#include "logformat_test.h"
#include "logformat_regex.h"
#include "logformat_log.h"

void logformat_log_format_test0() {
	struct flb_logformat_log_format *logformat_log_format = NULL;

	logformat_log_format = flb_logformat_log_format_create("%dateTime%,%logLevel%,%threadName%,%position%,%customTopic%,%log%");
	flb_logformat_log_format_print(logformat_log_format);
	flb_logformat_log_format_desctroy(logformat_log_format);
}

void logformat_log_format_test1() {
	struct flb_logformat_log_format *logformat_log_format = NULL;

	logformat_log_format = flb_logformat_log_format_create("%logLevel[I:INFO/W:WARN/E:ERROR/F:FATAL]%,%position%,%log%,<dateTime>$year$-%month%-%day% %time%");
	flb_logformat_log_format_print(logformat_log_format);
	flb_logformat_log_format_desctroy(logformat_log_format);
}

void flb_logformat_log_match_test0() {
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;

	logformat_log_match_result = flb_logformat_log_match_result_create("I0718 17:07:47.529308     758 server.go:770] Started logformatlet v1.5.1-148+69ea644b53bc73-dirty",
			flb_logformat_regex_init_userdefined("^(?<logLevel>[\\w])(?<month>\\d\\d)(?<day>\\d\\d)[\\s]*(?<time>[^\\s]*)[\\s]*(?<pid>[\\d]*)[\\s]*(?<position>[^\\s]*)\\][\\s]*(?<log>.*)$"));
	flb_hash_print(logformat_log_match_result->hash, NULL);
	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
}

void flb_logformat_log_match_test1() {
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;

	logformat_log_match_result = flb_logformat_log_match_result_create("2017-07-16T15:55:48.059+0800 I NETWORK  [conn13272] received client metadata from 172.5.240.8:37262 conn13272: { application: { name: \"MongoDB Shell\" }, driver: { name: \"MongoDB Internal Client\", version: \"3.4.6\" }, os: { type: \"Linux\", name: \"Ubuntu\", architecture: \"x86_64\", version: \"16.04\" } }\n",
			flb_logformat_regex_init_userdefined("^(?<date>[\\d\\-]+)T(?<time>[\\d\\:\\.]+)[^\\s]*[\\s]*(?<logLevel>[^\\s]+)[\\s]*(?<position>[^\\s]*)[\\s]*\\[(?<threadName>[^\\s\\]]*)\\][\\s]*(?<log>.*)$"));
	flb_hash_print(logformat_log_match_result->hash, NULL);
	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
}

void flb_logformat_log_match_test2() {
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_regex *regex = flb_logformat_regex_init_userdefined("^(?<dateTime>[\\d\\-]+[\\s]*[\\d\\:\\.]+)[\\s]*(?<logLevel>[\\w]+)[\\s]*(?<pid>[\\d]+)[\\s\\-]*\\[(?<threadName>[^\\]]+)\\][\\s]*(?<position>[^\\s]+)[\\s:]*(\\[topic=(?<customTopic>[^\\]]*)\\])?[\\s]*(?<log>.*)$");

	logformat_log_match_result = flb_logformat_log_match_result_create("2017-06-14 16:39:04.229  INFO 26069 --- [onPool-worker-1] c.g.filters.post.RequestAuditFilter      : [topic=console-audit] RequestAuditMessage=RequestAuditMessage{service=GATEWAY, requestId='1be6e1c5-2857-426d-a308-2cbf814dc87e', userId='null', namespaceName='null', url='https://localhost:8809/gw/as/api/v1', httpMethod='GET', httpStatus=200, clientIp='127.0.0.1', startTime=Wed Jun 14 16:39:04 CST 2017, elapsed=80, extras='{}'}",
			regex);
	flb_hash_print(logformat_log_match_result->hash, NULL);
	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
}

void flb_logformat_log_match_test3() {
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_regex *regex = flb_logformat_regex_init_userdefined("^(?<dateTime>[\\d\\-]+[\\s]*[\\d\\:\\.]+)[\\s]*(?<logLevel>[\\w]+)[\\s]*(?<pid>[\\d]+)[\\s\\-]*\\[(?<threadName>[^\\]]+)\\][\\s]*(?<position>[^\\s]+)[\\s:]*(\\[topic=(?<customTopic>[^\\]]*)\\])?[\\s]*(?<log>.*)$");

	logformat_log_match_result = flb_logformat_log_match_result_create("2017-06-14 16:39:04.229  INFO 26069 --- [onPool-worker-1] c.g.filters.post.RequestAuditFilter      : RequestAuditMessage=RequestAuditMessage{service=GATEWAY, requestId='1be6e1c5-2857-426d-a308-2cbf814dc87e', userId='null', namespaceName='null', url='https://localhost:8809/gw/as/api/v1', httpMethod='GET', httpStatus=200, clientIp='127.0.0.1', startTime=Wed Jun 14 16:39:04 CST 2017, elapsed=80, extras='{}'}",
			regex);
	flb_hash_print(logformat_log_match_result->hash, NULL);
	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
}

void flb_logformat_log_result_test0() {
	struct flb_logformat_log_format *logformat_log_format = NULL;
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_logformat_log_result *logformat_log_result = NULL;

	logformat_log_match_result = flb_logformat_log_match_result_create("I0718 17:07:47.529308     758 server.go:770] Started logformatlet v1.5.1-148+69ea644b53bc73-dirty",
		flb_logformat_regex_init_userdefined("^(?<logLevel>[\\w])(?<month>\\d\\d)(?<day>\\d\\d)[\\s]*(?<time>[^\\s]*)[\\s]*(?<pid>[\\d]*)[\\s]*(?<position>[^\\s]*)\\][\\s]*(?<log>.*)$"));
	logformat_log_format = flb_logformat_log_format_create("%logLevel[I:INFO/W:WARN/E:ERROR/F:FATAL]%,%position%,%log%,<dateTime>$year$-%month%-%day% %time%");

	logformat_log_result = flb_logformat_log_result_create(logformat_log_match_result, logformat_log_format);
	flb_logformat_log_result_print(logformat_log_result);

	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
	flb_logformat_log_format_desctroy(logformat_log_format);
	flb_logformat_log_result_desctroy(logformat_log_result);
}

void flb_logformat_log_result_test1() {
	struct flb_logformat_log_format *logformat_log_format = NULL;
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_logformat_log_result *logformat_log_result = NULL;

	logformat_log_match_result = flb_logformat_log_match_result_create("2017-07-16T15:55:48.059+0800 I NETWORK  [conn13272] received client metadata from 172.5.240.8:37262 conn13272: { application: { name: \"MongoDB Shell\" }, driver: { name: \"MongoDB Internal Client\", version: \"3.4.6\" }, os: { type: \"Linux\", name: \"Ubuntu\", architecture: \"x86_64\", version: \"16.04\" } }\n",
				flb_logformat_regex_init_userdefined("^(?<date>[\\d\\-]+)T(?<time>[\\d\\:\\.]+)[^\\s]*[\\s]*(?<logLevel>[^\\s]+)[\\s]*(?<position>[^\\s]*)[\\s]*\\[(?<threadName>[^\\s\\]]*)\\][\\s]*(?<log>.*)$"));
	logformat_log_format = flb_logformat_log_format_create("%logLevel[I:INFO/W:WARN/E:ERROR/F:FATAL]%,%position%,%log%,<dateTime>%date% %time%,%threadName%");

	logformat_log_result = flb_logformat_log_result_create(logformat_log_match_result, logformat_log_format);
	flb_logformat_log_result_print(logformat_log_result);

	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
	flb_logformat_log_format_desctroy(logformat_log_format);
	flb_logformat_log_result_desctroy(logformat_log_result);
}

void flb_logformat_log_result_test2() {
	struct flb_logformat_log_format *logformat_log_format = NULL;
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_logformat_log_result *logformat_log_result = NULL;

	struct flb_regex *regex = flb_logformat_regex_init_userdefined("^(?<dateTime>[\\d\\-]+[\\s]*[\\d\\:\\.]+)[\\s]*(?<logLevel>[\\w]+)[\\s]*(?<pid>[\\d]+)[\\s\\-]*\\[(?<threadName>[^\\]]+)\\][\\s]*(?<position>[^\\s]+)[\\s:]*(\\[topic=(?<customTopic>[^\\]]*)\\])?[\\s]*(?<log>.*)$");

	logformat_log_match_result = flb_logformat_log_match_result_create("2017-06-14 16:39:04.229  INFO 26069 --- [onPool-worker-1] c.g.filters.post.RequestAuditFilter      : [topic=console-audit] RequestAuditMessage=RequestAuditMessage{service=GATEWAY, requestId='1be6e1c5-2857-426d-a308-2cbf814dc87e', userId='null', namespaceName='null', url='https://localhost:8809/gw/as/api/v1', httpMethod='GET', httpStatus=200, clientIp='127.0.0.1', startTime=Wed Jun 14 16:39:04 CST 2017, elapsed=80, extras='{}'}",
			regex);
	logformat_log_format = flb_logformat_log_format_create("%dateTime%,%logLevel%,%threadName%,%position%,%customTopic%,%log%");

	logformat_log_result = flb_logformat_log_result_create(logformat_log_match_result, logformat_log_format);
	flb_logformat_log_result_print(logformat_log_result);

	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
	flb_logformat_log_format_desctroy(logformat_log_format);
	flb_logformat_log_result_desctroy(logformat_log_result);
}

void flb_logformat_log_result_test3() {
	struct flb_logformat_log_format *logformat_log_format = NULL;
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_logformat_log_result *logformat_log_result = NULL;

	struct flb_regex *regex = flb_logformat_regex_init_userdefined("^(?<dateTime>[\\d\\-]+[\\s]*[\\d\\:\\.]+)[\\s]*(?<logLevel>[\\w]+)[\\s]*(?<pid>[\\d]+)[\\s\\-]*\\[(?<threadName>[^\\]]+)\\][\\s]*(?<position>[^\\s]+)[\\s:]*(\\[topic=(?<customTopic>[^\\]]*)\\])?[\\s]*(?<log>.*)$");

	logformat_log_match_result = flb_logformat_log_match_result_create("2017-06-14 16:39:04.229  INFO 26069 --- [onPool-worker-1] c.g.filters.post.RequestAuditFilter      : RequestAuditMessage=RequestAuditMessage{service=GATEWAY, requestId='1be6e1c5-2857-426d-a308-2cbf814dc87e', userId='null', namespaceName='null', url='https://localhost:8809/gw/as/api/v1', httpMethod='GET', httpStatus=200, clientIp='127.0.0.1', startTime=Wed Jun 14 16:39:04 CST 2017, elapsed=80, extras='{}'}",
			regex);
	logformat_log_format = flb_logformat_log_format_create("%dateTime%,%logLevel%,%threadName%,%position%,%customTopic%,%log%");

	logformat_log_result = flb_logformat_log_result_create(logformat_log_match_result, logformat_log_format);
	flb_logformat_log_result_print(logformat_log_result);

	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
	flb_logformat_log_format_desctroy(logformat_log_format);
	flb_logformat_log_result_desctroy(logformat_log_result);
}

void flb_logformat_log_result_error_test0() {
	struct flb_logformat_log_format *logformat_log_format = NULL;
	struct flb_logformat_log_match_result *logformat_log_match_result = NULL;
	struct flb_logformat_log_result *logformat_log_result = NULL;

	struct flb_regex *regex = flb_logformat_regex_init_userdefined("^(?<dateTime>[\\d\\-]+[\\s]*[\\d\\:\\.]+)[\\s]*(?<logLevel>[\\w]+)[\\s]*(?<pid>[\\d]+)[\\s\\-]*\\[(?<threadName>[^\\]]+)\\][\\s]*(?<position>[^\\s]+)[\\s:]*(\\[topic=(?<customTopic>[^\\]]*)\\])?[\\s]*(?<log>.*)$");

	logformat_log_match_result = flb_logformat_log_match_result_create("INFO 26069 --- [onPool-worker-1] c.g.filters.post.RequestAuditFilter      : RequestAuditMessage=RequestAuditMessage{service=GATEWAY, requestId='1be6e1c5-2857-426d-a308-2cbf814dc87e', userId='null', namespaceName='null', url='https://localhost:8809/gw/as/api/v1', httpMethod='GET', httpStatus=200, clientIp='127.0.0.1', startTime=Wed Jun 14 16:39:04 CST 2017, elapsed=80, extras='{}'}",
			regex);
	logformat_log_format = flb_logformat_log_format_create("%dateTime%,%logLevel%,%threadName%,%position%,%customTopic%,%log%");

	if (logformat_log_match_result != NULL) {
		logformat_log_result = flb_logformat_log_result_create(logformat_log_match_result, logformat_log_format);
		flb_logformat_log_result_print(logformat_log_result);
	} else {
		printf("match failed\n");
	}

	flb_logformat_log_match_result_desctroy(logformat_log_match_result);
	flb_logformat_log_format_desctroy(logformat_log_format);
	flb_logformat_log_result_desctroy(logformat_log_result);
}

void logformat_test() {
	logformat_log_format_test0();
	printf("----------------------------------------------------\n");
	logformat_log_format_test1();

	printf("----------------------------------------------------\n");
	printf("----------------------------------------------------\n");

	flb_logformat_log_match_test0();
	printf("----------------------------------------------------\n");
	flb_logformat_log_match_test1();
	printf("----------------------------------------------------\n");
	flb_logformat_log_match_test2();
	printf("----------------------------------------------------\n");
	flb_logformat_log_match_test3();

	printf("----------------------------------------------------\n");
	printf("----------------------------------------------------\n");

	flb_logformat_log_result_test0();
	printf("----------------------------------------------------\n");
	flb_logformat_log_result_test1();
	printf("----------------------------------------------------\n");
	flb_logformat_log_result_test2();
	printf("----------------------------------------------------\n");
	flb_logformat_log_result_test3();

	printf("----------------------------------------------------\n");
	printf("----------------------------------------------------\n");
	flb_logformat_log_result_error_test0();
}
