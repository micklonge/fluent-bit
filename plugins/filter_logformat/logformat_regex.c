/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>

#include "logformat_regex.h"
#include "logformat_conf.h"

struct flb_regex *flb_logformat_regex_init_tag()
{
    return flb_regex_create((unsigned char *) LOGFORMAT_TAG_TO_REGEX);
}

struct flb_regex *flb_logformat_regex_init_userdefined(char *regex) {
	if (regex == NULL) {
		return NULL;
	}

	return flb_regex_create((unsigned char *) regex);
}
