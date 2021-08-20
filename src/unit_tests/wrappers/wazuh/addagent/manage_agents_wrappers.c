/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "manage_agents_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

double __wrap_OS_AgentAntiquity(__attribute__((unused)) const char *name,
                             __attribute__((unused)) const char *ip) {
    return mock();
}

void __wrap_OS_RemoveAgentGroup(__attribute__((unused)) const char *id) {
    // Empty wrapper
}
