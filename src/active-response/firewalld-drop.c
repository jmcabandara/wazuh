/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define LOCK_PATH "active-response/bin/fw-drop"
#define LOCK_FILE "active-response/bin/fw-drop/pid"
#define DEFAULT_FW_CMD "/bin/firewall-cmd"

int main (int argc, char **argv) {
    (void)argc;
    char rule[COMMANDSIZE_4096];
    char log_msg[OS_MAXSTR];
    char lock_path[COMMANDSIZE_4096];
    char lock_pid_path[COMMANDSIZE_4096];
    int action = OS_INVALID;
    cJSON *input_json = NULL;
    struct utsname uname_buffer;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get srcip
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        write_debug_file(argv[0], "Cannot read 'srcip' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (action == ADD_COMMAND) {
        char **keys = NULL;
        int action2 = OS_INVALID;

        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        action2 = send_keys_and_check_message(argv, keys);

        os_free(keys);

        // If necessary, abort execution
        if (action2 != CONTINUE_COMMAND) {
            cJSON_Delete(input_json);

            if (action2 == ABORT_COMMAND) {
                write_debug_file(argv[0], "Aborted");
                return OS_SUCCESS;
            } else {
                return OS_INVALID;
            }
        }
    }

    int ip_version = get_ip_version(srcip);
    memset(rule, '\0', COMMANDSIZE_4096);
    if (ip_version == 4) {
        snprintf(rule, COMMANDSIZE_4096 -1, "rule family=ipv4 source address=%s drop", srcip);
    } else if (ip_version == 6) {
        snprintf(rule, COMMANDSIZE_4096 -1, "rule family=ipv6 source address=%s drop", srcip);
    } else {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Unable to run active response (invalid IP: '%s').", srcip);
        write_debug_file(argv[0], log_msg);
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (uname(&uname_buffer) != 0) {
        write_debug_file(argv[0], "Cannot get system name");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (!strcmp("Linux", uname_buffer.sysname)) {
        char arg1[COMMANDSIZE_4096];
        char fw_cmd[COMMANDSIZE_4096];
        char fw_cmd_tmp[COMMANDSIZE_4096 - 5];

        memset(arg1, '\0', COMMANDSIZE_4096);
        if (action == ADD_COMMAND) {
            strcpy(arg1, "--add-rich-rule=");
        } else {
            strcpy(arg1, "--remove-rich-rule=");
        }
        memset(fw_cmd_tmp, '\0', COMMANDSIZE_4096);
        strcpy(fw_cmd_tmp, DEFAULT_FW_CMD);

        memset(fw_cmd, '\0', COMMANDSIZE_4096);

        // Checking if firewall-cmd is present
        if (access(fw_cmd_tmp, F_OK) < 0) {
            char fw_cmd_path[COMMANDSIZE_4096];
            memset(fw_cmd_path, '\0', COMMANDSIZE_4096);
            snprintf(fw_cmd_path, COMMANDSIZE_4096 - 1, "/usr%s", fw_cmd_tmp);
            if (access(fw_cmd_path, F_OK) < 0) {
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR -1, "The firewall-cmd file '%s' is not accessible: %s (%d)", fw_cmd_path, strerror(errno), errno);
                write_debug_file(argv[0], log_msg);
                cJSON_Delete(input_json);
                return OS_INVALID;
            }
            strncpy(fw_cmd, fw_cmd_path, COMMANDSIZE_4096 - 1);
        } else {
            strncpy(fw_cmd, fw_cmd_tmp, COMMANDSIZE_4096 - 1);
        }

        memset(lock_path, '\0', COMMANDSIZE_4096);
        memset(lock_pid_path, '\0', COMMANDSIZE_4096);
        snprintf(lock_path, COMMANDSIZE_4096 - 1, "%s", LOCK_PATH);
        snprintf(lock_pid_path, COMMANDSIZE_4096 - 1, "%s", LOCK_FILE);

        // Taking lock
        if (lock(lock_path, lock_pid_path, argv[0], basename(argv[0])) == OS_INVALID) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Unable to take lock. End.");
            write_debug_file(argv[0], log_msg);
            cJSON_Delete(input_json);
            return OS_INVALID;
        }

        int count = 0;
        bool flag = true;
        while (flag) {
            char system_command[OS_MAXSTR];
            memset(system_command, '\0', OS_MAXSTR);
            snprintf(system_command, OS_MAXSTR -1, "%s %s\"%s\"", fw_cmd, arg1, rule);
            if (system(system_command) != 0) {
                count++;
                write_debug_file(argv[0], "Unable to run firewall-cmd");
                sleep(count);

                if (count > 4) {
                    flag = false;
                }
            } else {
                flag = false;
            }
        }
        unlock(lock_path, argv[0]);

    } else {
        write_debug_file(argv[0], "Invalid system");
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}
