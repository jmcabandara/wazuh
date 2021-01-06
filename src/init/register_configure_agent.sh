#!/bin/bash

# Copyright (C) 2015-2021, Wazuh Inc.
# March 6, 2019.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

sed="sed -ri"
# By default, use gnu sed (gsed).
use_unix_sed="False"

unix_sed() {
    sed_expression="$1"
    target_file="$2"

    sed "${sed_expression}" "${target_file}" > "${target_file}.tmp"
    cat "${target_file}.tmp" > "${target_file}"
    rm "${target_file}.tmp"
}

edit_value_tag() {
    if [ "$#" == "2" ] && [ ! -z "$2" ]; then
        if [ "${use_unix_sed}" = "False" ] ; then
            ${sed} "s#<$1>.*</$1>#<$1>$2</$1>#g" "${WAZUH_HOME}/etc/ossec.conf"
        else
            unix_sed "s#<$1>.*</$1>#<$1>$2</$1>#g" "${WAZUH_HOME}/etc/ossec.conf"
        fi
    fi

    if [ "$?" != "0" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') agent-auth: Error updating $2 with variable $1." >> ${WAZUH_HOME}/logs/ossec.log
    fi
}

add_adress_block() {

    SET_ADDRESSES=("$@")

    # Remove the server configuration
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<server>/,/\/server>/d" ${WAZUH_HOME}/etc/ossec.conf
    else
        unix_sed "/<server>/,/\/server>/d" "${WAZUH_HOME}/etc/ossec.conf"
    fi

    # Get the client configuration generated by gen_ossec.sh
    start_config="$(grep -n "<client>" ${WAZUH_HOME}/etc/ossec.conf | cut -d':' -f 1)"
    end_config="$(grep -n "</client>" ${WAZUH_HOME}/etc/ossec.conf | cut -d':' -f 1)"
    start_config=$(( start_config + 1 ))
    end_config=$(( end_config - 1 ))
    client_config="$(sed -n "${start_config},${end_config}p" ${WAZUH_HOME}/etc/ossec.conf)"

    # Remove the client configuration
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<client>/,/\/client>/d" ${WAZUH_HOME}/etc/ossec.conf
    else
        unix_sed "/<client>/,/\/client>/d" "${WAZUH_HOME}/etc/ossec.conf"
    fi

    # Write the client configuration block
    echo "<ossec_config>" >> ${WAZUH_HOME}/etc/ossec.conf
    echo "  <client>" >> ${WAZUH_HOME}/etc/ossec.conf
    for i in "${SET_ADDRESSES[@]}";
    do
        echo "    <server>" >> ${WAZUH_HOME}/etc/ossec.conf
        echo "      <address>$i</address>" >> ${WAZUH_HOME}/etc/ossec.conf
        echo "      <port>1514</port>" >> ${WAZUH_HOME}/etc/ossec.conf
        echo "      <protocol>tcp</protocol>" >> ${WAZUH_HOME}/etc/ossec.conf
        echo "    </server>" >> ${WAZUH_HOME}/etc/ossec.conf
    done

    echo "${client_config}" >> ${WAZUH_HOME}/etc/ossec.conf
    echo "  </client>" >> ${WAZUH_HOME}/etc/ossec.conf
    echo "</ossec_config>" >> ${WAZUH_HOME}/etc/ossec.conf
}

add_parameter () {
    if [ ! -z "$3" ]; then
        OPTIONS="$1 $2 $3"
    fi
    echo ${OPTIONS}
}

get_deprecated_vars () {
    if [ ! -z "${WAZUH_MANAGER_IP}" ] && [ -z "${WAZUH_MANAGER}" ]; then
        WAZUH_MANAGER=${WAZUH_MANAGER_IP}
    fi
    if [ ! -z "${WAZUH_AUTHD_SERVER}" ] && [ -z "${WAZUH_REGISTRATION_SERVER}" ]; then
        WAZUH_REGISTRATION_SERVER=${WAZUH_AUTHD_SERVER}
    fi
    if [ ! -z "${WAZUH_AUTHD_PORT}" ] && [ -z "${WAZUH_REGISTRATION_PORT}" ]; then
        WAZUH_REGISTRATION_PORT=${WAZUH_AUTHD_PORT}
    fi
    if [ ! -z "${WAZUH_PASSWORD}" ] && [ -z "${WAZUH_REGISTRATION_PASSWORD}" ]; then
        WAZUH_REGISTRATION_PASSWORD=${WAZUH_PASSWORD}
    fi
    if [ ! -z "${WAZUH_NOTIFY_TIME}" ] && [ -z "${WAZUH_KEEP_ALIVE_INTERVAL}" ]; then
        WAZUH_KEEP_ALIVE_INTERVAL=${WAZUH_NOTIFY_TIME}
    fi
    if [ ! -z "${WAZUH_CERTIFICATE}" ] && [ -z "${WAZUH_REGISTRATION_CA}" ]; then
        WAZUH_REGISTRATION_CA=${WAZUH_CERTIFICATE}
    fi
    if [ ! -z "${WAZUH_PEM}" ] && [ -z "${WAZUH_REGISTRATION_CERTIFICATE}" ]; then
        WAZUH_REGISTRATION_CERTIFICATE=${WAZUH_PEM}
    fi
    if [ ! -z "${WAZUH_KEY}" ] && [ -z "${WAZUH_REGISTRATION_KEY}" ]; then
        WAZUH_REGISTRATION_KEY=${WAZUH_KEY}
    fi
    if [ ! -z "${WAZUH_GROUP}" ] && [ -z "${WAZUH_AGENT_GROUP}" ]; then
        WAZUH_AGENT_GROUP=${WAZUH_GROUP}
    fi
}

set_vars () {
    export WAZUH_MANAGER=$(launchctl getenv WAZUH_MANAGER)
    export WAZUH_MANAGER_PORT=$(launchctl getenv WAZUH_MANAGER_PORT)
    export WAZUH_PROTOCOL=$(launchctl getenv WAZUH_PROTOCOL)
    export WAZUH_REGISTRATION_SERVER=$(launchctl getenv WAZUH_REGISTRATION_SERVER)
    export WAZUH_REGISTRATION_PORT=$(launchctl getenv WAZUH_REGISTRATION_PORT)
    export WAZUH_REGISTRATION_PASSWORD=$(launchctl getenv WAZUH_REGISTRATION_PASSWORD)
    export WAZUH_KEEP_ALIVE_INTERVAL=$(launchctl getenv WAZUH_KEEP_ALIVE_INTERVAL)
    export WAZUH_TIME_RECONNECT=$(launchctl getenv WAZUH_TIME_RECONNECT)
    export WAZUH_REGISTRATION_CA=$(launchctl getenv WAZUH_REGISTRATION_CA)
    export WAZUH_REGISTRATION_CERTIFICATE=$(launchctl getenv WAZUH_REGISTRATION_CERTIFICATE)
    export WAZUH_REGISTRATION_KEY=$(launchctl getenv WAZUH_REGISTRATION_KEY)
    export WAZUH_AGENT_NAME=$(launchctl getenv WAZUH_AGENT_NAME)
    export WAZUH_AGENT_GROUP=$(launchctl getenv WAZUH_AGENT_GROUP)

    # The following variables are yet supported but all of them are deprecated
    export WAZUH_MANAGER_IP=$(launchctl getenv WAZUH_MANAGER_IP)
    export WAZUH_NOTIFY_TIME=$(launchctl getenv WAZUH_NOTIFY_TIME)
    export WAZUH_AUTHD_SERVER=$(launchctl getenv WAZUH_AUTHD_SERVER)
    export WAZUH_AUTHD_PORT=$(launchctl getenv WAZUH_AUTHD_PORT)
    export WAZUH_PASSWORD=$(launchctl getenv WAZUH_PASSWORD)
    export WAZUH_GROUP=$(launchctl getenv WAZUH_GROUP)
    export WAZUH_CERTIFICATE=$(launchctl getenv WAZUH_CERTIFICATE)
    export WAZUH_KEY=$(launchctl getenv WAZUH_KEY)
    export WAZUH_PEM=$(launchctl getenv WAZUH_PEM)
}

unset_vars() {

    OS=$1

    vars=(WAZUH_MANAGER_IP WAZUH_PROTOCOL WAZUH_MANAGER_PORT WAZUH_NOTIFY_TIME \
          WAZUH_TIME_RECONNECT WAZUH_AUTHD_SERVER WAZUH_AUTHD_PORT WAZUH_PASSWORD \
          WAZUH_AGENT_NAME WAZUH_GROUP WAZUH_CERTIFICATE WAZUH_KEY WAZUH_PEM \
          WAZUH_MANAGER WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT \
          WAZUH_REGISTRATION_PASSWORD WAZUH_KEEP_ALIVE_INTERVAL WAZUH_REGISTRATION_CA \
          WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY WAZUH_AGENT_GROUP)


    for var in "${vars[@]}"; do
        if [ "${OS}" = "Darwin" ]; then
            launchctl unsetenv ${var}
        fi
        unset ${var}
    done
}

tolower () {
   echo $1 | tr '[:upper:]' '[:lower:]'
}

main () {

    uname_s=$(uname -s)

    if [ "${uname_s}" = "Darwin" ]; then
        sed="sed -ire"
        set_vars
    elif [ "${uname_s}" = "AIX" ] || [ "${uname_s}" = "SunOS" ] || [ "${uname_s}" = "HP-UX" ]; then
        use_unix_sed="True"
    fi

    get_deprecated_vars

    if [ ! -s ${WAZUH_HOME}/etc/client.keys ] && [ ! -z ${WAZUH_MANAGER} ]; then
        if [ ! -f ${WAZUH_HOME}/logs/ossec.log ]; then
            touch -f ${WAZUH_HOME}/logs/ossec.log
            chmod 660 ${WAZUH_HOME}/logs/ossec.log
            chown root:ossec ${WAZUH_HOME}/logs/ossec.log
        fi

        # Check if multiples IPs are defined in variable WAZUH_MANAGER
        WAZUH_MANAGER=$(echo ${WAZUH_MANAGER} | sed "s#,#;#g")
        ADDRESSES=(${WAZUH_MANAGER//;/ })
        if [ ${#ADDRESSES[@]} -gt 1 ]; then
            # Get uniques values
            ADDRESSES=($(echo "${ADDRESSES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
            add_adress_block "${ADDRESSES[@]}"
            if [ -z ${WAZUH_REGISTRATION_SERVER} ]; then
                WAZUH_REGISTRATION_SERVER=${ADDRESSES[0]}
            fi
        else
            # Single address
            edit_value_tag "address" ${WAZUH_MANAGER}
            if [ -z ${WAZUH_REGISTRATION_SERVER} ]; then
                WAZUH_REGISTRATION_SERVER=${WAZUH_MANAGER}
            fi
        fi

        # Options to be modified in ossec.conf
        edit_value_tag "protocol" "$(tolower ${WAZUH_PROTOCOL})"
        edit_value_tag "port" ${WAZUH_MANAGER_PORT}
        edit_value_tag "notify_time" ${WAZUH_KEEP_ALIVE_INTERVAL}
        edit_value_tag "time-reconnect" ${WAZUH_TIME_RECONNECT}

    elif [ -s ${WAZUH_HOME}/etc/client.keys ] && [ ! -z ${WAZUH_MANAGER} ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') agent-auth: ERROR: The agent is already registered." >> ${WAZUH_HOME}/logs/ossec.log
    fi

    if [ ! -s ${WAZUH_HOME}/etc/client.keys ] && [ ! -z ${WAZUH_REGISTRATION_SERVER} ]; then
        # Options to be used in register time.
        OPTIONS="-m ${WAZUH_REGISTRATION_SERVER}"
        OPTIONS=$(add_parameter "${OPTIONS}" "-p" "${WAZUH_REGISTRATION_PORT}")
        OPTIONS=$(add_parameter "${OPTIONS}" "-P" "${WAZUH_REGISTRATION_PASSWORD}")
        OPTIONS=$(add_parameter "${OPTIONS}" "-A" "${WAZUH_AGENT_NAME}")
        OPTIONS=$(add_parameter "${OPTIONS}" "-G" "${WAZUH_AGENT_GROUP}")
        OPTIONS=$(add_parameter "${OPTIONS}" "-v" "${WAZUH_REGISTRATION_CA}")
        OPTIONS=$(add_parameter "${OPTIONS}" "-k" "${WAZUH_REGISTRATION_KEY}")
        OPTIONS=$(add_parameter "${OPTIONS}" "-x" "${WAZUH_REGISTRATION_CERTIFICATE}")
        ${WAZUH_HOME}/bin/agent-auth ${OPTIONS} >> ${WAZUH_HOME}/logs/ossec.log 2>/dev/null
    fi

    unset_vars ${uname_s}
}

main
