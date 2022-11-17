#!/bin/bash
CWD=$(pwd)
TIMESTAMP="$(date +%s)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}\n"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}\n"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}\n"
}

UNAME="$(uname -a | awk -F' ' '{print $1_$3_$4}')"
OS_VERSION="$(lsb_release -a 2>/dev/null | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)"
OUTPUT_FILE="${OS_VERSION}_find_newer"

TODAY="$(date '+%Y-%m-%d %k:%M:%S')"
THREE_WEEKS="$(date -d '-3 week' '+%Y-%m-%d %k:%M:%S')"
TWO_WEEKS="$(date -d '-2 week' '+%Y-%m-%d %k:%M:%S')"
ONE_WEEK="$(date -d '-1 week' '+%Y-%m-%d %k:%M:%S')"
THREE_DAYS="$(date -d '-3 day' '+%Y-%m-%d %k:%M:%S')"
ONE_DAY="$(date -d '-1 day' '+%Y-%m-%d %k:%M:%S')"
HALF_DAY="$(date -d '-12 hour' '+%Y-%m-%d %k:%M:%S')"
QUARTER_DAY="$(date -d '-6 hour' '+%Y-%m-%d %k:%M:%S')"
FIFTH_DAY="$(date -d '-3 hour' '+%Y-%m-%d %k:%M:%S')"
SIXTH_DAY="$(date -d '-1 hour' '+%Y-%m-%d %k:%M:%S')"

function files_from ( ) {
    if [[ "$#" -eq 2 ]];
    then
        echo_info "[ + ] ${TIMESTAMP} Files_from : THEN: ${1} -> TODAY: ${2}"
        find / -newermt "${1}" ! -newermt "${2}" -ls 2>/dev/null | grep -v ' /var/lib\| /sys\| /proc' | tee "${OUTPUT_FILE}.log"
    else
        echo_info "[ + ] ${TIMESTAMP} Files_from : THEN: ${1} -> TODAY: ${TODAY}"
        find / -newermt "${1}" ! -newermt "${TODAY}" -ls 2>/dev/null | grep -v ' /var/lib\| /sys\| /proc' | tee "${OUTPUT_FILE}.log"
    fi
}

echo ""
#files_from ${THREE_WEEKS} "${1}"
#files_from ${TWO_WEEKS} "${1}"
#files_from ${ONE_WEEK} "${1}"
#files_from ${THREE_DAYS} "${1}"
#files_from ${ONE_DAY} "${1}"
#files_from ${HALF_DAY}
#files_from ${QUARTER_DAY}
#files_from ${FIFTH_DAY} "${1}"
#files_from "${SIXTH_DAY}" "${1}"

# This looks for files 1 week from right now up to 12 hours ago
files_from ${ONE_WEEK} ${HALF_DAY}

# This looks for files 6 hours old from right now
#files_from ${QUARTER_DAY}

echo_info "[ + ] find_newer completed"
