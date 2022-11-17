#!/bin/bash
CWD=$(pwd)
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

USER="$(cat /etc/passwd | grep '1000' | cut -d ':' -f 1)"
OS_VERSION="$(lsb_release -a 2>/dev/null | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)"

function echo_info ( ) {
    echo -n -e "${GREEN}${1}${NC}\n"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW}${1}${NC}\n"
}

function echo_fail ( ) {
    echo -n -e "${RED}${1}${NC}\n"
}

echo ""
echo_info "[ + ] Copying all system logs..."
find /var/log -type f -regex '.*\.log$' -exec cp "{}" "${CWD}" \; 2>/dev/null
lastlog > "./lastlog.log"
chown -R ${USER}: "${CWD}/"
echo_fail "[ + ] Done copying system logs"
