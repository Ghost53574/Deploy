#!/bin/bash
CHKROOT_VERSION="chkrootkit-0.55"
OS_VERSION="$(lsb_release -a 2>/dev/null | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'
STRINGS="$(which strings)"

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

if [[ -z "${STRINGS}" ]];
then
    echo_fail "[ ! ] Install strings to use this script"
    exit 1
fi

echo ""
cd .. && rm -rf "./${CHKROOT_VERSION}"
echo_fail "[ + ] ${CHKROOT_VERSION} scan complete, output is ${CHKROOT_VERSION}.log"