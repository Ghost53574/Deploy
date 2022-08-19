#!/bin/bash
CWD=$(pwd)
TIMESTAMP="$(date +%s)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

SSH="$(which ssh)"

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

CORPUS="/home/kali/Projects/Automation/corpus"
HASHES="${1}"
DIR_PATH="${CWD}/${HASHES}"

echo_info "What is the Operating System (debian, ubuntu, centos)? > "
read OS_VERSION
echo_info "What is the version of the Operating System? > "
read VERSION_NUM

echo_info "Testing ${HASHES} against files in ${CORPUS}/${OS_VERSION}/${VERSION_NUM}\n"

for FILE in $(find "${CORPUS}/${OS_VERSION}/${VERSION_NUM}" -type f 2>/dev/null);
do
    diff --color=always --tabsize=4 --suppress-common-lines --width=150 -y -Z -B -I -a -d --from-file=${HASHES} ${FILE}
done
