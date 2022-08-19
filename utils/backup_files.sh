#!/bin/sh
CWD=$(pwd)
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

function backup_dir ( ) {

    BACKUP_DIR="${1}"
    DIR_DIVIDE="$(echo ${1} | tr '/' '_')"
    OUTPUT_FILE="${DIR_DIVIDE}_${TIMESTAMP}.tar"
    echo_info "Backing up directory ${BACKUP_DIR} on ${TIMESTAMP}\n"
    find "${BACKUP_DIR}" -type f 2>/dev/null | tar cvf "./${OUTPUT_FILE}" --files-from=-
}


