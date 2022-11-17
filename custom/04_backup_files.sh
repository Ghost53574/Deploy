#!/bin/sh
CWD=$(pwd)
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
OS_VERSION="$(lsb_release -a 2>/dev/null | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)" 
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

BACKUP_DIRS=("/etc" "/home")

function echo_info ( ) {
    echo -n -e "[${TIMESTAMP}]${GREEN} ${1} ${NC}\n"
}

function echo_warn ( ) {
    echo -n -e "[${TIMESTAMP}]${YELLOW} ${1} ${NC}\n"
}

function echo_fail ( ) {
    echo -n -e "[${TIMESTAMP}]${RED} ${1} ${NC}\n"
}

function backup_dir ( ) {
    
    DIR_DIVIDE="$(echo ${1} | tr '/' '_')"
    OUTPUT_FILE="${OS_VERSION}${DIR_DIVIDE}_${TIMESTAMP}.tar"
    find "${1}" -type f 2>/dev/null | tar cvf "./${OUTPUT_FILE}" --files-from=- 2>/dev/null 1>/dev/null
    mv "${OUTPUT_FILE}" "${OUTPUT_FILE}.log"
}

echo ""
echo_warn "[ + ] Backing up directories"
for DIR in "${BACKUP_DIRS[@]}";
do
    echo_info "[ - ] Backing up directory ${DIR}"
    backup_dir ${DIR} 
done
echo_warn "[ + ] Backup done"