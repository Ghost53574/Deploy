#!/bin/bash
CWD=$(pwd)
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

OS_VERSION="$(lsb_release -a | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)"
CHATTR="$(which chattr)"

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

function freeze_dir ( ) {
    if [[ ! -d "/${1}" ]];
    then
        echo_fail "Directory ${1} does not exist\n"
        return
    fi
    TARGET_DIR="/${1}"
    OUTPUT_DIR="${OS_VERSION}_freeze.log"
    find "${TARGET_DIR}" -type f -exec $CHATTR +i {} \; 2>/dev/null >> "${OUTPUT_DIR}"
}

function freeze_file ( ) {
    if [[ ! -f "${1}" ]];
    then
        echo_fail "File ${1} does not exist\n"
        return
    fi
    $CHATTR +i ${1} 2>/dev/null >> "${OS_VERSION}_freeze.log"
}

function unfreeze_fir ( ) {
    if [[ ! -d "/${1}" ]];
    then
        echo_fail "Directory ${1} does not exist\n"
        return
    fi
    TARGET_DIR="/${1}"
    OUTPUT_DIR="${OS_VERSION}_freeze.log"
    find "${TARGET_DIR}" -type f -exec $CHATTR -i {} \; 2>/dev/null >> "${OUTPUT_DIR}"
}

function unfreeze_file ( ) {
    if [[ ! -f "${1}" ]];
    then
        echo_fail "File ${1} does not exist\n"
        return
    fi
    $CHATTR -i ${1} 2>/dev/null >> "${OS_VERSION}_freeze.log"
}