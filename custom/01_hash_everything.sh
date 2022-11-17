#!/bin/bash
CWD=$(pwd)
OS_VERSION="$(lsb_release -a 2>/dev/null | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)" 
TIMESTAMP="$(date +%s)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

IPSET="$(which ip)"
IFCONFIG="$(which ifconfig)"
ROUTE="$(which route)"

IP=""

if [[ ! -z "${IPSET}" ]];
then
    INTERFACE="$(ip route list | grep default | awk '{print $5} ')"
    IP="$(ip route list | grep "${INTERFACE}" | tail -n 1 | rev | cut -d ' ' -f 2 | rev)"
else
    INTERFACE="$(ifconfig $(route | grep -E "eth|ens" | awk -F' ' '{print $8}' | sort -u))"
    IP="$(echo "${INTERFACE}" | grep -oP 'addr\:.*\s' | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)"
fi

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}\n"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}\n"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}\n"
}

function hash_dir ( ) {
    TARGET_DIR="/${1}"
    DIR_DIVIDE="$(echo ${1} | awk -F'/' '{print $1_$2}')"
    OUTPUT_DIR="${CWD}/${DIR_DIVIDE}_${OS_VERSION}_${IP}_md5.log"
    MD5OUT="$(find ${TARGET_DIR} -type f -exec md5sum {} \; 2>/dev/null)"
    echo "${MD5OUT}" | awk -F' ' '{print $2,$1}' > "${OUTPUT_DIR}"
}

function hash_wrapper ( ) {
    echo_info "[ + ] hash_dir ${1} done, output is ${CWD}/${1}_${OS_VERSION}_${IP}_md5.log"
    hash_dir ${1}
}

echo ""
echo_info "[ + ] Hashing directories on ${IP} @ ${TIMESTAMP}"
hash_wrapper boot
hash_wrapper etc
hash_wrapper home
hash_wrapper lib/systemd
hash_wrapper dev/shm
hash_wrapper var/log
hash_wrapper tmp
echo_fail "[ + ] hash_dir completed hashing all directories"
