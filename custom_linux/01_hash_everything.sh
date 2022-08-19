#!/bin/bash
CWD=$(pwd)
OS_VERSION="$(lsb_release -a 2>/dev/null | grep 'Desc' | sed 's/[ ]*//g' | cut -d $'\t' -f 2 | cut -d '/' -f 1)" 
TIMESTAMP="$(date +%s)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

IPSET="$(ip)"
IFCONFIG="$(ifconfig)"
ROUTE="$(which route)"

IP=""

if [[ ! -z "${IPSET}" ]];
then
    IP="$(ip route list | grep default | awk '{print $5} ')"
else
    IP="$(ifconfig $(route | grep -E "eth|ens" | awk -F' ' '{print $8}' | sort -u))"
fi

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

function hash_dir ( ) {
    TARGET_DIR="/${1}"
    DIR_DIVIDE="$(echo ${1} | awk -F'/' '{print $1_$2}')"
    OUTPUT_DIR="${CWD}/${DIR_DIVIDE}_${OS_VERSION}_${IP}_md5.log"
    MD5OUT="$(find ${TARGET_DIR} -type f -exec md5sum {} \; 2>/dev/null)"
    echo "${MD5OUT}" | awk -F' ' '{print $2,$1}' > "${OUTPUT_DIR}"
}
echo_fail "[ + ] Hashing directories on ${TIMESTAMP}"
echo_info "[ + ] hash_dir boot done, output is ${CWD}/boot_${OS_VERSION}_${IP}_md5.log\n"
hash_dir boot
echo_info "[ + ] hash_dir etc done, output is ${CWD}/etc_${OS_VERSION}_${IP}_md5.log\n"
hash_dir etc
echo_info "[ + ] hash_dir home done, output is ${CWD}/home_${OS_VERSION}_${IP}_md5.log\n"
hash_dir home
echo_info "[ + ] hash_dir lib/systemd done, output is ${CWD}/lib_systemd_${OS_VERSION}_${IP}_md5.log\n"
hash_dir lib/systemd
echo_info "[ + ] hash_dir dev/shm done, output is ${CWD}/dev_shm_${OS_VERSION}_${IP}_md5.log\n"
hash_dir dev/shm
echo_info "[ + ] hash_dir var/log done, output is ${CWD}/var_log_${OS_VERSION}_${IP}_md5.log\n"
hash_dir var/log
echo_info "[ + ] hash_dir tmp done, output is ${CWD}/tmp_${OS_VERSION}_${IP}_md5.log\n"
hash_dir tmp
echo_fail "[ + ] hash_dir completed hashing all directories\n"
