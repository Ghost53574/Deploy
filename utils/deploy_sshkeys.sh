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

if [[ ! -d "${CWD}/sshkeys" ]];
then
    echo_warn "sshkeys directory doesn't exist in current directory, creating\n"
    mkdir "${CWD}/sshkeys"
fi

echo_info "Deploying all public keys to all boxes\n"
for pub_key in $(find -type f -name *.pub 2>/dev/null);
do
    echo_info "Deploying ${pub_key}\n"
    echo_info "What is public keys ${pub_key}'s IP address: "
    read IP_ADDRESS
    echo_info "What is ${IP_ADDRESS}'s username: "
    read USERNAME
    CMD="$(cat ${pub_key} | base64 -w 0)"
    $SSH "${USERNAME}@${IP_ADDRESS}" "echo ${CMD} | base64 -d >> /home/${USERNAME}/.ssh/authorized_keys"
done