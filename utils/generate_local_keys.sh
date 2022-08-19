#!/bin/bash
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

if [[ ! -d "${CWD}/sshkeys" ]];
then
    echo_warn "sshkeys directory doesn't exist in current directory, creating\n"
    mkdir "${CWD}/sshkeys"
fi

echo_info "Welcome to the generate all your keys shop, I hope you have enough entropy!\n"
echo_info "How many keys would you like? > "
read key_count
KEYS="$(echo $((${key_count})))"
for (( i = 0; i < $KEYS; i++ ));
do
    echo_fail "Creating key ${i}...\n"
    ssh-keygen -t rsa -b 4096 -f "${CWD}/sshkeys/id_rsa_${i}" -q
done
