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

function usage ( ) {
    echo_warn """
    ./run.sh {arguments to deploy.py}
    --root      : use sudo with root
    --host      : single host
    --task      : single task
    --arguments : additional arugments, mainly used with task
    --sshkey    : use a single ssh-key
    --log       : if there are output *.log files this command will tar them up and download them, then delete them

    example is:
    ./run.sh --root --host 192.168.1.2 --task hash_dir.sh --sshkey \"/home/user/.ssh/id_rsa\" --log
    ./run.sh --root --task create_dump.sh --arguments 666
    """
}

if [[ "$#" -lt 1 ]];
then
    echo_fail "Supply more arguments!\n"
    usage
    exit 1
fi

ARGUMENTS="$@"

echo_info "Please enter a starting directory, from your current directory excluded. Like files or files/custom.\n>"
read DIR
find "${DIR}" -type f > ./files.txt
if [[ "$?" != "0" ]];
then
    echo_fail "Error in directory declaration"
fi
echo_info "Starting on ${TIMESTAMP}\n"
echo_info "Targeting ${CWD}/${DIR}\n"
python3 ./deploy.py --files ./files.txt --config ./configs/config.json ${ARGUMENTS}
