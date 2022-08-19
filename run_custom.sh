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
DIR="custom"
find "${DIR}" -type f > ./files.txt
if [[ "$?" != "0" ]];
then
    echo_fail "Error in directory declaration"
fi
echo_fail "[ + ] Starting in custom linear mode, starting on ${TIMESTAMP}"
echo_info "[ + ] Targeting ${CWD}/${DIR}\n"
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 00_find_newer.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 01_hash_everything.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 02_process_dump_all.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 03_find_suspicous.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 04_chkrootkits_run.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 05_linpeas_run.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 06_deploy_issue.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 07_pull_logs.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 08_deploy_auditd.sh ${ARGUMENTS}
python3 ./deploy.py --files ./files.txt --config ./configs/config.json --task 09_apply_linux_stigs.sh ${ARGUMENTS}