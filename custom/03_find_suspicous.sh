#!/bin/bash
CWD=$(pwd)
TIMESTAMP="$(date +%s)"
UNAME="$(uname -a | awk -F' ' '{print $1_$3_$4}')"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

STRINGS="$(which strings)"
DIR_LIST=("/home" "/usr/bin" "/bin" "/opt" "/tmp" "/dev/shm" "/etc")

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}\n"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}\n"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}\n"
}

echo ""
echo_info "[ + ] Finding ELF files with weird extensions"
find / -regex ".*\.\(gz\|tar\|rar\|gzip\|zip\|sh\|txt\|jpg\|gif\|png\|jpeg\)" -type f -exec file -p '{}' \; 2>/dev/null | grep ELF | cut -d':' -f 1 > "./${UNAME}_${TIMESTAMP}_file_ext.log"
echo_info "[ + ] Finding ELF files with a bin shell or system()"
for DIR in "${DIR_LIST[@]}";
do
    echo_warn "[ + ] Checking ${DIR}"
    for FILE in $(find ${DIR} -type f -exec file -p '{}' \; 2>/dev/null | grep ELF | cut -d ':' -f 1);
    do
        IS_SH=""
        if [[ ! -z "${STRINGS}" ]];
        then
            IS_SH="$(strings "${FILE}" | grep -e ".*/bin/.*sh|system(")"
        else
            IS_SH="$(grep -a -E ".*/bin/.*sh|system\(" "${FILE}")"
        fi
        if [[ ! -z "${IS_SH}" ]];
        then
            echo_fail "[ - ] ${FILE} has system or /bin/sh"
            FILE_NAME="$(echo ${FILE} | rev | cut -d '/' -f 1 | rev)"
            echo "${IS_SH}" >> "./${UNAME}_${TIMESTAMP}_${FILE_NAME}_sh.log"
        fi
    done
done
echo_info "[ + ] Finding unsinged kernel modules"
lsmod | cut -d' ' -f1 | xargs modinfo 2>/dev/null | grep filename | sed 's/\s\+/ /g' | cut -d' ' -f2 | xargs grep -FL '~Module signature appended' > "./${UNAME}_${TIMESTAMP}_kern_modules.log"
