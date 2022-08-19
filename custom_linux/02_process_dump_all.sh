#!/bin/bash
CWD=$(pwd)
TIMESTAMP="$(date +%s)"
UNAME="$(uname -a | awk -F' ' '{print $1_$3_$4}')"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

PY2="$(which python2)"
PY3="$(which python3)"
WRITE_MEM=""

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

if [[ ! -z "${PY3}" ]];
then
    WRITE_MEM="IyEvdXNyL2Jpbi9weXRob24KCiMgaHR0cHM6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvMTI5NzcxNzkvcmVhZGluZy1saXZpbmctcHJvY2Vzcy1tZW1vcnktd2l0aG91dC1pbnRlcnJ1cHRpbmctaXQKCgppbXBvcnQgcmUKaW1wb3J0IHN5cwppbXBvcnQgb3MKZGVmIHByaW50X21lbW9yeV9vZl9waWQocGlkLCBvbmx5X3dyaXRhYmxlPVRydWUpOgogICAgIiIiIAogICAgUnVuIGFzIHJvb3QsIHRha2UgYW4gaW50ZWdlciBQSUQgYW5kIHJldHVybiB0aGUgY29udGVudHMgb2YgbWVtb3J5IHRvIFNURE9VVAogICAgIiIiCiAgICBjdXJyZW50X2RpcmVjdG9yeSA9IG9zLmdldGN3ZCgpCiAgICBtZW1vcnlfcGVybWlzc2lvbnMgPSAncncnIGlmIG9ubHlfd3JpdGFibGUgZWxzZSAnci0nCiAgICBwcm9jX21hcHMgPSAiL3Byb2MvIiArIHN0cihwaWQpICsgIi9tYXBzIgogICAgcHJvY19tZW0gID0gIi9wcm9jLyIgKyBzdHIocGlkKSArICIvbWVtIgogICAgd2l0aCBvcGVuKHByb2NfbWFwcywgJ3InKSBhcyBtYXBzX2ZpbGU6CiAgICAgICAgd2l0aCBvcGVuKHByb2NfbWVtLCAncmInKSBhcyBtZW1fZmlsZToKICAgICAgICAgICAgZm9yIGxpbmUgaW4gbWFwc19maWxlLnJlYWRsaW5lcygpOiAgIyBmb3IgZWFjaCBtYXBwZWQgcmVnaW9uCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgbSA9IHJlLm1hdGNoKHInKFswLTlBLUZhLWZdKyktKFswLTlBLUZhLWZdKykgKFstcl1bLXddKScsIGxpbmUpCiAgICAgICAgICAgICAgICAgICAgaWYgbS5ncm91cCgzKSA9PSBtZW1vcnlfcGVybWlzc2lvbnM6IAogICAgICAgICAgICAgICAgICAgICAgICBzdGFydCA9IGludChtLmdyb3VwKDEpLCAxNikKICAgICAgICAgICAgICAgICAgICAgICAgaWYgc3RhcnQgPiAweEZGRkZGRkZGRkZGRjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICAgICAgICAgIGVuZCA9IGludChtLmdyb3VwKDIpLCAxNikKICAgICAgICAgICAgICAgICAgICAgICAgbWVtX2ZpbGUuc2VlayhzdGFydCkgICMgc2VlayB0byByZWdpb24gc3RhcnQKICAgICAgICAgICAgICAgICAgICAgICAgY2h1bmsgPSBtZW1fZmlsZS5yZWFkKGVuZCAtIHN0YXJ0KSMgcmVhZCByZWdpb24gY29udGVudHMKICAgICAgICAgICAgICAgICAgICAgICAgcGF0aF9kaXIgPSBjdXJyZW50X2RpcmVjdG9yeSArICIvIiArIHN0cihwaWQpICsgIl9kbXAubG9nIgogICAgICAgICAgICAgICAgICAgICAgICB3aXRoIG9wZW4ocGF0aF9kaXIsICd3YicpIGFzIG91dDojIGR1bXAgY29udGVudHMgdG8gc3RhbmRhcmQgb3V0cHV0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvdXQud3JpdGUoY2h1bmspCiAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgICAgICAgICAgcHJpbnQoIk1lc3NhZ2U6IiwgZSkKCmlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6ICMgRXhlY3V0ZSB0aGlzIGNvZGUgd2hlbiBydW4gZnJvbSB0aGUgY29tbWFuZGxpbmUuCiAgICBhcmd1bWVudHMgPSAnICcuam9pbihzeXMuYXJndikKICAgIHRyeToKICAgICAgICBhc3NlcnQgbGVuKHN5cy5hcmd2KSA9PSAyLCAiUHJvdmlkZSBleGFjdGx5IDEgUElEIChwcm9jZXNzIElEKSIKICAgICAgICBwaWQgPSBpbnQoc3lzLmFyZ3ZbMV0pCiAgICAgICAgcHJpbnRfbWVtb3J5X29mX3BpZChwaWQpCiAgICAgICAgcHJpbnQoIkR1bXBpbmcgUElEOiAiICsgc3RyKHBpZCkpCiAgICBleGNlcHQgKEFzc2VydGlvbkVycm9yLCBWYWx1ZUVycm9yKSBhcyBlOgogICAgICAgIHByaW50KCJQbGVhc2UgcHJvdmlkZSAxIFBJRCBhcyBhIGNvbW1hbmRsaW5lIGFyZ3VtZW50LiIpCiAgICAgICAgcHJpbnQoIllvdSBlbnRlcmVkOiAiICsgYXJndW1lbnRzKQogICAgICAgIHJhaXNlIGUK"
else
    WRITE_MEM="IyEvdXNyL2Jpbi9weXRob24yCgppbXBvcnQgcmUKaW1wb3J0IHN5cwppbXBvcnQgb3MKCmN1cnJlbnRfZGlyZWN0b3J5ID0gb3MuZ2V0Y3dkKCkKCmRlZiBwcmludF9tZW1vcnlfb2ZfcGlkKHBpZCwgb25seV93cml0YWJsZT1UcnVlKToKICAgICIiIiAKICAgIFJ1biBhcyByb290LCB0YWtlIGFuIGludGVnZXIgUElEIGFuZCByZXR1cm4gdGhlIGNvbnRlbnRzIG9mIG1lbW9yeSB0byBTVERPVVQKICAgICIiIgogICAgbWVtb3J5X3Blcm1pc3Npb25zID0gJ3J3JyBpZiBvbmx5X3dyaXRhYmxlIGVsc2UgJ3ItJwogICAgdHJ5OgogICAgICAgIHdpdGggb3BlbigiL3Byb2MvJWQvbWFwcyIgJSBwaWQsICdyJykgYXMgbWFwc19maWxlOgogICAgICAgICAgICB3aXRoIG9wZW4oIi9wcm9jLyVkL21lbSIgJSBwaWQsICdyJywgMCkgYXMgbWVtX2ZpbGU6CiAgICAgICAgICAgICAgICBmb3IgbGluZSBpbiBtYXBzX2ZpbGUucmVhZGxpbmVzKCk6ICAjIGZvciBlYWNoIG1hcHBlZCByZWdpb24KICAgICAgICAgICAgICAgICAgICBtID0gcmUubWF0Y2gocicoWzAtOUEtRmEtZl0rKS0oWzAtOUEtRmEtZl0rKSAoWy1yXVstd10pJywgbGluZSkKICAgICAgICAgICAgICAgICAgICBpZiBtLmdyb3VwKDMpID09IG1lbW9yeV9wZXJtaXNzaW9uczogCiAgICAgICAgICAgICAgICAgICAgICAgIHN0YXJ0ID0gaW50KG0uZ3JvdXAoMSksIDE2KQogICAgICAgICAgICAgICAgICAgICAgICBpZiBzdGFydCA+IDB4RkZGRkZGRkZGRkZGOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgICAgICAgICAgZW5kID0gaW50KG0uZ3JvdXAoMiksIDE2KQogICAgICAgICAgICAgICAgICAgICAgICBtZW1fZmlsZS5zZWVrKHN0YXJ0KSAgIyBzZWVrIHRvIHJlZ2lvbiBzdGFydAogICAgICAgICAgICAgICAgICAgICAgICBjaHVuayA9IG1lbV9maWxlLnJlYWQoZW5kIC0gc3RhcnQpICAjIHJlYWQgcmVnaW9uIGNvbnRlbnRzCiAgICAgICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IGN1cnJlbnRfZGlyZWN0b3J5ICsgIi8iICsgc3RyKHBpZCkgKyAiX2RtcC5sb2ciCiAgICAgICAgICAgICAgICAgICAgICAgIHdpdGggb3BlbihvdXRwdXQsICd3JykgYXMgb3V0OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3V0LndyaXRlKGNodW5rKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHByaW50ICJNZXNzYWdlOiAlcyIgJSBlCgppZiBfX25hbWVfXyA9PSAnX19tYWluX18nOiAjIEV4ZWN1dGUgdGhpcyBjb2RlIHdoZW4gcnVuIGZyb20gdGhlIGNvbW1hbmRsaW5lLgogICAgdHJ5OgogICAgICAgIGFzc2VydCBsZW4oc3lzLmFyZ3YpID09IDIsICJQcm92aWRlIGV4YWN0bHkgMSBQSUQgKHByb2Nlc3MgSUQpIgogICAgICAgIHBpZCA9IGludChzeXMuYXJndlsxXSkKICAgICAgICBwcmludCAiRHVtcGluZyBQSUQ6ICVzIiAlIHBpZAogICAgICAgIHByaW50X21lbW9yeV9vZl9waWQocGlkKQogICAgZXhjZXB0IChBc3NlcnRpb25FcnJvciwgVmFsdWVFcnJvcikgYXMgZToKICAgICAgICBwcmludCAiUGxlYXNlIHByb3ZpZGUgMSBQSUQgYXMgYSBjb21tYW5kbGluZSBhcmd1bWVudC4iCiAgICAgICAgcHJpbnQgIllvdSBlbnRlcmVkOiAlcyIgJSAnICcuam9pbihzeXMuYXJndikKICAgICAgICByYWlzZSBlCg=="
fi

function create_dump ( ) {
    echo "${WRITE_MEM}" | base64 -d > ./write_mem.py
    if [[ ! -z "${PY3}" ]];
    then
        python3 ./write_mem.py ${1}
    else
        python2 ./write_mem.py ${1}
    fi
}

for PID in {0..32768};
do
    if [[ ! -d "/proc/${PID}" ]];
    then
        continue
    fi
    ENVIRON="$(cat /proc/${PID}/environ 2>/dev/null)"
    CMDLINE="$(cat < /proc/${PID}/cmdline 2>/dev/null)"
    CWD_DIR="$(ls -la /proc/${PID}/cwd 2>/dev/null)"
    EXE_DIR="$(ls -la /proc/${PID}/exe 2>/dev/null)"
    MAPPEDM="$(cat /proc/${PID}/maps 2>/dev/null)"
    if [[ -z "${ENVIRON}" && -z "${CMDLINE}" && -z "${MAPPEDM}" ]];
    then
        continue
    fi
    echo_fail "[ + ] Grabbing PID ${PID} information\n"
    echo -e """
    PID:${PID}
    ENV:\t${ENVIRON}
    CMD:\t${CMDLINE}
    CWD:\t${CWD_DIR}
    EXE:\t${EXE_DIR}
    MAPPED_MEMORY:\n
    ${MAPPEDM}
    """ >> "./${UNAME}_pid.log"

    echo_fail "[ + ] Grabbing PID ${PID} executable\n"

    cat "/proc/${PID}/exe" 2>/dev/null > "./${PID}_exe.log"

    create_dump ${PID}
done
rm -rf ./write_mem.py
echo_warn "[ + ] proc_info done, output is: ${OS_VERSION}_pid.log"
