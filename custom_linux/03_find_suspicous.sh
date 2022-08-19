#!/bin/bash

COMMON_FILES_ELF="$(find / -regex ".*\.\(gz\|tar\|rar\|gzip\|zip\|sh\|txt\|jpg\|gif\|png\|jpeg)" -type f -exec file -p '{}' \; | grep ELF | cut -d":" -f1)"

UNSINGED_KERNEL_MOD="$(lsmod | cut -d' ' -f1 | xargs modinfo 2>/dev/null | grep filename | sed 's/\s\+/ /g' | cut -d' ' -f2 | xargs grep -FL '~Module signature appended')"
