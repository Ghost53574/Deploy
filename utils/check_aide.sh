#!/bin/bash

# PvJ Blue Team check for AIDE
#
# This requires a root SSH public/private key setup.

host="$1"
local_dir="$2"

if [ -z "$host" ] || [ -z "$local_dir" ]
then
  echo
  echo "ERROR: Please use the correct syntax."
  echo
  echo "Syntax: bash aide_setup.sh <host> <local_dir>"
  echo
  exit 1
fi

local_aide_db=$local_dir/aide.db.${host}.gz

if ! [ -f $local_aide_db ]
then
  echo
  echo "ERROR: $local_aide_db doesn't exit."
  echo
  exit 1
fi

scp -q $local_aide_db root@$host:/var/lib/aide/aide.db.gz
scp_retval=$?

if [ $scp_retval -ne 0 ]
then
  echo
  echo "ERROR: Something went wrong while uploading $local_aide_db."
  echo
  exit 1
fi



local_aide_report=$local_dir/aide.report.${host}.$(date +%s).txt

ssh root@$host "aide -c /etc/aide_pvj.conf --check" > $local_aide_report

echo
echo "OK: Report written to $local_aide_report."
echo

exit 0

