#!/usr/bin/env bash
uname -a
cat /proc/self/environ | tr $'\x00' $'\n'
echo "hi"
