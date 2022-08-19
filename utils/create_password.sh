#!/bin/bash
tr -dc '[:graph:]' < /dev/urandom | dd bs=4 count=12 2>/dev/null
