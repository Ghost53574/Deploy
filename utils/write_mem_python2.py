#!/usr/bin/python2

import re
import sys
import os

current_directory = os.getcwd()

def print_memory_of_pid(pid, only_writable=True):
    """ 
    Run as root, take an integer PID and return the contents of memory to STDOUT
    """
    memory_permissions = 'rw' if only_writable else 'r-'
    try:
        with open("/proc/%d/maps" % pid, 'r') as maps_file:
            with open("/proc/%d/mem" % pid, 'r', 0) as mem_file:
                for line in maps_file.readlines():  # for each mapped region
                    m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r][-w])', line)
                    if m.group(3) == memory_permissions: 
                        start = int(m.group(1), 16)
                        if start > 0xFFFFFFFFFFFF:
                            continue
                        end = int(m.group(2), 16)
                        mem_file.seek(start)  # seek to region start
                        chunk = mem_file.read(end - start)  # read region contents
                        output = current_directory + "/" + str(pid) + "_dmp.log"
                        with open(output, 'w') as out:
                            out.write(chunk)
    except Exception as e:
        print "Message: %s" % e

if __name__ == '__main__': # Execute this code when run from the commandline.
    try:
        assert len(sys.argv) == 2, "Provide exactly 1 PID (process ID)"
        pid = int(sys.argv[1])
        print "Dumping PID: %s" % pid
        print_memory_of_pid(pid)
    except (AssertionError, ValueError) as e:
        print "Please provide 1 PID as a commandline argument."
        print "You entered: %s" % ' '.join(sys.argv)
        raise e
