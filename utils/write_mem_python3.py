#!/usr/bin/python

# https://stackoverflow.com/questions/12977179/reading-living-process-memory-without-interrupting-it


import re
import sys
import os
def print_memory_of_pid(pid, only_writable=True):
    """ 
    Run as root, take an integer PID and return the contents of memory to STDOUT
    """
    current_directory = os.getcwd()
    memory_permissions = 'rw' if only_writable else 'r-'
    proc_maps = "/proc/" + str(pid) + "/maps"
    proc_mem  = "/proc/" + str(pid) + "/mem"
    with open(proc_maps, 'r') as maps_file:
        with open(proc_mem, 'rb') as mem_file:
            for line in maps_file.readlines():  # for each mapped region
                try:
                    m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r][-w])', line)
                    if m.group(3) == memory_permissions: 
                        start = int(m.group(1), 16)
                        if start > 0xFFFFFFFFFFFF:
                            continue
                        end = int(m.group(2), 16)
                        mem_file.seek(start)  # seek to region start
                        chunk = mem_file.read(end - start)# read region contents
                        path_dir = current_directory + "/" + str(pid) + "_dmp.log"
                        with open(path_dir, 'wb') as out:# dump contents to standard output
                            out.write(chunk)
                except Exception as e:
                    print("Message:", e)

if __name__ == '__main__': # Execute this code when run from the commandline.
    arguments = ' '.join(sys.argv)
    try:
        assert len(sys.argv) == 2, "Provide exactly 1 PID (process ID)"
        pid = int(sys.argv[1])
        print_memory_of_pid(pid)
        print("Dumping PID: " + str(pid))
    except (AssertionError, ValueError) as e:
        print("Please provide 1 PID as a commandline argument.")
        print("You entered: " + arguments)
        raise e
