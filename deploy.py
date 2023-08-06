#!/usr/bin/python3
import sys
import json
import argparse
from pathlib import Path

from .modules import utils
from .modules import connector
from .modules import classes

BANNER = f'''{utils.HEADER}{utils.BOLD}
            .______  ._______._______ .___    ._______   ____   ____
    .       :_ _   \ : .____/: ____  ||   |   : .___  \  \   \_/   / .
            |   |   || : _/\ |    :  ||   |   | :   |  |  \___ ___/    .
       .    | . |   ||   /  \|   |___||   |/\ |     :  |    |   |   
            |. ____/ |_.: __/|___|    |   /  \ \_. ___/     |___|   .
            :/         :/            |______/   :/                 
  .         :                                   :                     .
            |               .          .         |         .  .  
                          .                      |                .
        .         .           . |       .           .
             .                       .           .           .      .
          .         .    .               .             .         .
                                                         by: ⧸𝒸o𝓏⧸
{utils.ENDC}'''

# https://github.com/pyinvoke/invoke/issues/15
# https://github.com/algrebe/python-tee


# Author:  c0z
# Date:    2022-07-25
# License: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html (GPL2)

# Impliment WinRM NTLM/CredSSP/HTTPS auth like ansible
# Needs to use paramiko==2.7.2 due to paramiko bug https://github.com/paramiko/paramiko/pull/1606 
# treating encrypted RSA keys as DSA keys

import sys
import subprocess
import pkg_resources

required = {'pypsrp', 'fabric2'}
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = required - installed

if missing:
    python = sys.executable
    subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog='Deploy',
            description='Deploy\'s scripts to servers with fabric2\'s ssh or pypsrp winrm via threading')
    parser.add_argument('-e', '--ext', type=str, action='store', default="Nothing", help='The files you want to or can execute')
    parser.add_argument('-k', '--command', type=str, action='store', default="Nothing", help='If specifed, will run the command on hosts selected')
    parser.add_argument('-c', '--config', type=argparse.FileType('r'), required=True, help='Loads a JSON config file with hosts, and stuff')
    parser.add_argument('-t', '--task', type=str, action='store', default="Nothing", help='Run a specific file on all hosts')
    parser.add_argument('-a', '--arguments', type=str, action='store', default="Nothing", help='Use with --task if task needs arguments')
    parser.add_argument('-i', '--host', type=str, action='store', default="Nothing", help='If specifed with only run against declared host')
    parser.add_argument('-S', '--sudo', type=utils.str_to_bool, nargs='?', const=True, default=False, help='Executes user with sudo')
    parser.add_argument('-v', '--log', type=utils.str_to_bool, nargs='?', const=True, default=False, help='Set this flag if you want to have log files generated on the host downloaded locally')
    parser.add_argument('-q', '--quiet', type=utils.str_to_bool, nargs='?', const=True, default=False, help='Set this flag for very little output')
    parser.add_argument('-s', '--ssh', type=utils.str_to_bool, nargs='?', const=True, default=False, help='Set this flag to use SSH for Windows')
    parser.add_argument('-L', '--list', type=utils.str_to_bool, nargs='?', const=True, default=False, help='List hosts from config')
    args = parser.parse_args()

    if not args.quiet:
        QUIET=False
        print(BANNER)

    config = json.load(args.config)

    if args.list:
        utils.print_info("Printing out available hosts:")
        for host, values in config.items():
            utils.print_warn(f"{host} @ {values['address']}")
        print("")

    cwd = Path(".")

    settings: classes.Settings = None
    
    exts = None
    if args.ext != "Nothing":
        exts = args.ext
    else:
        exts = [ "py3", "py", "sh", "bat", "ps", "pl" ]
    
    files = utils.parse_files(current_dir=cwd,
                              accepted_exts=exts)
    scripts = utils.load_scripts(file_list=files, 
                                 current_dir=cwd)

    if args.list:
        utils.print_info("Printing out available files:")
        for script in scripts:
            utils.print_warn(f"{script}")
        sys.exit(0)

    if args.sudo:
        settings.admin=True

    if args.host != "Nothing":
        settings.single_host=True

    if args.command != "Nothing":
        settings.single_command=True
        settings.single_task=True
    
    if args.task != "Nothing":
        settings.single_task=True

    if args.arguments != "Nothing":
        settings.extra_args=True
    
    if args.log:
        settings.logging=True

    if args.ssh:
        settings.force_ssh=True

    connector.Threader(config=config, 
                       scripts=scripts, 
                       task=args.task, 
                       comamnd=args.command, 
                       arguments=args.arguments, 
                       host=args.host, 
                       settings=settings)
