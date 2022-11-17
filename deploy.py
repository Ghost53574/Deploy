#!/usr/bin/python3
import sys
import json
import pypsrp
from pypsrp._utils import to_bytes, to_string
from pypsrp.exceptions import AuthenticationError, WinRMError
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import NAMESPACES, WSMan
import argparse
from time import sleep
import concurrent.futures
from pathlib import Path
from fabric2 import Connection, Config

# https://github.com/pyinvoke/invoke/issues/15
# https://github.com/algrebe/python-tee


# Author:  c0z
# Date:    2022-07-25
# License: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html (GPL2)

# Impliment WinRM NTLM/CredSSP/HTTPS auth like ansible
# Needs to use paramiko==2.7.2 due to paramiko bug https://github.com/paramiko/paramiko/pull/1606 treating encrypted RSA keys as DSA keys

BANNER = '''
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
'''

NEED_ADMIN=False
SINGLE_HOST=False
SINGLE_COMMAND=False
SINGLE_TASK=False
EXTRA_ARGS=False
LOGGING=False
QUIET=True
FORCE_SSH=False
LOCAL=False

HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
INFO = '\033[92m'
WARN = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def str_to_bool(value):
    if value.lower() in {'false', 'f', '0', 'no', 'n'}:
        return False
    elif value.lower() in {'true', 't', '1', 'yes', 'y'}:
        return True
    raise ValueError(f'{value} is not a valid boolean value')

class Script:
    def __init__(self, name, path, directory, extension):
        self.name      = name
        self.path      = path
        self.directory = directory
        self.extension = extension

    def name(self) -> str:
        return self.name

    def path(self) -> str:
        return self.path

    def directory(self) -> str:
        return self.d

    def extension(self) -> str:
        return self.extension

def print_results(conn, results: list):
    for result in results:
        print(f"{INFO}[{conn}]{ENDC}: {result}")

def execute_task(conn, os, script_name, script_path, script_ext, command, arguments, sudo_password) -> list:
    results = []
    try:
        if os == "linux":
            PREAMBLE = f"sudo -H -u root -S < <(echo '{sudo_password}') "
            if script_ext == ".sh":
                CMD=""
                if EXTRA_ARGS:
                    CMD=f"bash {script_name} {arguments}"
                else:
                    CMD=f"bash {script_name}"
                if NEED_ADMIN:
                    conn.put(script_path, script_name)  
                    conn.run("chmod +x " + script_name, warn=True, echo=QUIET)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=QUIET, hide=True))
                    conn.run("rm -rf " + script_name, warn=True, echo=QUIET)
                else:
                    conn.put(script_path, script_name)
                    conn.run("chmod +x " + script_name, warn=True, echo=QUIET)
                    results.append(conn.run(CMD, warn=True, echo=QUIET, hide=True))
                    conn.run("rm -rf " + script_name, warn=True, echo=QUIET)
            elif script_ext == ".py2":
                CMD=""
                if EXTRA_ARGS:
                    CMD=f"python2 {script_name} {arguments}"
                else:
                    CMD=f"python2 {script_name}"
                if NEED_ADMIN:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=QUIET, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=QUIET, hide=True))
            elif script_ext == ".py3":
                CMD=""
                if EXTRA_ARGS:
                    CMD=f"python3 {script_name} {arguments}"
                else:
                    CMD=f"python3 {script_name}"
                if NEED_ADMIN:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=QUIET, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=QUIET, hide=True))
            elif script_ext == ".py":
                CMD=""
                if EXTRA_ARGS:
                    CMD=f"python {script_name} {arguments}"
                else:
                    CMD=f"python {script_name}"
                if NEED_ADMIN:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=QUIET, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=QUIET, hide=True))
            elif script_ext == ".pl":
                CMD=""
                if EXTRA_ARGS:
                    CMD=f"perl {script_name} {arguments}"
                else:
                    CMD=f"perl {script_name}"
                if NEED_ADMIN:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=QUIET, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=QUIET, hide=True))
                if NEED_ADMIN:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=QUIET, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=QUIET, hide=True))
        if os == "windows":
            with RunspacePool(conn) as runspace:
                ps = PowerShell(runspace)
                if SINGLE_COMMAND:
                    ps.add_cmdlet(command).add_argument(arguments)
                    ps.invoke()
                    results.append(ps.output)
                else:
                    with open(f"{script_path}", 'r') as f:
                        script = f.read()[:-1]
                        if script_ext == ".ps1":
                            ps.add_script(script)
                            ps.invoke()
                            print(ps.output)
                        elif script_ext == ".bat":
                            command=f"C:\\Windows\\System32\\cmd.exe /c '{script}'"
                            ps.add_script(command)
                            ps.invoke()
                            results.append(ps.output)
    except Exception as e:
        print(f"{FAIL}Exception: {e}{ENDC}")
        pass
    return results

def execute_script(conn, os, host, scripts, task, command, arguments):
    LOOP=True
    SUDO_PASS=""
    print(f"{INFO}Connecting to {host} {ENDC}")
    if os == "linux":
        SUDO_PASS = conn['sudo']['password']
    if SINGLE_TASK:
        LOOP=False
    for script_name, script in scripts.items():
        script_path = script.path
        script_ext  = script.extension
        if LOOP:
            results = execute_task(conn, os, script_name, script_path, script_ext, command, arguments, SUDO_PASS)
            print_results(conn, results)
        else:
            if SINGLE_COMMAND:
                results = execute_task(conn, os, script_name, script_path, script_ext, command, arguments, SUDO_PASS)
                print_results(conn, results)
                break
            if script_name == task:
                results = execute_task(conn, os, script_name, script_path, script_ext, command, arguments, SUDO_PASS)
                print_results(conn, results)
                break
            else:
                continue
        sleep(1)
    if LOGGING:
        if os == "linux":
            PREAMBLE = f"sudo -H -u root -S < <(echo '{SUDO_PASS}') "
            conn.run(f"{PREAMBLE} chown 1000:1000 *.log", echo=QUIET)
            conn.run(f"tar cvf ./{host}_{host}_log.tar ./*.log 1>/dev/null", echo=QUIET)
            conn.get(f"{host}_{host}_log.tar", f"{host}_{host}_log.tar")
            conn.run(f"{PREAMBLE} rm -rf ./*.log && {PREAMBLE} rm -rf ./{host}_{host}_log.tar", echo=QUIET)
        elif os == "windows":
            None

class Threader:
    def __init__(self, config, scripts, task, comamnd, arguments, target_host):
        self.workers = 25
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = []
            if SINGLE_HOST:
                host = target_host
                USE_SSHKEY=False
                if host in config.keys():
                    values = config[f"{host}"]
                    if "username" in values:
                        username = values["username"]
                    else:
                        raise Exception(f"{FAIL}{host} needs a username!{ENDC}")
                    if "address" in values:
                        address  = values["address"]
                    else:
                        raise Exception(f"{FAIL}{host} needs an address!{ENDC}")
                    if "os" in values:
                        os       = values["os"]
                    else:
                        raise Exception(f"{FAIL}{host} needs an os!{ENDC}")
                    if "port" in values:
                        port     = values["port"]
                    else:
                        print(f"{WARN}{host} using default port for protocol {ENDC}")
                    if "password" in values:
                        password = values["password"]
                    elif "sshkey" in values:
                        USE_SSHKEY=True
                        sshkey   = values["sshkey"]
                    else:
                        raise Exception(f"{host} needs either a password or sshkey!")
                    
                    if os == "linux" or FORCE_SSH:
                        if port == "":
                            port = "22"
                        if not USE_SSHKEY:
                            ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password }, 'connect_kwargs': { 'password': password }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': {'password': password }})
                            try:
                                with Connection(host=address, user=username,
                                                port=port, config=ssh_config) as c:
                                        futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                print(f"{FAIL}Exception: {e}{ENDC}")
                        else:
                            sshkey_passphrase = ""
                            sshkey_response = input("Is the private key encrypted? (y/n): ")[:1]
                            if sshkey_response == "y":
                                sshkey_passphrase = input("Enter the private SSH key passphrase : ")
                            ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password }, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }})
                            try:
                                with Connection(host=address, user=username,
                                                port=port, config=ssh_config) as c:
                                    futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                print(f"{FAIL}Exception: {e}{ENDC}")
                    # Otherwise we use WinRM for Windows
                    elif os == "windows":
                        if port == "":
                            port = "5985"
                        try:
                            with WSMan(server=address, port=port, username=username, password=password, ssl=False, cert_validation=False) as conn:
                                futures.append(
                                    ex.submit(execute_script, conn, os, host, scripts, task, comamnd, arguments)
                                )
                        except Exception as e:
                                print(f"{FAIL}Exception: {e.with_traceback} {e.args} {ENDC}")
            else:
                for host, values in config.items():
                    USE_SSHKEY=False
                    username = values["username"]
                    address  = values["address"]
                    os       = values["os"]
                    port     = values["port"]
                    
                    if "username" in values:
                        username = values["username"]
                    else:
                        raise Exception(f"{FAIL}{host} needs a username!{ENDC}")
                    if "address" in values:
                        address  = values["address"]
                    else:
                        raise Exception(f"{FAIL}{host} needs an address!{ENDC}")
                    if "os" in values:
                        os       = values["os"]
                    else:
                        raise Exception(f"{FAIL}{host} needs an os!{ENDC}")
                    if "port" in values:
                        port     = values["port"]
                    else:
                        print(f"{WARN}{host} using default port for protocol {ENDC}")
                    if "password" in values:
                        password = values["password"]
                    elif "sshkey" in values:
                        USE_SSHKEY=True
                        sshkey   = values["sshkey"]
                    else:
                        raise Exception(f"{host} needs either a password or sshkey!")
                    
                    if os == "linux" or FORCE_SSH:
                        if port == "":
                            port = "22"
                        if not USE_SSHKEY:
                            ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password}, 'connect_kwargs': { 'password': password }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': {'password': password }})
                            try:
                                with Connection(host=address, user=username,
                                                port=port, config=ssh_config) as c:
                                    futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                print(f"{FAIL}Exception: {e}{ENDC}")
                        else:
                            sshkey_passphrase = ""
                            sshkey_response = input("Is the private key encrypted? : ")[:1]
                            if sshkey_response == "y":
                                sshkey_passphrase = input("Enter the private SSH key passphrase : ")
                            ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password}, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }})
                            try:
                                with Connection(host=address, user=username,
                                                port=port, config=ssh_config) as c:
                                    futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                print(f"{FAIL}Exception: {e}{ENDC}")
                    # Otherwise we use WinRM for Windows
                    elif os == "windows":
                        if port == "":
                            port = "5985"
                        try:
                            with WSMan(server=address, port=port, username=username, password=password, ssl=False, cert_validation=False) as conn:
                                futures.append(
                                    ex.submit(execute_script, conn, os, host, scripts, task, comamnd, arguments)
                                )
                        except Exception as e:
                                print(f"{FAIL}Exception: {e.with_traceback} {e.args} {ENDC}")
            completed, not_complete = concurrent.futures.wait(futures)
            for result in completed:
                if not result:
                    print("{}".format(result.result()))
                else:
                    try:
                        pass
                    except:
                        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog='Deploy',
            description='Deploy\'s scripts to servers with fabric2\'s ssh or pypsrp winrm via threading')
    parser.add_argument('-f', '--files', type=argparse.FileType('r'), required=True, help='The files you want to or can execute')
    parser.add_argument('-k', '--command', type=str, action='store', default="Nothing", help='If specifed, will run the command on hosts selected')
    parser.add_argument('-c', '--config', type=argparse.FileType('r'), required=True, help='Loads a JSON config file with hosts, and stuff')
    parser.add_argument('-t', '--task', type=str, action='store', default="Nothing", help='Run a specific file on all hosts')
    parser.add_argument('-a', '--arguments', type=str, action='store', default="Nothing", help='Use with --task if task needs arguments')
    parser.add_argument('-i', '--host', type=str, action='store', default="Nothing", help='If specifed with only run against declared host')
    parser.add_argument('-S', '--sudo', type=str_to_bool, nargs='?', const=True, default=False, help='Executes user with sudo')
    parser.add_argument('-v', '--log', type=str_to_bool, nargs='?', const=True, default=False, help='Set this flag if you want to have log files generated on the host downloaded locally')
    parser.add_argument('-q', '--quiet', type=str_to_bool, nargs='?', const=True, default=False, help='Set this flag for very little output')
    parser.add_argument('-s', '--ssh', type=str_to_bool, nargs='?', const=True, default=False, help='Set this flag to use SSH for Windows')
    parser.add_argument('-L', '--list', type=str_to_bool, nargs='?', const=True, default=False, help='List hosts from config')
    args = parser.parse_args()

    if not args.quiet:
        QUIET=False
        print(BANNER)

    config = json.load(args.config)

    if args.list:
        for host, values in config.items():
            print(f"{host} @ {values['address']}")
        sys.exit(0)

    cwd = Path(".")

    if args.sudo:
        NEED_ADMIN=True

    if args.host != "Nothing":
        SINGLE_HOST=True
    elif args.local and args.host != "Nothing":
        LOCAL=True
    elif args.local and args.host == "Nothing":
        raise Exception("If [ -l, --local ] is specified you need to specify a [ -i, --host ] host as well!")

    if args.command != "Nothing":
        SINGLE_COMMAND=True
        SINGLE_TASK=True
    
    if args.task != "Nothing":
        SINGLE_TASK=True

    if args.arguments != "Nothing":
        EXTRA_ARGS=True
    
    if args.log:
        LOGGING=True

    if args.ssh:
        FORCE_SSH=True

    files = []
    if args.files:
        files = args.files.readlines()

    scripts = {}
    for f in files:
        p = Path(str(cwd.cwd()) + "/" + f)
        script_name = str(p.name)[:-1]
        script_dir  = str(p.parts[-2])
        script_path = str(p)[:-1]
        script_ext  = str(p.suffix)[:-1]
        scripts[script_name] = Script(script_name, script_path, script_dir, script_ext)

    Threader(config, scripts, args.task, args.command, args.arguments, args.host)