#!/usr/bin/python3
import json
import winrm
import argparse
from time import sleep
import concurrent.futures
from pathlib import Path
from fabric2 import Connection, Config

# Author:  c0z
# Date:    2022-07-25
# License: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html (GPL2)

# Impliment WinRM NTLM/CredSSP/HTTPS auth like ansible
# Needs to use paramiko==2.7.2 due to paramiko bug https://github.com/paramiko/paramiko/pull/1606 treating encrypted RSA keys as DSA keys

BANNER = '''
            .______  ._______._______ .___    ._______   ____   ____
            :_ _   \ : .____/: ____  ||   |   : .___  \  \   \_/   /
            |   |   || : _/\ |    :  ||   |   | :   |  |  \___ ___/ 
            | . |   ||   /  \|   |___||   |/\ |     :  |    |   |   
            |. ____/ |_.: __/|___|    |   /  \ \_. ___/     |___|   
            :/         :/            |______/   :/                 
            :                                   :                  
            --------------------------------------------------------
            # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
            #      H             H             H             H      #
            # H     H        H         H         H    H         H   #
            #     H     H H        HH          H             H      #
            # Having issues with running scripts against a ton of   #
            # hosts all at once because the red team beat you to    #
            # the punch? Well no fear, deploy is here!              #
            # - - - - - - - - - - - - - - - - - - - - - - somerando #
'''

NEED_ADMIN=False
SINGLE_HOST=False
SINGLE_TASK=False
EXTRA_ARGS=False
LOGGING=False
QUIET=True

class bcolors:
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

class BashScript:
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

def execute_task(conn, script_name, script_path, script_ext, arguments, sudo_password):
    PREAMBLE = f"sudo -H -u root -S < <(echo '{sudo_password}') "
    try:
        if script_ext == ".sh":
            CMD=""
            if EXTRA_ARGS:
                CMD=f"bash {script_name} {arguments}"
            else:
                CMD=f"bash {script_name}"
            if NEED_ADMIN:
                conn.put(script_path, script_name)
                conn.run("chmod +x " + script_name, warn=True, echo=QUIET)
                conn.run(PREAMBLE + CMD, warn=True, echo=QUIET)
                conn.run("rm -rf " + script_name, warn=True, echo=QUIET)
            else:
                conn.put(script_path, script_name)
                conn.run("chmod +x " + script_name, warn=True, echo=QUIET)
                conn.run(CMD, warn=True, echo=QUIET)
                conn.run("rm -rf " + script_name, warn=True, echo=QUIET)
        elif script_ext == ".py2":
            CMD=""
            if EXTRA_ARGS:
                CMD=f"python2 {script_name} {arguments}"
            else:
                CMD=f"python2 {script_name}"
            if NEED_ADMIN:
                conn.put(script_path, script_name)
                conn.run(PREAMBLE + CMD, warn=True, echo=QUIET)
            else:
                conn.run(CMD, warn=True, echo=QUIET)
        elif script_ext == ".py3":
            CMD=""
            if EXTRA_ARGS:
                CMD=f"python3 {script_name} {arguments}"
            else:
                CMD=f"python3 {script_name}"
            if NEED_ADMIN:
                conn.put(script_path, script_name)
                conn.run(PREAMBLE + CMD, warn=True, echo=QUIET)
            else:
                conn.run(CMD, warn=True, echo=QUIET)
        elif script_ext == ".py":
            CMD=""
            if EXTRA_ARGS:
                CMD=f"python {script_name} {arguments}"
            else:
                CMD=f"python {script_name}"
            if NEED_ADMIN:
                conn.put(script_path, script_name)
                conn.run(PREAMBLE + CMD, warn=True, echo=QUIET)
            else:
                conn.run(CMD, warn=True, echo=QUIET)
        elif script_ext == ".pl":
            CMD=""
            if EXTRA_ARGS:
                CMD=f"perl {script_name} {arguments}"
            else:
                CMD=f"perl {script_name}"
            if NEED_ADMIN:
                conn.put(script_path, script_name)
                conn.run(PREAMBLE + CMD, warn=True, echo=QUIET)
            else:
                conn.run(CMD, warn=True, echo=QUIET)
            if NEED_ADMIN:
                conn.put(script_path, script_name)
                conn.run(PREAMBLE + CMD, warn=True, echo=QUIET)
            else:
                conn.run(CMD, warn=True, echo=QUIET)
    except Exception as e:
        print(f"{bcolors.FAIL}Exception: {e}{bcolors.ENDC}")
        pass

def execute_script(conn, host, scripts, task, arguments):
    LOOP=True
    if SINGLE_TASK:
        LOOP=False
    for script_name, script in scripts.items():
        script_path = script.path
        script_ext  = script.extension
        if LOOP:
            print(f"{bcolors.WARN}[{conn.host}] Running {script_name}{bcolors.ENDC}")
            execute_task(conn, script_name, script_path, script_ext, arguments, conn['sudo']['password'])
        else:
            if script_name == task:
                print(f"{bcolors.WARN}[{conn.host}] Running only this {task}{bcolors.ENDC}")
                execute_task(conn, script_name, script_path, script_ext, arguments, conn['sudo']['password'])
                break
            else:
                continue
        sleep(1)
    if LOGGING:
        conn.run(f"tar cvf ./{host}_{conn.host}_log.tar ./*.log 1>/dev/null", echo=QUIET)
        conn.get(f"{host}_{conn.host}_log.tar", f"{host}_{conn.host}_log.tar")
        conn.run(f"rm -rf ./*.log && rm -rf ./{host}_{conn.host}_log.tar", echo=QUIET)

class Threader:
    def __init__(self, config, scripts, task, arguments, shost):
        self.workers = 25
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = []
            if SINGLE_HOST:
                if shost in config.keys():
                    host_values = config[f"{shost}"]
                    username = host_values["username"]
                    password = host_values["password"]
                    address  = host_values["address"]
                    os       = host_values["os"]
                    port     = host_values["port"]
                    sshkey   = host_values["sshkey"]
                    if address == "" or username == "":
                        print(f"{bcolors.FAIL} Host has no address or username in config! {bcolors.ENDC}")
                        return None
                    if port == "":
                        port = "22"
                    if not sshkey:
                        print(f"{bcolors.INFO}Connecting to {shost} {bcolors.ENDC}")
                        ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password }, 'connect_kwargs': { 'password': password }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': {'password': password }})
                        try:
                            with Connection(host=address, user=username,
                                            port=port, config=ssh_config) as c:
                                    futures.append(
                                    ex.submit(execute_script, c, shost, scripts, task, arguments)
                                )
                        except Exception as e:
                            print(f"{bcolors.FAIL}Exception: {e}{bcolors.ENDC}")
                    else:
                        sshkey_passphrase = ""
                        sshkey_response = input("Is the private key encrypted?(y/n) : ")[:1]
                        if sshkey_response == "y":
                            sshkey_passphrase = input("Enter the private SSH key passphrase : ")
                        print(f"{bcolors.INFO}Connecting to {shost} {bcolors.ENDC}")
                        ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password }, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }})
                        try:
                            with Connection(host=address, user=username,
                                            port=port, config=ssh_config) as c:
                                futures.append(
                                    ex.submit(execute_script, c, shost, scripts, task, arguments)
                                )
                        except Exception as e:
                            print(f"{bcolors.FAIL}Exception: {e}{bcolors.ENDC}")
            else:
                for host, values in config.items():
                    username = values["username"]
                    password = values["password"]
                    address  = values["address"]
                    os       = values["os"]
                    port     = values["port"]
                    sshkey   = values["sshkey"]
                    if address == "" or username == "":
                        continue
                    if port == "":
                        port = "22"
                    if sshkey:
                        print(f"{bcolors.INFO}Connecting to {host} {bcolors.ENDC}")
                        ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password}, 'connect_kwargs': { 'password': password }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': {'password': password }})
                        try:
                            with Connection(host=address, user=username,
                                            port=port, config=ssh_config) as c:
                                futures.append(
                                    ex.submit(execute_script, c, host, scripts, task, arguments)
                                )
                        except Exception as e:
                            print(f"{bcolors.FAIL}Exception: {e}{bcolors.ENDC}")
                    else:
                        sshkey_passphrase = ""
                        sshkey_response = input("Is the private key encrypted? : ")[:1]
                        if sshkey_response == "y":
                            sshkey_passphrase = input("Enter the private SSH key passphrase : ")
                        print(f"{bcolors.INFO}Connecting to {shost} {bcolors.ENDC}")
                        ssh_config = Config(overrides={'sudo': { 'user': 'root', 'password': password}, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }}) if NEED_ADMIN else Config(overrides={'user': username, 'password': password, 'connect_kwargs': { 'key_filename': sshkey, 'passphrase': sshkey_passphrase, 'look_for_keys': False }})
                        try:
                            with Connection(host=address, user=username,
                                            port=port, config=ssh_config) as c:
                                futures.append(
                                    ex.submit(execute_script, c, host, scripts, task, arguments)
                                )
                        except Exception as e:
                            print(f"{bcolors.FAIL}Exception: {e}{bcolors.ENDC}")
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
            description='Deploy\'s scripts to servers with fabric2\'s ssh via threading')
    parser.add_argument('--files', type=argparse.FileType('r'), required=True, help='The files you want to or can execute')
    parser.add_argument('--config', type=argparse.FileType('r'), required=True, help='Loads a JSON config file with hosts, and stuff')
    parser.add_argument('--task', type=str, action='store', default="Nothing", help='Run a specific file on all hosts')
    parser.add_argument('--arguments', type=str, action='store', default="Nothing", help='Use with --task if task needs arguments')
    parser.add_argument('--host', type=str, action='store', default="Nothing", help='If specifed with only run against declared host')
    parser.add_argument('--root', type=str_to_bool, nargs='?', const=True, default=False, help='Executes user with sudo as root')
    parser.add_argument('--log', type=str_to_bool, nargs='?', const=True, default=False, help='Set this flag if you want to have log files generated on the host downloaded locally')
    parser.add_argument('--quiet', type=str_to_bool, nargs='?', const=True, default=False, help='Set this flag for very little output')
    args = parser.parse_args()

    if not args.quiet:
        QUIET=False
        print(BANNER)

    config = json.load(args.config)

    cwd = Path(".")

    if args.root:
        NEED_ADMIN=True

    if args.host != "Nothing":
        SINGLE_HOST=True

    if args.task != "Nothing":
        SINGLE_TASK=True

    if args.arguments != "Nothing":
        EXTRA_ARGS=True

    if args.log:
        LOGGING=True

    files = []
    if args.files:
        files = args.files.readlines()

    bashscripts = {}
    for f in files:
        p = Path(str(cwd.cwd()) + "/" + f)
        script_name = str(p.name)[:-1]
        script_dir  = str(p.parts[-2])
        script_path = str(p)[:-1]
        script_ext  = str(p.suffix)[:-1]
        bashscripts[script_name] = BashScript(script_name, script_path, script_dir, script_ext)

    Threader(config, bashscripts, args.task, args.arguments, args.host)