import concurrent.futures
from pypsrp.wsman import WSMan
from fabric2 import Connection, Config
from pypsrp.powershell import PowerShell, RunspacePool

import utils
import classes

def execute_task(conn, 
                 os, 
                 script_name, 
                 script_path, 
                 script_ext, 
                 command, 
                 arguments, 
                 sudo_password,
                 settings: classes.Settings) -> list:
    results = []
    try:
        if os == "linux":
            PREAMBLE = f"sudo -H -u root -S < <(echo '{sudo_password}') "
            if settings.single_command:
                CMD=""
                if settings.extra_args:
                    CMD=f"{command} {arguments}"
                else:
                    CMD=f"{command}"
                if settings.admin:
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=settings.quiet, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=settings.quiet, hide=True))
            elif script_ext == ".sh":
                CMD=""
                if settings.extra_args:
                    CMD=f"bash {script_name} {arguments}"
                else:
                    CMD=f"bash {script_name}"
                if settings.admin:
                    conn.put(script_path, script_name)  
                    conn.run("chmod +x " + script_name, warn=True, echo=settings.quiet)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=settings.quiet, hide=True))
                    conn.run("rm -rf " + script_name, warn=True, echo=settings.quiet)
                else:
                    conn.put(script_path, script_name)
                    conn.run("chmod +x " + script_name, warn=True, echo=settings.quiet)
                    results.append(conn.run(CMD, warn=True, echo=settings.quiet, hide=True))
                    conn.run("rm -rf " + script_name, warn=True, echo=settings.quiet)
            elif script_ext == ".py2":
                CMD=""
                if settings.extra_args:
                    CMD=f"python2 {script_name} {arguments}"
                else:
                    CMD=f"python2 {script_name}"
                if settings.admin:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=settings.quiet, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=settings.quiet, hide=True))
            elif script_ext == ".py3":
                CMD=""
                if settings.extra_args:
                    CMD=f"python3 {script_name} {arguments}"
                else:
                    CMD=f"python3 {script_name}"
                if settings.admin:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=settings.quiet, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=settings.quiet, hide=True))
            elif script_ext == ".py":
                CMD=""
                if settings.extra_args:
                    CMD=f"python {script_name} {arguments}"
                else:
                    CMD=f"python {script_name}"
                if settings.admin:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=settings.quiet, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=settings.quiet, hide=True))
            elif script_ext == ".pl":
                CMD=""
                if settings.extra_args:
                    CMD=f"perl {script_name} {arguments}"
                else:
                    CMD=f"perl {script_name}"
                if settings.admin:
                    conn.put(script_path, script_name)
                    results.append(conn.run(PREAMBLE + CMD, warn=True, echo=settings.quiet, hide=True))
                else:
                    results.append(conn.run(CMD, warn=True, echo=settings.quiet, hide=True))
        if os == "windows":
            with RunspacePool(conn) as runspace:
                ps = PowerShell(runspace)
                if settings.single_command:
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
        utils.print_fail(f"Exception: {e}")
        pass
    return results

def execute_script(conn, 
                   os, 
                   host, 
                   scripts, 
                   task, 
                   command, 
                   arguments,
                   settings: classes.Settings):
    LOOP=True
    SUDO_PASS=""
    utils.print_info(f"Connecting to {host}")
    if os == "linux":
        SUDO_PASS = conn['sudo']['password']
    if settings.single_task:
        LOOP=False
    for script_name, script in scripts.items():
        script_path = script.path
        script_ext  = script.extension
        if LOOP:
            results = execute_task(conn, os, script_name, script_path, script_ext, command, arguments, SUDO_PASS)
            utils.print_results(conn, results)
        else:
            if settings.single_command:
                results = execute_task(conn, os, script_name, script_path, script_ext, command, arguments, SUDO_PASS)
                utils.print_results(conn, results)
                break
            if script_name == task:
                results = execute_task(conn, os, script_name, script_path, script_ext, command, arguments, SUDO_PASS)
                utils.print_results(conn, results)
                break
            else:
                continue
    if settings.logging:
        if os == "linux":
            PREAMBLE = f"sudo -H -u root -S < <(echo '{SUDO_PASS}') "
            conn.run(f"{PREAMBLE} chown 1000:1000 *.log", echo=settings.quiet)
            conn.run(f"tar cvf ./{host}_{host}_log.tar ./*.log 1>/dev/null", echo=settings.quiet)
            conn.get(f"{host}_{host}_log.tar", f"{host}_{host}_log.tar")
            conn.run(f"{PREAMBLE} rm -rf ./*.log && {PREAMBLE} rm -rf ./{host}_{host}_log.tar", echo=settings.quiet)
        elif os == "windows":
            None

class Threader:
    def __init__(self, 
                 config, 
                 scripts, 
                 task: str, 
                 comamnd: str, 
                 arguments: str, 
                 target_host: str,
                 settings: classes.Settings):
        self.workers = 25
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = []
            if settings.single_host:
                host = target_host
                USE_SSHKEY=False
                if host in config.keys():
                    values = config[f"{host}"]
                    if "username" in values:
                        username = values["username"]
                    else:
                        raise Exception(f"{utils.FAIL}{host} needs a username!{utils.ENDC}")
                    if "address" in values:
                        address  = values["address"]
                    else:
                        raise Exception(f"{utils.FAIL}{host} needs an address!{utils.ENDC}")
                    if "os" in values:
                        os       = values["os"]
                    else:
                        raise Exception(f"{utils.FAIL}{host} needs an os!{utils.ENDC}")
                    if "port" in values:
                        port     = values["port"]
                    else:
                        utils.print_warn(f"{host} using default port for protocol")
                    if "password" in values:
                        password = values["password"]
                    elif "sshkey" in values:
                        USE_SSHKEY=True
                        sshkey   = values["sshkey"]
                    else:
                        raise Exception(f"{host} needs either a password or sshkey!")
                    
                    if os == "linux" or settings.force_ssh:
                        if port == "":
                            port = "22"
                        if not USE_SSHKEY:
                            ssh_config = Config(
                                overrides={
                                    'sudo': { 
                                        'user': 'root', 
                                        'password': password },
                                        'connect_kwargs': { 
                                            'password': password 
                                        }
                                    }
                                ) if settings.admin else Config(
                                overrides={
                                    'user': username, 
                                    'password': password,
                                    'connect_kwargs': {
                                        'password': password 
                                        }
                                    }
                                )
                            try:
                                with Connection(host=address, 
                                                user=username,
                                                port=port, 
                                                config=ssh_config) as c:
                                        futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                utils.print_fail(f"Exception: {e}")
                        else:
                            sshkey_passphrase = ""
                            sshkey_response = input("Is the private key encrypted? (y/n): ")[:1]
                            if sshkey_response == "y":
                                sshkey_passphrase = input("Enter the private SSH key passphrase : ")
                            ssh_config = Config(
                                overrides={
                                    'sudo': { 
                                        'user': 'root', 
                                        'password': password }, 
                                        'connect_kwargs': { 
                                            'key_filename': sshkey, 
                                            'passphrase': sshkey_passphrase, 
                                            'look_for_keys': False 
                                        }
                                    }
                                ) if settings.admin else Config(
                                overrides={
                                    'user': username, 
                                    'password': password,
                                    'connect_kwargs': { 
                                        'key_filename': sshkey, 
                                        'passphrase': sshkey_passphrase, 
                                        'look_for_keys': False 
                                    }
                                }
                            )
                            try:
                                with Connection(host=address, 
                                                user=username,
                                                port=port, 
                                                config=ssh_config) as c:
                                    futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                utils.print_fail(f"Exception: {e}")
                    # Otherwise we use WinRM for Windows
                    elif os == "windows":
                        if port == "":
                            port = "5985"
                        try:
                            with WSMan(server=address, 
                                       port=port, 
                                       username=username, 
                                       password=password, 
                                       ssl=False, 
                                       cert_validation=False) as conn:
                                futures.append(
                                    ex.submit(execute_script, conn, os, host, scripts, task, comamnd, arguments)
                                )
                        except Exception as e:
                                utils.print_fail(f"Exception: {e.with_traceback} {e.args}")
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
                        raise Exception(f"{utils.FAIL}{host} needs a username!{utils.ENDC}")
                    if "address" in values:
                        address  = values["address"]
                    else:
                        raise Exception(f"{utils.FAIL}{host} needs an address!{utils.ENDC}")
                    if "os" in values:
                        os       = values["os"]
                    else:
                        raise Exception(f"{utils.FAIL}{host} needs an os!{utils.ENDC}")
                    if "port" in values:
                        port     = values["port"]
                    else:
                        utils.print_warn(f"{host} using default port for protocol")
                    if "password" in values:
                        password = values["password"]
                    elif "sshkey" in values:
                        USE_SSHKEY=True
                        sshkey   = values["sshkey"]
                    else:
                        raise Exception(f"{host} needs either a password or sshkey!")
                    
                    if os == "linux" or settings.force_ssh:
                        if port == "":
                            port = "22"
                        if not USE_SSHKEY:
                            ssh_config = Config(
                                overrides={
                                    'sudo': { 
                                        'user': 'root', 
                                        'password': password 
                                    },
                                        'connect_kwargs': { 
                                            'password': password 
                                        }
                                    }
                                ) if settings.admin else Config(
                                overrides={
                                    'user': username, 
                                    'password': password,
                                    'connect_kwargs': {
                                        'password': password 
                                        }
                                    }
                                )
                            try:
                                with Connection(host=address, user=username,
                                                port=port, config=ssh_config) as c:
                                        futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                utils.print_fail(f"Exception: {e}")
                        else:
                            sshkey_passphrase = ""
                            sshkey_response = input("Is the private key encrypted? (y/n): ")[:1]
                            if sshkey_response == "y":
                                sshkey_passphrase = input("Enter the private SSH key passphrase : ")
                            ssh_config = Config(
                                overrides={
                                    'sudo': { 
                                        'user': 'root', 
                                        'password': password 
                                    }, 
                                        'connect_kwargs': { 
                                            'key_filename': sshkey, 
                                            'passphrase': sshkey_passphrase, 
                                            'look_for_keys': False 
                                        }
                                    }
                                ) if settings.admin else Config(
                                overrides={
                                    'user': username, 
                                    'password': password,
                                    'connect_kwargs': { 
                                        'key_filename': sshkey, 
                                        'passphrase': sshkey_passphrase, 
                                        'look_for_keys': False 
                                    }
                                }
                            )
                            try:
                                with Connection(host=address, 
                                                user=username,
                                                port=port, 
                                                config=ssh_config) as c:
                                    futures.append(
                                        ex.submit(execute_script, c, os, host, scripts, task, comamnd, arguments)
                                    )
                            except Exception as e:
                                utils.print_fail(f"Exception: {e}")
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
                                utils.print_fail(f"Exception: {e.with_traceback} {e.args}")
            completed, not_complete = concurrent.futures.wait(futures)
            for result in completed:
                if not result:
                    print("{}".format(result.result()))
                else:
                    try:
                        pass
                    except:
                        pass