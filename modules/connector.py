import concurrent.futures
from pypsrp.wsman import WSMan
from fabric2 import Connection, Config

import netmiko

import utils
import classes
import executor

DEFAULT_WORKER_THREADS = 25

class Threader:
    def __init__(self, 
                 config: dict, 
                 scripts: dict, 
                 task: str, 
                 comamnd: str, 
                 arguments: str, 
                 target_host: str,
                 settings: classes.Settings):
        self.workers = DEFAULT_WORKER_THREADS
        
        hosts = {}
        for hostname, host_config in config.items():
            hosts[hostname] = classes.Host(
                config=host_config
            )
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
                                            ex.submit(
                                                executor.execute_script, 
                                                c, 
                                                os, 
                                                host, 
                                                scripts, 
                                                task, 
                                                comamnd, 
                                                arguments, 
                                                settings
                                        )
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
                                            ex.submit(
                                                executor.execute_script, 
                                                c, 
                                                os, 
                                                host, 
                                                scripts, 
                                                task, 
                                                comamnd, 
                                                arguments, 
                                                settings
                                        )
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
                                            ex.submit(
                                                executor.execute_script, 
                                                conn, 
                                                os, 
                                                host, 
                                                scripts, 
                                                task, 
                                                comamnd, 
                                                arguments, 
                                                settings
                                        )
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
                                            ex.submit(
                                                executor.execute_script, 
                                                c, 
                                                os, 
                                                host, 
                                                scripts, 
                                                task, 
                                                comamnd, 
                                                arguments, 
                                                settings
                                        )
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
                                            ex.submit(
                                                executor.execute_script, 
                                                c, 
                                                os, 
                                                host, 
                                                scripts, 
                                                task, 
                                                comamnd, 
                                                arguments, 
                                                settings
                                        )
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
                                            ex.submit(
                                                executor.execute_script, 
                                                c, 
                                                os, 
                                                host, 
                                                scripts, 
                                                task, 
                                                comamnd, 
                                                arguments, 
                                                settings
                                        )
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