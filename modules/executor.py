from pypsrp.powershell import PowerShell, RunspacePool
import logging

import classes
import utils

log = logging.getLogger(__name__)

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
            results = execute_task(
                conn=conn,
                os=os,
                script_name=script_name,
                script_path=script_path,
                script_ext=script_ext,
                command=command,
                arguments=arguments,
                sudo_password=SUDO_PASS,
                settings=settings
            )
            utils.print_results(conn, results)
        else:
            if settings.single_command:
                results = execute_task(
                    conn=conn,
                    os=os,
                    script_name=script_name,
                    script_path=script_path,
                    script_ext=script_ext,
                    command=command,
                    arguments=arguments,
                    sudo_password=SUDO_PASS,
                    settings=settings
                )
                utils.print_results(conn, results)
                break
            if script_name == task:
                results = execute_task(
                    conn=conn,
                    os=os,
                    script_name=script_name,
                    script_path=script_path,
                    script_ext=script_ext,
                    command=command,
                    arguments=arguments,
                    sudo_password=SUDO_PASS,
                    settings=settings
                )
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
