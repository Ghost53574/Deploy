import time
from pathlib import Path

from modules.task_manager import TaskManager
from modules.classes import Host, Script, Settings
import modules.connections as connections_module
from modules.connections import BaseConnection


class FakeConnection(BaseConnection):
    def __init__(self, host, settings):
        super().__init__(host, settings)

    def _create_connection(self) -> None:
        # No real connection needed for tests
        return None

    def close(self) -> None:
        # No resources to close in fake
        return None

    def execute_command(self, command, arguments="", admin=False):
        return f"cmd:{command} {arguments} on {self.host.hostname}"

    def execute_script(self, script, arguments="", admin=False):
        return f"script:{script.name} {arguments} on {self.host.hostname}"
 
class FakeSlowConnection(FakeConnection):
    def execute_command(self, command, arguments="", admin=False):
        # Sleep longer than typical task timeout to trigger timeout handling
        time.sleep(2)
        return super().execute_command(command, arguments, admin)

def test_task_manager_basic_execution():
    settings = Settings()
    settings.max_workers = 2
    settings.task_timeout = 5
    settings.executor_timeout = 10

    tm = TaskManager(settings)

    # Add a host
    host_cfg = {"username": "u", "password": "p", "os": "linux", "address": "192.0.2.100"}
    host = Host("h1", host_cfg)
    tm.add_host(host.hostname, host)

    # Add a script
    # Create a temporary file for script path
    tmp = Path.cwd()
    script_path = tmp / "dummy.sh"
    script_path.write_text("#!/bin/bash\necho ok")
    script = Script(name=str(script_path.name), path=script_path, directory=str(tmp), extension=".sh")
    tm.add_script(script.name, script)

    # Patch connection factory to return our fake connection
    orig_create = connections_module.ConnectionFactory.create_connection
    connections_module.ConnectionFactory.create_connection = staticmethod(lambda host, settings: FakeConnection(host, settings))

    try:
        # Add tasks
        tm.add_script_task(hostname="h1", script_name=script.name)
        tm.add_command_task(hostname="h1", command="echo hello", arguments="-a")

        results = tm.execute_tasks()
        # Expect two results (script and command)
        assert len(results) == 2
        outs = [r.output for r in results]
        assert any("script:dummy.sh" in str(o) for o in outs)
        assert any("cmd:echo hello" in str(o) for o in outs)
        print("[PASS] test_task_manager_basic_execution")
    finally:
        # restore
        connections_module.ConnectionFactory.create_connection = orig_create
        try:
            script_path.unlink()
        except Exception:
            pass

def test_task_manager_timeout_handling():
    settings = Settings()
    settings.max_workers = 1
    settings.task_timeout = 1  # seconds
    settings.executor_timeout = 5

    tm = TaskManager(settings)

    host_cfg = {"username": "u", "password": "p", "os": "linux", "address": "192.0.2.101"}
    host = Host("h2", host_cfg)
    tm.add_host(host.hostname, host)

    # Patch to slow connection
    orig_create = connections_module.ConnectionFactory.create_connection
    connections_module.ConnectionFactory.create_connection = staticmethod(lambda host, settings: FakeSlowConnection(host, settings))

    try:
        tm.add_command_task(hostname="h2", command="sleepy")
        results = tm.execute_tasks()
        assert len(results) == 1
        r = results[0]
        assert r.success is False
        # error should be present (TimeoutError)
        assert r.error is not None
        print("[PASS] test_task_manager_timeout_handling")
    finally:
        connections_module.ConnectionFactory.create_connection = orig_create
