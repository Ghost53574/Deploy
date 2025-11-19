import tempfile
from pathlib import Path
from typing import Optional

from modules.classes import Script, ScriptType

def _write_script(tmpdir: str, filename: str, content: str, extension: Optional[str] = None) -> Script:
    p = Path(tmpdir) / filename
    p.write_text(content)
    ext = extension if extension is not None else p.suffix
    return Script(name=str(p.name), path=p, directory=str(Path(tmpdir)), extension=ext)


def test_get_executor_type_config():
    with tempfile.TemporaryDirectory() as td:
        s = _write_script(td, "example.conf", "interface eth0\n ip address 10.0.0.1/24", ".conf")
        assert s.get_executor_type() == ScriptType.CONFIG


def test_get_executor_type_script_and_shebang():
    with tempfile.TemporaryDirectory() as td:
        s = _write_script(td, "run.sh", "#!/bin/bash\necho hello", ".sh")
        assert s.get_executor_type() == ScriptType.SCRIPT
        # shebang-less .py with env shebang
        s2 = _write_script(td, "pyenv.py", "#!/usr/bin/env python3\nprint(1)", ".py")
        assert s2.get_interpreter_command() == "python3"


def test_get_interpreter_fallbacks():
    with tempfile.TemporaryDirectory() as td:
        s_py = _write_script(td, "noshebang.py", "print(1)", ".py")
        assert s_py.get_interpreter_command().startswith("python")

        s_sh = _write_script(td, "noshebang.sh", "echo hi", ".sh")
        assert s_sh.get_interpreter_command() == "bash"

        s_ps1 = _write_script(td, "script.ps1", "Write-Host \"hi\"", ".ps1")
        assert s_ps1.get_interpreter_command() == "powershell"

