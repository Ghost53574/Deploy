import classes
from pathlib import Path

HEADER = '\033[95m'
INFO = '\033[92m'
WARN = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def print_info(msg: str = None) -> None:
    if msg:
        print(f"{INFO}{msg}{ENDC}")

def print_warn(msg: str = None) -> None:
    if msg:
        print(f"{WARN}{msg}{ENDC}")

def print_fail(msg: str = None) -> None:
    if msg:
        print(f"{FAIL}{msg}{ENDC}")

def print_results(conn, results: list):
    for result in results:
        print(f"{INFO}[{conn}]{ENDC}: {result}")

def str_to_bool(value):
    if value.lower() in {'false', 'f', '0', 'no', 'n'}:
        return False
    elif value.lower() in {'true', 't', '1', 'yes', 'y'}:
        return True
    raise ValueError(f'{value} is not a valid boolean value')

def parse_files(current_dir: str,
                accepted_exts: list
                ) -> list:
    files = []
    for f in Path(current_dir).rglob("*"):
        if f.is_file():
            f_parts = f.name.split('.')
            if len(f_parts) is 2:
                f_ext = f_parts[1]
                if f_ext is not None and f_ext in accepted_exts:
                    files.append(f.name)
    return files

def load_scripts(file_list: str, 
                 current_dir: str
                 ) -> dict:
    scripts = {}
    for f in file_list:
        p = Path(str(current_dir.cwd()) + "/" + f)
        script_name = str(p.name)[:]
        script_dir  = str(p.parts[-2])
        script_path = str(p)[:]
        script_ext  = str(p.suffix)[:]
        scripts[script_name] = classes.Script(script_name, script_path, script_dir, script_ext)
    return scripts