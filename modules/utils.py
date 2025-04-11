import re
import csv
import json
from pathlib import Path
from typing import Literal, Optional
import classes

HEADER = '\033[95m'
INFO = '\033[92m'
WARN = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def print_info(msg: Optional[str] = None) -> None:
    if msg:
        print(f"{INFO}{msg}{ENDC}")

def print_warn(msg: Optional[str] = None) -> None:
    if msg:
        print(f"{WARN}{msg}{ENDC}")

def print_fail(msg: Optional[str] = None) -> None:
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

def parse_files(current_dir: Path,
                accepted_exts: list
                ) -> list:
    files = []
    for f in Path(current_dir).rglob("*"):
        if f.is_file():
            f_parts = f.name.split('.')
            if len(f_parts) == 2:
                f_ext = f_parts[1]
                if f_ext is not None and f_ext in accepted_exts:
                    files.append(f.name)
    return files

def load_scripts(file_list: list, 
                 current_dir: Path
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

def increment_hostname(input_str, hostname_list):
    def replace_hostname(match):
        prefix = match.group(2)
        num = int(match.group(3))
        new_hostname = f'{prefix}{num}'
        
        while new_hostname in hostname_list:
            num += 1
            new_hostname = f'{prefix}{num}'
        
        hostname_list.append(new_hostname)
        return new_hostname

    pattern = r'(([a-zA-Z-]*?)(\d+))'
    return re.sub(pattern, replace_hostname, input_str, flags=re.MULTILINE)

def parse_json_structure(data_str):
    lines = data_str.strip().split("\n")
    data = {}
    current_item = None
    hostname_list = []
    parent_key = ""

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().split('"')[1]
        value = value.strip()

        if value == "{":
            if key != parent_key:
                if key not in hostname_list:
                    hostname_list.append(key)
                    parent_key = key
                else:
                    parent_key = increment_hostname(key, hostname_list)
            current_item = {
                "address": None,
                "os": None,
                "username": None,
                "password": None,
                "port": None,
            }
            data[parent_key] = current_item
        elif key == "address":
            data[parent_key]["address"] = value.split('"')[1]
        elif key == "os":
            data[parent_key]["os"] = value.split('"')[1]
        elif key == "username":
            data[parent_key]["username"] = value.split('"')[1]
        elif key == "password":
            data[parent_key]["password"] = value.split('"')[1]
        elif key == "port":
            port = value.split('"')[1]
            if port == "None" or port is None:
                data[parent_key]["port"] = "22"
            else:
                data[parent_key]["port"] = port
        hostname_list.sort()
    return data

def csv_to_json(csv_file_path):
    data = []
    with open(csv_file_path, 'r') as csvfile:
        csv_reader = csv.DictReader(csvfile)
        for row in csv_reader:
            data.append(row)

    print(json.dumps(data, indent=4))