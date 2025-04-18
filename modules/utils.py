import re
import csv
import json
import classes
import base64
import logging
from pathlib import Path
from typing import Dict, List, Optional
from modules.classes import Host, Script, ValidationError

logger = logging.getLogger(__name__)

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
    return json.dumps(data, indent=4)
    
class Field:
    """Enumeration of CSV fields."""
    HOSTNAME = "hostname"
    OS = "os"
    GENERIC_IP = "ip"
    TCP_PORTS_OPEN = "tcp_ports"
    PURPOSE = "purpose"
    NOTES = "notes"
    DEFAULT_USER = "username"
    DEFAULT_PASSWORD = "password"

def parse_csv_file(file_path: str) -> List[Dict[str, str]]:
    """Parse a CSV file into a list of dictionaries."""
    import csv
    
    records = []
    with open(file_path, 'r') as csvfile:
        logger.info(f"Opened CSV: {file_path}")
        reader = csv.DictReader(csvfile)
        for row in reader:
            records.append(row)
    
    return records

def match_ip_to_network(ip_address: str, network: str) -> bool:
    """Check if an IP address belongs to a network."""
    import ipaddress
    try:
        if '/' in ip_address:
            ip = ipaddress.ip_address(ip_address.split('/')[0])
        else:
            ip = ipaddress.ip_address(ip_address)
        net = ipaddress.ip_network(network, strict=False)
        return ip in net
    except ValueError:
        return False

def get_network_from_ip(ip_address: str, netmask: str) -> str:
    import ipaddress
    if '/' in ip_address:
        ip = ipaddress.ip_address(ip_address.split('/')[0])
    else:
        ip = ipaddress.ip_address(ip_address)
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(net.network_address)

def get_hosts_from_network(network_address: str, netmask: str) -> List[str]:
    import ipaddress
    net = ipaddress.IPv4Network(f"{network_address}/{netmask}", strict=False)
    hosts = []
    for ip in net.hosts():
        hosts.append(ip)
    return hosts

def add_ip_to_networks(records: List[Dict[str, str]], networks: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """Organize records by network."""
    network_db = {}
    for network in networks:
        network_db[network] = []
        for record in records:
            if Field.GENERIC_IP in record and match_ip_to_network(record[Field.GENERIC_IP], network):
                network_db[network].append(record)
    return network_db

def parse_ports(ports_str: str) -> List[int]:
    """Parse a comma-separated list of ports."""
    if not ports_str:
        return []
    
    result = []
    ports = ports_str.split(',')
    for port in ports:
        port = port.strip()
        if '-' in port:  # Handle port ranges
            start, end = port.split('-')
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(port))
    
    return result

def check_ports(ip: str, ports: List[int]) -> bool:
    """Check if any of the ports are open on the host."""
    import socket
    
    if not ports:
        return True  # No ports to check
    
    ip_addr = ip.split('/')[0]  # Remove CIDR notation if present
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_addr, port))
        sock.close()
        if result == 0:
            return True  # At least one port is open
    
    return False

def check_os(os_name: str, accepted_os: List[str]) -> bool:
    """Check if the OS is in the list of accepted OS."""
    os_lower = os_name.lower()
    for accepted in accepted_os:
        if accepted.lower() in os_lower:
            return True
    return False

def get_ip_address(interface: str) -> str:
    """Get the IP address of a network interface."""
    import socket
    import platform
    
    # Different implementation for different OS
    if platform.system() == "Linux":
        try:
            import fcntl
            import struct
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode())
            )[20:24])
        except Exception as e:
            logger.error(f"Error getting IP address: {e}")
            return ""
    else:
        # Windows implementation
        try:
            import subprocess
            output = subprocess.check_output(f"ipconfig", shell=True).decode('utf-8')
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if interface in line:
                    # Look for IPv4 address in subsequent lines
                    for j in range(i, min(i + 5, len(lines))):
                        if "IPv4 Address" in lines[j]:
                            ip = lines[j].split(":")[-1].strip()
                            return ip
            return ""
        except:
            return ""

def script_inline_replace(pattern: str, replacement: str, content: str) -> str:
    """Replace patterns in script content."""
    return content.replace(pattern, replacement)

def text_to_base64(text: str) -> str:
    """Convert text to base64."""
    return base64.b64encode(text.encode()).decode()

def xor_encrypt(key: str, data: str) -> str:
    """XOR encrypt data with key."""
    encrypted = []
    for i in range(len(data)):
        key_char = key[i % len(key)]
        encrypted_char = ord(data[i]) ^ ord(key_char)
        encrypted.append(format(encrypted_char, '02x'))
    return ''.join(encrypted)

def create_script_from_template(template_path: str, replacements: Dict[str, str]) -> str:
    """Create a script from a template with replacements."""
    with open(template_path, 'r') as f:
        content = f.read()
    
    for pattern, replacement in replacements.items():
        content = script_inline_replace(pattern, replacement, content)
    
    return content

def load_config(config_file: str) -> Dict:
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Config file not found: {config_file}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}")

def create_hosts_from_json(config: Dict) -> Dict[str, Host]:
    """Create Host objects from JSON configuration."""
    hosts = {}
    for hostname, host_config in config.items():
        try:
            hosts[hostname] = Host(hostname=hostname, config=host_config)
        except ValidationError as e:
            logger.error(f"Invalid host configuration: {e}")
    return hosts

def create_hosts_from_csv(records: List[Dict[str, str]], accepted_os: Optional[List[str]] = None) -> Dict[str, Host]:
    """Create Host objects from CSV records."""
    if accepted_os is None:
        accepted_os = ['ubuntu', 'debian', 'linux', 'centos', 'windows']
    
    hosts = {}
    for record in records:
        hostname = record.get(Field.HOSTNAME, "")
        os_name = record.get(Field.OS, "")
        
        # Skip if hostname is empty or OS is not accepted
        if not hostname or (accepted_os and not check_os(os_name, accepted_os)):
            continue
        
        ip_addr = record.get(Field.GENERIC_IP, "")
        username = record.get(Field.DEFAULT_USER, "")
        password = record.get(Field.DEFAULT_PASSWORD, "")
        
        # Skip if no IP address
        if not ip_addr:
            continue
        
        port = None
        tcp_ports = record.get(Field.TCP_PORTS_OPEN, "")
        if tcp_ports:
            port = tcp_ports.split(' ')[0]
        
        # Create a host config compatible with Deploy's Host class
        host_config = {
            "username": username,
            "password": password,
            "os": "linux" if check_os(os_name, ["linux", "ubuntu", "debian", "centos"]) else "windows",
            "address": ip_addr.split('/')[0],
            "port": port if port else ""
        }
        
        try:
            hosts[hostname] = Host(hostname=hostname, config=host_config)
        except ValidationError as e:
            logger.error(f"Invalid host configuration for {hostname}: {e}")
    return hosts

def find_scripts(current_dir: Path, accepted_exts: List[str]) -> Dict[str, Script]:
    """Find and create Script objects from files in the current directory."""
    scripts = {}
    
    # Find files with matching extensions
    files = parse_files(current_dir, accepted_exts)
    
    # Create Script objects
    for file_name in files:
        path = Path(str(current_dir) + "/" + file_name)
        script_name = str(path.name)
        script_dir = str(path.parts[-2])
        script_path = str(path)
        script_ext = str(path.suffix)
        
        try:
            scripts[script_name] = Script(
                name=script_name,
                path=script_path,
                directory=script_dir,
                extension=script_ext
            )
        except ValidationError as e:
            logger.error(f"Invalid script: {e}")
    
    return scripts