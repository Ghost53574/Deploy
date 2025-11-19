"""
Utility functions for the Deploy application.
Provides helper functions for CSV parsing, network operations, and file handling.
"""

import json
import logging
import fnmatch
from pathlib import Path
from typing import Dict, List, Optional
from modules.classes import Host, Script, ValidationError

logger = logging.getLogger(__name__)

class FilterCriteria:
    """
    Represents parsed filter criteria for hosts and scripts.
    """
    
    def __init__(self):
        self.os: Optional[List[str]] = None
        self.username: Optional[str] = None
        self.address: Optional[str] = None
        self.port: Optional[List[str]] = None
        self.network: Optional[str] = None
        self.device: Optional[List[str]] = None
        self.hostname: Optional[str] = None
        self.host: Optional[str] = None
        self.task: Optional[str] = None
        self.script: Optional[str] = None

def parse_filter_string(filter_string: str) -> FilterCriteria:
    """
    Parse a filter string into FilterCriteria object.
    
    Args:
        filter_string: String in format "key1=value1,key2=value2,..."
        
    Returns:
        FilterCriteria object with parsed values
        
    Raises:
        ValueError: If filter string format is invalid
    """
    if not filter_string:
        return FilterCriteria()
    
    criteria = FilterCriteria()
    
    # Split by commas, but handle commas within values
    pairs = []
    current_pair = ""
    paren_count = 0
    
    for char in filter_string:
        if char == ',' and paren_count == 0:
            pairs.append(current_pair.strip())
            current_pair = ""
        else:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
            current_pair += char
    
    if current_pair.strip():
        pairs.append(current_pair.strip())
    
    # Parse each key=value pair
    for pair in pairs:
        if '=' not in pair:
            raise ValueError(f"Invalid filter format: '{pair}'. Expected 'key=value'")
        
        key, value = pair.split('=', 1)
        key = key.strip().lower()
        value = value.strip()
        
        if key == 'os':
            # Support comma-separated OS values
            criteria.os = [os.strip() for os in value.split(',')]
        elif key == 'username':
            criteria.username = value
        elif key == 'address':
            criteria.address = value
        elif key == 'port':
            # Support comma-separated port values
            criteria.port = [port.strip() for port in value.split(',')]
        elif key == 'network':
            criteria.network = value
        elif key == 'device':
            # Support comma-separated device types
            criteria.device = [device.strip() for device in value.split(',')]
        elif key == 'hostname':
            criteria.hostname = value
        elif key == 'host':
            criteria.host = value
        elif key in ['task', 'script']:
            # Both task and script filter the same thing
            criteria.task = value
            criteria.script = value
        else:
            raise ValueError(f"Unknown filter key: '{key}'. Supported keys: os, username, address, port, network, device, hostname, host, task, script")
    
    return criteria

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
    with open(file_path, "r", encoding="utf-8") as csvfile:
        logger.info(f"Opened CSV: {file_path}")
        reader = csv.DictReader(csvfile)
        for row in reader:
            records.append(row)

    return records

def match_ip_to_network(ip_address: str, network: str) -> bool:
    """Check if an IP address belongs to a network."""
    import ipaddress

    try:
        if "/" in ip_address:
            ip = ipaddress.ip_address(ip_address.split("/")[0])
        else:
            ip = ipaddress.ip_address(ip_address)
        net = ipaddress.ip_network(network, strict=False)
        return ip in net
    except ValueError:
        return False

def get_network_from_ip(ip_address: str, netmask: str) -> str:
    import ipaddress

    if "/" in ip_address:
        ip = ipaddress.ip_address(ip_address.split("/")[0])
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

def add_ip_to_networks(
    records: List[Dict[str, str]], networks: List[str]
) -> Dict[str, List[Dict[str, str]]]:
    """Organize records by network."""
    network_db = {}
    for network in networks:
        network_db[network] = []
        for record in records:
            if Field.GENERIC_IP in record and match_ip_to_network(
                record[Field.GENERIC_IP], network
            ):
                network_db[network].append(record)
    return network_db

def parse_ports(ports_str: str) -> List[int]:
    """Parse a comma-separated list of ports."""
    if not ports_str:
        return []

    result = []
    ports = ports_str.split(",")
    for port in ports:
        port = port.strip()
        if "-" in port:  # Handle port ranges
            start, end = port.split("-")
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(port))

    return result

def check_ports(ip: str, ports: List[int]) -> bool:
    """Check if any of the ports are open on the host."""
    import socket

    if not ports:
        return True  # No ports to check

    ip_addr = ip.split("/")[0]  # Remove CIDR notation if present

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
            return socket.inet_ntoa(
                fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack("256s", interface[:15].encode()),
                )[20:24]
            )
        except Exception as e:
            logger.error(f"Error getting IP address: {e}")
            return ""
    else:
        # Windows implementation
        try:
            import subprocess

            output = subprocess.check_output("ipconfig", shell=True).decode("utf-8")
            lines = output.split("\n")
            for i, line in enumerate(lines):
                if interface in line:
                    # Look for IPv4 address in subsequent lines
                    for j in range(i, min(i + 5, len(lines))):
                        if "IPv4 Address" in lines[j]:
                            ip = lines[j].split(":")[-1].strip()
                            return ip
            return ""
        except Exception:
            return ""

def script_inline_replace(pattern: str, replacement: str, content: str) -> str:
    """Replace patterns in script content."""
    return content.replace(pattern, replacement)

def create_script_from_template(
    template_path: str, replacements: Dict[str, str]
) -> str:
    """Create a script from a template with replacements."""
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    for pattern, replacement in replacements.items():
        content = script_inline_replace(pattern, replacement, content)

    return content

def load_config(config_file: str) -> Dict:
    """Load configuration from a JSON file."""
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Config file not found: {config_file}") from exc
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}") from e

def create_hosts_from_json(config: Dict) -> Dict[str, Host]:
    """Create Host objects from JSON configuration."""
    hosts = {}
    for hostname, host_config in config.items():
        try:
            hosts[hostname] = Host(hostname=hostname, config=host_config)
        except ValidationError as e:
            logger.error(f"Invalid host configuration: {e}")
    return hosts

def create_hosts_from_csv(
    records: List[Dict[str, str]], accepted_os: Optional[List[str]] = None
) -> Dict[str, Host]:
    """Create Host objects from CSV records."""
    if accepted_os is None:
        accepted_os = ["ubuntu", "debian", "linux", "centos", "windows"]

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
            port = tcp_ports.split(" ")[0]

        # Create a host config compatible with Deploy's Host class
        host_config = {
            "username": username,
            "password": password,
            "os": (
                "linux"
                if check_os(os_name, ["linux", "ubuntu", "debian", "centos"])
                else "windows"
            ),
            "address": ip_addr.split("/")[0],
            "port": port if port else "",
        }

        try:
            hosts[hostname] = Host(hostname=hostname, config=host_config)
        except ValidationError as e:
            logger.error(f"Invalid host configuration for {hostname}: {e}")
    return hosts

def parse_files(current_dir: Path, accepted_exts: list) -> List[Path]:
    files = []
    path = Path(current_dir)
    if path:
        for f in path.rglob("*"):
            if f.is_file():
                f_parts = f.name.split(".")
                if len(f_parts) == 2:
                    f_ext = f_parts[1]
                    if f_ext is not None and f_ext in accepted_exts:
                        files.append(f.absolute())
    else:
        raise ValidationError(f"Path is not correct: {current_dir}")
    return files

def find_scripts(current_dir: Path, accepted_exts: List[str]) -> Dict[str, Script]:
    """Find and create Script objects from files in the current directory."""
    scripts = {}

    current_dir = current_dir.absolute()

    for file in parse_files(current_dir, accepted_exts):
        path = file.relative_to(current_dir)
        script_name = str(path.name)
        script_dir = str(path.parent)
        script_ext = str(path.suffix)
        # Pass Path object directly instead of converting to string
        script_path = file
        
        try:
            scripts[script_name] = Script(
                name=script_name,
                path=script_path,  # Now a Path object
                directory=script_dir,
                extension=script_ext,
            )
        except ValidationError as e:
            logger.error(f"Invalid script: {e}")

    return scripts

def matches_wildcard_pattern(value: str, pattern: str) -> bool:
    """
    Check if a value matches a wildcard pattern.
    
    Args:
        value: The value to check
        pattern: The pattern to match against (supports * and ? wildcards)
        
    Returns:
        True if value matches pattern, False otherwise
    """
    if not pattern:
        return True
    
    # Convert to lowercase for case-insensitive matching
    value_lower = value.lower()
    pattern_lower = pattern.lower()
    
    # Use fnmatch for wildcard support
    return fnmatch.fnmatch(value_lower, pattern_lower)

def matches_network_pattern(ip_address: str, pattern: str) -> bool:
    """
    Check if an IP address matches a network pattern.
    Supports CIDR notation and wildcard patterns.
    
    Args:
        ip_address: The IP address to check
        pattern: The pattern to match against (CIDR or wildcard)
        
    Returns:
        True if IP matches pattern, False otherwise
    """
    if not pattern:
        return True
    
    # Handle CIDR notation
    if '/' in pattern:
        return match_ip_to_network(ip_address, pattern)
    
    # Handle wildcard patterns
    if '*' in pattern or '?' in pattern:
        return matches_wildcard_pattern(ip_address, pattern)
    
    # Exact match
    return ip_address == pattern

def filter_hosts_by_criteria(hosts: Dict[str, Host], filter_criteria) -> Dict[str, Host]:
    """
    Filter hosts based on filter criteria.
    
    Args:
        hosts: Dictionary of hosts to filter
        filter_criteria: FilterCriteria object with filter conditions
        
    Returns:
        Filtered dictionary of hosts
    """
    if not filter_criteria:
        return hosts
    
    filtered_hosts = {}
    
    for hostname, host in hosts.items():
        # Check OS filter
        if filter_criteria.os:
            if not host.os or not any(
                matches_wildcard_pattern(host.os, os_pattern) 
                for os_pattern in filter_criteria.os
            ):
                continue
        
        # Check username filter
        if filter_criteria.username:
            if not host.username or not matches_wildcard_pattern(
                host.username, filter_criteria.username
            ):
                continue
        
        # Check address filter
        if filter_criteria.address:
            if not host.address or not matches_wildcard_pattern(
                host.address, filter_criteria.address
            ):
                continue
        
        # Check port filter
        if filter_criteria.port:
            if not host.port or not any(
                str(host.port) == port_pattern or matches_wildcard_pattern(
                    str(host.port), port_pattern
                )
                for port_pattern in filter_criteria.port
            ):
                continue
        
        # Check network filter
        if filter_criteria.network:
            if not host.address or not matches_network_pattern(
                host.address, filter_criteria.network
            ):
                continue
        
        # Check device type filter
        if filter_criteria.device:
            if not host.device_type or not any(
                matches_wildcard_pattern(host.device_type, device_pattern)
                for device_pattern in filter_criteria.device
            ):
                continue
        
        # Check hostname filter
        if filter_criteria.hostname:
            if not matches_wildcard_pattern(hostname, filter_criteria.hostname):
                continue
        
        # Check host filter (matches both hostname and address/network)
        if filter_criteria.host:
            hostname_match = matches_wildcard_pattern(hostname, filter_criteria.host)
            address_match = False
            if host.address:
                address_match = matches_network_pattern(host.address, filter_criteria.host)
            
            if not (hostname_match or address_match):
                continue
        
        # If all filters pass, include the host
        filtered_hosts[hostname] = host
    
    return filtered_hosts

def filter_scripts_by_criteria(scripts: Dict[str, Script], filter_criteria) -> Dict[str, Script]:
    """
    Filter scripts based on filter criteria.
    
    Args:
        scripts: Dictionary of scripts to filter
        filter_criteria: FilterCriteria object with filter conditions
        
    Returns:
        Filtered dictionary of scripts
    """
    if not filter_criteria or not filter_criteria.task:
        return scripts
    
    filtered_scripts = {}
    
    for script_name, script in scripts.items():
        # Check task/script name filter
        if matches_wildcard_pattern(script_name, filter_criteria.task):
            filtered_scripts[script_name] = script
    
    return filtered_scripts
