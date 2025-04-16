![image](https://github.com/user-attachments/assets/36181a91-1ff0-41d9-8285-5ca108861aee)


## Overview
Deploy is a remote execution framework similar to Ansible. This creates a unified system for target management, script deployment, and ongoing control.

## Architecture
```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Unified CLI    │────▶│  Target Manager  │────▶│  Task Manager  │
└─────────────────┘     └──────────────────┘     └────────────────┘
        │                        │                       │
        ▼                        ▼                       ▼
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│ Config Handlers │     │  Script Manager  │     │  Connections   │
│  - JSON         │     │  - Template      │     │  - SSH         │
│  - CSV          │     │  - Manipulation  │     │  - WinRM       │
└─────────────────┘     └──────────────────┘     └────────────────┘
                                                          │
                                                          ▼
                                                ┌────────────────┐
                                                │     Output     │
                                                └────────────────┘
```
## Requirements
- Python 3.6+
- Dependencies: fabric2, paramiko, pypsrp, netmiko, faker

## Usage
### Basic Usage
```bash
# Execute a command on all hosts defined in a JSON config
python deploy.py -j configs/config.json -k "uptime"

# Execute a specific script on hosts defined in a CSV file
python deploy.py -c targets.csv -t script.sh -S

# Deploy botnet components to all Linux hosts
python deploy.py -c targets.csv -b -I eth0 -o linux
```

### Command Line Options
#### Input Sources
- `-j, --json FILE`: JSON config file with hosts
- `-c, --csv FILE`: CSV file with host information

#### Execution Options
- `-i, --host HOST`: Target a specific host
- `-S, --sudo`: Execute with admin privileges
- `-s, --ssh`: Force SSH for Windows hosts
- `-w, --workers N`: Number of concurrent workers (default: 25)

#### Task Options
- `-k, --command CMD`: Execute a command on hosts
- `-t, --task SCRIPT`: Execute a specific script
- `-b, --botnet`: Deploy botnet components
- `-a, --arguments ARGS`: Additional arguments for command or script

#### Filter Options
- `-o, --os OS`: Filter by OS (comma-separated)
- `-n, --network CIDR`: Filter by network (CIDR notation)

#### Other Options
- `-q, --quiet`: Minimal output
- `-v, --verbose`: Verbose output
- `-L, --list`: List hosts and scripts without executing

## Examples

### 1. List All Hosts from a CSV File
```bash
python deploy.py -c inventory.csv -L
```

### 2. Execute a Command on Specific Hosts
```bash
python deploy.py -j configs/config.json -k "uname -a" -o linux
```

### 3. Deploy a Script with Arguments
```bash
python deploy.py -j configs/config.json -t update.sh -a "--force" -S
```

## CSV Format
When using CSV files as input, the following columns are supported:
- `hostname`: Hostname or identifier for the target
- `os`: Operating system (linux, windows, etc.)
- `ip`: IP address of the target
- `tcp_ports`: List of open TCP ports (comma-separated)
- `username`: Username for authentication
- `password`: Password for authentication
- `purpose`: Purpose of the host (optional)
- `notes`: Additional notes (optional)

Example:
```csv
hostname,os,ip,tcp_ports,username,password,purpose,notes
web1,ubuntu,192.168.1.10,22,80,443,admin,secret_pass,Web server,Production
db1,centos,192.168.1.20,22,3306,dbadmin,db_pass,Database,Staging
```

## JSON Format
The JSON configuration follows the Deploy format:
```json
{
  "web1": {
    "username": "admin",
    "password": "secret_pass",
    "os": "linux",
    "address": "192.168.1.10",
    "port": "22"
  },
  "win1": {
    "username": "Administrator",
    "password": "windows_pass",
    "os": "windows",
    "address": "192.168.1.30",
    "port": "5985"
  }
}
```

## License

This project is licensed under the GPL v2 License.
