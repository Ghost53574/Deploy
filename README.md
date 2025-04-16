# Integrated Deploy, Bottering, and Booter

This repository contains an integrated solution that combines three projects:
- **Deploy**: A robust remote execution framework similar to Ansible
- **Bottering**: A tool for deploying to hosts using CSV-based target information
- **Booter**: A command & control (C2) server with botnet capabilities

## Overview

The integration leverages the strengths of each component:
- Deploy's improved connection management and task execution
- Bottering's CSV parsing and network targeting
- Booter's command and control capabilities

This creates a unified system for target management, script deployment, and ongoing control.

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
                                               │  C2 Reporter   │
                                               └────────────────┘
```

The integration is implemented in a new script called `integrated_deploy.py`, which provides a unified interface to all functionality.

## Features

- **Multiple Input Sources**: Load targets from CSV files or JSON configurations
- **Robust Connection Handling**: Connect to both Linux and Windows targets via SSH or WinRM
- **Concurrent Execution**: Execute tasks on multiple hosts simultaneously
- **Script Templating**: Create customized scripts with dynamic content replacement
- **Botnet Deployment**: Deploy botnet agents with persistence mechanisms
- **Command & Control**: Centralized command execution and data collection

## Requirements

- Python 3.6+
- Dependencies: fabric2, paramiko, pypsrp, netmiko, faker

## Usage

### Basic Usage

```bash
# Execute a command on all hosts defined in a JSON config
python integrated_deploy.py -j configs/config.json -k "uptime"

# Execute a specific script on hosts defined in a CSV file
python integrated_deploy.py -c targets.csv -t script.sh -S

# Deploy botnet components to all Linux hosts
python integrated_deploy.py -c targets.csv -b -I eth0 -o linux
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

#### C2 Options
- `-I, --interface IFACE`: Network interface for C2 server
- `-p, --port PORT`: Port for C2 server (default: 8080)

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
python integrated_deploy.py -c inventory.csv -L
```

### 2. Execute a Command on Specific Hosts

```bash
python integrated_deploy.py -j configs/config.json -k "uname -a" -o linux
```

### 3. Deploy a Script with Arguments

```bash
python integrated_deploy.py -j configs/config.json -t update.sh -a "--force" -S
```

### 4. Deploy Botnet Components

```bash
python integrated_deploy.py -c targets.csv -b -I eth0 -p 8080
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

## C2 Server

When using the botnet deployment feature, you'll need to run the C2 server to receive connections and issue commands:

```bash
python server.py --host 0.0.0.0 --port 8080
```

Then visit the admin panel at `http://localhost:8080/admin` to view and control connected bots.

## Security Considerations

This tool includes capabilities that could be misused. Please ensure you:

1. Only use on systems you own or have explicit permission to test
2. Follow all applicable laws and regulations
3. Use strong authentication mechanisms
4. Keep deployment logs for audit purposes

## License

This project is licensed under the GPL v2 License.
