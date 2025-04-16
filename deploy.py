#!/usr/bin/env python3
"""
Integrated Deploy, Bottering, and Booter - Combined Command & Control Framework

This script combines the improved Deploy architecture with Bottering's CSV parsing
and Booter's C2 capabilities to create a comprehensive deployment and control framework.
"""
import sys
import logging
import argparse
from pathlib import Path
from modules import utils

# Make sure not to create __pycache__ files
sys.dont_write_bytecode = True

# Custom modules from Deploy
from modules.classes import Host, Script, Settings, ValidationError
from modules.task_manager import TaskManager
import modules.utils as utils

try:
    from faker import Factory
    Faker = Factory.create
    fake = Faker()
except ImportError:
    print("Faker library not found. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'faker', '--break-system-packages'], 
                         stdout=subprocess.DEVNULL)
    from faker import Factory
    Faker = Factory.create
    fake = Faker()

# Banner
BANNER = f'''{utils.HEADER}{utils.BOLD}
            .______  ._______._______ .___    ._______   ____   ____
    .       :_ _   \ : .____/: ____  ||   |   : .___  \  \   \_/   / .
            |   |   || : _/\ |    :  ||   |   | :   |  |  \___ ___/    .
       .    | . |   ||   /  \|   |___||   |/\ |     :  |    |   |   
            |. ____/ |_.: __/|___|    |   /  \ \_. ___/     |___|   .
            :/         :/            |______/   :/                 
  .         :                                   :                     .
            |               INTEGRATED DEPLOY         .  .  
                          .           C2             |                .
        .         .           . |       .           .
             .                       .           .           .      .
          .         .    .               .             .         .
                                                         by: ⧸𝒸o𝓏⧸
{utils.ENDC}'''

class CustomFormatter(logging.Formatter):
    """Custom formatter with colored output."""
    grey = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    bold_red = f'\033[1m{red}'
    reset = '\033[0m'
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{grey}{fmt}{reset}",
        logging.WARNING: f"{yellow}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{bold_red}{fmt}{reset}"
    }

    def format(self, record):
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging with custom formatter."""
    logger = logging.Logger(__name__, level=logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(CustomFormatter())
    logger.addHandler(handler)
    
    return logger

def main():
    """Main entry point."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        prog='Integrated Deploy',
        description='Integrated deployment and control framework'
    )
    
    # Input sources - choose one
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-j', '--json', type=str, help='JSON config file with hosts')
    source_group.add_argument('-c', '--csv', type=str, help='CSV file with host information')
    
    # General options
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Execution options
    parser.add_argument('-i', '--host', type=str, help='Target specific host')
    parser.add_argument('-S', '--sudo', action='store_true', help='Execute with admin privileges')
    parser.add_argument('-s', '--ssh', action='store_true', help='Force SSH for Windows hosts')
    parser.add_argument('-w', '--workers', type=int, default=25, help='Number of concurrent workers')
    
    # Task options
    task_group = parser.add_mutually_exclusive_group()
    task_group.add_argument('-k', '--command', type=str, help='Execute a command on hosts')
    task_group.add_argument('-t', '--task', type=str, help='Execute a specific script')
    
    # C2 options
    c2_group = parser.add_argument_group('C2 Options')
    c2_group.add_argument('-I', '--interface', type=str, help='Network interface for C2 server')
    c2_group.add_argument('-p', '--port', type=int, default=8080, help='Port for C2 server')
    
    # Additional options
    parser.add_argument('-a', '--arguments', type=str, help='Arguments for command or script')
    parser.add_argument('-L', '--list', action='store_true', help='List hosts and scripts without executing')
    
    # Filter options
    filter_group = parser.add_argument_group('Filter Options')
    filter_group.add_argument('-o', '--os', type=str, help='Filter by OS (comma-separated)')
    filter_group.add_argument('-n', '--network', type=str, help='Filter by network (CIDR notation)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set up logging
    logger = setup_logging(args.verbose)
    
    # Print banner unless quiet mode
    if not args.quiet:
        print(BANNER)
    
    # Get interface IP if specified
    interface_ip = None
    if args.interface:
        interface_ip = get_ip_address(args.interface)
        if interface_ip:
            utils.print_info(f"Interface {args.interface} has IP: {interface_ip}")
        else:
            utils.print_fail(f"Could not get IP address for interface {args.interface}")
            return 1
    
    # Create settings object
    settings = Settings(
        admin=args.sudo,
        single_host=bool(args.host),
        single_command=bool(args.command),
        single_task=bool(args.task),
        extra_args=bool(args.arguments),
        logging=False,
        quiet=args.quiet,
        force_ssh=args.ssh,
        max_workers=args.workers
    )
    
    # Load hosts from CSV or JSON
    hosts = {}
    if args.csv:
        # Accepted OS filter
        accepted_os = args.os.split(',') if args.os else ['ubuntu', 'debian', 'linux', 'centos', 'windows']
        
        # Parse CSV file
        try:
            records = parse_csv_file(args.csv)
            utils.print_info(f"Loaded {len(records)} records from CSV file")
            
            # Filter by network if specified
            if args.network:
                networks = [args.network]
                network_db = add_ip_to_networks(records, networks)
                filtered_records = []
                for network, records_in_network in network_db.items():
                    filtered_records.extend(records_in_network)
                records = filtered_records
                utils.print_info(f"Filtered to {len(records)} records in network {args.network}")
            
            # Create hosts
            hosts = create_hosts_from_csv(records, accepted_os)
        except Exception as e:
            utils.print_fail(f"Error loading CSV: {e}")
            return 1
    elif args.json:
        # Load JSON config
        try:
            config = load_config(args.json)
            hosts = create_hosts_from_json(config)
        except Exception as e:
            utils.print_fail(f"Error loading JSON config: {e}")
            return 1
    
    # Filter to specific host if requested
    if args.host:
        if args.host in hosts:
            hosts = {args.host: hosts[args.host]}
        else:
            utils.print_fail(f"Host {args.host} not found")
            return 1
    
    # Report number of hosts
    utils.print_info(f"Loaded {len(hosts)} hosts")
    
    # If list mode, just show hosts and exit
    if args.list:
        for hostname, host in hosts.items():
            utils.print_warn(f"{hostname} @ {host.address} ({host.os})")
        return 0
    
    # Find scripts in scripts directory
    scripts_dir = Path("./scripts")
    if not scripts_dir.exists():
        utils.print_warn("Scripts directory not found, using current directory")
        scripts_dir = Path(".")
    
    exts = ["py3", "py", "sh", "bat", "ps1", "pl"]
    scripts = find_scripts(scripts_dir, exts)
    
    # Create task manager
    task_manager = TaskManager(settings)
    task_manager.add_hosts(hosts)
    task_manager.add_scripts(scripts)
    
    # Set up tasks based on command line arguments
    try:
        if args.command:
            # Execute a command on hosts
            utils.print_info(f"Executing command: {args.command}")
            
            for hostname in hosts:
                task_manager.add_command_task(
                    hostname=hostname,
                    command=args.command,
                    arguments=args.arguments or "",
                    admin=args.sudo
                )
                
        elif args.task:
            # Execute a specific script
            if args.task not in scripts:
                utils.print_fail(f"Script '{args.task}' not found")
                return 1
                
            utils.print_info(f"Executing script: {args.task}")
            
            for hostname in hosts:
                task_manager.add_script_task(
                    hostname=hostname,
                    script_name=args.task,
                    arguments=args.arguments or "",
                    admin=args.sudo
                )
        else:
            utils.print_fail("No action specified. Use --command, --task, or --botnet.")
            return 1
            
    except Exception as e:
        utils.print_fail(f"Error setting up tasks: {e}")
        return 1
    
    # Execute tasks
    try:
        utils.print_info("Executing tasks...")
        results = task_manager.execute_tasks()
        
        # Print results
        successes = 0
        failures = 0
        
        for result in results:
            if result.success:
                successes += 1
                utils.print_info(f"SUCCESS: {result.task}")
                if result.output:
                    print(f"  Output: {result.output}")
            else:
                failures += 1
                utils.print_fail(f"FAILED: {result.task}")
                if result.error:
                    print(f"  Error: {result.error}")
        
        utils.print_info(f"Task execution completed: {successes} successful, {failures} failed")
        
    except Exception as e:
        utils.print_fail(f"Error executing tasks: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
