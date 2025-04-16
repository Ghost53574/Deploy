#!/usr/bin/env python3
import sys
import logging
import argparse
from pathlib import Path

# Make sure not to create __pycache__ files
sys.dont_write_bytecode = True

# Custom modules from Deploy
from modules.classes import Settings
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
BANNER = f'''\033[1m\033[91m
            .______  ._______._______ .___    ._______   ____   ____
    .       :_ _   \ : .____/: ____  ||   |   : .___  \  \   \_/   / .
            |   |   || : _/\ |    :  ||   |   | :   |  |  \___ ___/    .
       .    | . |   ||   /  \|   |___||   |/\ |     :  |    |   |   
            |. ____/ |_.: __/|___|    |   /  \ \_. ___/     |___|   .
            :/         :/            |______/   :/                 
  .         :                                   :                     .
            |                                         .  .  
                          .                          |                .
        .         .           . |       .           .
             .                       .           .           .      .
          .         .    .               .             .         .
                                                         by: ⧸𝒸o𝓏⧸\033[0m'''

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
    parser.add_argument('-d', '--scripts', type=str, default="scripts", help='Path to scripts directory')
    
    # Execution options
    parser.add_argument('-i', '--host', type=str, help='Target specific host')
    parser.add_argument('-S', '--sudo', action='store_true', help='Execute with admin privileges')
    parser.add_argument('-s', '--ssh', action='store_true', help='Force SSH for Windows hosts')
    parser.add_argument('-w', '--workers', type=int, default=25, help='Number of concurrent workers')
    
    # Task options
    task_group = parser.add_mutually_exclusive_group()
    task_group.add_argument('-k', '--command', type=str, help='Execute a command on hosts')
    task_group.add_argument('-t', '--task', type=str, help='Execute a specific script')
    
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
        accepted_os = args.os.split(',') if args.os else [
            'linux',
            'windows'
        ]
        
        # Parse CSV file
        try:
            records = utils.parse_csv_file(args.csv)
            logger.info(f"Loaded {len(records)} records from CSV file")
            
            # Filter by network if specified
            if args.network:
                networks = [args.network]
                network_db = utils.add_ip_to_networks(records, networks)
                filtered_records = []
                for network, records_in_network in network_db.items():
                    filtered_records.extend(records_in_network)
                records = filtered_records
                logger.info(f"Filtered to {len(records)} records in network {args.network}")
            
            hosts = utils.create_hosts_from_csv(records, accepted_os)
        except Exception as e:
            logger.error(f"Error loading CSV: {e}")
            return 1
    elif args.json:
        # Load JSON config
        try:
            config = utils.load_config(args.json)
            hosts = utils.create_hosts_from_json(config)
        except Exception as e:
            logger.error(f"Error loading JSON config: {e}")
            return 1
    # Filter to specific host if requested
    if args.host:
        if args.host in hosts:
            hosts = {args.host: hosts[args.host]}
        else:
            logger.error(f"Host {args.host} not found")
            return 1
    
    logger.info(f"Loaded {len(hosts)} hosts")
    
    # Find scripts in scripts directory
    scripts_dir = Path(args.scripts)
    if not scripts_dir.exists():
        logger.warning("Scripts directory not found, using current directory")
        scripts_dir = Path(".")
    
    exts = ["py3", "py", "sh", "bat", "ps1", "pl"]
    scripts = utils.find_scripts(scripts_dir, exts)

    if args.list:
        logger.warning("Listing available hosts and scripts:")
        for hostname, host in hosts.items():
            logger.info(f"Host: {hostname}@{host.address}")
        for script in scripts:
            logger.info(f"Script: {script}")
        return 0
    
    # Create task manager
    task_manager = TaskManager(settings)
    task_manager.add_hosts(hosts)
    task_manager.add_scripts(scripts)
    
    # Set up tasks based on command line arguments
    try:
        if args.command:
            # Execute a command on hosts
            logger.info(f"Executing command: {args.command}")
            
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
                logger.error(f"Script '{args.task}' not found")
                return 1
                
            logger.info(f"Executing script: {args.task}")
            
            for hostname in hosts:
                task_manager.add_script_task(
                    hostname=hostname,
                    script_name=args.task,
                    arguments=args.arguments or "",
                    admin=args.sudo
                )
        else:
            logger.info(f"Executing all scripts in {scripts_dir}")
            for script in task_manager.scripts:
                task_manager.add_task_for_all_hosts(
                script_name=script
            )

    except Exception as e:
        logger.error(f"Error setting up tasks: {e}")
        return 1
    
    # Execute tasks
    try:
        logger.info("Executing tasks...")
        results = task_manager.execute_tasks()
        
        # Print results
        successes = 0
        failures = 0
        
        for result in results:
            if result.success:
                successes += 1
                logger.info(f"SUCCESS: {result.task}")
                if result.output:
                    print(f"{result.output}")
            else:
                failures += 1
                logger.error(f"FAILED: {result.task}")
                if result.error:
                    logger.error(f"Error: {result.error}")
        
        logger.info(f"Task execution completed: {successes} successful, {failures} failed")
    except Exception as e:
        logger.error(f"Error executing tasks: {e}")
        return 1
    except KeyboardInterrupt as e:
        logger.error(f"Inturrupted")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
