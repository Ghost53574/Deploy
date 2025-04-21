#!/usr/bin/env python3
"""
This is Deploy, a ghetto version of ansible that takes a bunch of scripts and
executes them on as many hosts as possible in a multi-threaded way.
"""
import sys
sys.dont_write_bytecode = True
import argparse
from pathlib import Path
from modules as utils
from logging import logging, config
from modules.classes import Settings, Host
from modules.task_manager import TaskManager

BANNER = '''
            \033[1;31m██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗   ██╗\033[0m
            \033[1;31m██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗╚██╗ ██╔╝\033[0m
            \033[1;31m██║  ██║█████╗  ██████╔╝██║     ██║   ██║ ╚████╔╝ \033[0m
            \033[1;31m██║  ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║  ╚██╔╝  \033[0m
            \033[1;31m██████╔╝███████╗██║     ███████╗╚██████╔╝   ██║   \033[0m
            \033[1;31m╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝    ╚═╝   \033[0m

\033[1;35m                                               by ⧸𝒸o𝓏⧸\033[0m
'''
class DispatchingFormatter(logging.Formatter):
"""
DispatchingFormatter class allows for the creation of
different formatters to be created and then called upon
with the __name__ of the module or a specified name
"""
    def __init__(self, formatters, default_formatter):
        """
        __init__(
        self,
        formatters: Dict[str, logging.Formatter],
        default_formatter: logging.Formatter
        ):
        """
        self._formatters = formatters
        self._default_formatter = default_formatter

    def format(self, record):
        """
        format(
        self,
        record: str
        ):

        record is the name of the formatter to retrieve
        """
        formatter = self._formatters.get(record.name, self._default_formatter)
        return formatter.format(record)

class CustomGeneralLogFormatter(logging.Formatter):
    """
    Custom formatter with colored output. The formatter
    is used for all normal logging messages.
    """
    green = '\033[92m'
    grey = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    bold_red = f'\033[1m{red}'
    reset = '\033[0m'
    fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{green}{fmt}{reset}",
        logging.WARNING: f"{yellow}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{bold_red}{fmt}{reset}"
    }

    def format(self, record):
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)

class CustomMessageFormatter(logging.Formatter):
    """
    Custom formatter with colored output. The formatter
    is used for all print styled messages that isn't 
    normal logging.
    """
    bg_green = '\033[102m'
    bg_yellow = '\033[43m'
    green = '\033[92m'
    grey = '\033[90m'
    yellow = '\033[93m'
    red = '\033[101m'
    black = '\033[30m'
    reset = '\033[0m'
    fmt = "%(message)s"
    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{bg_green}{black}{fmt}{reset}",
        logging.WARNING: f"{bg_yellow}{black}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{red}{fmt}{reset}"
    }

    def format(self, record):
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)

def setup_logging(verbose: bool = False):
    """Set up logging with custom formatter."""
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(DispatchingFormatter({
            'default': CustomMessageFormatter()
        },
        CustomGeneralLogFormatter(),
    ))
    logging.getLogger().addHandler(handler)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        prog='Deploy',
        description='Deployment and control framework'
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
    parser.add_argument('-l', '--local', type=str, help='Execute tasks or commands locally "username,password"')
    parser.add_argument('-S', '--sudo', action='store_true', help='Execute with admin privileges')
    parser.add_argument('-s', '--ssh', action='store_true', help='Force SSH for Windows hosts')
    parser.add_argument('-w', '--workers', type=int, default=25, help='Number of concurrent workers')
    
    # Timeout options
    timeout_group = parser.add_argument_group('Timeout Options')
    timeout_group.add_argument('--connection-timeout', type=int, default=30, 
                              help='Timeout in seconds for establishing connections (default: 30)')
    timeout_group.add_argument('--task-timeout', type=int, default=300, 
                              help='Timeout in seconds for executing individual tasks (default: 300)')
    timeout_group.add_argument('--executor-timeout', type=int, default=1800, 
                              help='Timeout in seconds for the entire execution (default: 1800)')
    
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
    setup_logging()
    logger = logging.getLogger("default")
    
    # Print banner unless quiet mode
    if not args.quiet:
        print(BANNER)

    # Load hosts from CSV or JSON
    hosts = {}
    if args.local is not None:
        import platform
        creds = args.local.split(',')
        hosts["localhost"] = Host(
            hostname="localhost",
            config={
                "username": creds[0],
                "password": creds[1],
                "os": platform.system().lower(),
                "address": "10.0.0.82",
                "port": 5985,
            }
        )
    else:
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
                    filtered_records = []
                    for _, records_in_network in utils.add_ip_to_networks(records, networks).items():
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
                if args.network:
                    filtered_config = {}
                    for network in [args.network]:
                        for hostname, host_config in config.items():
                            ip_address = host_config.get("address")
                            if host_config.get("address") is not None:
                                if utils.match_ip_to_network(
                                    ip_address=ip_address,
                                    network=network
                                ):
                                    filtered_config[hostname] = host_config
                    hosts = utils.create_hosts_from_json(filtered_config)
                else:
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
        logger.warning("-----------------------------")
        for hostname, host in hosts.items():
            if args.verbose:
                logger.info(f"Host: {hostname}")
                logger.info(f"Address: {host.address}")
                logger.info(f"Port: {host.port}")
                logger.info(f"OS: {host.os}")
                logger.info(f"Username: {host.username}")
                logger.info(f"Password: {host.password}")
            else:
                logger.info(f"Host: {hostname}@{host.address}")
            logger.warning("-----------------------------")
        for script_name, script_data in scripts.items():
            if args.verbose:
                logger.info(f"Script: {script_name}")
                logger.info(f"Path: {script_data.path}")
                logger.info(f"Extension: {script_data.extension}")
                logger.info(f"Executor Type: {script_data.get_executor_type()}")
            else:
                logger.info(f"Script: {script_name}")
            logger.warning("-----------------------------")
        return 0
    
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
        verbose=args.verbose,
        max_workers=args.workers,
        connection_timeout=args.connection_timeout,
        task_timeout=args.task_timeout,
        executor_timeout=args.executor_timeout
    )
    
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
