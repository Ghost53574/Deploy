#!/usr/bin/env python3
"""
Deploy - A Multi-threaded Deployment and Control Framework

A lightweight deployment tool that executes scripts and commands across multiple
hosts concurrently. Supports Linux, Windows, and network devices with flexible
configuration options.

Author: /coz/
Version: 2.0.0
"""
import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from modules import utils
from modules.classes import Settings, Host
from modules.task_manager import TaskManager

sys.dont_write_bytecode = True

__version__ = "2.0.0"
__author__ = "/coz/"

BANNER = f"""
            \033[1;31m██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗   ██╗\033[0m
            \033[1;31m██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗╚██╗ ██╔╝\033[0m
            \033[1;31m██║  ██║█████╗  ██████╔╝██║     ██║   ██║ ╚████╔╝ \033[0m
            \033[1;31m██║  ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║  ╚██╔╝  \033[0m
            \033[1;31m██████╔╝███████╗██║     ███████╗╚██████╔╝   ██║   \033[0m
            \033[1;31m╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝    ╚═╝   \033[0m

\033[1;35m                                       v{__version__} by {__author__}\033[0m
"""

# Default configuration
DEFAULT_CONFIG = {
    "max_workers": 25,
    "connection_timeout": 30,
    "task_timeout": 300,
    "executor_timeout": 1800,
    "script_extensions": ["py3", "py", "sh", "bat", "ps1", "pl"],
    "default_os_filter": ["linux", "windows"],
}


def load_config_file(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from JSON file.

    Args:
        config_path: Path to configuration file (optional)

    Returns:
        Configuration dictionary
    """
    file_config = DEFAULT_CONFIG.copy()

    # Look for config file in common locations
    possible_paths = [
        config_path,
        "config.json",
        "deploy.json",
        os.path.expanduser("~/.deploy/config.json"),
        "/etc/deploy/config.json",
    ]

    for path in possible_paths:
        if path and Path(path).exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded_config = json.load(f)
                    if loaded_config:
                        # Merge with defaults
                        if "defaults" in loaded_config:
                            file_config.update(loaded_config["defaults"])
                        deploy_logger = logging.getLogger("deploy")
                        deploy_logger.info(f"Loaded configuration from: {path}")
                        return file_config
            except json.JSONDecodeError as e:
                deploy_logger = logging.getLogger("deploy")
                deploy_logger.warning(f"Invalid JSON in config file {path}: {e}")
            except Exception as e:
                deploy_logger = logging.getLogger("deploy")
                deploy_logger.warning(f"Could not load config file {path}: {e}")

    return file_config


class DeployError(Exception):
    """Base exception class for Deploy application errors."""


class ConfigurationError(DeployError):
    """Raised when there's an error in configuration."""


class HostLoadError(DeployError):
    """Raised when there's an error loading hosts."""


class ScriptLoadError(DeployError):
    """Raised when there's an error loading scripts."""


class DispatchingFormatter(logging.Formatter):
    """
    DispatchingFormatter class allows for the creation of
    different formatters to be created and then called upon
    with the __name__ of the module or a specified name
    """

    def __init__(
        self,
        formatters: Dict[str, logging.Formatter],
        default_formatter: logging.Formatter,
    ):
        """
        Initialize DispatchingFormatter.

        Args:
            formatters: Dictionary mapping logger names to formatters
            default_formatter: Default formatter to use when no specific formatter found
        """
        super().__init__()
        self._formatters = formatters
        self._default_formatter = default_formatter

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record using the appropriate formatter.

        Args:
            record: The log record to format

        Returns:
            Formatted log message
        """
        formatter = self._formatters.get(record.name, self._default_formatter)
        return formatter.format(record)


class CustomGeneralLogFormatter(logging.Formatter):
    """
    Custom formatter with colored output. The formatter
    is used for all normal logging messages.
    """

    green = "\033[92m"
    grey = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    bold_red = f"\033[1m{red}"
    reset = "\033[0m"
    fmt = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    )
    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{green}{fmt}{reset}",
        logging.WARNING: f"{yellow}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{bold_red}{fmt}{reset}",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with appropriate color and style."""
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)


class CustomMessageFormatter(logging.Formatter):
    """
    Custom formatter with colored output. The formatter
    is used for all print styled messages that isn't
    normal logging.
    """

    bg_green = "\033[102m"
    bg_yellow = "\033[43m"
    green = "\033[92m"
    grey = "\033[90m"
    yellow = "\033[93m"
    red = "\033[101m"
    black = "\033[30m"
    reset = "\033[0m"
    fmt = "%(message)s"
    FORMATS = {
        logging.DEBUG: f"{grey}{fmt}{reset}",
        logging.INFO: f"{bg_green}{black}{fmt}{reset}",
        logging.WARNING: f"{bg_yellow}{black}{fmt}{reset}",
        logging.ERROR: f"{red}{fmt}{reset}",
        logging.CRITICAL: f"{red}{fmt}{reset}",
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format message-style log record with appropriate color and style."""
        return logging.Formatter(self.FORMATS.get(record.levelno)).format(record)


def setup_logging(verbose: bool = False) -> None:
    """
    Set up logging with custom formatter.

    Args:
        verbose: Enable debug level logging if True
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Remove all handlers first to avoid duplicate logs
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(
        DispatchingFormatter(
            {"default": CustomMessageFormatter()}, CustomGeneralLogFormatter()
        )
    )
    root_logger.addHandler(handler)


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="Deploy",
        description="Multi-threaded deployment and control framework",
        epilog=f"Deploy v{__version__} - Execute scripts and commands across multiple hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Version information
    parser.add_argument(
        "--version", action="version", version=f"Deploy {__version__} by {__author__}"
    )

    # Input sources - mutually exclusive
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-j", "--json", type=str, help="JSON configuration file with host definitions"
    )
    source_group.add_argument(
        "-c", "--csv", type=str, help="CSV file with host information"
    )

    # General options
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Minimal output mode"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose debug output"
    )
    parser.add_argument(
        "-d",
        "--scripts",
        type=str,
        default="scripts",
        help="Path to scripts directory (default: scripts)",
    )
    parser.add_argument(
        "-C", "--config", type=str, help="Path to configuration file (JSON format)"
    )

    # Execution options
    parser.add_argument("-i", "--host", type=str, help="Target a specific host by name")
    parser.add_argument(
        "-l",
        "--local",
        type=str,
        help='Execute locally with credentials: "username,password"',
    )
    parser.add_argument(
        "-S",
        "--sudo",
        action="store_true",
        help="Execute with administrative privileges",
    )
    parser.add_argument(
        "-s",
        "--ssh",
        action="store_true",
        help="Force SSH connection for Windows hosts",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_CONFIG["max_workers"],
        help=f'Number of concurrent workers (default: {DEFAULT_CONFIG["max_workers"]})',
    )
    # Timeout configuration
    timeout_group = parser.add_argument_group("Timeout Configuration")
    timeout_group.add_argument(
        "--connection-timeout",
        type=int,
        default=DEFAULT_CONFIG["connection_timeout"],
        help=f'Connection timeout in seconds (default: {DEFAULT_CONFIG["connection_timeout"]})',
    )
    timeout_group.add_argument(
        "--task-timeout",
        type=int,
        default=DEFAULT_CONFIG["task_timeout"],
        help=f'Task execution timeout in seconds (default: {DEFAULT_CONFIG["task_timeout"]})',
    )
    timeout_group.add_argument(
        "--executor-timeout",
        type=int,
        default=DEFAULT_CONFIG["executor_timeout"],
        help=f'Overall execution timeout in seconds (default: {DEFAULT_CONFIG["executor_timeout"]})',
    )

    # Task execution options
    task_group = parser.add_mutually_exclusive_group()
    task_group.add_argument(
        "-k", "--command", type=str, help="Execute a shell command on target hosts"
    )
    task_group.add_argument(
        "-t", "--task", type=str, help="Execute a specific script by name"
    )

    # Additional options
    parser.add_argument(
        "-a", "--arguments", type=str, help="Arguments to pass to command or script"
    )
    parser.add_argument(
        "-L",
        "--list",
        action="store_true",
        help="List available hosts and scripts without executing",
    )

    # Filtering options
    filter_group = parser.add_argument_group("Host Filtering")
    filter_group.add_argument(
        "-o",
        "--os",
        type=str,
        help="Filter hosts by operating system (comma-separated list)",
    )
    filter_group.add_argument(
        "-n", "--network", type=str, help="Filter hosts by network using CIDR notation"
    )
    return parser.parse_args()


def load_hosts(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Host]:
    """
    Load hosts from the specified configuration source.

    Args:
        args: Parsed command line arguments
        logger: Logger instance for output

    Returns:
        Dictionary of hostname to Host objects

    Raises:
        HostLoadError: If there's an error loading host configuration
    """
    hosts: Dict[str, Host] = {}

    # Handle local execution mode
    if args.local is not None:
        hosts = _create_local_host(args.local)
        return hosts

    # Load hosts from CSV or JSON
    if args.csv:
        hosts = _load_hosts_from_csv(args, logger)
    elif args.json:
        hosts = _load_hosts_from_json(args, logger)

    # Filter to specific host if requested
    if args.host:
        if args.host in hosts:
            hosts = {args.host: hosts[args.host]}
        else:
            available_hosts = ", ".join(hosts.keys())
            raise HostLoadError(
                f"Host '{args.host}' not found. Available hosts: {available_hosts}"
            )

    if not hosts:
        raise HostLoadError("No hosts loaded. Check your configuration file.")

    return hosts


def _create_local_host(local_credentials: str) -> Dict[str, Host]:
    """Create a localhost host configuration."""
    import platform

    try:
        creds = local_credentials.split(",")
        if len(creds) != 2:
            raise ValueError("Local credentials must be in format: username,password")

        return {
            "localhost": Host(
                hostname="localhost",
                config={
                    "username": creds[0],
                    "password": creds[1],
                    "os": platform.system().lower(),
                    "address": "127.0.0.1",
                    "port": 5985,
                },
            )
        }
    except Exception as e:
        raise HostLoadError(f"Error creating local host configuration: {e}") from e


def _load_hosts_from_csv(
    args: argparse.Namespace, logger: logging.Logger
) -> Dict[str, Host]:
    """Load hosts from CSV file."""
    try:
        accepted_os = (
            args.os.split(",") if args.os else DEFAULT_CONFIG["default_os_filter"]
        )

        records = utils.parse_csv_file(args.csv)
        logger.info(f"Loaded {len(records)} records from CSV file: {args.csv}")

        # Apply network filtering if specified
        if args.network:
            networks = [args.network]
            filtered_records = []
            for _, records_in_network in utils.add_ip_to_networks(
                records, networks
            ).items():
                filtered_records.extend(records_in_network)
            records = filtered_records
            logger.info(f"Filtered to {len(records)} records in network {args.network}")

        return utils.create_hosts_from_csv(records, accepted_os)

    except Exception as e:
        raise HostLoadError(f"Error loading CSV file '{args.csv}': {e}") from e


def _load_hosts_from_json(
    args: argparse.Namespace, logger: logging.Logger
) -> Dict[str, Host]:
    """Load hosts from JSON configuration file."""
    try:
        config = utils.load_config(args.json)
        logger.info(f"Loaded configuration from JSON file: {args.json}")

        # Apply network filtering if specified
        if args.network:
            filtered_config = {}
            for hostname, host_config in config.items():
                ip_address = host_config.get("address")
                if ip_address and utils.match_ip_to_network(
                    ip_address=ip_address, network=args.network
                ):
                    filtered_config[hostname] = host_config

            logger.info(
                f"Filtered to {len(filtered_config)} hosts in network {args.network}"
            )
            return utils.create_hosts_from_json(filtered_config)

        return utils.create_hosts_from_json(config)

    except Exception as e:
        raise HostLoadError(f"Error loading JSON file '{args.json}': {e}") from e


def load_scripts(args: argparse.Namespace, logger: logging.Logger) -> Dict[str, Any]:
    """
    Load available scripts from the specified directory.

    Args:
        args: Parsed command line arguments
        logger: Logger instance for output

    Returns:
        Dictionary of script name to script objects

    Raises:
        ScriptLoadError: If there's an error loading scripts
    """
    try:
        scripts_dir = Path(args.scripts)

        if not scripts_dir.exists():
            logger.warning(
                f"Scripts directory '{scripts_dir}' not found, using current directory"
            )
            scripts_dir = Path(".")

        scripts = utils.find_scripts(scripts_dir, DEFAULT_CONFIG["script_extensions"])
        logger.info(f"Found {len(scripts)} scripts in directory: {scripts_dir}")

        # Filter to specific script if requested
        if args.task:
            if args.task in scripts:
                scripts = {args.task: scripts[args.task]}
                logger.info(f"Filtered to script: {args.task}")
            else:
                available_scripts = ", ".join(scripts.keys())
                raise ScriptLoadError(
                    f"Script '{args.task}' not found. Available scripts: {available_scripts}"
                )

        return scripts

    except Exception as e:
        if isinstance(e, ScriptLoadError):
            raise
        raise ScriptLoadError(
            f"Error loading scripts from '{args.scripts}': {e}"
        ) from e


def list_hosts_and_scripts(
    hosts: Dict[str, Host],
    scripts: Dict[str, Any],
    args: argparse.Namespace,
    logger: logging.Logger,
) -> None:
    """
    Display information about loaded hosts and scripts.

    Args:
        hosts: Dictionary of loaded hosts
        scripts: Dictionary of loaded scripts
        args: Parsed command line arguments
        logger: Logger instance for output
    """
    logger.info("=== LOADED HOSTS ===")
    for hostname, host in hosts.items():
        if args.verbose:
            logger.info(f"Host: {hostname}")
            logger.info(f"  Address: {host.address}")
            logger.info(f"  Port: {host.port}")
            logger.info(f"  OS: {host.os}")
            logger.info(f"  Username: {host.username}")
            # Note: Passwords are not logged for security
        else:
            logger.info(f"Host: {hostname}@{host.address}")

    logger.info("=== AVAILABLE SCRIPTS ===")
    for script_name, script_data in scripts.items():
        if args.verbose:
            logger.info(f"Script: {script_name}")
            logger.info(f"  Path: {script_data.path}")
            logger.info(f"  Extension: {script_data.extension}")
            logger.info(f"  Executor Type: {script_data.get_executor_type()}")
        else:
            logger.info(f"Script: {script_name}")


def create_settings(args: argparse.Namespace) -> Settings:
    """
    Create Settings object from command line arguments.

    Args:
        args: Parsed command line arguments

    Returns:
        Configured Settings object
    """
    return Settings(
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
        executor_timeout=args.executor_timeout,
    )


def setup_tasks(
    args: argparse.Namespace,
    task_manager: TaskManager,
    hosts: Dict[str, Host],
    scripts: Dict[str, Any],
    logger: logging.Logger,
) -> None:
    """
    Configure tasks in the task manager based on command line arguments.

    Args:
        args: Parsed command line arguments
        task_manager: TaskManager instance to configure
        hosts: Dictionary of loaded hosts
        scripts: Dictionary of loaded scripts
        logger: Logger instance for output

    Raises:
        ConfigurationError: If task configuration is invalid
    """
    if args.command:
        # Execute a command on all hosts
        logger.info(f"Executing command on {len(hosts)} hosts: {args.command}")
        for hostname in hosts:
            task_manager.add_command_task(
                hostname=hostname,
                command=args.command,
                arguments=args.arguments or "",
                admin=args.sudo,
            )

    elif args.task:
        # Execute a specific script on all hosts
        if args.task not in scripts:
            raise ConfigurationError(
                f"Script '{args.task}' not found in loaded scripts"
            )

        logger.info(f"Executing script '{args.task}' on {len(hosts)} hosts")
        for hostname in hosts:
            task_manager.add_script_task(
                hostname=hostname,
                script_name=args.task,
                arguments=args.arguments or "",
                admin=args.sudo,
            )
    else:
        # Execute all scripts on all hosts
        logger.info(f"Executing {len(scripts)} scripts on {len(hosts)} hosts")
        for script_name in scripts:
            task_manager.add_task_for_all_hosts(script_name=script_name)


def execute_and_report(task_manager: TaskManager, logger: logging.Logger) -> None:
    """
    Execute all configured tasks and report results.

    Args:
        task_manager: TaskManager instance with configured tasks
        logger: Logger instance for output
    """
    logger.info("Starting task execution...")

    try:
        results = task_manager.execute_tasks()

        # Analyze and report results
        successes = 0
        failures = 0

        for result in results:
            if result.success:
                successes += 1
                logger.info(f"✓ SUCCESS: {result.task}")
                if result.output and not logger.getEffectiveLevel() == logging.ERROR:
                    # Only show output if not in quiet mode
                    print(f"Output: {result.output}")
            else:
                failures += 1
                logger.error(f"✗ FAILED: {result.task}")
                if result.error:
                    logger.error(f"Error: {result.error}")

        # Summary
        total_tasks = successes + failures
        success_rate = (successes / total_tasks * 100) if total_tasks > 0 else 0

        logger.info("Task execution completed:")
        logger.info(f"  Total tasks: {total_tasks}")
        logger.info(f"  Successful: {successes}")
        logger.info(f"  Failed: {failures}")
        logger.info(f"  Success rate: {success_rate:.1f}%")

    except KeyboardInterrupt:
        logger.warning("Task execution interrupted by user")
        raise
    except Exception as e:
        logger.error(f"Error during task execution: {e}")
        raise


if __name__ == "__main__":
    """
    Main entry point for the Deploy application.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    # Load configuration early
    args = parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("deploy")

    if not args.quiet:
        print(BANNER)

    try:
        # Load configuration file
        config = load_config_file(args.config)
        print(config)
        hosts = load_hosts(args, logger)
        scripts = load_scripts(args, logger)

        if args.list:
            list_hosts_and_scripts(hosts, scripts, args, logger)
            sys.exit(0)

        logger.info(f"Loaded {len(hosts)} hosts and {len(scripts)} scripts")

        settings = create_settings(args)
        task_manager = TaskManager(settings)
        task_manager.add_hosts(hosts)
        task_manager.add_scripts(scripts)

        setup_tasks(args, task_manager, hosts, scripts, logger)
        execute_and_report(task_manager, logger)

    except (ConfigurationError, HostLoadError, ScriptLoadError) as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback

            logger.error(traceback.format_exc())
        sys.exit(1)
    sys.exit(0)
