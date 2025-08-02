import os
import json
import logging
import argparse

from pathlib import Path
from typing import Dict, Any, Optional

from modules import utils
from modules.classes import Settings, Host
from modules.task_manager import TaskManager
from modules.exceptions import HostLoadError, ScriptLoadError, ConfigurationError
from modules.utils import parse_filter_string, FilterCriteria

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

    # Apply unified filter if specified
    if hasattr(args, 'filter') and args.filter:
        try:
            hosts = utils.filter_hosts_by_criteria(hosts, parse_filter_string(args.filter))
        except ValueError as e:
            raise HostLoadError(f"Invalid filter syntax: {e}") from e

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
        # Load all records without filtering - unified filter will handle this
        records = utils.parse_csv_file(args.csv)
        logger.info(f"Loaded {len(records)} records from CSV file: {args.csv}")

        # Use default OS filter for basic validation
        accepted_os = DEFAULT_CONFIG["default_os_filter"]
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

        # Load all hosts without filtering - unified filter will handle this
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
        logger.debug(f"Found {len(scripts)} scripts in directory: {scripts_dir}")

        # Apply unified filter if specified
        if hasattr(args, 'filter') and args.filter:
            try:
                scripts = utils.filter_scripts_by_criteria(scripts, parse_filter_string(args.filter))
            except ValueError as e:
                raise ScriptLoadError(f"Invalid filter syntax: {e}") from e

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
    # Display hosts (already filtered by unified filter system)
    logger.info(f"Hosts ({len(hosts)}):")
    for hostname, host in hosts.items():
        if args.verbose:
            logger.info(f"  Host: {hostname}")
            logger.info(f"    Address: {host.address}")
            logger.info(f"    Port: {host.port}")
            logger.info(f"    OS: {host.os}")
            logger.info(f"    Username: {host.username}")
            if host.device_type:
                logger.info(f"    Device Type: {host.device_type}")
            # Note: Passwords are not logged for security
        else:
            logger.info(f"  {hostname}@{host.address} ({host.os})")

    # Display scripts (already filtered by unified filter system)
    logger.info(f"Scripts ({len(scripts)}):")
    for script_name, script_data in scripts.items():
        if args.verbose:
            logger.info(f"  Script: {script_name}")
            logger.info(f"    Path: {script_data.path}")
            logger.info(f"    Extension: {script_data.extension}")
            logger.info(f"    Executor Type: {script_data.get_executor_type()}")
        else:
            logger.info(f"  {script_name}")


def create_settings(args: argparse.Namespace) -> Settings:
    """
    Create Settings object from command line arguments.

    Args:
        args: Parsed command line arguments

    Returns:
        Configured Settings object
    """
    # Check if we have a task filter to determine single_task
    single_task = False
    if hasattr(args, 'filter') and args.filter:
        try:
            filter_criteria = parse_filter_string(args.filter)
            single_task = bool(filter_criteria.task)
        except ValueError:
            pass  # Ignore filter parsing errors here
    
    # Check if we have a hostname filter to determine single_host
    single_host = False
    if hasattr(args, 'filter') and args.filter:
        try:
            filter_criteria = parse_filter_string(args.filter)
            single_host = bool(filter_criteria.hostname)
        except ValueError:
            pass  # Ignore filter parsing errors here
    
    return Settings(
        admin=args.sudo,
        single_host=single_host,
        single_command=bool(args.command),
        single_task=single_task,
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
    elif len(scripts) == 1:
        # Execute the single filtered script on all hosts
        script_name = next(iter(scripts))
        logger.info(f"Executing script '{script_name}' on {len(hosts)} hosts")
        for hostname in hosts:
            task_manager.add_script_task(
                hostname=hostname,
                script_name=script_name,
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
