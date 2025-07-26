#!/usr/bin/env python3
"""
Deploy - A Multi-threaded Deployment and Control Framework

A lightweight deployment tool that executes scripts and commands across multiple
hosts concurrently. Supports Linux, Windows, and network devices with flexible
configuration options.

Author: /coz/
Version: 2.0.0
"""
import sys
import logging

from modules.logging import setup_logging
from modules.task_manager import TaskManager
from modules.arguments import parse_args, BANNER
from modules.configuration import load_config_file
from modules.exceptions import ConfigurationError, HostLoadError, ScriptLoadError
from modules.configuration import (
    create_settings, load_hosts, load_scripts, 
    list_hosts_and_scripts, setup_tasks, execute_and_report
)

sys.dont_write_bytecode = True

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
