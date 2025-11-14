import argparse

from modules import __version__, __author__

# Default configuration values (to avoid circular import)
DEFAULT_CONFIG = {
    "max_workers": 25,
    "connection_timeout": 30,
    "task_timeout": 300,
    "executor_timeout": 1800,
}

BANNER = f"""
            \033[1;31m██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗   ██╗\033[0m
            \033[1;31m██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗╚██╗ ██╔╝\033[0m
            \033[1;31m██║  ██║█████╗  ██████╔╝██║     ██║   ██║ ╚████╔╝ \033[0m
            \033[1;31m██║  ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║  ╚██╔╝  \033[0m
            \033[1;31m██████╔╝███████╗██║     ███████╗╚██████╔╝   ██║   \033[0m
            \033[1;31m╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝    ╚═╝   \033[0m

\033[1;35m                                       v{__version__} by {__author__}\033[0m
"""


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

    # Unified filtering options
    parser.add_argument(
        "-f",
        "--filter",
        type=str,
        help="Filter hosts and tasks using key=value pairs (comma-separated). "
             "Supported keys: os, username, address, port, network, device, hostname, host, task, script. "
             "Note: 'hostname' filters by hostname only, 'host' filters by both hostname and IP address. "
             "Example: --filter os=windows,task=*.ps1,host=192.168.1.*",
    )

    # Output and execution mode options
    parser.add_argument(
        "-O",
        "--output-format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format for results (default: text)",
    )
    parser.add_argument(
        "--save-results",
        type=str,
        metavar="FILE",
        help="Save execution results to specified file (supports .json or .txt)",
    )
    
    return parser.parse_args()
