#!/usr/bin/env python3
"""
Connection module for the Deploy application.
Implements the factory pattern for different connection types.
"""
from abc import ABC, abstractmethod
import logging
import os
from typing import Any, Dict
import getpass

from fabric2 import Connection, Config
from pypsrp.powershell import PowerShell, RunspacePool
from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoTimeoutException, NetMikoAuthenticationException

from modules.classes import Host, Settings, OSType, ScriptType, Script
from modules.wsman_transport import WSManDeploy

logger = logging.getLogger(__name__)

# Define authentication constants for WinRM
# These would typically come from pypsrp.auth but we'll define them here for compatibility
AUTH_BASIC = "basic"
AUTH_CREDSSP = "credssp"
AUTH_KERBEROS = "kerberos"
AUTH_CERTIFICATE = "certificate"
AUTH_NEGOTIATE = "negotiate"

class DeployConnectionError(Exception):
    """Exception raised for connection errors."""
    pass

class BaseConnection(ABC):
    """
    Abstract base class for all connection types.
    Provides common interface for executing commands and scripts.
    """

    def __init__(self, host: Host, settings: Settings):
        """
        Initialize a connection to a host.

        Args:
            host: The host to connect to
            settings: Deployment settings
        """
        self.host = host
        self.settings = settings
        self.connection = None
        self._connected = False

    def connect(self) -> "BaseConnection":
        """
        Establish a connection to the host.

        Returns:
            Self for method chaining

        Raises:
            DeployConnectionError: If connection fails
        """
        if not self._connected:
            self._create_connection()
            self._connected = True
        return self

    @abstractmethod
    def _create_connection(self) -> None:
        """
        Create the actual connection to the host.

        Raises:
            DeployConnectionError: If connection fails
        """

    @abstractmethod
    def execute_command(
        self, command: str, arguments: str = "", admin: bool = False
    ) -> Any:
        """
        Execute a command on the host.

        Args:
            command: The command to execute
            arguments: Optional arguments to the command
            admin: Whether to execute with admin privileges

        Returns:
            Command execution results

        Raises:
            DeployConnectionError: If execution fails
        """

    @abstractmethod
    def execute_script(
        self,
        script: "Script",
        arguments: str = "",
        admin: bool = False,
    ) -> Any:
        """
        Execute a script on the host.

        Args:
            script: Script object containing path, name, and type information
            arguments: Optional arguments to the script
            admin: Whether to execute with admin privileges

        Returns:
            Script execution results

        Raises:
            DeployConnectionError: If execution fails
        """

    @abstractmethod
    def close(self) -> None:
        """Close the connection."""

    def __enter__(self):
        """Enter context manager."""
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.close()

    def __str__(self) -> str:
        """Return string representation."""
        return f"{self.__class__.__name__} to {self.host}"


class SSHConnection(BaseConnection):
    """
    SSH connection using Fabric2.
    Supports both password and key-based authentication.
    """

    def _create_connection(self) -> None:
        """
        Create an SSH connection to the host with timeout support.

        Raises:
            DeployConnectionError: If connection fails or times out
        """
        try:
            # Apply connection timeout from settings
            connect_timeout = self.settings.connection_timeout
            if connect_timeout and connect_timeout > 0:
                logger.debug(f"Using connection timeout of {connect_timeout} seconds")

            # Determine authentication method
            if self.host.ssh_keyfile:
                self.connection = self._connect_with_key()
            else:
                self.connection = self._connect_with_password()
        except Exception as e:
            raise DeployConnectionError(f"Failed to connect to {self.host}: {str(e)}") from e

    def _connect_with_password(self) -> Connection:
        """
        Connect using password authentication.

        Returns:
            Fabric2 Connection object
        """
        # Create SSH config
        ssh_config = (
            Config(
                overrides={
                    "sudo": {"user": "root", "password": self.host.password},
                    "connect_kwargs": {
                        "password": self.host.password,
                        "look_for_keys": False,
                        "allow_agent": False,
                        "banner_timeout": 60,
                    },
                }
            )
            if self.settings.admin
            else Config(
                overrides={
                    "user": self.host.username,
                    "password": self.host.password,
                    "connect_kwargs": {
                        "password": self.host.password,
                        "look_for_keys": False,
                        "allow_agent": False,
                        "banner_timeout": 60,
                    },
                }
            )
        )

        # Create connection
        return Connection(
            host=self.host.address,
            user=self.host.username,
            port=int(self.host.port),
            config=ssh_config,
        )

    def _connect_with_key(self) -> Connection:
        """
        Connect using SSH key authentication.

        Returns:
            Fabric2 Connection object
        """
        # Get key passphrase if needed and not provided
        passphrase = self.host.ssh_key_pass
        if (
            not passphrase
            and self.host.ssh_keyfile
            and os.path.exists(self.host.ssh_keyfile)
        ):
            try:
                import paramiko

                # Try to load the key to see if it's encrypted
                try:
                    paramiko.RSAKey.from_private_key_file(self.host.ssh_keyfile) # Do more keys and encryption types
                    # If we get here, the key is not encrypted
                except paramiko.PasswordRequiredException:
                    # Key is encrypted, ask for passphrase
                    passphrase = getpass.getpass(
                        f"Enter passphrase for {self.host.ssh_keyfile}: "
                    )
            except ImportError:
                # If paramiko isn't available directly, fall back to asking
                sshkey_response = input("Is the private key encrypted? (y/n): ")[:1]
                if sshkey_response.lower() == "y":
                    passphrase = getpass.getpass(
                        "Enter the private SSH key passphrase: "
                    )

        # Create SSH config
        ssh_config = (
            Config(
                overrides={
                    "sudo": {
                        "user": "root",
                        "password": self.host.password if self.host.password else None,
                    },
                    "connect_kwargs": {
                        "key_filename": self.host.ssh_keyfile,
                        "passphrase": passphrase,
                        "look_for_keys": True,
                        "banner_timeout": 60,
                    },
                }
            )
            if self.settings.admin
            else Config(
                overrides={
                    "user": self.host.username,
                    "connect_kwargs": {
                        "key_filename": self.host.ssh_keyfile,
                        "passphrase": passphrase,
                        "look_for_keys": True,
                        "banner_timeout": 60,
                    },
                }
            )
        )

        # Create connection
        return Connection(
            host=self.host.address,
            user=self.host.username,
            port=int(self.host.port),
            config=ssh_config,
        )

    def execute_command(
        self, command: str, arguments: str = "", admin: bool = False
    ) -> Any:
        """
        Execute a command on the host via SSH.

        Args:
            command: The command to execute
            arguments: Optional arguments to the command
            admin: Whether to execute with admin privileges

        Returns:
            Command execution results

        Raises:
            DeployConnectionError: If execution fails
        """
        if not self._connected:
            self.connect()

        if not self.connection:
            raise DeployConnectionError("No active connection")

        try:
            cmd = f"{command} {arguments}" if arguments else command

            if admin:
                sudo_password = self.host.password
                if not sudo_password:
                    sudo_password = getpass.getpass("Enter sudo password: ")
                preamble = f"sudo -H -u root -S < <(echo '{sudo_password}') "
                result = self.connection.run(
                    preamble + cmd,
                    warn=True,
                    echo=not self.settings.quiet
                    or (not self.settings.quiet and self.settings.verbose),
                    hide=self.settings.quiet,
                )
            else:
                result = self.connection.run(
                    cmd,
                    warn=True,
                    echo=not self.settings.quiet
                    or (not self.settings.quiet and self.settings.verbose),
                    hide=self.settings.quiet,
                )

            return result
        except Exception as e:
            raise DeployConnectionError(
                f"Failed to execute command '{command}' on {self.host}: {str(e)}"
            ) from e

    def execute_script(
        self,
        script: Script,
        arguments: str = "",
        admin: bool = False,
    ) -> Any:
        """
        Execute a script on the host via SSH.

        Args:
            script_path: Path to the script file (Path object)
            script_name: Name of the script
            script_type: Type of script (ScriptType enum)
            arguments: Optional arguments to the script
            admin: Whether to execute with admin privileges

        Returns:
            Script execution results

        Raises:
            DeployConnectionError: If execution fails
        """
        if not self._connected:
            self.connect()

        if not self.connection:
            raise DeployConnectionError("No active connection")

        try:
            # Convert Path to string for fabric and upload
            script_path_str = str(script.path)
            self.connection.put(script_path_str, script.name)

            # Determine executor type (SCRIPT vs CONFIG)
            executor_type = script.get_executor_type()

            # If this is a script, try to resolve interpreter and use it;
            # otherwise fall back to executing the file directly.
            if executor_type == ScriptType.SCRIPT:
                interpreter_cmd = script.get_interpreter_command()

                # Attempt to resolve interpreter full path on remote host
                which_result = self.connection.run(
                    f"which {interpreter_cmd}", warn=True, hide=True
                )
                if which_result.ok and which_result.stdout.strip():
                    interpreter_path = which_result.stdout.strip()
                else:
                    interpreter_path = interpreter_cmd

                # If interpreter looks like a shell built-in name we still
                # call it directly (remote PATH should resolve it).
                cmd = f"{interpreter_path} {script.name}"
            else:
                # CONFIG or unknown: treat as text/config - try to run as executable
                # Make executable and run directly
                self.connection.run(
                    f"chmod +x {script.name}",
                    warn=True,
                    echo=not self.settings.quiet or (
                        not self.settings.quiet and self.settings.verbose
                    ),
                )
                cmd = f"./{script.name}"

            # Add arguments if provided
            if arguments:
                cmd = f"{cmd} {arguments}"

            # Execute with sudo if admin requested
            result = None
            if admin:
                sudo_password = self.host.password
                if not sudo_password:
                    sudo_password = getpass.getpass("Enter sudo password: ")
                preamble = f"sudo -H -u root -S < <(echo '{sudo_password}') "
                result = self.connection.run(
                    preamble + cmd,
                    warn=True,
                    echo=not self.settings.quiet or (
                        not self.settings.quiet and self.settings.verbose
                    ),
                )
            else:
                result = self.connection.run(
                    cmd,
                    warn=True,
                    echo=not self.settings.quiet or (
                        not self.settings.quiet and self.settings.verbose
                    ),
                    hide=self.settings.quiet,
                )

            # Clean up remote script
            self.connection.run(
                f"rm -f {script.name}",
                warn=True,
                echo=not self.settings.quiet or (
                    not self.settings.quiet and self.settings.verbose
                ),
            )

            return result
        except Exception as e:
            raise DeployConnectionError(
                f"Failed to execute script '{script.name}' on {self.host}: {str(e)}"
            ) from e

    def close(self) -> None:
        """Close the SSH connection."""
        if self.connection:
            self.connection.close()
            self.connection = None

class NetmikoConnection(BaseConnection):
    """
    Connection for network devices using Netmiko.
    Supports various network device types (Cisco, Juniper, etc.).
    """

    def _create_connection(self) -> None:
        """
        Create a Netmiko connection to the network device with timeout support.

        Raises:
            DeployConnectionError: If connection fails or times out
        """
        try:
            # Use connection timeout from settings or host-specific timeout
            timeout = self.settings.connection_timeout or int(self.host.timeout)
            if self.settings.verbose:
                logger.debug(
                    f"Using connection timeout of {timeout} seconds for network device"
                )

            # Prepare device parameters
            device_params = {
                "device_type": self.host.device_type,
                "ip": self.host.address,
                "username": self.host.username,
                "password": self.host.password,
                "port": int(self.host.port),
                "global_delay_factor": float(self.host.global_delay_factor),
                "timeout": timeout,
            }

            # Add enable password if provided
            if self.host.enable_password:
                device_params["secret"] = self.host.enable_password

            # Use SSH key if provided
            if self.host.ssh_keyfile:
                device_params["use_keys"] = True
                device_params["key_file"] = self.host.ssh_keyfile
                if self.host.ssh_key_pass:
                    device_params["passphrase"] = self.host.ssh_key_pass

            # Create connection
            self.connection = ConnectHandler(**device_params)

            # Enter enable mode if an enable password is provided
            if self.host.enable_password:
                self.connection.enable()

        except NetMikoTimeoutException as exc:
            raise DeployConnectionError(f"Connection timeout to {self.host.address}") from exc
        except NetMikoAuthenticationException as exc:
            raise DeployConnectionError(
                f"Authentication failed for {self.host.username}@{self.host.address}"
            ) from exc
        except Exception as e:
            raise DeployConnectionError(f"Failed to connect to {self.host}: {str(e)}") from e

    def execute_command(
        self, command: str, arguments: str = "", admin: bool = False
    ) -> Any:
        """
        Execute a command on the network device.

        Args:
            command: The command to execute
            arguments: Optional arguments to the command
            admin: Whether to execute with admin privileges (uses enable mode)

        Returns:
            Command execution results

        Raises:
            DeployConnectionError: If execution fails
        """
        if not self._connected:
            self.connect()

        if not self.connection:
            raise DeployConnectionError("No active connection")

        try:
            # Build full command
            cmd = f"{command} {arguments}" if arguments else command

            # Execute command
            if (
                admin
                and self.host.enable_password
                and not self.connection.check_enable_mode()
            ):
                self.connection.enable()

            # Send command and get output
            output = self.connection.send_command(cmd)
            return output
        except Exception as e:
            raise DeployConnectionError(
                f"Failed to execute command '{command}' on {self.host}: {str(e)}"
            ) from e

    def execute_script(
        self,
        script: Script,
        arguments: str = "",
        admin: bool = False,
    ) -> Any:
        """
        Execute a network device configuration script via Netmiko.

        Network devices only accept CONFIG-type scripts. The Script object
        will be validated by the caller; here we enforce CONFIG semantics.

        Args:
            script: Script object containing path, name, and type information
            arguments: Optional arguments to substitute into commands
            admin: Whether to enter enable mode before applying config

        Returns:
            Results from sending the configuration commands

        Raises:
            DeployConnectionError: If execution fails or script type is not CONFIG
        """
        if not self._connected:
            self.connect()

        if not self.connection:
            raise DeployConnectionError("No active connection")

        # Enforce CONFIG-type for network devices
        if script.get_executor_type() != ScriptType.CONFIG:
            raise DeployConnectionError(
                f"Network devices can only execute CONFIG type scripts. Got {script.get_executor_type().value} for {script.name}"
            )

        try:
            script_path_str = str(script.path)

            # Read the script file as a list of commands, ignoring comments/empty lines
            with open(script_path_str, "r", encoding="utf-8") as f:
                commands = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]

            # Replace placeholder args if provided
            if arguments:
                commands = [c.replace("{args}", arguments) for c in commands]

            # Enter enable mode if requested
            if admin and self.host.enable_password and not self.connection.check_enable_mode():
                self.connection.enable()

            # Send configuration set
            output = self.connection.send_config_set(commands)
            return output
        except Exception as e:
            raise DeployConnectionError(
                f"Failed to execute script '{script.name}' on {self.host}: {str(e)}"
            ) from e

    def close(self) -> None:
        """Close the Netmiko connection."""
        if self.connection:
            self.connection.disconnect()
            self.connection = None


class WinRMConnection(BaseConnection):
    """
    WinRM connection using pypsrp.
    Supports multiple authentication methods: Basic, CredSSP, Kerberos, and Certificate.
    """

    def _create_connection(self) -> None:
        """
        Create a WinRM connection to the host.

        Raises:
            DeployConnectionError: If connection fails
        """
        try:
            host = ""
            if self.host.address:
                host = self.host.address

            # Authentication options
            # If SSL is False, cert_validation must be False
            # If SSL is True, use server_cert_validation from config (default to True if not specified)
            ssl_enabled = self.host.ssl if self.host.ssl else False
            if not ssl_enabled:
                cert_validation = False
            else:
                # SSL is enabled, check for server_cert_validation setting
                if self.host.server_cert_validation:
                    cert_validation = self.host.server_cert_validation
                else:
                    cert_validation = True
            
            kwargs = {
                "server": host,
                "port": int(self.host.port),
                "username": self.host.username,
                "ssl": ssl_enabled,
                "cert_validation": cert_validation,
                "encryption": "auto",
            }

            # Try to connect with specified auth method first
            auth_method = self._get_auth_method()
            try:
                self._attempt_connection(kwargs, auth_method)
            except Exception as e:
                # If CredSSP specifically fails, try basic auth as fallback
                if auth_method == AUTH_CREDSSP and "CredSSP" in str(e):
                    logger.warning(
                        f"CredSSP authentication failed: {str(e)}. Trying basic auth as fallback."
                    )
                    self._attempt_connection(kwargs, AUTH_BASIC)
                else:
                    # Re-raise other exceptions
                    raise
        except Exception as e:
            raise DeployConnectionError(f"Failed to connect to {self.host}: {str(e)}") from e

    def _attempt_connection(self, kwargs: Dict[str, Any], auth_method: str) -> None:
        """
        Attempt to create a WinRM connection with the specified authentication method.

        Args:
            kwargs: Connection keyword arguments
            auth_method: Authentication method to use

        Raises:
            Exception: If connection fails
        """
        conn_kwargs = kwargs.copy()

        # Add authentication parameters based on method
        if auth_method == AUTH_BASIC:
            # Basic auth - needs password and special encryption handling
            conn_kwargs["password"] = self.host.password
            conn_kwargs["auth"] = auth_method

            # For Basic auth, we need to set encryption to 'never' if SSL is not used
            if not conn_kwargs.get("ssl", False):
                conn_kwargs["encryption"] = "never"

        elif auth_method == AUTH_CREDSSP:
            # CredSSP uses password
            conn_kwargs["password"] = self.host.password
            conn_kwargs["auth"] = auth_method

        elif auth_method == AUTH_KERBEROS:
            # Kerberos doesn't need password
            conn_kwargs["auth"] = AUTH_KERBEROS

        elif auth_method == AUTH_CERTIFICATE:
            # Certificate auth uses cert files
            conn_kwargs["cert_pem"] = self.host.cert_pem
            conn_kwargs["cert_key_pem"] = self.host.cert_key_pem
            conn_kwargs["auth"] = AUTH_CERTIFICATE

        elif auth_method == AUTH_NEGOTIATE:
            # Negotiate auth protocol (NTLM/Kerberos)
            conn_kwargs["password"] = self.host.password
            conn_kwargs["auth"] = AUTH_NEGOTIATE

        # Add enhanced connection parameters
        if hasattr(self.host, 'reconnection_retries') and self.host.reconnection_retries:
            conn_kwargs["reconnection_retries"] = self.host.reconnection_retries
        else:
            conn_kwargs["reconnection_retries"] = 3  # Default
            
        if hasattr(self.host, 'reconnection_backoff') and self.host.reconnection_backoff:
            conn_kwargs["reconnection_backoff"] = self.host.reconnection_backoff
        else:
            conn_kwargs["reconnection_backoff"] = 2.0  # Default
            
        if hasattr(self.host, 'connection_timeout') and self.host.connection_timeout:
            conn_kwargs["connection_timeout"] = self.host.connection_timeout
        elif self.settings.connection_timeout:
            conn_kwargs["connection_timeout"] = self.settings.connection_timeout
        else:
            conn_kwargs["connection_timeout"] = 30  # Default
            
        if hasattr(self.host, 'read_timeout') and self.host.read_timeout:
            conn_kwargs["read_timeout"] = self.host.read_timeout
        else:
            conn_kwargs["read_timeout"] = 30  # Default
            
        if hasattr(self.host, 'user_agent') and self.host.user_agent:
            conn_kwargs["user_agent"] = self.host.user_agent
        else:
            conn_kwargs["user_agent"] = "Microsoft WinRM Client"  # Default

        # Create WinRM connection
        self.connection = WSManDeploy(**conn_kwargs)

    def _get_auth_method(self) -> str:
        """
        Determine the authentication method based on host configuration.

        Returns:
            Authentication method constant
        """
        auth_protocol = self.host.auth_protocol.lower()

        if auth_protocol == "basic":
            return AUTH_BASIC
        elif auth_protocol == "credssp":
            return AUTH_CREDSSP
        elif auth_protocol == "kerberos":
            return AUTH_KERBEROS
        elif auth_protocol == "certificate":
            return AUTH_CERTIFICATE
        elif auth_protocol == "negotiate":
            return AUTH_NEGOTIATE
        else:
            # Default to basic negotiate
            return AUTH_NEGOTIATE

    def execute_command(
        self, command: str, arguments: str = "", admin: bool = False
    ) -> Any:
        """
        Execute a command on the host via WinRM.

        Args:
            command: The command to execute
            arguments: Optional arguments to the command
            admin: Whether to execute with admin privileges

        Returns:
            Command execution results

        Raises:
            DeployConnectionError: If execution fails
        """
        if not self._connected:
            self.connect()

        if not self.connection:
            raise DeployConnectionError("No active connection")

        try:
            with RunspacePool(self.connection) as runspace:
                ps = PowerShell(runspace)

                # Add command and arguments
                if arguments:
                    ps.add_cmdlet(command).add_argument(arguments)
                else:
                    ps.add_cmdlet(command)

                # Execute with admin if requested
                if admin:
                    # For PowerShell, we'd typically use "Start-Process" with "-Verb RunAs"
                    # This is simplified and may need adjustment based on your specific requirements
                    pass

                # Invoke and return results
                ps.invoke()
                return ps.output
        except Exception as e:
            raise DeployConnectionError(
                f"Failed to execute command '{command}' on {self.host}: {str(e)}"
            ) from e

    def execute_script(
        self,
        script: Script,
        arguments: str = "",
        admin: bool = False,
    ) -> Any:
        """
        Execute a script on the host via WinRM.

        Args:
            script_path: Path to the script file (Path object)
            script_name: Name of the script
            script_type: Type of script (ScriptType enum)
            arguments: Optional arguments to the script
            admin: Whether to execute with admin privileges

        Returns:
            Script execution results

        Raises:
            DeployConnectionError: If execution fails
        """
        if not self._connected:
            self.connect()

        if not self.connection:
            raise DeployConnectionError("No active connection")

        try:
            script_path_str = str(script.path)

            # Only PowerShell and batch are supported for WinRM execution
            if script.extension == ".ps1":
                with RunspacePool(self.connection) as runspace:
                    ps = PowerShell(runspace)
                    with open(script_path_str, "r", encoding="utf-8") as f:
                        script_content = f.read()
                    if arguments:
                        script_content += f" {arguments}"
                    ps.add_script(script_content)
                    ps.invoke()
                    return ps.output
            elif script.extension == ".bat":
                with RunspacePool(self.connection) as runspace:
                    ps = PowerShell(runspace)
                    with open(script_path_str, "r", encoding="utf-8") as f:
                        script_content = f.read()
                    command = f"cmd.exe /c '{script_content}'"
                    if arguments:
                        command += f" {arguments}"
                    ps.add_script(command)
                    ps.invoke()
                    return ps.output
            else:
                # For other script types, recommend using SSH (not supported via WinRM here)
                raise DeployConnectionError(
                    f"Unsupported script extension '{script.extension}' for WinRM. Use SSH for arbitrary interpreters."
                )
        except Exception as e:
            raise DeployConnectionError(
                f"Failed to execute script '{script.name}' on {self.host}: {str(e)}"
            ) from e

    def close(self) -> None:
        """Close the WinRM connection."""
        if self.connection:
            self.connection.close()
            self.connection = None


class ConnectionFactory:
    """
    Factory for creating appropriate connection objects.
    """

    @staticmethod
    def create_connection(host: Host, settings: Settings) -> BaseConnection:
        """
        Create a connection to a host based on its OS type.

        Args:
            host: The host to connect to
            settings: Deployment settings

        Returns:
            Appropriate connection object for the host

        Raises:
            ValueError: If the host OS is not supported
        """
        # Create connection based on OS
        if host.os == OSType.LINUX.value or settings.force_ssh:
            return SSHConnection(host, settings)
        elif host.os == OSType.WINDOWS.value:
            return WinRMConnection(host, settings)
        elif host.os == OSType.NETWORK.value:
            return NetmikoConnection(host, settings)
        else:
            raise ValueError(f"Unsupported OS: {host.os}")
