#!/usr/bin/env python3
"""
Connection module for the Deploy application.
Implements the factory pattern for different connection types.
"""
from abc import ABC, abstractmethod
import logging
import os
from typing import Any
import getpass

from fabric2 import Connection, Config
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

import modules.utils as utils
from modules.classes import Host, Settings

# Configure logger
logger = logging.getLogger(__name__)

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
    
    def connect(self) -> 'BaseConnection':
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
        pass
    
    @abstractmethod
    def execute_command(self, command: str, arguments: str = "", admin: bool = False) -> Any:
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
        pass
    
    @abstractmethod
    def execute_script(self, script_path: str, script_name: str, 
                      script_type: str, arguments: str = "",
                      admin: bool = False) -> Any:
        """
        Execute a script on the host.
        
        Args:
            script_path: Path to the script file
            script_name: Name of the script
            script_type: Type of script (bash, python, etc.)
            arguments: Optional arguments to the script
            admin: Whether to execute with admin privileges
            
        Returns:
            Script execution results
            
        Raises:
            DeployConnectionError: If execution fails
        """
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the connection."""
        pass
    
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
        Create an SSH connection to the host.
            
        Raises:
            DeployConnectionError: If connection fails
        """
        try:
            # Determine authentication method
            if self.host.ssh_keyfile:
                self.connection = self._connect_with_key()
            else:
                self.connection = self._connect_with_password()
        except Exception as e:
            raise DeployConnectionError(f"Failed to connect to {self.host}: {str(e)}")
    
    def _connect_with_password(self) -> Connection:
        """
        Connect using password authentication.
        
        Returns:
            Fabric2 Connection object
        """
        # Create SSH config
        ssh_config = Config(
            overrides={
                'sudo': {
                    'user': 'root',
                    'password': self.host.password
                },
                'connect_kwargs': {
                    'password': self.host.password
                }
            }
        ) if self.settings.admin else Config(
            overrides={
                'user': self.host.username,
                'password': self.host.password,
                'connect_kwargs': {
                    'password': self.host.password
                }
            }
        )
        
        # Create connection
        return Connection(
            host=self.host.address,
            user=self.host.username,
            port=int(self.host.port),
            config=ssh_config
        )
    
    def _connect_with_key(self) -> Connection:
        """
        Connect using SSH key authentication.
        
        Returns:
            Fabric2 Connection object
        """
        # Get key passphrase if needed and not provided
        passphrase = self.host.ssh_key_pass
        if not passphrase and self.host.ssh_keyfile and os.path.exists(self.host.ssh_keyfile):
            try:
                import paramiko
                # Try to load the key to see if it's encrypted
                try:
                    paramiko.RSAKey.from_private_key_file(self.host.ssh_keyfile)
                    # If we get here, the key is not encrypted
                except paramiko.PasswordRequiredException:
                    # Key is encrypted, ask for passphrase
                    passphrase = getpass.getpass(f"Enter passphrase for {self.host.ssh_keyfile}: ")
            except ImportError:
                # If paramiko isn't available directly, fall back to asking
                sshkey_response = input("Is the private key encrypted? (y/n): ")[:1]
                if sshkey_response.lower() == "y":
                    passphrase = getpass.getpass("Enter the private SSH key passphrase: ")
        
        # Create SSH config
        ssh_config = Config(
            overrides={
                'sudo': {
                    'user': 'root',
                    'password': self.host.password if self.host.password else None
                },
                'connect_kwargs': {
                    'key_filename': self.host.ssh_keyfile,
                    'passphrase': passphrase,
                    'look_for_keys': False
                }
            }
        ) if self.settings.admin else Config(
            overrides={
                'user': self.host.username,
                'connect_kwargs': {
                    'key_filename': self.host.ssh_keyfile,
                    'passphrase': passphrase,
                    'look_for_keys': False
                }
            }
        )
        
        # Create connection
        return Connection(
            host=self.host.address,
            user=self.host.username,
            port=int(self.host.port),
            config=ssh_config
        )
    
    def execute_command(self, command: str, arguments: str = "", admin: bool = False) -> Any:
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
            # Build full command
            cmd = f"{command} {arguments}" if arguments else command
            
            # Execute with sudo if admin requested
            if admin:
                sudo_password = self.host.password
                if not sudo_password:
                    sudo_password = getpass.getpass("Enter sudo password: ")
                preamble = f"sudo -H -u root -S < <(echo '{sudo_password}') "
                result = self.connection.run(preamble + cmd, warn=True, echo=not self.settings.quiet, hide=self.settings.quiet)
            else:
                result = self.connection.run(cmd, warn=True, echo=not self.settings.quiet, hide=self.settings.quiet)
            
            return result
        except Exception as e:
            raise DeployConnectionError(f"Failed to execute command '{command}' on {self.host}: {str(e)}")
    
    def execute_script(self, script_path: str, script_name: str, 
                      script_type: str, arguments: str = "",
                      admin: bool = False) -> Any:
        """
        Execute a script on the host via SSH.
        
        Args:
            script_path: Path to the script file
            script_name: Name of the script
            script_type: Type of script (bash, python, etc.)
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
            # Upload the script
            self.connection.put(script_path, script_name)
            
            # Make script executable for sh/bash scripts
            if script_type == "bash":
                self.connection.run(f"chmod +x {script_name}", warn=True, echo=not self.settings.quiet)
            
            # Build command based on script type
            if script_type == "bash":
                cmd = f"bash {script_name}"
            elif script_type == "python":
                cmd = f"python {script_name}"
            elif script_type == "python2":
                cmd = f"python2 {script_name}"
            elif script_type == "python3":
                cmd = f"python3 {script_name}"
            elif script_type == "perl":
                cmd = f"perl {script_name}"
            else:
                # Default to direct execution for executable scripts
                cmd = f"./{script_name}"
            
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
                result = self.connection.run(preamble + cmd, warn=True, echo=not self.settings.quiet, hide=self.settings.quiet)
            else:
                result = self.connection.run(cmd, warn=True, echo=not self.settings.quiet, hide=self.settings.quiet)
            
            # Clean up the script file
            self.connection.run(f"rm -f {script_name}", warn=True, echo=not self.settings.quiet)
            
            return result
        except Exception as e:
            raise DeployConnectionError(f"Failed to execute script '{script_name}' on {self.host}: {str(e)}")
    
    def close(self) -> None:
        """Close the SSH connection."""
        if self.connection:
            self.connection.close()
            self.connection = None

class WinRMConnection(BaseConnection):
    """
    WinRM connection using pypsrp.
    Supports password authentication.
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
            # Create WinRM connection
            self.connection = WSMan(
                server=host,
                port=int(self.host.port),
                username=self.host.username,
                password=self.host.password,
                ssl=False,  # Note: Consider making this configurable
                cert_validation=False  # Note: Consider making this configurable
            )
        except Exception as e:
            raise DeployConnectionError(f"Failed to connect to {self.host}: {str(e)}")
    
    def execute_command(self, command: str, arguments: str = "", admin: bool = False) -> Any:
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
                    # Note: In PowerShell, you'd typically use "Start-Process" with "-Verb RunAs"
                    # This is simplified and may need adjustment
                    pass
                
                # Invoke and return results
                ps.invoke()
                return ps.output
        except Exception as e:
            raise DeployConnectionError(f"Failed to execute command '{command}' on {self.host}: {str(e)}")
    
    def execute_script(self, script_path: str, script_name: str, 
                      script_type: str, arguments: str = "",
                      admin: bool = False) -> Any:
        """
        Execute a script on the host via WinRM.
        
        Args:
            script_path: Path to the script file
            script_name: Name of the script
            script_type: Type of script (powershell, batch, etc.)
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
            with RunspacePool(self.connection) as runspace:
                ps = PowerShell(runspace)
                
                # Read the script file
                with open(script_path, 'r') as f:
                    script_content = f.read()
                
                # Execute based on script type
                if script_type == "powershell":
                    # For PowerShell scripts, run the script directly
                    if arguments:
                        script_content += f" {arguments}"
                    ps.add_script(script_content)
                elif script_type == "batch":
                    # For batch files, use cmd.exe
                    command = f"cmd.exe /c '{script_content}'"
                    if arguments:
                        command += f" {arguments}"
                    ps.add_script(command)
                else:
                    raise DeployConnectionError(f"Unsupported script type '{script_type}' for Windows")
                
                # Invoke and return results
                ps.invoke()
                return ps.output
        except Exception as e:
            raise DeployConnectionError(f"Failed to execute script '{script_name}' on {self.host}: {str(e)}")
    
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
        # Force SSH if specified in settings
        if settings.force_ssh:
            return SSHConnection(host, settings)
        
        # Create connection based on OS
        if host.os == "linux":
            return SSHConnection(host, settings)
        elif host.os == "windows":
            return WinRMConnection(host, settings)
        else:
            raise ValueError(f"Unsupported OS: {host.os}")
