#!/usr/bin/env python3
"""
Improved data models for the Deploy application.
Includes proper type hints, validation, and better OOP structure.
"""
from typing import Dict, Any
import os

class ValidationError(Exception):
    """Exception raised for validation errors in the data models."""
    pass

class Host:
    """
    Represents a target host in the deployment configuration.
    Contains connection information and authentication details.
    """
    def __init__(self, hostname: str, config: Dict[str, Any]):
        """
        Initialize a host with configuration from config file.
        
        Args:
            hostname: The name/identifier of the host
            config: Dictionary containing host configuration
        
        Raises:
            ValidationError: If the host configuration is invalid
        """
        self.hostname = hostname
        self.username = config.get("username")
        self.password = config.get("password")
        self.os = config.get("os")
        self.address = config.get("address")
        self.port = config.get("port", "")
        self.ssh_keyfile = config.get("ssh_keyfile")
        self.ssh_key_pass = config.get("ssh_key_pass")
        
        # Validate the host configuration
        self.validate()
        
        # Set default port if not provided
        if not self.port:
            self.port = "22" if self.os == "linux" else "5985"
    
    def validate(self) -> None:
        """
        Validate that the host has all required fields and valid values.
        
        Raises:
            ValidationError: If validation fails
        """
        # Check required fields
        if not self.username:
            raise ValidationError(f"Host {self.hostname}: username is required")
        if not self.address:
            raise ValidationError(f"Host {self.hostname}: address is required")
        if not self.os:
            raise ValidationError(f"Host {self.hostname}: os is required")
        
        # Validate OS type
        if self.os not in ["linux", "windows"]:
            raise ValidationError(f"Host {self.hostname}: invalid os '{self.os}', must be 'linux' or 'windows'")
        
        # Check authentication
        if not self.password and not self.ssh_keyfile:
            raise ValidationError(f"Host {self.hostname}: either password or ssh_keyfile is required")
        
        # Validate SSH key file if provided
        if self.ssh_keyfile and not os.path.exists(self.ssh_keyfile):
            raise ValidationError(f"Host {self.hostname}: ssh_keyfile '{self.ssh_keyfile}' does not exist")
    
    def __str__(self) -> str:
        """Return a string representation of the host."""
        return f"{self.hostname} ({self.address})"
    
    def get_connection_params(self) -> Dict[str, Any]:
        """
        Get connection parameters for this host.
        
        Returns:
            Dictionary with connection parameters
        """
        params = {
            "hostname": self.hostname,
            "address": self.address,
            "username": self.username,
            "port": self.port,
            "os": self.os
        }
        
        # Add authentication parameters
        if self.password:
            params["password"] = self.password
        if self.ssh_keyfile:
            params["ssh_keyfile"] = self.ssh_keyfile
            params["ssh_key_pass"] = self.ssh_key_pass
            
        return params

class Script:
    """
    Represents a script that can be executed on remote hosts.
    """
    def __init__(self, name: str, path: str, directory: str, extension: str):
        """
        Initialize a script object.
        
        Args:
            name: The name of the script file
            path: The full path to the script file
            directory: The directory containing the script
            extension: The file extension
        """
        self.name = name
        self.path = path
        self.directory = directory
        self.extension = extension
        
        # Validate the script
        self.validate()
    
    def validate(self) -> None:
        """
        Validate that the script exists and has a supported extension.
        
        Raises:
            ValidationError: If validation fails
        """
        # Check that the script file exists
        if not os.path.exists(self.path):
            raise ValidationError(f"Script {self.name}: file '{self.path}' does not exist")
        
        # Validate extension
        valid_extensions = [".py", ".py2", ".py3", ".sh", ".bat", ".ps1", ".pl"]
        if self.extension not in valid_extensions:
            raise ValidationError(f"Script {self.name}: unsupported extension '{self.extension}'")
    
    def __str__(self) -> str:
        """Return a string representation of the script."""
        return self.name
    
    def get_executor_type(self) -> str:
        """
        Determine the executor type based on the script extension.
        
        Returns:
            String identifier for the executor type
        """
        if self.extension == ".sh":
            return "bash"
        elif self.extension in [".py", ".py2", ".py3"]:
            return "python"
        elif self.extension == ".pl":
            return "perl"
        elif self.extension == ".ps1":
            return "powershell"
        elif self.extension == ".bat":
            return "batch"
        else:
            return "unknown"

class Settings:
    """
    Configuration settings for the deployment operation.
    """
    def __init__(self, 
                 admin: bool = False, 
                 single_host: bool = False, 
                 single_command: bool = False, 
                 single_task: bool = False,
                 extra_args: bool = False,
                 logging: bool = False, 
                 quiet: bool = False, 
                 force_ssh: bool = False,
                 verbose: bool = False,
                 max_workers: int = 25):
        """
        Initialize settings with optional parameters.
        
        Args:
            admin: Whether to execute commands with admin privileges
            single_host: Whether to target a single host
            single_command: Whether to execute a single command
            single_task: Whether to execute a single task
            extra_args: Whether additional arguments are provided
            logging: Whether to enable logging
            quiet: Whether to suppress output
            force_ssh: Whether to force SSH for all connections
            local: Whether to execute locally
            max_workers: Maximum number of concurrent workers
        """
        self.admin = admin
        self.single_host = single_host
        self.single_command = single_command
        self.single_task = single_task
        self.extra_args = extra_args
        self.logging = logging
        self.quiet = quiet
        self.force_ssh = force_ssh
        self.verbose = verbose
        self.max_workers = max_workers
    
    def __str__(self) -> str:
        """Return a string representation of the settings."""
        settings = []
        if self.admin:
            settings.append("admin")
        if self.single_host:
            settings.append("single_host")
        if self.single_command:
            settings.append("single_command")
        if self.single_task:
            settings.append("single_task")
        if self.extra_args:
            settings.append("extra_args")
        if self.logging:
            settings.append("logging")
        if self.quiet:
            settings.append("quiet")
        if self.verbose:
            settings.append("verbose")
        if self.force_ssh:
            settings.append("force_ssh")
        if self.local:
            settings.append("local")
        if not settings:
            return "default settings"
        return ", ".join(settings)
