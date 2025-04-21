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
    Supports Linux, Windows, and network devices.
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
        
        # Network device specific parameters
        self.device_type = config.get("device_type")
        self.enable_password = config.get("enable_password")
        self.global_delay_factor = config.get("global_delay_factor", 1.0)
        self.timeout = config.get("timeout", 100)
        
        # Windows authentication parameters
        self.auth_protocol = config.get("auth_protocol", "basic")
        self.cert_pem = config.get("cert_pem")
        self.cert_key_pem = config.get("cert_key_pem")
        self.ssl = config.get("ssl", False)
        self.server_cert_validation = config.get("server_cert_validation", "ignore")
        
        # Validate the host configuration
        self.validate()
        
        # Set default port if not provided
        if not self.port:
            if self.os == "linux":
                self.port = "22"
            elif self.os == "windows":
                self.port = "5985"
            elif self.os == "network":
                self.port = "22"  # Default for most network devices
    
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
        if self.os not in ["linux", "windows", "network"]:
            raise ValidationError(f"Host {self.hostname}: invalid os '{self.os}', must be 'linux', 'windows', or 'network'")
        
        # Check authentication
        if not self.password and not self.ssh_keyfile and not (self.cert_pem and self.cert_key_pem):
            raise ValidationError(f"Host {self.hostname}: authentication credentials are required (password, ssh_keyfile, or certificates)")
        
        # Validate SSH key file if provided
        if self.ssh_keyfile and not os.path.exists(self.ssh_keyfile):
            raise ValidationError(f"Host {self.hostname}: ssh_keyfile '{self.ssh_keyfile}' does not exist")
            
        # Network device validation
        if self.os == "network" and not self.device_type:
            raise ValidationError(f"Host {self.hostname}: device_type is required for network devices")
            
        # Windows authentication protocol validation
        if self.os == "windows" and self.auth_protocol not in ["basic", "credssp", "kerberos", "certificate", "negotiate"]:
            raise ValidationError(f"Host {self.hostname}: invalid auth_protocol '{self.auth_protocol}', must be 'basic', 'credssp', 'kerberos', 'negotiate', or 'certificate'")
            
        # Certificate validation for certificate auth
        if self.os == "windows" and self.auth_protocol == "certificate":
            if not self.cert_pem:
                raise ValidationError(f"Host {self.hostname}: cert_pem is required for certificate authentication")
            if not self.cert_key_pem:
                raise ValidationError(f"Host {self.hostname}: cert_key_pem is required for certificate authentication")
            if not os.path.exists(self.cert_pem):
                raise ValidationError(f"Host {self.hostname}: cert_pem file '{self.cert_pem}' does not exist")
            if not os.path.exists(self.cert_key_pem):
                raise ValidationError(f"Host {self.hostname}: cert_key_pem file '{self.cert_key_pem}' does not exist")
    
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
            
        # Add network device parameters
        if self.os == "network":
            params["device_type"] = self.device_type
            params["enable_password"] = self.enable_password
            params["global_delay_factor"] = self.global_delay_factor
            params["timeout"] = self.timeout
            
        # Add Windows authentication parameters
        if self.os == "windows":
            params["auth_protocol"] = self.auth_protocol
            params["ssl"] = self.ssl
            params["server_cert_validation"] = self.server_cert_validation
            
            if self.auth_protocol == "certificate":
                params["cert_pem"] = self.cert_pem
                params["cert_key_pem"] = self.cert_key_pem
            
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
                 max_workers: int = 25,
                 connection_timeout: int = 30,
                 task_timeout: int = 300,
                 executor_timeout: int = 1800):
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
            connection_timeout: Timeout in seconds for establishing connections (default: 30)
            task_timeout: Timeout in seconds for executing individual tasks (default: 300)
            executor_timeout: Timeout in seconds for the entire execution (default: 1800)
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
        self.connection_timeout = connection_timeout
        self.task_timeout = task_timeout
        self.executor_timeout = executor_timeout
    
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
        if not settings:
            return "default settings"
        return ", ".join(settings)
