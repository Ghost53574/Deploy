class DeployError(Exception):
    """Base exception class for Deploy application errors."""
    def __init__(self, message=None):
        super().__init__(message or "An error occurred in the Deploy application.")

class ConfigurationError(DeployError):
    """Raised when there's an error in configuration."""
    def __init__(self, message=None):
        super().__init__(message or "Configuration error in the Deploy application.")

class HostLoadError(DeployError):
    """Raised when there's an error loading hosts."""
    def __init__(self, message=None):
        super().__init__(message or "Error loading hosts in the Deploy application.")

class ScriptLoadError(DeployError):
    """Raised when there's an error loading scripts."""
    def __init__(self, message=None):
        super().__init__(message or "Error loading scripts in the Deploy application.")