"""
Modules package contains all the functionality for the Deploy tool
This includes:
- classes: Holds definitions for Hosts, Scripts, and Settings
- connections: Handles the connections and different types of connections through a BaseConnection
- task_manager: Handles the execution of all tasks across many connection types
- utils: Utility functions that don't fit in other modules
"""

import sys
import os

sys.path.append(f"{os.getcwd()}/modules")
