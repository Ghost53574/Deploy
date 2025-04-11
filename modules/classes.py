from typing import Optional

class Host():
    username: Optional[str]
    password: Optional[str]
    os: Optional[str]
    address: Optional[str]
    port: Optional[str]
    ssh_keyfile: Optional[str]
    ssh_key_pass: Optional[str]
    
    def __init__(
            self, 
            config: dict
        ):
        self.username = config.get("username")
        self.password = config.get("password")
        self.os = config.get("os")
        self.address = config.get("address")
        self.port = config.get("port")
        self.ssh_keyfile = config.get("ssh_keyfile")
        self.ssh_key_pass = config.get("ssh_key_pass")

class Script():
    name: str
    path: str
    directory: str
    extension: str
    
    def __init__(self, name, path, directory, extension):
        self.name      = name
        self.path      = path
        self.directory = directory
        self.extension = extension

class Settings():
    admin: bool
    single_host: bool
    single_command: bool
    extra_args: bool
    logging: bool
    quiet: bool
    force_ssh: bool
    local: bool
    
    def __init__(self, 
                 admin: bool = False, 
                 single_host: bool = False, 
                 single_command: bool = False, 
                 single_task: bool = False,
                 extra_args: bool = False,
                 logging: bool = False, 
                 quiet: bool = False, 
                 force_ssh: bool = False,
                 local: bool = False):
        self.admin          = admin
        self.single_host    = single_host
        self.single_command = single_command
        self.single_task    = single_task
        self.extra_args     = extra_args
        self.logging        = logging
        self.quiet          = quiet
        self.force_ssh      = force_ssh
        self.local          = local