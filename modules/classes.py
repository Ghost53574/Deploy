class Script:
    def __init__(self, name, path, directory, extension):
        self.name      = name
        self.path      = path
        self.directory = directory
        self.extension = extension

    def name(self):
        return self.name

    def path(self):
        return self.path

    def directory(self):
        return self.directory

    def extension(self):
        return self.extension

class Settings:
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

    def admin(self):
        return self.admin

    def single_host(self):
        return self.path

    def single_command(self):
        return self.path

    def single_task(self):
        return self.path

    def extra_args(self):
        return self.extra_args

    def logging(self):
        return self.path

    def quiet(self):
        return self.path

    def force_ssh(self):
        return self.path

    def local(self):
        return self.path