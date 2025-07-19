#!/usr/bin/env python3
"""
Task Manager module for the Deploy application.
Implements the producer/consumer pattern for task distribution and execution.
"""
import concurrent.futures
import logging
import queue
import signal
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from modules.classes import Host, Script, Settings, ValidationError
from modules.connections import ConnectionFactory

# Configure logger
logger = logging.getLogger(__name__)


@dataclass
class Task:
    """
    Represents a task to be executed on a remote host.
    """

    host: Host
    script: Optional[Script] = None
    command: Optional[str] = None
    arguments: Optional[str] = None
    admin: bool = False
    timeout: Optional[int] = None

    def validate(self) -> None:
        """
        Validate that the task has either a script or command.

        Raises:
            ValidationError: If validation fails
        """
        if not self.script and not self.command:
            raise ValidationError("Task must have either a script or command")

    def __str__(self) -> str:
        """Return a string representation of the task."""
        if self.script:
            return f"Script '{self.script.name}' on {self.host.hostname}"
        elif self.command:
            return f"Command '{self.command}' on {self.host.hostname}"
        else:
            return f"Empty task on {self.host.hostname}"


@dataclass
class TaskResult:
    """
    Represents the result of a task execution.
    """

    task: Task
    success: bool
    output: Any = None
    error: Optional[Exception] = None

    def __str__(self) -> str:
        """Return a string representation of the result."""
        if self.success:
            return f"Success: {self.task}"
        else:
            return f"Failed: {self.task} - {self.error}"


class TaskManager:
    """
    Manages task distribution and execution using a producer/consumer pattern.
    """

    def __init__(self, settings: Settings):
        """
        Initialize the task manager.

        Args:
            settings: Deployment settings
        """
        self.settings = settings
        self.task_queue = queue.Queue()
        self.results = []
        self.futures = []
        self.hosts: Dict[str, Host] = {}
        self.scripts: Dict[str, Script] = {}

    def add_host(self, hostname: str, host: Host) -> None:
        """
        Add a host to the task manager.

        Args:
            hostname: The hostname/identifier
            host: The host object
        """
        self.hosts[hostname] = host

    def add_hosts(self, hosts: Dict[str, Host]) -> None:
        """
        Add multiple hosts to the task manager.

        Args:
            hosts: Dictionary of hostname -> host objects
        """
        self.hosts.update(hosts)

    def add_script(self, script_name: str, script: Script) -> None:
        """
        Add a script to the task manager.

        Args:
            script_name: The script name/identifier
            script: The script object
        """
        self.scripts[script_name] = script

    def add_scripts(self, scripts: Dict[str, Script]) -> None:
        """
        Add multiple scripts to the task manager.

        Args:
            scripts: Dictionary of script_name -> script objects
        """
        self.scripts.update(scripts)

    def add_task(self, task: Task) -> None:
        """
        Add a task to the queue.

        Args:
            task: The task to add
        """
        task.validate()
        self.task_queue.put(task)

    def add_command_task(
        self, hostname: str, command: str, arguments: str = "", admin: bool = False
    ) -> None:
        """
        Add a command task to the queue.

        Args:
            hostname: The hostname to execute on
            command: The command to execute
            arguments: Optional arguments for the command
            admin: Whether to execute with admin privileges

        Raises:
            ValueError: If the hostname is not found
        """
        if hostname not in self.hosts:
            raise ValueError(f"Unknown host: {hostname}")

        task = Task(
            host=self.hosts[hostname], command=command, arguments=arguments, admin=admin
        )
        if self.settings.verbose:
            logger.debug(f"Adding {task} to {hostname}")
        self.add_task(task)

    def add_script_task(
        self, hostname: str, script_name: str, arguments: str = "", admin: bool = False
    ) -> None:
        """
        Add a script task to the queue.

        Args:
            hostname: The hostname to execute on
            script_name: The name of the script to execute
            arguments: Optional arguments for the script
            admin: Whether to execute with admin privileges

        Raises:
            ValueError: If the hostname or script_name is not found
        """
        if hostname not in self.hosts:
            raise ValueError(f"Unknown host: {hostname}")
        if script_name not in self.scripts:
            raise ValueError(f"Unknown script: {script_name}")

        task = Task(
            host=self.hosts[hostname],
            script=self.scripts[script_name],
            arguments=arguments,
            admin=admin,
        )
        if self.settings.verbose:
            logger.debug(f"Adding {task} to {hostname}")
        self.add_task(task)

    def add_task_for_all_hosts(
        self,
        script_name: Optional[str] = None,
        command: Optional[str] = None,
        arguments: str = "",
        admin: bool = False,
    ) -> None:
        """
        Add a task to be executed on all hosts.

        Args:
            script_name: The name of the script to execute (if any)
            command: The command to execute (if any)
            arguments: Optional arguments
            admin: Whether to execute with admin privileges

        Raises:
            ValueError: If neither script_name nor command is provided
        """
        if not script_name and not command:
            raise ValueError("Either script_name or command must be provided")

        script = self.scripts.get(script_name) if script_name else None

        for hostname, host in self.hosts.items():
            task = Task(
                host=host,
                script=script,
                command=command,
                arguments=arguments,
                admin=admin,
            )
            if self.settings.verbose:
                logger.debug(f"Adding {task} to {hostname}")
            self.add_task(task)

    def execute_tasks(self) -> List[TaskResult]:
        """
        Execute all tasks in the queue using a thread pool with timeout support.

        Returns:
            List of task results
        """
        results = []
        import time

        # Set up exit event for signal handling
        exiting = threading.Event()

        def sig_handler(signum, _frame):
            logger.warning(f"Received signal {signum}, initiating graceful shutdown")
            exiting.set()

        # Register signal handlers
        signal.signal(signal.SIGTERM, sig_handler)
        signal.signal(signal.SIGINT, sig_handler)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.settings.max_workers
        ) as executor:
            futures = {}
            try:
                # Submit all tasks to the executor
                while not self.task_queue.empty():
                    task = self.task_queue.get()
                    # Apply task-specific timeout or default from settings
                    timeout = task.timeout or self.settings.task_timeout
                    if self.settings.verbose:
                        logger.info(f"Task timeout: {timeout} seconds")

                    # Submit the task with timeout info
                    future = executor.submit(
                        self._execute_task_with_timeout, task, timeout, exiting
                    )
                    futures[future] = task

                # Wait for completion with overall executor timeout
                start_time = time.time()
                remaining_futures = set(futures.keys())

                while remaining_futures and not exiting.is_set():
                    # Use wait with a short timeout to allow for checking signals
                    timeout_increment = 1.0  # Check for signals every second
                    done, remaining_futures = concurrent.futures.wait(
                        remaining_futures,
                        timeout=timeout_increment,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

                    # Process completed futures
                    for future in done:
                        task = futures[future]
                        try:
                            result = future.result()
                            results.append(
                                TaskResult(task=task, success=True, output=result)
                            )
                        except concurrent.futures.TimeoutError:
                            logger.error(f"Task timed out: {task}")
                            results.append(
                                TaskResult(
                                    task=task,
                                    success=False,
                                    error=TimeoutError(
                                        f"Task execution exceeded timeout of {task.timeout or self.settings.task_timeout} seconds"
                                    ),
                                )
                            )
                        except Exception as e:
                            logger.error(f"Task failed: {task} - {str(e)}")
                            results.append(
                                TaskResult(task=task, success=False, error=e)
                            )

                    # Check overall executor timeout
                    elapsed = time.time() - start_time
                    if elapsed > self.settings.executor_timeout:
                        logger.warning(
                            f"Executor timeout reached ({self.settings.executor_timeout} seconds)"
                        )
                        break

                # Cancel any remaining tasks
                for future in remaining_futures:
                    if not future.done():
                        future.cancel()
                        task = futures[future]
                        results.append(
                            TaskResult(
                                task=task,
                                success=False,
                                error=concurrent.futures.CancelledError(
                                    "Task cancelled due to timeout or interrupt"
                                ),
                            )
                        )
                        logger.warning(f"Cancelled task: {task}")

            except KeyboardInterrupt:
                logger.warning(
                    "Keyboard interrupt detected, initiating graceful shutdown"
                )
                exiting.set()

                # Cancel pending futures
                for future in futures:
                    if not future.done():
                        future.cancel()

        return results

    def _execute_task_with_timeout(
        self, task: Task, timeout: int, exit_event: threading.Event
    ) -> Any:
        """
        Execute a task with timeout support and exit event checking.
        This method uses a worker thread approach to allow for timeout enforcement even when
        the underlying task might be blocked on network operations that don't respect timeouts.

        Args:
            task: The task to execute
            timeout: Timeout in seconds for this specific task
            exit_event: Event to check for program-wide exit signal

        Returns:
            Task output from the executed task

        Raises:
            concurrent.futures.TimeoutError: If the task execution exceeds the timeout
            concurrent.futures.CancelledError: If the task was cancelled due to exit request
            Exception: If task execution fails with any other error
        """
        import time

        result = None
        exception = None
        execution_completed = threading.Event()

        # Define the worker thread function
        def worker():
            nonlocal result, exception
            try:
                result = self._execute_task(task)
                execution_completed.set()
            except Exception as e:
                exception = e
                execution_completed.set()

        # Start the worker thread
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

        # Wait for completion or timeout
        start_time = time.time()
        while not execution_completed.is_set() and not exit_event.is_set():
            # Wait with a short timeout to allow checking exit_event
            execution_completed.wait(0.1)

            # Check if we've exceeded the timeout
            if time.time() - start_time > timeout:
                logger.warning(f"Task timeout reached for {task} ({timeout} seconds)")
                raise concurrent.futures.TimeoutError(
                    f"Task execution exceeded timeout of {timeout} seconds"
                )

        # Check if we were asked to exit
        if exit_event.is_set() and not execution_completed.is_set():
            raise concurrent.futures.CancelledError(
                "Task cancelled due to exit request"
            )

        # Re-raise any exception from the worker thread
        if exception is not None:
            raise exception

        return result

    def _execute_task(self, task: Task) -> Any:
        """
        Execute a single task.

        Args:
            task: The task to execute

        Returns:
            Task output

        Raises:
            DeployConnectionError: If connection fails
            Exception: If task execution fails
        """
        logger.info(f"Executing task: {task}")
        if self.settings.verbose:
            logger.info(f"Command: {task.command} {task.arguments}")
            logger.info(f"Admin: {task.admin}")

        # Create connection
        connection = ConnectionFactory.create_connection(task.host, self.settings)
        if self.settings.verbose:
            logger.info(f"Connection: {connection}")
        # Connect and execute based on task type
        with connection:
            if task.script:
                return connection.execute_script(
                    script_path=task.script.path,
                    script_name=task.script.name,
                    script_type=task.script.get_executor_type(),
                    arguments=task.arguments or "",
                    admin=task.admin or self.settings.admin,
                )
            elif task.command:
                return connection.execute_command(
                    command=task.command,
                    arguments=task.arguments or "",
                    admin=task.admin or self.settings.admin,
                )
            else:
                raise ValueError("Task has neither script nor command")
