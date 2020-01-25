"""
Process related library for daemon classes and serviceworkers and such
"""

# Python STDLIB
import os
import sys
import abc
import inspect
import shutil
import queue
import signal
import atexit
import time
import threading
# Common
from common import stderr as _stderr, stdout as _stdout, hashobj


class daemon(abc.ABC):
    """
    Abstract class for a daemon subprocess
    """

    @abc.abstractmethod
    def __str__(self):
        """
        Get the service name
        """
        pass

    @abc.abstractmethod
    def status(self):
        """
        Get a dict with the status
        """
        pass

    @abc.abstractmethod
    def start(self):
        """
        Boot up/initialize the service worker
        """
        pass

    @abc.abstractmethod
    def run(self):
        """
        Run the service worker as an infinite loop
        """
        pass

    @abc.abstractmethod
    def stop(self):
        """
        Exit out of the worker
        """
        pass

    @abc.abstractmethod
    def kill(self):
        """
        Blocking kill of the Worker
        """
        pass

    @abc.abstractmethod
    def stopped_gracefully(self):
        """
        Boolean value that will return True if the thread has stopped and is in an appropriate state
        """
        pass

    def register_event_callback(self, callback_object, callback_function):
        """
        Register an event callback on the service worker
        """
        if not callable(callback_function):
            _stderr.writeline("Error registering callback: {0}, not a function".format(
                str(callback_function)
            ))
        elif len(inspect.getfullargspec(callback_function).args) != 2:
            _stderr.writeline("Error registering callback: {0}, takes too many/few arguments, expected 2.".format(
                callback_function.__name__
            ))
        else:
            self.event_callbacks.append((callback_object, callback_function))

    def do_event_callbacks(self):
        """
        Call all callbacks for a state change event
        """
        for callback_object, callback_function in self.event_callbacks:
            callback_function(callback_object, self)

    @abc.abstractmethod
    def is_running(self):
        """
        Return true if daemon is running, false otherwise
        """
        pass

    def get_sub_daemons(self):
        """
        Function to get a list of all sub daemons for this daemon
        """
        return []

    def notification(self):
        """
        Function to be called by a sub daemon to inform the main daemon of an event
        """
        pass


_service_states = hashobj()

# Values
_service_states.STOPPED = 0
_service_states.RUNNING = 1
_service_states.STOPPING = 2

# Lookup Table
_service_states.lookup = {
    _service_states.STOPPED: "stopped",
    _service_states.RUNNING: "running",
    _service_states.STOPPING: "stopping"
}


class service:
    """
    Code for a Daemon Service

    The daemon service:

    1. Runs tasks
    2. Runs service workers in a loop
    """

    states = _service_states

    def __init__(self, pidfile, stdin="/dev/null", stdout="/dev/null", stderr="/dev/null"):
        """
        Constructor
        """
        self.pidfile = pidfile
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.workers = []
        self.daemons = []
        self.tasks = queue.Queue()
        self.state = service.states.STOPPED
        for redirect_file in [self.stdin, self.stdout, self.stderr]:
            if os.path.isfile(redirect_file):
                shutil.move(redirect_file, "{0}.{1}".format(redirect_file, int(os.stat(redirect_file).st_ctime)))
        self.env = {}

    def daemonize(self):
        """
        Daemonize the Process

        1. Fork once and have the parent exit with the exit() call so that the orphaned child process gets re-parented
            to Init.
        2. Reset the environment to root instead of that of the parent process by:
            - Change Directory to /.
            - Create a new session in which the orphaned child is the leader, without a controlling terminal.
            - Set umask to 0 so that files and directories created by the process will have no priveleges revoked (files
                will be created with mod 0666 and directories will be created with mod 0777).
        3. Fork again and exit from the parent so that the orphaned child may be part of the new session while never
            becoming the leader of the session and thus, never being able to acquire/reattach to a controlling terminal
            device.

            While setsid() is supposed to make sure that the inital child has a new session and doesn't have a
            controlling terminal, the second fork ensures that no file descriptors remain from the first fork (even
            though the first fork must close them) and thus may never reacquire a controlling terminal. This is useful
            for System V based unices where a single fork and setsid() alone dont guarentee detachment from all FDs and
            thus the controlling terminal.

        See https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap11.html#tag_11_01_03 for more information.
        """
        # First Fork
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as os_err:
            _stderr.writeline("Fork #1 failed, error: {0}".format(os_err))
            sys.exit(1)
        # Clean the Environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
        # Fork again
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as err:
            _stderr.writeline("Fork #2 failed, error: {0}".format(err))
            sys.exit(1)
        # Redirect the Python standard File Descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        stdin = open(self.stdin, "r")
        stdout = open(self.stdout, "a+", 1)
        stderr = open(self.stderr, "a+", 1)
        os.dup2(stdin.fileno(), sys.stdin.fileno())
        os.dup2(stdout.fileno(), sys.stdout.fileno())
        os.dup2(stderr.fileno(), sys.stderr.fileno())

    def getpid_from_pidfile(self):
        """
        Gets the PID from the PID File

        1. If file doesn't exist or is invalid, return None.
        2. If PID doesn't correspond to a running process, return None.
        3. Else return parsed PID.
        """
        pid = None
        # Get the PID from the PID File
        try:
            pid_file = open(self.pidfile, "r")
            # An unsigned 64 bit number is never going to be longer than 20 digits
            pid = int(pid_file.read(20).strip())
        except ValueError as err:
            _stderr.writeline("PID file seems to be corrupt: {0}.".format(err))
            os.remove(self.pidfile)
        except IOError:
            pass
        if pid:
            try:
                # Check if a process exists and accepts signals
                os.kill(pid, 0)
            except OSError:
                # Process is not running
                pid = None
        return pid

    def start(self, daemon=True):
        """
        Starts up the daemon

        1. Checks for existing process.
        2. If no existing process, then daemonize and run.
        """
        pid = self.getpid_from_pidfile()
        if pid:
            _stderr.writeline("PID file {0} already exists, is the service already running?".format(self.pidfile))
        if daemon:
            self.daemonize()
        # Register the callback At Exit
        atexit.register(self.atexit)
        signal.signal(signal.SIGTERM, self.atexit)
        # Write out the PID file
        with open(self.pidfile, "w+") as pid_file:
            pid_file.write("{0}\n".format(os.getpid()))

    def run(self):
        """
        Event loop

        1. Runs the Tasks once
        2. Runs the Workers once every 16 seconds
        3. Restarts daemons if not running due to crash
        """
        self.state = service.states.RUNNING
        # Run an event loop for the async workers with a 16 second reset interval
        while self.state == service.states.RUNNING:
            # Check the time
            start_time = int(time.time())
            end_time = start_time + 16
            # Process Tasks
            while not self.tasks.empty():
                if self.state != service.states.RUNNING:
                    return
                service_task = self.tasks.get()
                service_task(self)
            # Process Daemons
            removal_daemons = []
            for service_daemon in self.daemons:
                if self.state != service.states.RUNNING:
                    return
                if not service_daemon.is_running():
                    if service_daemon.stopped_gracefully():
                        removal_daemons.append(service_daemon)
                    else:
                        service_daemon.thread = threading.Thread(target=self.run, daemon=True)
                        service_daemon.thread.start()
            for removal_daemon in removal_daemons:
                if self.state != service.states.RUNNING:
                    return
                self.daemons.remove(removal_daemon)
            # Process Workers
            for service_worker in self.workers:
                if self.state != service.states.RUNNING:
                    return
                service_worker(self)
            # Check the time
            cur_time = int(time.time())
            if cur_time < end_time:
                time.sleep(end_time - cur_time)
            elif cur_time > end_time:
                _stderr.writeline("Service loop took {0} seconds too long.".format(cur_time - end_time))
        _stdout.writeline("Exited Main Loop")
        self.state = service.states.STOPPED

    def stop(self):
        """
        Stops the daemon

        1. Checks if PID file is valid.
        2. Stops the process with that PID if it is valid.
        3. Prints an error otherwise.
        """
        pid = self.getpid_from_pidfile()
        if not pid:
            _stderr.writeline("The service does not seem to be running, nonexistant/invalid PID file.")
        else:
            try:
                while True:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(1)
            except OSError as err:
                if "No such process" in str(err):
                    if os.path.isfile(self.pidfile):
                        os.remove(self.pidfile)
                else:
                    _stderr.writeline("Error stopping service: {0}".format(err))

    def restart(self):
        """
        Restarts the daemon
        """
        self.stop()
        self.start()

    def atexit(self, *args, **kwargs):
        """
        Process cleanup function

        1. Remove the PID file
        """
        if self.state == service.states.RUNNING:
            self.state = service.states.STOPPING
            # Cleanup the daemons
            for service_daemon in self.daemons:
                service_daemon.stop()
            # Erase the PID File
            if os.path.isfile(self.pidfile):
                os.remove(self.pidfile)

    def status(self):
        """
        Prints the status of each worker
        """
        pass

    def register_daemon(self, service_daemon):
        """
        Register a long running daemon. Daemons are workers that run on their own thread.
        """
        if not isinstance(service_daemon, daemon):
            _stderr.writeline("Error registering service: {0}".format(service_daemon.__str__()))
        else:
            for sub_daemon in service_daemon.get_sub_daemons():
                self.register_daemon(sub_daemon)
            service_daemon.start()
            service_daemon.thread = threading.Thread(target=service_daemon.run, daemon=True)
            service_daemon.thread.start()
            self.daemons.append(service_daemon)
            _stdout.writeline("Registered service: {0}".format(service_daemon.__str__()))

    def register_worker(self, service_worker):
        """
        Register a service worker which is a function that takes one argument: the service object. Workers are called
        every 16 seconds.
        """
        if not callable(service_worker):
            _stderr.writeline("Error registering worker: {0}, not a function".format(str(service_worker)))
        elif len(inspect.getfullargspec(service_worker).args) != 1:
            _stderr.writeline("Error registering worker: {0}, takes wrong number of arguments, expected 1".format(
                service_worker.__name__
            ))
        else:
            self.workers.append(service_worker)
            _stdout.writeline("Registered worker: {0}".format(str(service_worker)))

    def register_task(self, service_task):
        """
        Register a service task which is a function that takes one argument: the service object. Tasks are called once
        and then deregistered
        """
        if not callable(service_task):
            _stderr.writeline("Error registering task: {0}, not a function".format(str(service_task)))
        elif len(inspect.getfullargspec(service_task).args) != 1:
            _stderr.writeline("Error registering task: {0}, takes too many/few arguments, expected 1".format(
                service_task.__name__
            ))
        else:
            self.tasks.put(service_task)
            _stdout.writeline("Registered task: {0}".format(str(service_task)))
