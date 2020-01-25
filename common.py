"""
Common Library of utility functions
"""

# Python STDLIB
import os
import sys
import time
import inspect
import subprocess


class hashobj(dict):
    """
    Hash object where fields are hashed members of a dictionary and can be get and set and deleted as desired.
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class cmd():
    """
    Functions to run commands.
    """
    @staticmethod
    def run(command, *args, envvars=None):
        """
        Runs a command as a child process while piping its output (STDOUT and STDERR).

        Parameters:
        command (str): The command to run
        *args (list(str)): The arguments to pass to the command
        envvars (dict): Dictionary of environment variables to pass to the process

        Returns:
        tuple(int, str, str): A tuple containing the Return Code, the STDOUT and the STDERR of the process.
        """
        command_list = list(args)
        command_list.insert(0, command)
        # Run the subprocess
        env = dict(os.environ)
        if envvars:
            env.update(envvars)
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        try:
            stdout = stdout.decode("ascii")
        except Exception:
            try:
                stdout = stdout.decode("utf-8")
            except Exception:
                pass
        try:
            stderr = stderr.decode("ascii")
        except Exception:
            try:
                stderr = stderr.decode("utf-8")
            except Exception:
                pass
        # Return the code, STDOUT and STDERR
        return process.returncode, stdout, stderr

    @staticmethod
    def run_shell(shell_command, envvars=None):
        """
        Runs a command in a subshell which is run as a child process while piping its output (STDOUT and STDERR).

        Parameters:
        shell_command (str): The shell command to run
        envvars (dict): Dictionary of environment variables to pass to the process

        Returns:
        tuple(int, str, str): A tuple containing the Return Code, the STDOUT and the STDERR of the process.
        """
        # Run the subprocess
        env = dict(os.environ)
        if envvars:
            env.update(envvars)
        process = subprocess.Popen(shell_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        try:
            stdout = stdout.decode("ascii")
        except Exception:
            try:
                stdout = stdout.decode("utf-8")
            except Exception:
                pass
        try:
            stderr = stderr.decode("ascii")
        except Exception:
            try:
                stderr = stderr.decode("utf-8")
            except Exception:
                pass
        # Return the code, STDOUT and STDERR
        return process.returncode, stdout, stderr


class logger():
    """
    logger functions
    """
    @staticmethod
    def _stack_time_header(prefix):
        """
        Get a string header with the stack and the time
        """
        try:
            stack = [f.function for f in inspect.stack()[2:5]]
        except ValueError:
            stack = []
        stacklen = len(stack)
        stackstring = ""
        for i in range(stacklen, 0, -1):
            stackstring += str(stack[i-1])
            if i != 1:
                stackstring += "/"
        if prefix:
            prefix = "({0}) ".format(prefix)
        return "[{0}] <{1}> {2}".format(
            stackstring,
            time.strftime("%H:%M:%S %d-%m-%Y", time.gmtime()),
            prefix
        )

    def __init__(self, ostream):
        """
        Constructor
        """
        self.ostream = ostream

    def writeline(self, printable_value, prefix=""):
        """
        Print a message with the datetime and function header.
        """
        printable_value = str(printable_value)
        header = logger._stack_time_header(prefix)
        self.ostream.write(header)
        hlen = len(header)
        linelen = 196 - hlen
        spacing = " " * hlen
        self.ostream.write(printable_value[:linelen])
        self.ostream.write("\n")
        printable_value = printable_value[linelen:]
        while printable_value:
            self.ostream.write(spacing)
            self.ostream.write(printable_value[:linelen])
            self.ostream.write("\n")
            printable_value = printable_value[linelen:]

    def write_byte_buffer_with_ascii(self, byte_buffer, prefix=""):
        """
        Print a byte buffer as mixed bytes and ASCII, useful for network packets. If printable ASCII, will print that,
        else will print byte hexdump.
        """
        if not isinstance(byte_buffer, bytes):
            raise ValueError("Type of byte_buffer is {0}, not bytes.".format(type(byte_buffer).__name__))
        header = logger._stack_time_header(prefix)
        hlen = len(header)
        spacing = " " * hlen
        linelen = 196 - hlen
        self.ostream.write(header)
        for b in byte_buffer[:linelen]:
            if 32 < b < 126:
                self.ostream.write(chr(b))
            else:
                self.ostream.write("\\x{0:02x}".format(b))
        self.ostream.write("\n")
        byte_buffer = byte_buffer[linelen:]
        while byte_buffer:
            self.ostream.write(spacing)
            for b in byte_buffer[:linelen]:
                if 32 < b < 126:
                    self.ostream.write(chr(b))
                else:
                    self.ostream.write("\\x{0:02x}".format(b))
            byte_buffer = byte_buffer[linelen:]
            self.ostream.write("\n")

    def write_named_dict(self, name, dictionary, prefix=""):
        """
        Write a named dictionary as a block across lines
        """
        header = logger._stack_time_header(prefix)
        hlen = len(header)
        spacing = " " * hlen
        linelen = 196 - hlen
        self.ostream.write(header)
        name = name.upper()
        self.ostream.write("[ ")
        self.ostream.write(name)
        self.ostream.write(" ]\n")
        for k, v in dictionary.items():
            k = str(k)
            v = str(v)
            keylen = len(k) + 2
            linelen2 = linelen - keylen
            self.ostream.write(spacing)
            self.ostream.write(k)
            self.ostream.write(": ")
            self.ostream.write(v[:linelen2])
            self.ostream.write("\n")
            v = v[linelen2:]
            while(v):
                self.ostream.write(spacing)
                self.ostream.write(" " * keylen)
                self.ostream.write(v[:linelen2])
                self.ostream.write("\n")
                v = v[linelen2:]
        self.ostream.write(spacing)
        self.ostream.write("[ - end of ")
        self.ostream.write(name)
        self.ostream.write(" - ]\n")

    def write_multiline_string(self, string, prefix=""):
        """
        Print an indented string with the datetime and function header.
        """
        header = logger._stack_time_header(prefix)
        self.ostream.write(header)
        hlen = len(header)
        spacing = " " * hlen
        lines = string.split('\n')
        self.ostream.write(lines[0])
        self.ostream.write("\n")
        for line in lines[1:]:
            self.ostream.write(spacing)
            self.ostream.write(line)
            self.ostream.write("\n")


# logger Objects for STDOUT and STDERR

stdout = logger(sys.stdout)

stderr = logger(sys.stderr)
