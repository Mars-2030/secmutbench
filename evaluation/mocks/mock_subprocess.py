"""
MockSubprocess - Mock for subprocess operations

Used for testing command injection vulnerabilities (CWE-78).
Tracks command execution patterns to detect injection attempts.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Union, Any


@dataclass
class MockCompletedProcess:
    """Mock subprocess.CompletedProcess result."""
    args: Union[str, List[str]]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class MockSubprocess:
    """
    Mock subprocess module for command injection testing.

    Tracks all command executions and their parameters to allow
    security tests to verify safe command construction.

    Security Contract:
    - SECURE: shell=False with command as list
    - INSECURE: shell=True with command as string (allows injection)

    Usage in tests:
        subprocess.reset()
        result = ping_host("localhost; cat /etc/passwd")
        assert subprocess.last_shell == False, "Insecure: shell=True used"
        assert ";" not in str(subprocess.last_command), "Injection in command"
    """

    # Common injection patterns to detect
    INJECTION_PATTERNS = [
        ";", "&&", "||", "|", "`", "$(",  # Command chaining/substitution
        "\n", "\r",  # Newline injection
        ">", "<", ">>",  # Redirection
    ]

    # Dangerous commands that indicate successful injection
    DANGEROUS_COMMANDS = [
        "rm ", "cat /etc", "wget ", "curl ", "nc ",
        "/bin/sh", "/bin/bash", "python ", "perl ",
        "chmod ", "chown ", "sudo ",
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all state."""
        self.last_command: Union[str, List[str], None] = None
        self.last_shell: bool = False
        self.last_kwargs: dict = {}
        self.commands_executed: List[dict] = []
        self.injection_detected: bool = False
        self.dangerous_command_detected: bool = False

    def run(
        self,
        args: Union[str, List[str]],
        shell: bool = False,
        capture_output: bool = False,
        text: bool = False,
        check: bool = False,
        timeout: Optional[float] = None,
        **kwargs
    ) -> MockCompletedProcess:
        """
        Mock subprocess.run().

        Args:
            args: Command to execute (string if shell=True, list if shell=False)
            shell: Whether to use shell execution
            capture_output: Capture stdout/stderr
            text: Return strings instead of bytes
            check: Raise on non-zero return code
            timeout: Timeout in seconds (ignored in mock)
            **kwargs: Additional arguments

        Returns:
            MockCompletedProcess with simulated output
        """
        # Record the execution
        self.last_command = args
        self.last_shell = shell
        self.last_kwargs = {
            'capture_output': capture_output,
            'text': text,
            'check': check,
            **kwargs
        }

        # Check for injection patterns
        command_str = args if isinstance(args, str) else " ".join(args)

        self.injection_detected = False
        self.dangerous_command_detected = False

        if shell and isinstance(args, str):
            # shell=True with string - vulnerable to injection
            for pattern in self.INJECTION_PATTERNS:
                if pattern in args:
                    self.injection_detected = True
                    break

            for dangerous in self.DANGEROUS_COMMANDS:
                if dangerous.lower() in args.lower():
                    self.dangerous_command_detected = True
                    break

        # Record execution history
        self.commands_executed.append({
            'command': args,
            'shell': shell,
            'injection_detected': self.injection_detected,
            'dangerous_detected': self.dangerous_command_detected,
        })

        # Generate mock output based on command
        stdout = self._generate_output(command_str)

        return MockCompletedProcess(
            args=args,
            returncode=0,
            stdout=stdout,
            stderr=""
        )

    def call(
        self,
        args: Union[str, List[str]],
        shell: bool = False,
        **kwargs
    ) -> int:
        """Mock subprocess.call() - returns exit code."""
        result = self.run(args, shell=shell, **kwargs)
        return result.returncode

    def check_output(
        self,
        args: Union[str, List[str]],
        shell: bool = False,
        **kwargs
    ) -> str:
        """Mock subprocess.check_output() - returns stdout."""
        result = self.run(args, shell=shell, capture_output=True, **kwargs)
        return result.stdout

    def Popen(
        self,
        args: Union[str, List[str]],
        shell: bool = False,
        **kwargs
    ) -> 'MockPopen':
        """Mock subprocess.Popen() - returns Popen object."""
        self.last_command = args
        self.last_shell = shell
        return MockPopen(args, shell=shell, **kwargs)

    def _generate_output(self, command: str) -> str:
        """Generate realistic mock output based on command."""
        command_lower = command.lower()

        if "ping" in command_lower:
            return "PING localhost (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.05 ms"

        if "cat /etc/passwd" in command_lower:
            return "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"

        if "whoami" in command_lower:
            return "testuser"

        if "ls" in command_lower:
            return "file1.txt\nfile2.txt\ndir1"

        if "echo" in command_lower:
            # Extract echo argument
            if "echo " in command_lower:
                return command.split("echo ", 1)[1].strip().strip('"\'')

        return "command executed"

    def has_injection(self) -> bool:
        """Check if any command had injection patterns."""
        return self.injection_detected

    def used_shell(self) -> bool:
        """Check if shell=True was used (insecure)."""
        return self.last_shell

    def get_command_string(self) -> str:
        """Get last command as string."""
        if isinstance(self.last_command, list):
            return " ".join(self.last_command)
        return self.last_command or ""


class MockPopen:
    """Mock subprocess.Popen object."""

    def __init__(self, args, shell=False, **kwargs):
        self.args = args
        self.shell = shell
        self.returncode = 0
        self.stdout = MockPipeIO("mock stdout output")
        self.stderr = MockPipeIO("")

    def communicate(self, input=None, timeout=None):
        """Mock communicate()."""
        return (self.stdout.read(), self.stderr.read())

    def wait(self, timeout=None):
        """Mock wait()."""
        return self.returncode

    def poll(self):
        """Mock poll()."""
        return self.returncode

    def kill(self):
        """Mock kill()."""
        pass

    def terminate(self):
        """Mock terminate()."""
        pass


class MockPipeIO:
    """Mock file-like object for stdout/stderr."""

    def __init__(self, content: str):
        self.content = content
        self.pos = 0

    def read(self, size=-1):
        if size == -1:
            result = self.content[self.pos:]
            self.pos = len(self.content)
        else:
            result = self.content[self.pos:self.pos + size]
            self.pos += size
        return result

    def readline(self):
        if self.pos >= len(self.content):
            return ""
        end = self.content.find('\n', self.pos)
        if end == -1:
            end = len(self.content)
        else:
            end += 1
        result = self.content[self.pos:end]
        self.pos = end
        return result

    def readlines(self):
        return self.content[self.pos:].splitlines(keepends=True)
