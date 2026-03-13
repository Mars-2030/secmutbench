"""
MockEval - Mock for code execution operations

Used for testing code injection vulnerabilities (CWE-94).
Tracks eval/exec usage to detect unsafe code execution.
"""

import ast
from typing import Any, Optional, List, Dict


class MockEval:
    """
    Mock module for code injection testing (CWE-94).

    Per MITRE CWE-94: eval() and exec() with user input allow
    arbitrary code execution.

    Security Contract:
    - INSECURE: eval(), exec() with untrusted input
    - SECURE: ast.literal_eval(), explicit parsing, validation

    Usage in tests:
        mock_eval.reset()
        result = process_input(user_data)
        assert not mock_eval.unsafe_eval_called, \\
            "Code injection: eval() used on user input"
    """

    # Dangerous patterns that indicate code injection attempts
    INJECTION_PATTERNS = [
        "__import__",
        "os.system",
        "subprocess",
        "open(",
        "exec(",
        "eval(",
        "__class__",
        "__bases__",
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "getattr(",
        "setattr(",
        "compile(",
    ]

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"last_code", "unsafe_eval_called", "unsafe_exec_called", "injection_detected"}

    def __init__(self):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.reset()

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockEval.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset all state."""
        self.unsafe_eval_called: bool = False
        self.unsafe_exec_called: bool = False
        self.safe_eval_called: bool = False
        self.eval_count: int = 0
        self.exec_count: int = 0
        self.last_code: Optional[str] = None
        self.injection_detected: bool = False
        self.operations: List[Dict[str, Any]] = []

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def _check_injection(self, code: str) -> bool:
        """Check if code contains injection patterns."""
        code_lower = code.lower()
        for pattern in self.INJECTION_PATTERNS:
            if pattern.lower() in code_lower:
                return True
        return False

    def eval(self, code: str, globals: Optional[Dict] = None, locals: Optional[Dict] = None) -> Any:
        """
        Mock eval() - UNSAFE code execution.

        This tracks usage of eval() which is dangerous with untrusted input.
        """
        self.unsafe_eval_called = True
        self.eval_count += 1
        self.last_code = code

        if self._check_injection(code):
            self.injection_detected = True

        self.operations.append({
            "type": "eval",
            "code": code,
            "injection_detected": self._check_injection(code),
        })

        # Try to actually evaluate safe expressions for testing
        try:
            # Only evaluate if it looks safe (literal)
            return ast.literal_eval(code)
        except:
            # Return a mock result for unsafe code
            return {"evaluated": True, "code": code[:50], "unsafe": True}

    def exec(
        self,
        code: str,
        globals: Optional[Dict] = None,
        locals: Optional[Dict] = None
    ) -> None:
        """
        Mock exec() - UNSAFE code execution.

        This tracks usage of exec() which is dangerous with untrusted input.
        """
        self.unsafe_exec_called = True
        self.exec_count += 1
        self.last_code = code

        if self._check_injection(code):
            self.injection_detected = True

        self.operations.append({
            "type": "exec",
            "code": code,
            "injection_detected": self._check_injection(code),
        })

        # Don't actually execute for safety

    def literal_eval(self, code: str) -> Any:
        """
        Mock ast.literal_eval() - SAFE evaluation of literals.

        Only evaluates Python literal structures: strings, numbers,
        tuples, lists, dicts, booleans, and None.
        """
        self.safe_eval_called = True
        self.last_code = code

        self.operations.append({
            "type": "literal_eval",
            "code": code,
            "safe": True,
        })

        # Use real ast.literal_eval since it's safe
        try:
            return ast.literal_eval(code)
        except (ValueError, SyntaxError) as e:
            raise ValueError(f"malformed node or string: {code}") from e

    def compile(
        self,
        source: str,
        filename: str,
        mode: str,
        flags: int = 0,
        dont_inherit: bool = False,
        optimize: int = -1
    ) -> Any:
        """
        Mock compile() - potentially unsafe.

        Compiling untrusted code is dangerous if subsequently executed.
        """
        self.last_code = source

        if self._check_injection(source):
            self.injection_detected = True

        self.operations.append({
            "type": "compile",
            "code": source,
            "filename": filename,
            "mode": mode,
        })

        # Return a mock code object
        return MockCodeObject(source)

    def is_safe_expression(self, code: str) -> bool:
        """
        Check if an expression is safe to evaluate.

        Returns True only for literal expressions that can be
        safely evaluated with ast.literal_eval.
        """
        try:
            tree = ast.parse(code, mode='eval')
            # Walk the AST and check for unsafe nodes
            for node in ast.walk(tree):
                # Allow only literal types
                if isinstance(node, (
                    ast.Expression, ast.Constant, ast.Num, ast.Str,
                    ast.List, ast.Tuple, ast.Dict, ast.Set,
                    ast.NameConstant, ast.UnaryOp, ast.UAdd, ast.USub
                )):
                    continue
                # Name is only safe for True, False, None
                if isinstance(node, ast.Name) and node.id in ('True', 'False', 'None'):
                    continue
                # Anything else is potentially unsafe
                return False
            return True
        except SyntaxError:
            return False


class MockCodeObject:
    """Mock code object returned by compile()."""

    def __init__(self, source: str):
        self.co_code = b''
        self.co_source = source
        self.co_filename = '<mock>'
        self.co_name = '<mock>'


# Provide mock builtins that can be used in test environments
class MockBuiltins:
    """
    Mock builtins with tracked eval/exec.

    Use this to replace builtins in test execution for tracking.
    """

    def __init__(self, mock_eval: MockEval):
        self._mock = mock_eval
        self._real_builtins = __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)

    def __getattr__(self, name: str) -> Any:
        if name == 'eval':
            return self._mock.eval
        if name == 'exec':
            return self._mock.exec
        if name == 'compile':
            return self._mock.compile
        # Fall back to real builtins
        if isinstance(self._real_builtins, dict):
            return self._real_builtins.get(name)
        return getattr(self._real_builtins, name)
