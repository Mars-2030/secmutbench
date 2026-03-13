"""
MockDeserializer - Mock for deserialization operations

Used for testing insecure deserialization vulnerabilities (CWE-502).
Tracks deserialization method usage to detect unsafe methods.
"""

import json
from typing import Any, Optional, List, BinaryIO, TextIO


class MockPickle:
    """
    Mock pickle module for insecure deserialization testing.

    Per MITRE CWE-502: pickle.loads() and pickle.load() are inherently
    dangerous with untrusted input as they can execute arbitrary code.

    Security Contract:
    - INSECURE: pickle.loads(), pickle.load(), cPickle
    - SECURE: json.loads(), yaml.safe_load(), custom validation

    Usage in tests:
        pickle.reset()
        result = deserialize_data(untrusted_data)
        assert not pickle.unsafe_load_called, \\
            "Insecure: pickle used for untrusted data"
    """

    # Exception classes that pickle provides
    class UnpicklingError(Exception):
        """Exception raised when unpickling fails."""
        pass

    class PicklingError(Exception):
        """Exception raised when pickling fails."""
        pass

    class PickleError(Exception):
        """Base exception for pickle errors."""
        pass

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"unsafe_load_called", "last_data", "load_count"}

    def __init__(self):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.reset()

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockPickle.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset all state."""
        self.unsafe_load_called: bool = False
        self.load_count: int = 0
        self.last_data: Optional[bytes] = None
        self.operations: List[str] = []

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def loads(self, data: bytes, **kwargs) -> Any:
        """
        Mock pickle.loads() - UNSAFE deserialization.

        In real code, this could execute arbitrary code embedded
        in the pickled data via __reduce__ methods.
        """
        self.unsafe_load_called = True
        self.load_count += 1
        self.last_data = data
        self.operations.append("loads")

        # Simulate returning a dict for testing purposes
        # In real pickle, this could execute malicious code
        return {"deserialized": True, "method": "pickle.loads", "unsafe": True}

    def load(self, file: BinaryIO, **kwargs) -> Any:
        """
        Mock pickle.load() - UNSAFE deserialization from file.
        """
        self.unsafe_load_called = True
        self.load_count += 1
        self.operations.append("load")

        # Read data if possible
        if hasattr(file, 'read'):
            try:
                self.last_data = file.read()
            except:
                pass

        return {"deserialized": True, "method": "pickle.load", "unsafe": True}

    def dumps(self, obj: Any, protocol: Optional[int] = None) -> bytes:
        """Mock pickle.dumps() - serialization (safe direction)."""
        self.operations.append("dumps")
        # Return mock serialized data
        return b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00}'

    def dump(self, obj: Any, file: BinaryIO, protocol: Optional[int] = None) -> None:
        """Mock pickle.dump() - serialization to file."""
        self.operations.append("dump")
        if hasattr(file, 'write'):
            file.write(b'\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00}')


class MockYAML:
    """
    Mock yaml module for insecure deserialization testing.

    Per MITRE CWE-502: yaml.load() without safe_load can instantiate
    arbitrary Python objects from YAML strings.

    Security Contract:
    - INSECURE: yaml.load() without Loader=SafeLoader
    - SECURE: yaml.safe_load(), yaml.load(data, Loader=yaml.SafeLoader)

    Usage in tests:
        yaml.reset()
        result = parse_config(yaml_string)
        assert not yaml.unsafe_load_called or yaml.safe_loader_used, \\
            "Insecure: yaml.load() without SafeLoader"
    """

    # Simulated Loader classes
    class SafeLoader:
        pass

    class FullLoader:
        pass

    class UnsafeLoader:
        pass

    class Loader:
        pass

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"unsafe_load_called", "safe_loader_used", "last_data", "load_count"}

    def __init__(self):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.reset()

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockYAML.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset all state."""
        self.unsafe_load_called: bool = False
        self.safe_loader_used: bool = False
        self.load_count: int = 0
        self.last_data: Optional[str] = None
        self.operations: List[str] = []

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def load(self, data: str, Loader=None) -> Any:
        """
        Mock yaml.load() - potentially UNSAFE without SafeLoader.
        """
        self.load_count += 1
        self.last_data = data
        self.operations.append("load")

        # Check if safe loader was used
        if Loader is None:
            # No loader specified - unsafe in older PyYAML versions
            self.unsafe_load_called = True
        elif Loader in [self.SafeLoader, "SafeLoader"]:
            self.safe_loader_used = True
        else:
            # FullLoader, UnsafeLoader, or Loader - potentially unsafe
            self.unsafe_load_called = True

        # Try to parse as JSON for simple test cases
        try:
            return json.loads(data.replace("'", '"'))
        except:
            return {"parsed": True, "content": data[:100]}

    def safe_load(self, data: str) -> Any:
        """
        Mock yaml.safe_load() - SAFE deserialization.
        """
        self.load_count += 1
        self.last_data = data
        self.safe_loader_used = True
        self.operations.append("safe_load")

        # Try to parse as JSON for simple test cases
        try:
            return json.loads(data.replace("'", '"'))
        except:
            return {"parsed": True, "content": data[:100], "safe": True}

    def safe_load_all(self, data: str) -> List[Any]:
        """Mock yaml.safe_load_all() - SAFE multi-document load."""
        self.safe_loader_used = True
        self.operations.append("safe_load_all")
        return [self.safe_load(data)]

    def dump(self, data: Any, stream: Optional[TextIO] = None) -> Optional[str]:
        """Mock yaml.dump() - serialization (safe direction)."""
        self.operations.append("dump")
        result = json.dumps(data)
        if stream:
            stream.write(result)
            return None
        return result

    def safe_dump(self, data: Any, stream: Optional[TextIO] = None) -> Optional[str]:
        """Mock yaml.safe_dump() - safe serialization."""
        self.operations.append("safe_dump")
        return self.dump(data, stream)


class MockMarshal:
    """
    Mock marshal module - also unsafe for untrusted data.
    """

    SECURITY_ATTRS = {"unsafe_load_called"}

    def __init__(self):
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.reset()

    def reset(self):
        self.unsafe_load_called: bool = False

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockMarshal.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def loads(self, data: bytes) -> Any:
        """Mock marshal.loads() - UNSAFE."""
        self.unsafe_load_called = True
        return {"deserialized": True, "method": "marshal.loads"}

    def load(self, file: BinaryIO) -> Any:
        """Mock marshal.load() - UNSAFE."""
        self.unsafe_load_called = True
        return {"deserialized": True, "method": "marshal.load"}

    def dumps(self, obj: Any) -> bytes:
        """Mock marshal.dumps()."""
        return b'\x00'

    def dump(self, obj: Any, file: BinaryIO) -> None:
        """Mock marshal.dump()."""
        file.write(b'\x00')
