"""
MockFlask - Mock for Flask web framework

Used for testing various web vulnerabilities:
- CWE-306: Missing Authentication
- CWE-94: Code Injection
- CWE-319: Cleartext Transmission
"""

from typing import Any, Callable, Dict, Optional


class MockRequest:
    """Mock Flask request object."""

    def __init__(self):
        self.method = "GET"
        self.form = {}
        self.args = {}
        self.json = None
        self.data = b""
        self.cookies = {}
        self.headers = {"Content-Type": "text/html"}
        self.remote_addr = "127.0.0.1"
        self.path = "/"
        self.url = "http://localhost/"
        self.is_secure = False  # HTTP by default (insecure)


class MockResponse:
    """Mock Flask response object."""

    def __init__(self, data: str = "", status: int = 200, mimetype: str = "text/html"):
        self.data = data
        self.status_code = status
        self.mimetype = mimetype
        self.headers = {}

    def set_cookie(self, key: str, value: str, **kwargs):
        """Set a cookie."""
        self.headers[f"Set-Cookie-{key}"] = value


class MockSession(dict):
    """Mock Flask session object."""

    def __init__(self):
        super().__init__()
        self.modified = False
        self.permanent = False


class MockG:
    """Mock Flask g object for request-scoped data."""
    pass


class MockFlask:
    """Mock Flask application."""

    def __init__(self, name: str = "__main__"):
        self.name = name
        self.routes = {}
        self.before_request_funcs = []
        self.config = {
            "SECRET_KEY": "mock_secret_key",
            "DEBUG": False,
        }

    def route(self, path: str, methods: list = None):
        """Decorator to register a route."""
        def decorator(func: Callable):
            self.routes[path] = {
                "handler": func,
                "methods": methods or ["GET"],
            }
            return func
        return decorator

    def before_request(self, func: Callable):
        """Register a before_request handler."""
        self.before_request_funcs.append(func)
        return func

    def run(self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False, ssl_context=None):
        """Mock run() - doesn't actually start server."""
        self.config["DEBUG"] = debug
        # Check for HTTPS
        self._using_https = ssl_context is not None


class MockAbort:
    """Mock Flask abort function."""

    def __call__(self, status_code: int, description: str = None):
        raise MockHTTPException(status_code, description)


class MockHTTPException(Exception):
    """Mock HTTP exception."""

    def __init__(self, code: int, description: str = None):
        self.code = code
        self.description = description
        super().__init__(f"HTTP {code}: {description}")


class MockRedirect:
    """Mock Flask redirect."""

    def __call__(self, location: str, code: int = 302):
        return MockResponse(f"Redirect to {location}", status=code)


class MockUrlFor:
    """Mock Flask url_for."""

    def __call__(self, endpoint: str, **values):
        return f"/{endpoint}"


class MockRender:
    """Mock Flask render_template."""

    def __call__(self, template: str, **context):
        return f"<html>Rendered: {template}</html>"


class MockJsonify:
    """Mock Flask jsonify."""

    def __call__(self, *args, **kwargs):
        import json
        if args:
            data = args[0]
        else:
            data = kwargs
        return MockResponse(json.dumps(data), mimetype="application/json")


class MockLoginRequired:
    """Mock Flask-Login login_required decorator."""

    def __call__(self, func: Callable):
        def wrapper(*args, **kwargs):
            # Check if user is authenticated
            if not getattr(g, 'user', None):
                raise MockHTTPException(401, "Login required")
            return func(*args, **kwargs)
        return wrapper


class MockMakeResponse:
    """Mock Flask make_response."""

    def __call__(self, *args):
        if len(args) == 0:
            return MockResponse()
        elif len(args) == 1:
            return MockResponse(data=str(args[0]))
        elif len(args) == 2:
            return MockResponse(data=str(args[0]), status=args[1])
        else:
            return MockResponse(data=str(args[0]), status=args[1])


# Create singleton instances
request = MockRequest()
session = MockSession()
g = MockG()
Flask = MockFlask
abort = MockAbort()
redirect = MockRedirect()
url_for = MockUrlFor()
render_template = MockRender()
jsonify = MockJsonify()
login_required = MockLoginRequired()
make_response = MockMakeResponse()

# For flask_login compatibility
current_user = None


def reset():
    """Reset all Flask mocks to initial state."""
    global request, session, g, current_user
    request = MockRequest()
    session = MockSession()
    g = MockG()
    current_user = None
