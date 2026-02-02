"""
Mock HTTP Client for SecMutBench

Provides mock HTTP response and client for testing SSRF vulnerabilities.
"""

import json
from typing import Dict, Any


class MockHTTPResponse:
    """Mock HTTP response for testing."""

    def __init__(self, status_code: int = 200, content: str = "", text: str = ""):
        self.status_code = status_code
        self.content = content
        self.text = text or content
        self.cookies = {}
        self.headers = {"Content-Type": "text/html"}

    def set_cookie(self, name: str, value: str, **kwargs):
        self.cookies[name] = {"value": value, **kwargs}

    def json(self) -> Dict:
        """Parse response as JSON."""
        return json.loads(self.text)

    def raise_for_status(self):
        """Raise exception for 4xx/5xx status codes."""
        if self.status_code >= 400:
            raise Exception(f"HTTP Error: {self.status_code}")


class MockHTTPClient:
    """Mock HTTP client for testing SSRF vulnerabilities."""

    def __init__(self):
        self._allowed_hosts = ["api.example.com", "cdn.example.com", "public.example.com"]
        self._internal_hosts = ["localhost", "127.0.0.1", "192.168.", "10.", "172.16.", "169.254."]
        self._responses = {
            "http://api.example.com/data": MockHTTPResponse(200, '{"status": "ok"}'),
            "http://localhost/admin": MockHTTPResponse(200, "admin_secret_data"),
            "http://127.0.0.1/internal": MockHTTPResponse(200, "internal_data"),
            "http://169.254.169.254/latest/meta-data/": MockHTTPResponse(200, "aws_metadata"),
        }
        self.last_url = None
        self.last_method = None
        self.request_count = 0
        self.ssrf_attempted = False

    def reset(self):
        """Reset client state."""
        self.last_url = None
        self.last_method = None
        self.request_count = 0
        self.ssrf_attempted = False

    def _is_internal(self, url: str) -> bool:
        """Check if URL targets internal resources."""
        for host in self._internal_hosts:
            if host in url.lower():
                return True
        return False

    def get(self, url: str, **kwargs) -> MockHTTPResponse:
        """Perform GET request."""
        self.last_url = url
        self.last_method = "GET"
        self.request_count += 1

        if self._is_internal(url):
            self.ssrf_attempted = True
            # Return internal data (simulating successful SSRF)
            if url in self._responses:
                return self._responses[url]
            return MockHTTPResponse(200, "internal_sensitive_data")

        return self._responses.get(url, MockHTTPResponse(200, "external_data"))

    def post(self, url: str, data: Any = None, json: Any = None, **kwargs) -> MockHTTPResponse:
        """Perform POST request."""
        self.last_url = url
        self.last_method = "POST"
        self.request_count += 1

        if self._is_internal(url):
            self.ssrf_attempted = True

        return MockHTTPResponse(200, '{"status": "created"}')

    def request(self, method: str, url: str, **kwargs) -> MockHTTPResponse:
        """Perform arbitrary HTTP request."""
        self.last_url = url
        self.last_method = method.upper()
        self.request_count += 1

        if self._is_internal(url):
            self.ssrf_attempted = True

        return MockHTTPResponse(200, "response_data")
