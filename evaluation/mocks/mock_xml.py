"""
Mock XML Parser for SecMutBench

Provides a mock XML parser for testing XXE vulnerabilities.
"""

from typing import Dict


class MockXMLParser:
    """Mock XML parser for testing XXE vulnerabilities."""

    def __init__(self):
        self.last_xml = None
        self.external_entities_resolved = False
        self.dtd_processed = False
        self._dangerous_patterns = [
            "<!ENTITY",
            "<!DOCTYPE",
            "SYSTEM",
            "file://",
            "http://",
            "expect://",
            "php://",
        ]

    def reset(self):
        """Reset parser state."""
        self.last_xml = None
        self.external_entities_resolved = False
        self.dtd_processed = False

    def parse_unsafe(self, xml_string: str) -> Dict:
        """Parse XML without security (vulnerable to XXE)."""
        self.last_xml = xml_string

        # Check for XXE patterns
        for pattern in self._dangerous_patterns:
            if pattern.lower() in xml_string.lower():
                self.external_entities_resolved = True
                if "<!DOCTYPE" in xml_string:
                    self.dtd_processed = True

        # Simulate XXE exploitation
        if "file:///etc/passwd" in xml_string:
            return {"content": "root:x:0:0:root:/root:/bin/bash", "xxe": True}

        return {"content": "parsed_content", "xxe": self.external_entities_resolved}

    def parse_safe(self, xml_string: str) -> Dict:
        """Parse XML safely (XXE protection enabled)."""
        self.last_xml = xml_string
        self.external_entities_resolved = False
        self.dtd_processed = False

        # Safe parser doesn't resolve external entities
        return {"content": "parsed_content", "xxe": False}

    def has_external_entities(self, xml_string: str) -> bool:
        """Check if XML contains external entity references."""
        return any(p.lower() in xml_string.lower() for p in self._dangerous_patterns)
