"""
Mock Database for SecMutBench

Provides a mock database for testing SQL-related code and detecting SQL injection.
"""

import os
import re
from typing import Dict, List, Any, Optional


class MockDatabase:
    """Mock database for testing SQL-related code."""

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"last_query", "last_params", "query_count"}

    def __init__(self):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self._default_tables = {
            "users": [
                # Both password (for insecure code) and password_hash (for secure bcrypt code)
                # password = plaintext value that insecure code compares against
                # password_hash = bcrypt hash for secure code (starts with $2b$)
                {"id": 1, "name": "alice", "username": "alice", "email": "alice@example.com",
                 "password": "test_password_alice", "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_alice_hash"},
                {"id": 2, "name": "bob", "username": "bob", "email": "bob@example.com",
                 "password": "test_password_bob", "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_bob_hash"},
                {"id": 3, "name": "charlie", "username": "charlie", "email": "charlie@example.com",
                 "password": "test_password_charlie", "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_charlie_hash"},
            ],
            "passwords": [
                {"user_id": 1, "hash": "hash1"},
                {"user_id": 2, "hash": "hash2"},
            ],
            "sessions": [
                {"session_id": "valid_session_123", "user_id": 1, "expires": "2099-12-31"},
            ],
            "products": [],
            "orders": [],
            "customers": [],
            "employees": [],
            "secrets": [
                {"id": 1, "key": "secret_api_key", "value": "supersecret123"},
            ],
        }
        self.tables = {k: [dict(row) for row in v] for k, v in self._default_tables.items()}
        self.last_query = None
        self.last_params = None
        self.query_count = 0
        self._last_results = []
        self._committed = False

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockDatabase.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset database to initial state."""
        self.tables = {k: [dict(row) for row in v] for k, v in self._default_tables.items()}
        self.last_query = None
        self.last_params = None
        self.query_count = 0
        self._last_results = []
        self._committed = False

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def add_row(self, table: str, row: Dict):
        """Add a row to a table."""
        if table not in self.tables:
            self.tables[table] = []
        self.tables[table].append(dict(row))

    def update_row(self, table: str, match_col: str, match_val: Any, updates: Dict):
        """Update rows matching a condition."""
        if table not in self.tables:
            return 0
        count = 0
        for row in self.tables[table]:
            if row.get(match_col) == match_val:
                row.update(updates)
                count += 1
        return count

    def delete_row(self, table: str, match_col: str, match_val: Any) -> int:
        """Delete rows matching a condition."""
        if table not in self.tables:
            return 0
        original_len = len(self.tables[table])
        self.tables[table] = [r for r in self.tables[table] if r.get(match_col) != match_val]
        return original_len - len(self.tables[table])

    def clear_table(self, table: str):
        """Clear all rows from a table."""
        if table in self.tables:
            self.tables[table] = []

    def get_table(self, table: str) -> List[Dict]:
        """Get all rows from a table."""
        return self.tables.get(table, [])

    def get_row(self, table: str, match_col: str, match_val: Any) -> Optional[Dict]:
        """Get a single row matching a condition."""
        for row in self.tables.get(table, []):
            if row.get(match_col) == match_val:
                return dict(row)
        return None

    def get_user(self, username: str) -> Optional[Dict]:
        """Get user by username - convenience method for auth tests.

        Used by CWE-287 authentication templates.
        Returns user dict with both 'password' and 'password_hash' fields.
        """
        for row in self.tables.get("users", []):
            if row.get("username") == username or row.get("name") == username:
                return dict(row)
        return None

    def cursor(self):
        """Return self as cursor (for cursor-based patterns)."""
        return self

    def fetchall(self) -> List[Dict]:
        """Fetch all results from last query."""
        return self._last_results

    def fetchone(self) -> Optional[Dict]:
        """Fetch one result from last query."""
        return self._last_results[0] if self._last_results else None

    def connection(self):
        """Return self for context manager pattern."""
        return self

    def commit(self):
        """Commit transaction (mock)."""
        self._committed = True

    def rollback(self):
        """Rollback transaction (mock - resets to defaults)."""
        self.reset()

    def close(self):
        """Close connection (mock - no-op)."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, query: str, params: tuple = None) -> List[Dict]:
        """Execute a query and return results."""
        self.last_query = query
        self.last_params = params
        self.query_count += 1

        # Detect SQL injection attempts in non-parameterized queries
        if params is None:
            injection_patterns = [
                "' OR '1'='1",
                "'; DROP TABLE",
                "UNION SELECT",
                "' OR ''='",
                "' OR 1=1",
                "OR 1=1--",
                "'; DELETE FROM",
                "'; UPDATE ",
                "1'; --",
            ]
            query_upper = query.upper()
            for pattern in injection_patterns:
                if pattern.upper() in query_upper:
                    # Simulate injection success - return all rows from relevant table
                    table_match = self._find_table_in_query(query)
                    if table_match:
                        self._last_results = list(self.tables.get(table_match, []))
                    else:
                        self._last_results = list(self.tables.get("users", []))
                    return self._last_results

        # Execute the query normally
        results = self._execute_simple_query(query, params)
        self._last_results = results
        return results

    def _find_table_in_query(self, query: str) -> Optional[str]:
        """Extract table name from query."""
        query_upper = query.upper()
        for table in self.tables.keys():
            if table.upper() in query_upper:
                return table
        return None

    def _execute_simple_query(self, query: str, params: tuple = None) -> List[Dict]:
        """Execute a simple SELECT query."""
        query_upper = query.upper()

        # Find the table
        table_match = self._find_table_in_query(query)
        if not table_match:
            return []

        rows = self.tables.get(table_match, [])

        # Handle LIKE queries
        if params and "LIKE" in query_upper:
            filtered = []
            for row in rows:
                for param in params:
                    param_str = str(param)
                    # Handle LIKE pattern matching
                    if param_str.startswith('%') and param_str.endswith('%'):
                        search_term = param_str[1:-1]
                        for col, val in row.items():
                            if search_term.lower() in str(val).lower():
                                if row not in filtered:
                                    filtered.append(row)
                                break
                    elif param_str.startswith('%'):
                        search_term = param_str[1:]
                        for col, val in row.items():
                            if str(val).lower().endswith(search_term.lower()):
                                if row not in filtered:
                                    filtered.append(row)
                                break
                    elif param_str.endswith('%'):
                        search_term = param_str[:-1]
                        for col, val in row.items():
                            if str(val).lower().startswith(search_term.lower()):
                                if row not in filtered:
                                    filtered.append(row)
                                break
            # Apply LIMIT if present
            if "LIMIT" in query_upper and params and len(params) > 1:
                try:
                    limit = int(params[-1])
                    filtered = filtered[:limit]
                except (ValueError, TypeError):
                    pass
            return filtered

        # H7 fix: Parse column names from WHERE clause and match positionally
        if params and "WHERE" in query_upper:
            filtered = []
            # Extract column names from WHERE clause (col = ? pattern)
            where_part = query_upper.split("WHERE", 1)[1].split("ORDER")[0].split("LIMIT")[0]
            where_cols = re.findall(r'(\w+)\s*=\s*\?', where_part)
            for row in rows:
                match = True
                for i, col_upper in enumerate(where_cols):
                    if i >= len(params):
                        break
                    # Find matching column (case-insensitive)
                    matched_col = None
                    for rc in row:
                        if rc.upper() == col_upper:
                            matched_col = rc
                            break
                    if matched_col is None or str(row[matched_col]) != str(params[i]):
                        match = False
                        break
                if match and row not in filtered:
                    filtered.append(row)
            return filtered

        return rows[:1] if rows else []

    def table_exists(self, table_name: str) -> bool:
        """Check if table exists."""
        return table_name in self.tables

    def count_rows(self, table: str) -> int:
        """Count rows in a table."""
        return len(self.tables.get(table, []))
