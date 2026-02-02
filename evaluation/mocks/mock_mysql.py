"""
MockMySQL - Mock for MySQL database connections

Used for testing hardcoded credentials (CWE-798).
"""


class MockConnection:
    """Mock MySQL connection."""

    def __init__(self, host, user, password, database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connected = True

    def cursor(self):
        return MockCursor()

    def close(self):
        self.connected = False

    def commit(self):
        pass

    def rollback(self):
        pass


class MockCursor:
    """Mock MySQL cursor."""

    def __init__(self):
        self.lastrowid = 0
        self.rowcount = 0
        self._results = []

    def execute(self, query, params=None):
        pass

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def close(self):
        pass


class MockMySQL:
    """
    Mock mysql.connector module.

    Tracks connection parameters to detect hardcoded credentials.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset state."""
        self.last_host = None
        self.last_user = None
        self.last_password = None
        self.last_database = None
        self.connect_called = False

    def connect(self, host=None, user=None, password=None, database=None, **kwargs):
        """Mock mysql.connector.connect()."""
        self.connect_called = True
        self.last_host = host
        self.last_user = user
        self.last_password = password
        self.last_database = database
        return MockConnection(host, user, password, database)


# Create singleton
_mock_mysql = MockMySQL()


def connect(*args, **kwargs):
    return _mock_mysql.connect(*args, **kwargs)


def reset():
    _mock_mysql.reset()


# For mysql.connector compatibility
connector = _mock_mysql
