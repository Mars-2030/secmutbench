"""
Pytest configuration and fixtures for SecMutBench tests.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def sample_secure_code():
    """Sample secure code for testing."""
    return '''
def get_user(user_id):
    db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return db.fetchone()
'''


@pytest.fixture
def sample_insecure_code():
    """Sample insecure code (SQL injection vulnerable)."""
    return '''
def get_user(user_id):
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return db.fetchone()
'''


@pytest.fixture
def sample_security_test():
    """Sample security test for SQL injection."""
    return '''
def test_sql_injection():
    get_user("1' OR '1'='1")
    assert db.last_params is not None, "SQL injection: query not parameterized"
'''


@pytest.fixture
def mock_db():
    """Provide a MockDatabase instance."""
    from evaluation.mocks import MockDatabase
    db = MockDatabase()
    yield db
    db.reset()


@pytest.fixture
def mock_subprocess():
    """Provide a MockSubprocess instance."""
    from evaluation.mocks import MockSubprocess
    sp = MockSubprocess()
    yield sp
    sp.reset()


@pytest.fixture
def test_runner():
    """Provide a TestRunner instance."""
    from evaluation.test_runner import TestRunner
    return TestRunner(timeout=5.0)


@pytest.fixture
def benchmark_sample():
    """Load a single benchmark sample for testing."""
    from evaluation.evaluate import load_benchmark
    benchmark = load_benchmark()
    if benchmark:
        return benchmark[0]
    return None
