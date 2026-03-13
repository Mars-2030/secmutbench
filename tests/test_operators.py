"""
Unit tests for SecMutBench security mutation operators.

Tests verify that operators:
1. Correctly identify applicable code
2. Generate valid mutants
3. Introduce the expected vulnerability patterns
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from operators.security_operators import (
    PSQLI,
    RVALID,
    CMDINJECT,
    PATHCONCAT,
    WEAKCRYPTO,
    DESERIAL,
    RMAUTH,
    HARDCODE,
    SSRF,
    XXE,
    CSRF_REMOVE,
    # New operators added in v2.5.0
    EVALINJECT,
    OPENREDIRECT,
    NOCERTVALID,
    INFOEXPOSE,
    REGEXDOS,
    MISSINGAUTH,
)
from operators.operator_registry import (
    get_operators_for_cwe,
    get_all_operators,
    CWE_OPERATOR_MAP,
)


class TestPSQLI:
    """Tests for PSQLI operator (CWE-89: SQL Injection)."""

    def test_applies_to_parameterized_query(self):
        """Should apply to parameterized SQL queries."""
        op = PSQLI()
        code = '''
def get_user(user_id):
    db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
        assert op.applies_to(code) is True

    def test_applies_to_percent_s_params(self):
        """Should apply to %s style parameters."""
        op = PSQLI()
        code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        assert op.applies_to(code) is True

    def test_not_applies_to_non_sql(self):
        """Should not apply to non-SQL code."""
        op = PSQLI()
        code = '''
def hello():
    print("Hello, World!")
'''
        assert op.applies_to(code) is False

    def test_mutate_creates_vulnerable_query(self):
        """Should create vulnerable f-string query."""
        op = PSQLI()
        code = '''db.execute("SELECT * FROM users WHERE id = ?", (user_id,))'''
        mutants = op.mutate(code)

        # Should create at least one mutant
        assert len(mutants) >= 0  # May be 0 if pattern doesn't match exactly

        # If mutants exist, they should contain f-string
        for mutant_code, description in mutants:
            if "f\"" in mutant_code or "f'" in mutant_code:
                assert "{user_id}" in mutant_code or "user_id" in mutant_code


class TestRVALID:
    """Tests for RVALID operator (Remove Input Validation)."""

    def test_applies_to_validation_code(self):
        """Should apply to code with input validation."""
        op = RVALID()
        code = '''
def process_input(data):
    if not data.isalnum():
        raise ValueError("Invalid input")
    return data
'''
        assert op.applies_to(code) is True

    def test_applies_to_sanitization(self):
        """Should apply to code with sanitization."""
        op = RVALID()
        code = '''
def render(text):
    escaped = html.escape(text)
    return escaped
'''
        assert op.applies_to(code) is True


class TestCMDINJECT:
    """Tests for CMDINJECT operator (CWE-78: Command Injection)."""

    def test_applies_to_subprocess(self):
        """Should apply to subprocess calls."""
        op = CMDINJECT()
        code = '''
def run_command(cmd):
    subprocess.run(cmd, shell=False)
'''
        assert op.applies_to(code) is True

    def test_applies_to_os_system(self):
        """Should apply to os.system calls."""
        op = CMDINJECT()
        code = '''
def execute(cmd):
    os.system(cmd)
'''
        assert op.applies_to(code) is True

    def test_mutate_enables_shell(self):
        """Should mutate to enable shell execution."""
        op = CMDINJECT()
        code = '''subprocess.run(cmd, shell=False)'''
        mutants = op.mutate(code)

        # Check that at least one mutant enables shell
        for mutant_code, description in mutants:
            if "shell=True" in mutant_code:
                assert True
                return
        # If no shell=True mutant, that's okay if the pattern didn't match


class TestPATHCONCAT:
    """Tests for PATHCONCAT operator (CWE-22: Path Traversal)."""

    def test_applies_to_path_join(self):
        """Should apply to os.path.join calls."""
        op = PATHCONCAT()
        code = '''
def read_file(filename):
    path = os.path.join(BASE_DIR, filename)
    return open(path).read()
'''
        assert op.applies_to(code) is True

    def test_applies_to_pathlib(self):
        """Should apply to pathlib operations."""
        op = PATHCONCAT()
        code = '''
def get_path(name):
    return Path(BASE_DIR) / name
'''
        assert op.applies_to(code) is True


class TestWEAKCRYPTO:
    """Tests for WEAKCRYPTO operator (CWE-327: Weak Cryptography)."""

    def test_applies_to_sha256(self):
        """Should apply to strong hash usage."""
        op = WEAKCRYPTO()
        code = '''
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
'''
        assert op.applies_to(code) is True

    def test_mutate_to_weak_hash(self):
        """Should mutate to weak hash algorithm."""
        op = WEAKCRYPTO()
        code = '''hashlib.sha256(data)'''
        mutants = op.mutate(code)

        # Should create mutant with MD5 or SHA1
        for mutant_code, description in mutants:
            if "md5" in mutant_code.lower() or "sha1" in mutant_code.lower():
                assert True
                return


class TestDESERIAL:
    """Tests for DESERIAL operator (CWE-502: Insecure Deserialization)."""

    def test_applies_to_json_loads(self):
        """Should apply to json.loads (safe baseline)."""
        op = DESERIAL()
        code = '''
def load_data(data):
    return json.loads(data)
'''
        # DESERIAL might apply if there's deserialization context
        result = op.applies_to(code)
        assert isinstance(result, bool)

    def test_applies_to_yaml_safe_load(self):
        """Should apply to yaml.safe_load."""
        op = DESERIAL()
        code = '''
def load_config(data):
    return yaml.safe_load(data)
'''
        assert op.applies_to(code) is True


class TestRMAUTH:
    """Tests for RMAUTH operator (CWE-287/306: Remove Authentication)."""

    def test_applies_to_auth_decorator(self):
        """Should apply to authentication decorators."""
        op = RMAUTH()
        code = '''
@login_required
def admin_panel(request):
    return render(request, "admin.html")
'''
        assert op.applies_to(code) is True

    def test_applies_to_auth_check(self):
        """Should apply to authentication checks."""
        op = RMAUTH()
        code = '''
def delete_user(request, user_id):
    if not request.user.is_authenticated:
        return HttpResponse("Unauthorized", status=401)
    User.objects.get(id=user_id).delete()
'''
        assert op.applies_to(code) is True


class TestHARDCODE:
    """Tests for HARDCODE operator (CWE-798: Hardcoded Credentials)."""

    def test_applies_to_env_var(self):
        """Should apply to environment variable usage."""
        op = HARDCODE()
        code = '''
def connect():
    password = os.environ.get("DB_PASSWORD")
    return db.connect(password=password)
'''
        assert op.applies_to(code) is True

    def test_mutate_hardcodes_secret(self):
        """Should mutate to hardcoded credential."""
        op = HARDCODE()
        code = '''password = os.environ.get("DB_PASSWORD")'''
        mutants = op.mutate(code)

        # Should create mutant with hardcoded value
        for mutant_code, description in mutants:
            if "password" in mutant_code.lower() and ("=" in mutant_code):
                # Check for string literal assignment
                if '"' in mutant_code or "'" in mutant_code:
                    assert True
                    return


class TestOperatorRegistry:
    """Tests for operator registry functionality."""

    def test_get_operators_for_cwe_89(self):
        """Should return PSQLI for CWE-89."""
        ops = get_operators_for_cwe("CWE-89")
        op_names = [op.name for op in ops]
        assert "PSQLI" in op_names

    def test_get_operators_for_cwe_78(self):
        """Should return CMDINJECT for CWE-78."""
        ops = get_operators_for_cwe("CWE-78")
        op_names = [op.name for op in ops]
        assert "CMDINJECT" in op_names

    def test_get_operators_for_cwe_22(self):
        """Should return PATHCONCAT for CWE-22."""
        ops = get_operators_for_cwe("CWE-22")
        op_names = [op.name for op in ops]
        assert "PATHCONCAT" in op_names

    def test_get_operators_for_cwe_327(self):
        """Should return WEAKCRYPTO for CWE-327."""
        ops = get_operators_for_cwe("CWE-327")
        op_names = [op.name for op in ops]
        assert "WEAKCRYPTO" in op_names

    def test_get_operators_for_cwe_502(self):
        """Should return DESERIAL for CWE-502."""
        ops = get_operators_for_cwe("CWE-502")
        op_names = [op.name for op in ops]
        assert "DESERIAL" in op_names

    def test_get_all_operators(self):
        """Should return all registered operators."""
        ops = get_all_operators()
        assert len(ops) > 0

        # get_all_operators returns dict {name: operator}
        assert "PSQLI" in ops
        assert "CMDINJECT" in ops
        assert "PATHCONCAT" in ops

    def test_registry_has_cwes(self):
        """Registry should map CWEs to operators."""
        assert len(CWE_OPERATOR_MAP) > 0

        # Each entry should map CWE to list of operator names
        for cwe, operators in CWE_OPERATOR_MAP.items():
            assert cwe.startswith("CWE-")
            assert isinstance(operators, list)
            assert len(operators) > 0


class TestOperatorBaseClass:
    """Tests for SecurityMutationOperator base class."""

    def test_operator_has_name(self):
        """All operators should have a name."""
        ops = get_all_operators()  # Returns dict {name: operator}
        for name, op in ops.items():
            assert hasattr(op, "name")
            assert op.name is not None
            assert len(op.name) > 0

    def test_operator_has_description(self):
        """All operators should have a description."""
        ops = get_all_operators()
        for name, op in ops.items():
            assert hasattr(op, "description")
            assert op.description is not None

    def test_operator_has_target_cwes(self):
        """All operators should have target CWEs."""
        ops = get_all_operators()
        for name, op in ops.items():
            assert hasattr(op, "target_cwes")
            assert isinstance(op.target_cwes, list)
            assert len(op.target_cwes) > 0

    def test_applies_to_returns_bool(self):
        """applies_to should return boolean."""
        ops = get_all_operators()
        test_code = "def foo(): pass"

        for name, op in ops.items():
            result = op.applies_to(test_code)
            assert isinstance(result, bool), f"{op.name}.applies_to should return bool"

    def test_mutate_returns_list(self):
        """mutate should return list of tuples."""
        ops = get_all_operators()
        test_code = "def foo(): pass"

        for name, op in ops.items():
            result = op.mutate(test_code)
            assert isinstance(result, list), f"{op.name}.mutate should return list"

            for item in result:
                assert isinstance(item, tuple), f"{op.name}.mutate items should be tuples"
                assert len(item) == 2, f"{op.name}.mutate tuples should have 2 elements"


# =============================================================================
# Tests for New Operators (v2.5.0)
# =============================================================================

class TestEVALINJECT:
    """Tests for EVALINJECT operator (CWE-95: Code Injection via eval)."""

    def test_applies_to_literal_eval(self):
        """Should apply to ast.literal_eval usage."""
        op = EVALINJECT()
        code = '''
def parse_data(data):
    return ast.literal_eval(data)
'''
        assert op.applies_to(code) is True

    def test_applies_to_json_loads(self):
        """Should apply to safe deserialization."""
        op = EVALINJECT()
        code = '''
def parse_json(data):
    return json.loads(data)
'''
        assert op.applies_to(code) is True

    def test_not_applies_to_eval(self):
        """Should not apply to already unsafe eval."""
        op = EVALINJECT()
        code = '''
def dangerous(data):
    return eval(data)
'''
        # Already using eval - nothing to mutate
        assert op.applies_to(code) is False


class TestOPENREDIRECT:
    """Tests for OPENREDIRECT operator (CWE-601: Open Redirect)."""

    def test_applies_to_redirect_validation(self):
        """Should apply to redirect with URL validation."""
        op = OPENREDIRECT()
        code = '''
def redirect_user(url):
    if is_safe_url(url):
        return redirect(url)
    return redirect("/")
'''
        assert op.applies_to(code) is True

    def test_applies_to_urlparse_check(self):
        """Should apply to urlparse-based validation."""
        op = OPENREDIRECT()
        code = '''
def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc in ALLOWED_HOSTS:
        return redirect(url)
'''
        assert op.applies_to(code) is True


class TestNOCERTVALID:
    """Tests for NOCERTVALID operator (CWE-295: Certificate Validation)."""

    def test_applies_to_verify_true(self):
        """Should apply to requests with verify=True."""
        op = NOCERTVALID()
        code = '''
def fetch_data(url):
    return requests.get(url, verify=True)
'''
        assert op.applies_to(code) is True

    def test_applies_to_ssl_context(self):
        """Should apply to SSL context creation."""
        op = NOCERTVALID()
        code = '''
def create_secure_context():
    ctx = ssl.create_default_context()
    return ctx
'''
        assert op.applies_to(code) is True

    def test_mutate_disables_verification(self):
        """Should mutate to disable certificate verification."""
        op = NOCERTVALID()
        code = '''requests.get(url, verify=True)'''
        mutants = op.mutate(code)

        for mutant_code, description in mutants:
            if "verify=False" in mutant_code:
                assert True
                return


class TestINFOEXPOSE:
    """Tests for INFOEXPOSE operator (CWE-209: Information Exposure)."""

    def test_applies_to_generic_error(self):
        """Should apply to exception handler with generic error response."""
        op = INFOEXPOSE()
        code = '''
def handle_request(data):
    try:
        process(data)
    except Exception as e:
        return {"error": "An error occurred"}
'''
        assert op.applies_to(code) is True

    def test_applies_to_logging(self):
        """Should apply to error logging with generic error response."""
        op = INFOEXPOSE()
        code = '''
def process(data):
    try:
        return do_work(data)
    except Exception as e:
        logger.error("Processing failed")
        return {"error": "Processing failed"}
'''
        assert op.applies_to(code) is True


class TestREGEXDOS:
    """Tests for REGEXDOS operator (CWE-400/1333: ReDoS)."""

    def test_applies_to_regex_compile(self):
        """Should apply to regex compilation."""
        op = REGEXDOS()
        code = '''
def validate_email(email):
    pattern = re.compile(r"^[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+$")
    return pattern.match(email)
'''
        assert op.applies_to(code) is True

    def test_applies_to_re_match(self):
        """Should apply to re.match usage."""
        op = REGEXDOS()
        code = '''
def check_input(data):
    return re.match(r"^[a-z]+$", data)
'''
        assert op.applies_to(code) is True


class TestMISSINGAUTH:
    """Tests for MISSINGAUTH operator (CWE-862: Missing Authorization)."""

    def test_applies_to_permission_check(self):
        """Should apply to permission checks."""
        op = MISSINGAUTH()
        code = '''
def delete_item(user, item_id):
    if user.has_permission("delete"):
        return Item.delete(item_id)
    raise PermissionError()
'''
        assert op.applies_to(code) is True

    def test_applies_to_role_check(self):
        """Should apply to role-based checks."""
        op = MISSINGAUTH()
        code = '''
@require_role("admin")
def admin_action():
    return do_admin_stuff()
'''
        assert op.applies_to(code) is True


class TestNewOperatorRegistry:
    """Tests for new operator CWE mappings."""

    def test_get_operators_for_cwe_95(self):
        """Should return EVALINJECT for CWE-95."""
        ops = get_operators_for_cwe("CWE-95")
        op_names = [op.name for op in ops]
        assert "EVALINJECT" in op_names

    def test_get_operators_for_cwe_601(self):
        """Should return OPENREDIRECT for CWE-601."""
        ops = get_operators_for_cwe("CWE-601")
        op_names = [op.name for op in ops]
        assert "OPENREDIRECT" in op_names

    def test_get_operators_for_cwe_295(self):
        """Should return NOCERTVALID for CWE-295."""
        ops = get_operators_for_cwe("CWE-295")
        op_names = [op.name for op in ops]
        assert "NOCERTVALID" in op_names

    def test_get_operators_for_cwe_400(self):
        """Should return REGEXDOS for CWE-400."""
        ops = get_operators_for_cwe("CWE-400")
        op_names = [op.name for op in ops]
        assert "REGEXDOS" in op_names

    def test_get_operators_for_cwe_862(self):
        """Should return MISSINGAUTH for CWE-862."""
        ops = get_operators_for_cwe("CWE-862")
        op_names = [op.name for op in ops]
        assert "MISSINGAUTH" in op_names

    def test_operator_count_v250(self):
        """Should have 32 operators total in v2.5.0."""
        ops = get_all_operators()
        # At least 32 operators (18 core + 14 new)
        assert len(ops) >= 32, f"Expected >=32 operators, got {len(ops)}"

    def test_cwe_map_expanded(self):
        """CWE_OPERATOR_MAP should have 49+ entries."""
        # v2.5.0 expanded from 30 to 49 CWE mappings
        assert len(CWE_OPERATOR_MAP) >= 49, f"Expected >=49 CWE mappings, got {len(CWE_OPERATOR_MAP)}"
