"""
Version tracking for SecMutBench

Provides version information for reproducibility and compatibility checking.
"""

import sys
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Core versions
__version__ = "2.5.0"
__benchmark_version__ = "v2.5"  # Dataset version (24 viable CWEs, 32 operators, 49 CWE mappings)
__schema_version__ = "2.1"      # Sample schema version (added mock_security_access)

# Minimum required versions of key dependencies
REQUIRED_VERSIONS = {
    "python": "3.8",
    "anthropic": "0.20.0",
    "openai": "1.0.0",
}


def get_installed_packages() -> Dict[str, str]:
    """
    Get versions of key dependencies.

    Returns:
        Dictionary mapping package names to their versions
    """
    packages = [
        "anthropic",
        "openai",
        "pytest",
        "coverage",
        "requests",
        "numpy",
    ]

    installed = {}

    try:
        import importlib.metadata as metadata
        for pkg in packages:
            try:
                installed[pkg] = metadata.version(pkg)
            except metadata.PackageNotFoundError:
                pass
    except ImportError:
        # Fallback for older Python
        try:
            import pkg_resources
            for pkg in packages:
                try:
                    installed[pkg] = pkg_resources.get_distribution(pkg).version
                except pkg_resources.DistributionNotFound:
                    pass
        except ImportError:
            pass

    return installed


def get_environment_info() -> Dict[str, str]:
    """
    Get environment information for reproducibility.

    Returns:
        Dictionary with environment details
    """
    return {
        "python_version": sys.version,
        "python_version_info": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": sys.platform,
        "cwd": os.getcwd(),
    }


def get_version_info() -> Dict:
    """
    Get complete version information for result files.

    Returns:
        Dictionary with all version and environment info
    """
    return {
        "secmutbench_version": __version__,
        "benchmark_version": __benchmark_version__,
        "schema_version": __schema_version__,
        "timestamp": datetime.now().isoformat(),
        "environment": get_environment_info(),
        "dependencies": get_installed_packages(),
    }


def check_compatibility() -> Tuple[bool, List[str]]:
    """
    Check if the current environment meets requirements.

    Returns:
        Tuple of (is_compatible, list of issues)
    """
    issues = []

    # Check Python version
    if sys.version_info < (3, 8):
        issues.append(f"Python 3.8+ required, found {sys.version_info.major}.{sys.version_info.minor}")

    # Check key dependencies exist
    installed = get_installed_packages()

    for pkg in ["anthropic", "openai"]:
        if pkg not in installed:
            issues.append(f"Missing optional dependency: {pkg}")

    return len(issues) == 0, issues


def format_version_string() -> str:
    """
    Format version info as a string for display.

    Returns:
        Formatted version string
    """
    info = get_version_info()
    deps = info["dependencies"]

    lines = [
        f"SecMutBench v{__version__}",
        f"Benchmark: {__benchmark_version__}",
        f"Python: {info['environment']['python_version_info']}",
        f"Dependencies: {', '.join(f'{k}={v}' for k, v in deps.items())}",
    ]

    return "\n".join(lines)


# Export
__all__ = [
    "__version__",
    "__benchmark_version__",
    "__schema_version__",
    "get_installed_packages",
    "get_environment_info",
    "get_version_info",
    "check_compatibility",
    "format_version_string",
]
