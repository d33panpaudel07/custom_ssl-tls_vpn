"""
Test runner that auto-discovers and executes all tests in the tests/ package.

Run from the project root:
    python -m custom_ssl_vpn.tests.run_all
    
Or from this directory:
    python run_all.py
"""

import sys
import os
import unittest

# Guarantee the project root is resolvable as a top-level package
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

_TESTS_DIR = os.path.dirname(__file__)


def suite() -> unittest.TestSuite:
    """Discover and collect all test cases under the tests/ directory."""
    loader = unittest.TestLoader()
    return loader.discover(
        start_dir=_TESTS_DIR,
        pattern="test_*.py",
        top_level_dir=_PROJECT_ROOT
    )


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stderr)
    result = runner.run(suite())
    sys.exit(0 if result.wasSuccessful() else 1)
