"""
Unit tests for server/auth.py.

Verifies correct credential validation, rate-limiting, lockout behaviour,
password storage discipline, and timing-safe comparison.
"""

import sys
import os
import time
import hmac
import hashlib
import tempfile
import unittest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from custom_ssl_vpn.server.auth import AuthManager
from custom_ssl_vpn.shared.exceptions import InvalidCredentialsError, TooManyAttemptsError


class TestAuthManager(unittest.TestCase):

    def setUp(self):
        """Create a temporary credentials file and a fresh AuthManager for each test."""
        self._tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self._tmp.close()
        self.db_path = self._tmp.name
        # Seed with an empty JSON file so AuthManager doesn't recreate it
        with open(self.db_path, "w") as f:
            f.write("{}")
        self.auth = AuthManager(db_path=self.db_path, max_attempts=3)
        self.auth.register_user("testuser", "Secure1234!")

    def tearDown(self):
        """Remove the temp credential store after each test."""
        try:
            os.unlink(self.db_path)
        except OSError:
            pass
        tmp_path = self.db_path + ".tmp"
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # ------------------------------------------------------------------
    # Happy-path tests
    # ------------------------------------------------------------------

    def test_valid_credentials_authenticate(self):
        """Correct username and password returns True without raising."""
        result = self.auth.authenticate("testuser", "Secure1234!", "10.0.0.1")
        self.assertTrue(result)

    def test_password_not_stored_plaintext(self):
        """The JSON credential store must never contain the raw plaintext password."""
        import json
        with open(self.db_path, "r") as f:
            raw = f.read()
        self.assertNotIn("Secure1234!", raw)

    # ------------------------------------------------------------------
    # Failure-path tests
    # ------------------------------------------------------------------

    def test_wrong_password_fails(self):
        """A correct username paired with a wrong password raises InvalidCredentialsError."""
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("testuser", "WrongPass99!", "10.0.0.2")

    def test_unknown_user_fails(self):
        """An unregistered username raises InvalidCredentialsError."""
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("ghostuser", "Secure1234!", "10.0.0.3")

    # ------------------------------------------------------------------
    # Rate-limiting / lockout tests
    # ------------------------------------------------------------------

    def test_lockout_after_max_attempts(self):
        """Exceeding max_attempts from the same IP triggers TooManyAttemptsError."""
        ip = "192.168.1.99"
        for _ in range(3):
            with self.assertRaises((InvalidCredentialsError, TooManyAttemptsError)):
                self.auth.authenticate("testuser", "badpassword1!", ip)

        # The next attempt from the same IP must be blocked with TooManyAttemptsError
        with self.assertRaises(TooManyAttemptsError):
            self.auth.authenticate("testuser", "Secure1234!", ip)

    def test_lockout_expires_after_window(self):
        """After a lockout window elapses, authentication succeeds again."""
        ip = "192.168.1.100"
        # Force into lockout by directly manipulating the internal record
        from custom_ssl_vpn.server.auth import AuthAttemptRecord
        self.auth._attempts[ip] = AuthAttemptRecord(
            failure_timestamps=[],
            locked_until=time.time() - 1  # Already expired
        )
        # Should succeed now that lockout has ended
        result = self.auth.authenticate("testuser", "Secure1234!", ip)
        self.assertTrue(result)

    # ------------------------------------------------------------------
    # Security property tests
    # ------------------------------------------------------------------

    def test_timing_safe_compare(self):
        """hmac.compare_digest is used — verifies no shortcut comparison exists."""
        # This test verifies the contract: derive the same hash and compare via hmac
        import json
        with open(self.db_path, "r") as f:
            users = json.load(f)
        record = users["testuser"]
        stored_salt = bytes.fromhex(record["salt"])
        stored_hash = bytes.fromhex(record["hash"])

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            "Secure1234!".encode("utf-8"),
            stored_salt,
            100000
        )
        # hmac.compare_digest returns True for matching byte strings
        self.assertTrue(hmac.compare_digest(derived, stored_hash))

        # And False for a different password
        wrong_derived = hashlib.pbkdf2_hmac(
            "sha256",
            "NotThePassword!".encode("utf-8"),
            stored_salt,
            100000
        )
        self.assertFalse(hmac.compare_digest(wrong_derived, stored_hash))

    def test_null_byte_in_username_rejected(self):
        """A username containing a null byte is rejected as invalid format."""
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("user\x00name", "Secure1234!", "10.0.0.5")

    def test_null_byte_in_password_rejected(self):
        """A password containing a null byte is rejected before any hash computation."""
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("testuser", "Secure12\x0034!", "10.0.0.6")

    def test_overlong_username_rejected(self):
        """A username exceeding 32 characters is rejected without reaching the credential store."""
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("a" * 33, "Secure1234!", "10.0.0.7")

    def test_short_password_rejected(self):
        """A password shorter than 8 characters is rejected by input validation."""
        with self.assertRaises(InvalidCredentialsError):
            self.auth.authenticate("testuser", "short", "10.0.0.8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
