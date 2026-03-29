"""
Unit tests for server/security.py.

Verifies that the SecurityPolicy correctly blocks hostile IPs,
respects temporal expiry durations, and lifts bans on demand.
"""

import sys
import os
import time
import unittest
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _make_policy():
    """Factory creating a SecurityPolicy with a mocked logger to suppress file I/O."""
    with patch("custom_ssl_vpn.server.security.get_logger") as mock_get_logger:
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        from custom_ssl_vpn.server.security import SecurityPolicy
        policy = SecurityPolicy()
        policy._logger = mock_logger
        return policy


class TestPermanentBlocking(unittest.TestCase):

    def test_blocked_ip_is_rejected(self):
        """An IP added to the permanent blocklist is flagged as blocked instantly."""
        policy = _make_policy()
        policy.block_ip("1.2.3.4", reason="Test block", duration_seconds=0)
        self.assertTrue(policy.is_blocked("1.2.3.4"))

    def test_unblocked_ip_is_allowed(self):
        """An IP not present in any blocklist is not flagged as blocked."""
        policy = _make_policy()
        self.assertFalse(policy.is_blocked("9.9.9.9"))

    def test_unblock_works(self):
        """Calling unblock_ip removes the IP from the permanent blocklist."""
        policy = _make_policy()
        policy.block_ip("5.6.7.8", reason="Permanent test", duration_seconds=0)
        self.assertTrue(policy.is_blocked("5.6.7.8"))

        policy.unblock_ip("5.6.7.8")
        self.assertFalse(policy.is_blocked("5.6.7.8"))

    def test_permanent_beats_temporary(self):
        """Permanently blocking an IP that had a temporal block keeps it permanently blocked."""
        policy = _make_policy()
        # Add temp block first with very short duration
        policy.block_ip("2.3.4.5", reason="temp", duration_seconds=1)
        # Upgrade to permanent
        policy.block_ip("2.3.4.5", reason="permanent upgrade", duration_seconds=0)

        # Even after the temp would have expired, it should remain blocked
        self.assertTrue(policy.is_blocked("2.3.4.5"))
        # And it should NOT appear in temporal blocks (permanent took precedence)
        self.assertNotIn("2.3.4.5", policy._temporal_blocks)


class TestTemporalBlocking(unittest.TestCase):

    def test_temporary_block_is_active_immediately(self):
        """An IP with a temporal block is recognised as blocked right after block_ip()."""
        policy = _make_policy()
        policy.block_ip("10.10.10.10", reason="Temp test", duration_seconds=60)
        self.assertTrue(policy.is_blocked("10.10.10.10"))

    def test_block_expires_after_duration(self):
        """A temporal block with a 1-second duration is lifted after expiry."""
        policy = _make_policy()
        policy.block_ip("11.11.11.11", reason="Short block", duration_seconds=1)
        self.assertTrue(policy.is_blocked("11.11.11.11"))

        time.sleep(1.1)  # Wait for the block to expire
        self.assertFalse(policy.is_blocked("11.11.11.11"))

    def test_unblock_clears_temporal_block(self):
        """Calling unblock_ip also removes an active temporal block."""
        policy = _make_policy()
        policy.block_ip("12.12.12.12", reason="Temp", duration_seconds=300)
        self.assertTrue(policy.is_blocked("12.12.12.12"))

        policy.unblock_ip("12.12.12.12")
        self.assertFalse(policy.is_blocked("12.12.12.12"))

    def test_multiple_ips_blocked_independently(self):
        """Blocking one IP does not affect the status of other IPs."""
        policy = _make_policy()
        policy.block_ip("20.0.0.1", reason="Blocked", duration_seconds=0)
        self.assertTrue(policy.is_blocked("20.0.0.1"))
        self.assertFalse(policy.is_blocked("20.0.0.2"))
        self.assertFalse(policy.is_blocked("20.0.0.3"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
