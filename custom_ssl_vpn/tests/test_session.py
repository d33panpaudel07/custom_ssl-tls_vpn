"""
Unit tests for server/session.py.

Verifies session creation UUIDs, expiry logic, max-client enforcement,
and thread-safety under concurrent session registrations.
"""

import sys
import os
import time
import uuid
import threading
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _make_manager(max_clients: int = 10, timeout: int = 3600):
    """Factory that creates a SessionManager with a mocked logger to avoid file I/O."""
    with patch("custom_ssl_vpn.server.session.get_logger") as mock_get_logger:
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        from custom_ssl_vpn.server.session import SessionManager
        manager = SessionManager(max_clients=max_clients, session_timeout_seconds=timeout)
        # Patch the logger on the instance so subsequent calls are silent
        manager._logger = mock_logger
        return manager


def _fake_ssl_socket():
    """Returns a MagicMock that behaves like ssl.SSLSocket sufficiently for tests."""
    sock = MagicMock()
    return sock


class TestSessionCreation(unittest.TestCase):

    def test_create_session_returns_uuid(self):
        """A new session is assigned a valid UUID4 string as its session_id."""
        manager = _make_manager()
        session = manager.create_session("10.0.0.1", 55000, _fake_ssl_socket())
        # Should parse as a valid UUID without raising
        parsed = uuid.UUID(session.session_id)
        self.assertEqual(parsed.version, 4)

    def test_get_nonexistent_session_returns_none(self):
        """Requesting a session ID that was never created returns None."""
        manager = _make_manager()
        result = manager.get_session("00000000-0000-0000-0000-000000000000")
        self.assertIsNone(result)

    def test_get_existing_session_returns_session(self):
        """A session retrieved by its ID is the same object that was created."""
        manager = _make_manager()
        created = manager.create_session("10.0.0.2", 55001, _fake_ssl_socket())
        fetched = manager.get_session(created.session_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.session_id, created.session_id)

    def test_active_count_increments(self):
        """The active session count reflects the number of created sessions."""
        manager = _make_manager()
        self.assertEqual(manager.get_active_count(), 0)
        manager.create_session("10.0.0.3", 55002, _fake_ssl_socket())
        self.assertEqual(manager.get_active_count(), 1)
        manager.create_session("10.0.0.4", 55003, _fake_ssl_socket())
        self.assertEqual(manager.get_active_count(), 2)


class TestSessionExpiry(unittest.TestCase):

    def test_session_expires_correctly(self):
        """A session whose last_active is older than timeout is detected as expired."""
        from custom_ssl_vpn.server.session import Session

        # Build a session with an old last_active timestamp
        old_time = datetime.now() - timedelta(seconds=3700)
        session = Session(
            session_id=str(uuid.uuid4()),
            client_ip="10.0.0.5",
            client_port=55004,
            created_at=old_time,
            last_active=old_time
        )
        self.assertTrue(session.is_expired(timeout_seconds=3600))

    def test_fresh_session_not_expired(self):
        """A recently created session is not flagged as expired."""
        from custom_ssl_vpn.server.session import Session

        session = Session(
            session_id=str(uuid.uuid4()),
            client_ip="10.0.0.6",
            client_port=55005,
            created_at=datetime.now(),
            last_active=datetime.now()
        )
        self.assertFalse(session.is_expired(timeout_seconds=3600))


class TestCapacityEnforcement(unittest.TestCase):

    def test_max_sessions_raises_error(self):
        """Creating a session beyond the max_clients limit raises SessionError."""
        from custom_ssl_vpn.server.session import SessionManager

        session_limit = 2
        manager = _make_manager(max_clients=session_limit)

        # Fill to capacity
        for i in range(session_limit):
            manager.create_session(f"10.0.{i}.1", 55000 + i, _fake_ssl_socket())

        # The next one must raise some kind of error (our SessionError or builtin SessionError)
        with self.assertRaises(Exception):
            manager.create_session("10.1.0.1", 56000, _fake_ssl_socket())

    def test_remove_session_frees_slot(self):
        """Removing a session allows a new one to be created at the limit boundary."""
        manager = _make_manager(max_clients=1)
        first = manager.create_session("10.0.0.10", 55000, _fake_ssl_socket())
        manager.remove_session(first.session_id)
        # Should not raise since we freed a slot
        second = manager.create_session("10.0.0.11", 55001, _fake_ssl_socket())
        self.assertIsNotNone(second)


class TestThreadSafety(unittest.TestCase):

    def test_thread_safety(self):
        """50 concurrent threads creating sessions all succeed without data corruption."""
        manager = _make_manager(max_clients=60)
        errors = []
        sessions_created = []
        lock = threading.Lock()

        def create():
            try:
                session = manager.create_session("10.0.1.1", 55000, _fake_ssl_socket())
                with lock:
                    sessions_created.append(session.session_id)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=create) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Unexpected errors: {errors}")
        self.assertEqual(len(sessions_created), 50)
        # All session_ids must be unique
        self.assertEqual(len(set(sessions_created)), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
