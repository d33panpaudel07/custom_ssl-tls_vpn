"""
Session lifecycle management for active VPN client connections.

Every accepted TLS connection is immediately registered as a ``Session``
and tracked by the ``SessionManager`` singleton.  Sessions advance through
three states:

1. **Pre-auth** — socket accepted, AUTH message not yet received.
2. **Authenticated** — ``authenticate_session`` called; username is known.
3. **Relaying** — ``TunnelRelay`` is running; ``touch_session`` is called
   on each forwarded packet.

A background daemon thread (``_expiry_loop``) scans for idle sessions every
60 seconds and removes them, closing their sockets.  On server shutdown,
``force_expire_all`` immediately tears down every remaining session before the
process exits.
"""

import threading
import socket
import uuid
import time
import ssl
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any

from custom_ssl_vpn.server.logger import get_logger
from custom_ssl_vpn.shared.exceptions import SessionError

__all__ = ["Session", "SessionManager"]


@dataclass
class Session:
    """Runtime state for a single active VPN client connection.

    Instances are created by ``SessionManager.create_session`` and
    remain alive until torn down by ``remove_session``, ``force_expire_all``,
    or the background ``_expiry_loop``.

    Attributes:
        session_id: UUID-4 string uniquely identifying this session.
        client_ip: Dotted-decimal source IP of the connecting client.
        client_port: Ephemeral TCP source port of the connecting client.
        created_at: Timestamp when the session was first registered.
        last_active: Timestamp of the most recent ``touch_session`` call.
            Updated on every forwarded packet.
        username: Authenticated username.  Empty string before AUTH completes.
        is_authenticated: ``True`` once ``authenticate_session`` has been called.
        bytes_up: Total bytes forwarded from client to the internal service.
            Updated by ``TunnelRelay._cleanup``.
        bytes_down: Total bytes forwarded from the internal service to the client.
            Updated by ``TunnelRelay._cleanup``.
        tls_socket: Live ``ssl.SSLSocket``.  ``None`` after teardown.  Excluded
            from ``repr`` to avoid accidentally printing socket descriptors.
    """

    session_id: str
    client_ip: str
    client_port: int
    created_at: datetime
    last_active: datetime
    username: str = ""
    is_authenticated: bool = field(default=False)
    bytes_up: int = field(default=0)
    bytes_down: int = field(default=0)
    tls_socket: Optional[ssl.SSLSocket] = field(default=None, repr=False)

    def is_expired(self, timeout_seconds: int) -> bool:
        """Return ``True`` if this session has been idle longer than *timeout_seconds*.

        Computed from the wall-clock difference between ``datetime.now()`` and
        ``last_active``.  Used by the background ``_expiry_loop`` sweeper.

        Args:
            timeout_seconds: Maximum allowed idle duration in seconds.  Should
                match ``ServerConfig.SESSION_TIMEOUT_SECONDS``.

        Returns:
            ``True`` if the session has been inactive longer than the threshold,
            ``False`` otherwise.

        Example:
            >>> from datetime import datetime, timedelta
            >>> s = Session(
            ...     session_id="", client_ip="", client_port=0,
            ...     created_at=datetime.now(),
            ...     last_active=datetime.now() - timedelta(hours=2),
            ... )
            >>> s.is_expired(timeout_seconds=3600)
            True
        """
        # Centralizes the expiration business logic into the data model
        delta = (datetime.now() - self.last_active).total_seconds()
        return delta > timeout_seconds


class _ReentrantSessionLock:
    """Context manager that holds ``SessionManager``'s ``RLock`` for the duration of a block.

    Returned by ``SessionManager.lock()`` so that callers outside the class can
    perform multi-step reads atomically without directly accessing the private
    ``_rlock`` attribute.

    Example:
        >>> with session_manager.lock():
        ...     sessions = session_manager.list_sessions()
        ...     count = session_manager.get_active_count()
    """

    def __init__(self, rlock: threading.RLock) -> None:
        self._rlock = rlock

    def __enter__(self) -> None:
        self._rlock.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._rlock.release()


class SessionManager:
    """
    Manager responsible for tracking and lifecycle events of client sessions.

    Manages max connection limits, tracks timing metadata, and runs a detached
    background sweeper to silently close disconnected or timed out tunnels.
    """

    def __init__(self, max_clients: int, session_timeout_seconds: int) -> None:
        """
        Initializes the session manager storage and starts the background reaper.

        Args:
            max_clients (int): The absolute maximum concurrent sessions allowed.
            session_timeout_seconds (int): Idle duration after which a session expires.
        """
        self._max_clients = max_clients
        self._session_timeout_seconds = session_timeout_seconds

        # Concurrent active session map
        self._sessions: Dict[str, Session] = {}

        # Ensures atomic state mutations via Reentrant Lock
        self._rlock = threading.RLock()

        self._logger = get_logger("SessionManager")
        self._running = True

        # Daemon thread to regularly reap abandoned sessions
        self._reaper_thread = threading.Thread(
            target=self._expiry_loop, daemon=True, name="SessionReaper"
        )
        self._reaper_thread.start()

    def lock(self) -> _ReentrantSessionLock:
        """
        Returns a context manager to explicitly hold the manager's lock.
        Useful when iterating over sessions atomically outside this class.

        Returns:
            _ReentrantSessionLock: Context manager instance.
        """
        return _ReentrantSessionLock(self._rlock)

    def create_session(
        self, client_ip: str, client_port: int, tls_socket: ssl.SSLSocket
    ) -> Session:
        """
        Registers a new unauthenticated active session for an incoming connection.

        Args:
            client_ip (str): The IP address of the connected client.
            client_port (int): The source port of the client.
            tls_socket (ssl.SSLSocket): The active secure socket.

        Returns:
            Session: The initialized session object.

        Raises:
            SessionError: If the maximum client capacity has already been reached.
        """
        with self._rlock:
            if len(self._sessions) >= self._max_clients:
                self._logger.log_security_event(
                    "MAX_CLIENTS_REACHED", {"attempt_ip": client_ip}
                )
                raise SessionError(
                    f"Server at maximum capacity ({self._max_clients} clients)."
                )

            session_id = str(uuid.uuid4())
            now = datetime.now()

            session = Session(
                session_id=session_id,
                client_ip=client_ip,
                client_port=client_port,
                created_at=now,
                last_active=now,
                tls_socket=tls_socket,
            )

            self._sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieves active session details by session ID.

        Args:
            session_id (str): The unique identifier of the target session.

        Returns:
            Optional[Session]: The session reference if found, else None.
        """
        with self._rlock:
            return self._sessions.get(session_id)

    def authenticate_session(self, session_id: str, username: str) -> None:
        """
        Promotes an unauthenticated session into a trusted, fully authenticated state.

        Args:
            session_id (str): The target session ID.
            username (str): The username successfully validated for this session.

        Raises:
            SessionError: If the session ID does not exist.
        """
        with self._rlock:
            session = self._sessions.get(session_id)
            if not session:
                raise SessionError(f"Cannot authenticate unknown session {session_id}.")

            session.username = username
            session.is_authenticated = True
            session.last_active = datetime.now()

    def touch_session(self, session_id: str) -> None:
        """
        Updates the session's last active timer to prevent timeout expiration.

        Args:
            session_id (str): The target session ID.
        """
        with self._rlock:
            session = self._sessions.get(session_id)
            if session:
                session.last_active = datetime.now()

    def remove_session(self, session_id: str) -> None:
        """
        Ends an active session, closes its socket, and removes it from state tracking.

        Args:
            session_id (str): The unique identifier of the session to terminate.
        """
        with self._rlock:
            session = self._sessions.pop(session_id, None)
            if session:
                self._close_socket(session)
                self._logger.log_disconnect(session_id, "Session explicitly removed.")

    def get_active_count(self) -> int:
        """
        Gets the current number of tracked sessions (both authenticated and pending).

        Returns:
            int: Total sessions.
        """
        with self._rlock:
            return len(self._sessions)

    def list_sessions(self) -> List[Session]:
        """
        Retrieves a shallow snapshot list of all currently tracked sessions.

        Returns:
            List[Session]: List of session instances.
        """
        with self._rlock:
            return list(self._sessions.values())

    def _close_socket(self, session: Session) -> None:
        """Gracefully shut down and close the TLS socket attached to *session*.

        Suppresses ``OSError`` from ``shutdown()`` in case the peer has already
        dropped the connection.  Sets ``session.tls_socket`` to ``None`` after
        closing so subsequent calls are no-ops.

        Args:
            session: The session whose socket should be closed.
        """
        if session.tls_socket:
            try:
                # SSLSocket suppressive shutdown to avoid EOF exceptions
                # inside the tunnel stream if the peer already dropped.
                session.tls_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            finally:
                try:
                    session.tls_socket.close()
                except Exception:
                    pass
                session.tls_socket = None

    def _expiry_loop(self) -> None:
        """
        Background maintenance loop that sweeps for and terminates timed-out sessions.
        Runs every 60 seconds until shutdown.
        """
        while self._running:
            time.sleep(60)
            now = datetime.now()
            expired_ids = []

            with self._rlock:
                for session_id, session in self._sessions.items():
                    if session.is_expired(self._session_timeout_seconds):
                        expired_ids.append(session_id)

                for session_id in expired_ids:
                    session = self._sessions.pop(session_id)
                    self._close_socket(session)
                    self._logger.log_disconnect(session_id, "Session timeout expired.")

    def shutdown(self) -> None:
        """Stop the background reaper thread and immediately close all active sessions.

        Sets ``_running = False`` so the reaper loop exits on its next
        iteration, calls ``force_expire_all`` to close sockets synchronously,
        then joins the thread with a 1-second timeout.

        This is the correct teardown entry point; calling ``force_expire_all``
        directly skips the reaper-thread cleanup.
        """
        self._running = False
        self.force_expire_all()

        if self._reaper_thread.is_alive():
            # Wait briefly for thread to detect shutdown flag if waking,
            # though it's a daemon thread so it will die automatically with main anyway.
            self._reaper_thread.join(timeout=1.0)

    def force_expire_all(self) -> None:
        """Immediately close every tracked session without waiting for the reaper.

        Acquires the ``_rlock``, closes every socket, and clears the internal
        session dictionary.  Called by ``shutdown()`` during server teardown.

        Security note:
            This method does NOT attempt a graceful TLS ``close_notify``
            because the server is shutting down.  Peers will receive a TCP RST
            or EOF.  This is expected and acceptable during server shutdown.
        """
        with self._rlock:
            for session_id, session in list(self._sessions.items()):
                self._close_socket(session)
            self._sessions.clear()
