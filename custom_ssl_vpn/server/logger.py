"""
Structured, JSON-formatted logging for the VPN server.

Every log record is serialised as a single JSON object (NDJSON / JSON-Lines)
containing ``timestamp``, ``level``, ``event``, and ``data`` keys.  This
format can be consumed directly by log aggregators such as Elasticsearch,
Splunk, or a simple ``grep | jq`` pipeline.

Design decisions:

* **No ``print()`` calls** — everything goes through ``VPNLogger``.
* **Sanitisation before write** — any dict key matching ``password``,
  ``secret``, ``key``, or ``token`` is replaced with ``"[REDACTED]"``
  before the record is written to disk or stderr.
* **Thread safety** — a ``threading.Lock`` serialises counter mutations.
* **Singleton pattern** — ``setup_logger`` creates the global instance and
  ``get_logger`` retrieves it from any module without re-importing the object.
"""

import logging
import json
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, List

__all__ = ["VPNLogger", "setup_logger", "get_logger"]


class JSONFormatter(logging.Formatter):
    """
    Custom logging formatter that outputs records as JSON lines.
    Includes time, severity, the main event message, and arbitrarily
    attached secure context data.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Serialise a log record to a single-line JSON string.

        Args:
            record: Standard library ``LogRecord`` object.  If the record
                carries an extra ``data`` attribute (attached via
                ``extra={"data": {...}}``), it is included in the output.

        Returns:
            A JSON string with keys ``timestamp``, ``level``, ``event``,
            and ``data``.  Guaranteed to contain no embedded newlines.
        """
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "event": record.getMessage(),
        }

        if hasattr(record, "data"):
            log_data["data"] = getattr(record, "data")
        else:
            log_data["data"] = {}

        return json.dumps(log_data)


def sanitize(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively scrub sensitive values from a dict before it is logged.

    Walks the entire *data* dict (including nested dicts) and replaces the
    value of any key that contains the substrings ``"password"``,
    ``"secret"``, ``"key"``, or ``"token"`` (case-insensitive) with the
    literal string ``"[REDACTED]"``.

    Args:
        data: The dictionary to sanitise.  Nested dicts are processed
            recursively; non-dict values that are not under a sensitive key
            are passed through unchanged.

    Returns:
        A new dictionary (the input is not modified in-place) with all
        sensitive fields replaced by ``"[REDACTED]"``.

    Security note:
        Call this on every ``data`` dict before passing it to any logging
        method.  The ``VPNLogger._log`` helper does this automatically;
        call ``sanitize`` explicitly only when building structured output
        outside of ``VPNLogger``.

    Example:
        >>> sanitize({"username": "alice", "password": "s3cr3t"})
        {'username': 'alice', 'password': '[REDACTED]'}
        >>> sanitize({"nested": {"api_token": "abc123"}})
        {'nested': {'api_token': '[REDACTED]'}}
    """
    redacted = {}
    sensitive_substrings = ["password", "secret", "key", "token"]

    for k, v in data.items():
        is_sensitive = any(sub in k.lower() for sub in sensitive_substrings)

        if is_sensitive:
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = sanitize(v)
        else:
            redacted[k] = v

    return redacted


class VPNLogger:
    """
    Thread-safe structured logger for the VPN server.
    Wraps the standard logging module to enforce JSON formatting,
    data sanitization, and basic operational metric tracking.
    """

    def __init__(
        self, name: str, log_file: str, level: str = "INFO", log_to_stderr: bool = False
    ) -> None:
        """
        Initializes the logger and backing metrics.

        Args:
            name (str): Name of the underlying python logger representation.
            log_file (str): Path to output the log messages.
            level (str): Minimum severity level to log.
            log_to_stderr (bool): Whether to duplicate logs to sys.stderr.
        """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        # Clear existing handlers to prevent duplicates
        if self._logger.hasHandlers():
            self._logger.handlers.clear()

        formatter = JSONFormatter()

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

        if log_to_stderr:
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            self._logger.addHandler(stream_handler)

        # Metrics state lock to ensure thread safety
        self._lock = threading.Lock()

        self._connection_count = 0
        self._auth_failure_count = 0
        self._active_sessions_count = 0

        self._total_bytes_up = 0
        self._total_bytes_down = 0
        self._ip_auth_failures: Dict[str, List[float]] = {}
        self._start_time = time.time()

    def _log(
        self, level: int, event: str, data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Sanitise *data* and emit a log record at the given severity level.

        Args:
            level: A ``logging`` module integer constant such as
                ``logging.INFO`` or ``logging.WARNING``.
            event: A short, human-readable description of the logged event.
            data: Optional context dict attached to the record under the
                ``"data"`` key after sanitisation.
        """
        safe_data = sanitize(data) if data else {}
        self._logger.log(level, event, extra={"data": safe_data})

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns a snapshot of the current operational metrics.

        Returns:
            dict: Internal counter metrics mapping names to integers.
        """
        with self._lock:
            return {
                "connection_count": self._connection_count,
                "auth_failure_count": self._auth_failure_count,
                "active_sessions_count": self._active_sessions_count,
                "total_bytes_up": self._total_bytes_up,
                "total_bytes_down": self._total_bytes_down,
                "uptime_seconds": int(time.time() - self._start_time),
            }

    def log_connection(self, client_ip: str, client_port: int) -> None:
        """Record an incoming TCP/TLS connection and increment the connection counter.

        Args:
            client_ip: Dotted-decimal IPv4 (or IPv6 string) of the connecting client.
            client_port: Ephemeral source port of the client.
        """
        with self._lock:
            self._connection_count += 1

        self._log(
            logging.INFO,
            "New Client Connection",
            {"client_ip": client_ip, "client_port": client_port},
        )

    def log_auth_success(self, username: str, session_id: str) -> None:
        """Record a successful authentication event and increment the active-session counter.

        Args:
            username: The authenticated username (never a password or credential).
            session_id: UUID-4 string assigned to the newly authenticated session.

        Security note:
            Only the username is logged — never pass password or hash values here.
        """
        with self._lock:
            self._active_sessions_count += 1

        self._log(
            logging.INFO,
            "Authentication Success",
            {"username": username, "session_id": session_id},
        )

    def log_auth_failure(
        self, username: str, reason: str, attempt: int, client_ip: str
    ) -> None:
        """Record a failed authentication attempt and update the per-IP sliding window.

        Timestamps of failures are maintained in a 300-second (5-minute) rolling
        window per IP, used by ``MonitoringDashboard.detect_anomalies`` to flag
        brute-force patterns.

        Args:
            username: The username that was attempted.  May be an unknown user.
            reason: Short human-readable reason for the failure.
            attempt: Ordinal attempt number (1-based) for this IP within the window.
            client_ip: IP address of the failing client, used for both the log
                record and the per-IP failure-rate tracking.

        Security note:
            Never pass the attempted password as *reason* or any other argument.
        """
        current_time = time.time()
        with self._lock:
            self._auth_failure_count += 1

            # Record time of failure for anomalies calculations (track 5 min window)
            ip_failures = self._ip_auth_failures.setdefault(client_ip, [])
            cutoff = current_time - 300
            self._ip_auth_failures[client_ip] = [t for t in ip_failures if t > cutoff]
            self._ip_auth_failures[client_ip].append(current_time)

        self._log(
            logging.WARNING,
            "Authentication Failure",
            {
                "username": username,
                "client_ip": client_ip,
                "reason": reason,
                "attempt": attempt,
            },
        )

    def log_disconnect(self, session_id: str, reason: str) -> None:
        """Record session termination and decrement the active-session counter.

        Args:
            session_id: UUID-4 of the terminated session.
            reason: Human-readable reason string (e.g. ``"Session timeout expired."``).
        """
        with self._lock:
            # Prevent going below 0 if some out-of-order state happens
            if self._active_sessions_count > 0:
                self._active_sessions_count -= 1

        self._log(
            logging.INFO,
            "Client Disconnected",
            {"session_id": session_id, "reason": reason},
        )

    def log_tunnel_open(
        self, session_id: str, target_host: str, target_port: int
    ) -> None:
        """Record the opening of a bidirectional relay to an internal service.

        Args:
            session_id: UUID-4 of the session that owns this tunnel.
            target_host: Hostname or IP of the internal destination service.
            target_port: TCP port of the internal destination service.
        """
        self._log(
            logging.INFO,
            "Tunnel Open",
            {
                "session_id": session_id,
                "target_host": target_host,
                "target_port": target_port,
            },
        )

    def log_tunnel_close(self, session_id: str) -> None:
        """Record the closure of the bidirectional relay for a session.

        Args:
            session_id: UUID-4 of the session whose tunnel has been torn down.
        """
        self._log(logging.INFO, "Tunnel Closed", {"session_id": session_id})

    def log_traffic(self, bytes_up: int, bytes_down: int) -> None:
        """Accumulate global byte counters after a tunnel closes.

        Called by ``TunnelRelay._cleanup`` with the final byte counts for a
        single session.  Counters are accessible via ``get_stats()``.

        Args:
            bytes_up: Bytes forwarded from the VPN client to the internal service.
            bytes_down: Bytes forwarded from the internal service to the VPN client.
        """
        with self._lock:
            self._total_bytes_up += bytes_up
            self._total_bytes_down += bytes_down

    def get_ip_auth_failures(self, window_seconds: int = 300) -> Dict[str, int]:
        """Return recent authentication failure counts per source IP.

        Used by ``MonitoringDashboard`` to detect brute-force patterns.

        Args:
            window_seconds: Length of the lookback window in seconds.  Only
                failures recorded within this window are counted.  Defaults
                to 300 (5 minutes).

        Returns:
            A dict mapping each IP that had ≥ 1 failure in the window to its
            failure count.  IPs with zero recent failures are omitted.

        Example:
            >>> stats = logger.get_ip_auth_failures(window_seconds=60)
            >>> stats.get("1.2.3.4", 0)
            3
        """
        failure_rates = {}
        current_time = time.time()
        cutoff = current_time - window_seconds

        with self._lock:
            for ip, failures in self._ip_auth_failures.items():
                recent_failures = len([t for t in failures if t > cutoff])
                if recent_failures > 0:
                    failure_rates[ip] = recent_failures

        return failure_rates

    def log_security_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Record a security-notable event at WARNING severity.

        Use for events that are not normal operational flow: blocked IPs,
        TLS handshake failures, protocol violations, relay errors, etc.

        Args:
            event_type: A short machine-readable tag for the event
                (e.g. ``"BLOCKED_IP_REJECTED"``, ``"TLS_HANDSHAKE_FAILED"``).
            data: Dict of supporting context.  Sensitive fields are
                automatically redacted by the ``_log`` helper.
        """
        self._log(
            logging.WARNING,
            "Security Event",
            {"event_type": event_type, "details": data},
        )


# Global logger instance management loosely coupling components
_global_logger: Optional[VPNLogger] = None


def setup_logger(
    log_level: str = "INFO", log_file: str = "server.log", log_to_stderr: bool = False
) -> None:
    import os
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    """Initialise the process-wide ``VPNLogger`` singleton.

    Must be called once at application start (typically from ``main()`` in
    ``vpn_server.py``) before any other module calls ``get_logger()``.  If
    ``get_logger`` is called before ``setup_logger``, a default fallback
    logger writing to ``"server.log"`` at ``INFO`` level is created
    automatically.

    Args:
        log_level: Minimum severity to record.  One of ``"DEBUG"``,
            ``"INFO"``, ``"WARNING"``, ``"ERROR"``, ``"CRITICAL"``.
            Defaults to ``"INFO"``.
        log_file: Absolute or relative path to the JSON log file.  The parent
            directory must exist; the file is created or appended.
        log_to_stderr: When ``True``, a second ``StreamHandler`` is attached
            so log records are also written to ``sys.stderr``.  Useful for
            development and containerised deployments.
    """
    global _global_logger
    _global_logger = VPNLogger("vpn_server", log_file, log_level, log_to_stderr)


def get_logger(module_name: str = "") -> "VPNLogger":
    """Retrieve the process-wide ``VPNLogger`` singleton, lazily creating it if needed.

    Modules should call ``get_logger(__name__)`` or simply ``get_logger()``
    at the point of use rather than caching the result in a module-level
    variable, because ``setup_logger`` may be called after the module's import
    time.

    Args:
        module_name: Informational only — the structured JSON output does not
            include a per-module logger name.  Kept for call-site readability
            (e.g. ``get_logger("TunnelRelay")``).

    Returns:
        The active ``VPNLogger`` instance.  If ``setup_logger`` has not been
        called, a default instance writing to ``"server.log"`` at ``INFO``
        level is created and returned.
    """
    global _global_logger
    if _global_logger is None:
        setup_logger()
    return _global_logger  # type: ignore
