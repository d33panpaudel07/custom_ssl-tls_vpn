"""
Custom exception hierarchy for the SSL/TLS VPN project.

This module defines a tree of domain-specific exceptions that map cleanly
to distinct failure categories: authentication, tunneling, protocol parsing,
and session management. Using typed exceptions instead of bare ``Exception``
lets callers catch exactly the failures they understand, rather than silently
swallowing unrelated errors.

Every exception carries a human-readable *message* and an optional *context*
dict that callers can attach with debugging metadata (IPs, session IDs, etc.)
without polluting the message string.
"""

from typing import Dict, Any, Optional

__all__ = [
    "VPNBaseException",
    "AuthenticationError",
    "InvalidCredentialsError",
    "TooManyAttemptsError",
    "TunnelError",
    "ConnectionRefusedError",
    "ForwardingError",
    "ProtocolError",
    "MalformedMessageError",
    "UnknownCommandError",
    "SessionError",
    "SessionExpiredError",
    "SessionNotFoundError",
]


class VPNBaseException(Exception):
    """Base class for all custom VPN exceptions.

    Subclass this for every domain-specific error rather than raising the
    built-in ``Exception`` directly.  The *context* dict keeps structured
    metadata separate from the user-facing *message*, making machine-readable
    log analysis straightforward.

    Args:
        message: Human-readable description of what went wrong.
        context: Optional dictionary of extra debugging data (e.g. IP address,
            session ID, attempt count).  Defaults to an empty dict.

    Example:
        >>> raise VPNBaseException("Something broke", context={"ip": "1.2.3.4"})
        Traceback (most recent call last):
            ...
        VPNBaseException: Something broke (context: {'ip': '1.2.3.4'})
    """

    def __init__(
        self, message: str, context: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def __str__(self) -> str:
        """Returns the message with appended context when context is non-empty."""
        if self.context:
            return f"{self.message} (context: {self.context})"
        return self.message


# ---------------------------------------------------------------------------
# Authentication branch
# ---------------------------------------------------------------------------


class AuthenticationError(VPNBaseException):
    """Base class for all authentication-related failures.

    Raised when the auth handshake cannot be completed, regardless of the
    specific cause.  Callers that want to distinguish *why* auth failed should
    catch the more specific sub-classes below.
    """


class InvalidCredentialsError(AuthenticationError):
    """Raised when the supplied username or password cannot be verified.

    This covers both "user does not exist" and "password mismatch" to avoid
    leaking enumerable information to an attacker via different error messages.

    Args:
        message: Reason for rejection (must NOT include the raw password).
        context: Optional dict — may include ``username`` but never the password.

    Security note:
        Do not include password text or partial hashes in *message* or *context*.

    Example:
        >>> raise InvalidCredentialsError("Authentication failed.")
    """


class TooManyAttemptsError(AuthenticationError):
    """Raised when an IP address exceeds the allowed authentication attempt rate.

    Triggered by ``AuthManager.rate_limit_check`` once an IP crosses the
    per-IP threshold (default: 3 failures / 60 s) or the global threshold
    (default: 100 failures across all IPs / 60 s).

    Args:
        message: Explanation of which limit was breached.
        context: Optional dict — may include ``client_ip`` and ``attempt_count``.

    Example:
        >>> raise TooManyAttemptsError("Max login attempts exceeded", {"client_ip": "1.2.3.4"})
    """


# ---------------------------------------------------------------------------
# Tunnel branch
# ---------------------------------------------------------------------------


class TunnelError(VPNBaseException):
    """Base class for failures in the bidirectional traffic relay.

    Raised when the underlying TCP or TLS connection between the VPN and the
    internal service encounters an unrecoverable error.
    """


class ConnectionRefusedError(TunnelError):
    """Raised when the internal target service actively refuses the TCP connection.

    Wraps the OS-level ``ConnectionRefusedError`` into the project's typed
    hierarchy so it can be caught uniformly alongside other VPN errors.

    Args:
        message: Human-readable description including host and port.
        context: Optional dict — typically ``{"host": ..., "port": ..., "error": ...}``.

    Example:
        >>> raise ConnectionRefusedError(
        ...     "Connection refused to 10.0.0.1:8080",
        ...     context={"host": "10.0.0.1", "port": 8080},
        ... )
    """


class ForwardingError(TunnelError):
    """Raised when a read or write fails mid-stream during traffic relay.

    Indicates that data transfer between the client TLS socket and the internal
    service socket was interrupted (e.g. peer reset, broken pipe).

    Args:
        message: Description of which direction failed.
        context: Optional dict — may include ``session_id`` and ``error`` text.
    """


# ---------------------------------------------------------------------------
# Protocol branch
# ---------------------------------------------------------------------------


class ProtocolError(VPNBaseException):
    """Base class for failures during VPN message encoding or decoding.

    Raised when a raw byte stream cannot be interpreted as a valid ``VPNMessage``
    or when an outbound message violates wire-format constraints.
    """


class MalformedMessageError(ProtocolError):
    """Raised when a byte frame does not conform to the expected wire format.

    Situations include: frame shorter than the 41-byte minimum header, a
    length-field mismatch, or a session_id that cannot be decoded as ASCII.

    Args:
        message: Specific constraint that was violated.
        context: Optional dict — may include ``received_length``, ``expected_length``.

    Example:
        >>> raise MalformedMessageError(
        ...     "Message too short: 5 bytes received, minimum 41 required.",
        ...     context={"received_length": 5},
        ... )
    """


class UnknownCommandError(ProtocolError):
    """Raised when a command byte or command string is not recognized by the protocol.

    Triggered on encode if an invalid command name is used, or on decode if the
    single-byte command field maps to no known ``Commands`` enum member.

    Args:
        message: The unrecognized value as a string.
        context: Optional dict — may include ``cmd_byte`` or ``command``.

    Example:
        >>> raise UnknownCommandError("Received unknown command byte: 255", {"cmd_byte": 255})
    """


# ---------------------------------------------------------------------------
# Session branch
# ---------------------------------------------------------------------------


class SessionError(VPNBaseException):
    """Base class for errors arising from invalid session state or capacity violations."""


class SessionExpiredError(SessionError):
    """Raised when an operation is attempted on a session that has timed out.

    The ``SessionManager`` background reaper thread calls ``Session.is_expired()``
    every 60 seconds.  Any code that retains a session reference across that
    boundary may encounter this.

    Args:
        message: Includes the expired session_id where helpful.
        context: Optional dict — may include ``session_id`` and ``timeout_seconds``.
    """


class SessionNotFoundError(SessionError):
    """Raised when a session_id lookup returns no result from the ``SessionManager``.

    This can happen if the session was already reaped, never created, or if the
    session_id is malformed.

    Args:
        message: Includes the missing session_id for tracing.
        context: Optional dict — may include ``session_id``.
    """
